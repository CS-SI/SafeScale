/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package iaas

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"

	scribble "github.com/nanobox-io/golang-scribble"
	uuid "github.com/satori/go.uuid"
	"github.com/xrash/smetrics"

	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	providers "github.com/CS-SI/SafeScale/lib/server/iaas/providers/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/volumestate"
	imagefilters "github.com/CS-SI/SafeScale/lib/server/iaas/resources/filters/images"
	templatefilters "github.com/CS-SI/SafeScale/lib/server/iaas/resources/filters/templates"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/crypt"
)

//go:generate mockgen -destination=mocks/mock_serviceapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/iaas Service

// Service agglomerates Provider and ObjectStorage interfaces in a single interface
// completed with higher-level methods
type Service interface {
	// --- from service ---

	CreateHostWithKeyPair(resources.HostRequest) (*resources.Host, *userdata.Content, *resources.KeyPair, error)
	FilterImages(string) ([]resources.Image, error)
	GetMetadataKey() *crypt.Key
	GetMetadataBucket() objectstorage.Bucket
	ListHostsByName() (map[string]*resources.Host, error)
	SearchImage(string) (*resources.Image, error)
	SelectTemplatesBySize(resources.SizingRequirements, bool) ([]*resources.HostTemplate, error)
	SelectTemplateByName(string) (*resources.HostTemplate, error)
	WaitHostState(string, hoststate.Enum, time.Duration) error
	WaitVolumeState(string, volumestate.Enum, time.Duration) (*resources.Volume, error)

	// --- from interface iaas.Providers ---
	providers.Provider

	// --- from interface ObjectStorage ---

	objectstorage.Location
}

// Service ...
type service struct {
	providers.Provider
	objectstorage.Location
	metadataBucket objectstorage.Bucket
	metadataKey    *crypt.Key

	whitelistTemplateRE *regexp.Regexp
	blacklistTemplateRE *regexp.Regexp
	whitelistImageRE    *regexp.Regexp
	blacklistImageRE    *regexp.Regexp
}

const (
	// CoreDRFWeight is the Dominant Resource Fairness weight of a core
	CoreDRFWeight float32 = 1.0
	// RAMDRFWeight is the Dominant Resource Fairness weight of 1 GB of RAM
	RAMDRFWeight float32 = 1.0 / 8.0
	// DiskDRFWeight is the Dominant Resource Fairness weight of 1 GB of Disk
	DiskDRFWeight float32 = 1.0 / 16.0
	// CPUFreqDRFWeight is the Dominant Resource Fairness weight of 1 GHz of cpu
	CPUFreqDRFWeight float32 = 1.0 / 2.0
	// GPUDRFWeight is the Dominant Resource Fairness weight of 1 GPU
	GPUDRFWeight float32 = 16.0
)

// RankDRF computes the Dominant Resource Fairness Rank of an host template
func RankDRF(t *resources.HostTemplate) float32 {
	fc := float32(t.Cores)
	fr := t.RAMSize
	fd := float32(t.DiskSize)
	ff := t.CPUFreq
	fg := float32(t.GPUNumber)
	return fc*CoreDRFWeight + fr*RAMDRFWeight + fd*DiskDRFWeight + ff*CPUFreqDRFWeight + fg*GPUDRFWeight
}

// ByRankDRF implements sort.Interface for []HostTemplate based on
// the Dominant Resource Fairness
type ByRankDRF []*resources.HostTemplate

func (a ByRankDRF) Len() int           { return len(a) }
func (a ByRankDRF) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByRankDRF) Less(i, j int) bool { return RankDRF(a[i]) < RankDRF(a[j]) }

// // HostAccess an host and the SSH Key Pair
// type HostAccess struct {
// 	Host    *resources.Host
// 	Key     *resources.KeyPair
// 	User    string
// 	Gateway *HostAccess
// }

// // GetAccessIP returns the access IP
// func (access *HostAccess) GetAccessIP() string {
// 	return access.Host.GetAccessIP()
// }

func (svc *service) GetMetadataBucket() objectstorage.Bucket {
	return svc.metadataBucket
}

func (svc *service) GetMetadataKey() *crypt.Key {
	return svc.metadataKey
}

// SetProvider allows to change provider interface of service object (mainly for test purposes)
func (svc *service) SetProvider(provider providers.Provider) {
	svc.Provider = provider
}

// WaitHostState waits an host achieve state
// If host in error state, returns utils.ErrNotAvailable
// If timeout is reached, returns utils.ErrTimeout
func (svc *service) WaitHostState(hostID string, state hoststate.Enum, timeout time.Duration) error {
	if svc == nil {
		return scerr.InvalidInstanceError()
	}

	var err error

	timer := time.After(timeout)
	host := resources.NewHost()
	host.ID = hostID

	c := make(chan error)

	go func() {
		defer close(c)
		for {
			host, err = svc.InspectHost(host)
			if err != nil {
				continue
			}
			if host.LastState == state {
				c <- nil
				break
			}
			if host.LastState == hoststate.ERROR {
				c <- scerr.NotAvailableError("host in error state")
				break
			}

			time.Sleep(1 * time.Second)
		}
	}()

	select {
	case <-timer:
		return scerr.TimeoutError("Wait host state timeout", timeout, nil)
	case err := <-c:
		return err
	}
}

// WaitVolumeState waits an host achieve state
// If timeout is reached, returns utils.ErrTimeout
func (svc *service) WaitVolumeState(volumeID string, state volumestate.Enum, timeout time.Duration) (*resources.Volume, error) {
	if svc == nil {
		return nil, scerr.InvalidInstanceError()
	}

	cout := make(chan int)
	next := make(chan bool)
	vc := make(chan *resources.Volume)

	go pollVolume(svc, volumeID, state, cout, next, vc)
	for {
		select {
		case res := <-cout:
			if res == 0 {
				return nil, fmt.Errorf("error getting host state")
			}
			if res == 1 {
				return <-vc, nil
			}
			if res == 2 {
				next <- true
			}
		case <-time.After(timeout):
			next <- false
			return nil, scerr.TimeoutError("Wait host state timeout", timeout, nil)
		}
	}
}

func pollVolume(svc *service, volumeID string, state volumestate.Enum, cout chan int, next chan bool, hostc chan *resources.Volume) {
	for {
		v, err := svc.GetVolume(volumeID)
		if err != nil {
			cout <- 0
			return
		}
		if v.State == state {
			cout <- 1
			hostc <- v
			return
		}
		cout <- 2
		if !<-next {
			return
		}
	}
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (svc *service) ListTemplates(all bool) ([]resources.HostTemplate, error) {
	allTemplates, err := svc.Provider.ListTemplates(all)
	if err != nil {
		return nil, err
	}
	if all {
		return allTemplates, nil
	}
	return svc.reduceTemplates(allTemplates), nil
}

// SelectTemplateByName returns the template by its name
func (svc *service) SelectTemplateByName(name string) (*resources.HostTemplate, error) {
	allTemplates, err := svc.Provider.ListTemplates(true)
	if err != nil {
		return nil, err
	}
	for _, i := range allTemplates {
		if i.Name == name {
			return &i, nil
		}
	}
	return nil, scerr.NotFoundError(fmt.Sprintf("template named '%s' not found", name))
}

func (svc *service) reduceTemplates(tpls []resources.HostTemplate) []resources.HostTemplate {
	var finalFilter *templatefilters.Filter
	if svc.whitelistTemplateRE != nil {
		finalFilter = templatefilters.NewFilter(filterTemplatesByRegex(svc.whitelistTemplateRE))
	}
	if svc.blacklistTemplateRE != nil {
		blackFilter := templatefilters.NewFilter(filterTemplatesByRegex(svc.blacklistTemplateRE))
		if finalFilter == nil {
			finalFilter = blackFilter.Not()
		} else {
			finalFilter = finalFilter.And(blackFilter.Not())
		}
	}
	if finalFilter != nil {
		return templatefilters.FilterTemplates(tpls, finalFilter)
	}
	return tpls
}

func filterTemplatesByRegex(re *regexp.Regexp) templatefilters.Predicate {
	return func(tpl resources.HostTemplate) bool {
		return re.Match([]byte(tpl.Name))
	}
}

// SelectTemplatesBySize select templates satisfying sizing requirements
// returned list is ordered by size fitting
func (svc *service) SelectTemplatesBySize(sizing resources.SizingRequirements, force bool) (selectedTpls []*resources.HostTemplate, err error) {
	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if svc == nil {
		return nil, scerr.InvalidInstanceError()
	}

	allTpls, err := svc.ListTemplates(false)
	if err != nil {
		return nil, err
	}
	logSizingRequirement(sizing)
	//if scanner db is found complement HostTemplate with scanner DB info
	svc.tryReadInfoFromScannerDB(allTpls)

	for _, t := range allTpls {
		standardFit := templateFitStandardSizing(&t, sizing)
		additionalFit := templateFitAdditionalSizing(&t, sizing)
		if standardFit && (additionalFit || force) {
			tpl := t
			selectedTpls = append(selectedTpls, &tpl)
		}
	}

	sort.Sort(ByRankDRF(selectedTpls))
	return selectedTpls, nil
}

func logSizingRequirement(sizing resources.SizingRequirements) {
	if sizing.MinCores == 0 && sizing.MaxCores == 0 && sizing.MinRAMSize == 0 && sizing.MaxRAMSize == 0 {
		log.Debugf("Looking for a host template as small as possible")
	} else {
		coreMsg := ""
		if sizing.MinCores > 0 {
			if sizing.MaxCores > 0 {
				coreMsg = fmt.Sprintf("between %d and %d", sizing.MinCores, sizing.MaxCores)
			} else {
				coreMsg = fmt.Sprintf("at least %d", sizing.MinCores)
			}
		} else {
			coreMsg = fmt.Sprintf("at most %d", sizing.MaxCores)
		}
		ramMsg := ""
		if sizing.MinRAMSize > 0 {
			if sizing.MaxRAMSize > 0 {
				ramMsg = fmt.Sprintf("between %.01f and %.01f", sizing.MinRAMSize, sizing.MaxRAMSize)
			} else {
				ramMsg = fmt.Sprintf("at least %.01f", sizing.MinRAMSize)
			}
		} else {
			coreMsg = fmt.Sprintf("at most %.01f", sizing.MaxRAMSize)
		}
		diskMsg := ""
		if sizing.MinDiskSize > 0 {
			diskMsg = fmt.Sprintf(" and at least %d GB of disk", sizing.MinDiskSize)
		}

		log.Debugf(fmt.Sprintf("Looking for a host template with: %s cores, %s RAM%s", coreMsg, ramMsg, diskMsg))
	}
}
func templateFitStandardSizing(tpl *resources.HostTemplate, sizing resources.SizingRequirements) bool{
	fit := tpl.Cores >= sizing.MinCores || tpl.Cores <= sizing.MaxCores
	fit = fit && tpl.RAMSize >= sizing.MinRAMSize && tpl.RAMSize <= sizing.MaxRAMSize
	return fit
}

func templateFitAdditionalSizing(tpl *resources.HostTemplate, sizing resources.SizingRequirements) bool {
	fit :=  tpl.CPUFreq >= sizing.MinFreq
	fit = fit && tpl.GPUNumber >= sizing.MinGPU
	return fit
}


func addScannerInfo(tpl *resources.HostTemplate, images map[string]resources.StoredCPUInfo){
	if img, ok := images[tpl.ID]; ok{
		tpl.GPUNumber = img.GPU
		tpl.CPUFreq = float32(img.CPUFrequency)
		tpl.GPUType = img.GPUModel
	}
}

func (svc *service) tryReadInfoFromScannerDB(allTpls []resources.HostTemplate)  {
	_ = os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777)
	db, err := scribble.New(utils.AbsPathify("$HOME/.safescale/scanner/db"), nil)
	if err != nil {
		return
	}
	authOpts, err := svc.GetAuthenticationOptions()
	if err != nil {
		return
	}
	region, ok := authOpts.Get("Region")
	if !ok {
		log.Error("region value unset")
		return
	}
	folder := fmt.Sprintf("images/%s/%s", svc.GetName(), region)

	imageList, err := db.ReadAll(folder)
	if err != nil {
		return
	}
	images := make(map[string]resources.StoredCPUInfo)
	for _, f := range imageList {
		imageFound := resources.StoredCPUInfo{}
		if err := json.Unmarshal([]byte(f), &imageFound); err != nil {
			log.Error(fmt.Sprintf("error unmarsalling image %s : %v", f, err))
		}
		images[imageFound.ID] = imageFound
	}
	for i:=0; i<len(allTpls); i++{//overload values, do not use range
		addScannerInfo(&allTpls[i], images)
	}

	return
}

type scoredImage struct {
	resources.Image
	score float64
}

type scoredImages []scoredImage

func (a scoredImages) Len() int           { return len(a) }
func (a scoredImages) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a scoredImages) Less(i, j int) bool { return a[i].score < a[j].score }

// FilterImages search an images corresponding to OS Name
func (svc *service) FilterImages(filter string) ([]resources.Image, error) {
	if svc == nil {
		return nil, scerr.InvalidInstanceError()
	}

	var imgs []resources.Image
	err := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			var err error
			imgs, err = svc.ListImages(false)
			return err
		},
		temporal.GetExecutionTimeout(),
	)
	if err != nil {
		return nil, err
	}
	imgs = svc.reduceImages(imgs)

	if len(filter) == 0 {
		return imgs, nil
	}
	var simgs []scoredImage
	//fields := strings.Split(strings.ToUpper(osname), " ")
	for _, img := range imgs {
		//score := 1 / float64(smetrics.WagnerFischer(strings.ToUpper(img.Name), strings.ToUpper(osname), 1, 1, 2))
		score := smetrics.JaroWinkler(strings.ToUpper(img.Name), strings.ToUpper(filter), 0.7, 5)
		//score := matchScore(fields, strings.ToUpper(img.Name))
		//score := SimilarityScore(filter, img.Name)
		if score > 0.5 {
			simgs = append(simgs, scoredImage{
				Image: img,
				score: score,
			})
		}

	}
	var fimgs []resources.Image
	sort.Sort(scoredImages(simgs))
	for _, simg := range simgs {
		fimgs = append(fimgs, simg.Image)
	}

	return fimgs, nil

}

func (svc *service) reduceImages(imgs []resources.Image) []resources.Image {
	var finalFilter *imagefilters.Filter
	if svc.whitelistImageRE != nil {
		finalFilter = imagefilters.NewFilter(filterImagesByRegex(svc.whitelistImageRE))
	}
	if svc.blacklistImageRE != nil {
		blackFilter := imagefilters.NewFilter(filterImagesByRegex(svc.blacklistImageRE))
		if finalFilter == nil {
			finalFilter = blackFilter.Not()
		} else {
			finalFilter = finalFilter.And(blackFilter.Not())
		}
	}
	if finalFilter != nil {
		// templateFilter := templatefilters.NewFilter(finalFilter)
		return imagefilters.FilterImages(imgs, finalFilter)
	}
	return imgs
}

func filterImagesByRegex(re *regexp.Regexp) imagefilters.Predicate {
	return func(img resources.Image) bool {
		return re.Match([]byte(img.Name))
	}
}

// ListImages reduces the list of needed
func (svc *service) ListImages(all bool) ([]resources.Image, error) {
	imgs, err := svc.Provider.ListImages(all)
	if err != nil {
		return nil, err
	}
	return svc.reduceImages(imgs), nil
}

// SearchImage search an image corresponding to OS Name
func (svc *service) SearchImage(osname string) (*resources.Image, error) {
	if svc == nil {
		return nil, scerr.InvalidInstanceError()
	}

	imgs, err := svc.ListImages(false)
	if err != nil {
		return nil, err
	}

	log.Debugf("We are looking for an image for %s", svc.GetName())

	if svc.GetName() == "aws" {
		// FIXME AWS Mappings

		if strings.EqualFold(osname, "CentOS 7.3") {
			osname = "ami-0ec8d2a455affc7e4"
		}

		if strings.EqualFold(osname, "Ubuntu 18.04") {
			osname = "ami-0cc0a36f626a4fdf5"
		}
	}

	// If is an exact match for an Image return that image
	for _, img := range imgs {
		if img.ID == osname {
			return &img, nil
		}
	}

	maxscore := 0.0
	maxi := -1
	//fields := strings.Split(strings.ToUpper(osname), " ")
	for i, img := range imgs {
		//score := 1 / float64(smetrics.WagnerFischer(strings.ToUpper(img.Name), strings.ToUpper(osname), 1, 1, 2))
		score := smetrics.JaroWinkler(strings.ToUpper(img.Name), strings.ToUpper(osname), 0.7, 5)
		//score := matchScore(fields, strings.ToUpper(img.Name))
		//score := SimilarityScore(osname, img.Name)
		if score > maxscore {
			maxscore = score
			maxi = i
		}

	}
	//fmt.Println(fields, len(fields))
	//fmt.Println(len(fields))
	if maxscore < 0.5 || maxi < 0 || len(imgs) == 0 {
		return nil, fmt.Errorf("unable to find an image matching %s", osname)
	}

	log.Infof("Selected image: '%s' (ID='%s')", imgs[maxi].Name, imgs[maxi].ID)
	return &imgs[maxi], nil
}

// CreateHostWithKeyPair creates an host
func (svc *service) CreateHostWithKeyPair(request resources.HostRequest) (*resources.Host, *userdata.Content, *resources.KeyPair, error) {
	if svc == nil {
		return nil, nil, nil, scerr.InvalidInstanceError()
	}

	_, err := svc.GetHostByName(request.ResourceName)
	if err == nil {
		return nil, nil, nil, resources.ResourceDuplicateError("Host", request.ResourceName)
	}

	// Create temporary key pair
	kpNameuuid, err := uuid.NewV4()
	if err != nil {
		return nil, nil, nil, err
	}

	kpName := kpNameuuid.String()
	kp, err := svc.CreateKeyPair(kpName)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create host
	hostReq := resources.HostRequest{
		ResourceName:   request.ResourceName,
		HostName:       request.HostName,
		ImageID:        request.ImageID,
		KeyPair:        kp,
		PublicIP:       request.PublicIP,
		Networks:       request.Networks,
		DefaultRouteIP: request.DefaultRouteIP,
		DefaultGateway: request.DefaultGateway,
		TemplateID:     request.TemplateID,
	}
	host, userData, err := svc.CreateHost(hostReq)
	if err != nil {
		return nil, nil, nil, err
	}
	return host, userData, kp, nil
}

// ListHostsByName list hosts by name
func (svc *service) ListHostsByName() (map[string]*resources.Host, error) {
	if svc == nil {
		return nil, scerr.InvalidInstanceError()
	}

	hosts, err := svc.ListHosts()
	if err != nil {
		return nil, err
	}
	hostMap := make(map[string]*resources.Host)
	for _, host := range hosts {
		hostMap[host.Name] = host
	}
	return hostMap, nil
}

func runeIndexes(s string, r rune) []int {
	var positions []int
	for i, l := range s {
		if l == r {
			positions = append(positions, i)
		}
	}
	return positions

}

func runesIndexes(ref string, s string) [][]int {
	var positions [][]int
	uref := strings.ToUpper(ref)
	us := strings.ToUpper(s)
	for _, r := range uref {
		if r != ' ' {
			positions = append(positions, runeIndexes(us, r))
		}
	}
	return positions
}

func recPossiblePathes(positions [][]int, level int) [][]int {
	var newPathes [][]int
	if level >= len(positions) {
		return [][]int{
			[]int{},
		}
	}
	pathes := recPossiblePathes(positions, level+1)
	if len(positions[level]) == 0 {
		for _, path := range pathes {
			newPathes = append(newPathes, append([]int{-1}, path...))
		}
	} else {
		for _, idx := range positions[level] {
			for _, path := range pathes {
				newPathes = append(newPathes, append([]int{idx}, path...))
			}
		}
	}

	return newPathes
}

func possiblePathes(positions [][]int) [][]int {
	return recPossiblePathes(positions, 0)
}

func bestPath(pathes [][]int, size int) (int, int) {
	if len(pathes) == 0 {
		return -1, 10000
	}
	minD := distance(pathes[0], size)
	bestI := 0
	for i, p := range pathes {
		d := distance(p, size)
		if d < minD {
			minD = d
			bestI = i
		}
	}
	return bestI, minD
}

func distance(path []int, size int) int {
	d := 0
	previous := path[0]
	for _, index := range path {
		if index < 0 {
			d += size
		} else {
			di := index - previous
			d += di
			if di < 0 {
				d += di + size
			}
		}
		previous = index
	}
	return d
}

func score(d int, rsize int) float64 {
	return float64(rsize-1) / float64(d)
}

// SimilarityScore computes a similariy score between 2 strings
func SimilarityScore(ref string, s string) float64 {
	size := len(s)
	rsize := len(ref)
	if rsize > size {
		return SimilarityScore(s, ref)
	}
	_, d := bestPath(possiblePathes(runesIndexes(ref, s)), size)
	ds := math.Abs(float64(size-rsize)) / float64(rsize)
	return score(d, len(ref)) / (math.Log10(10 * (1. + ds)))
}

// InitializeBucket creates the Object Storage Container/Bucket that will store the metadata
func InitializeBucket(svc *service, location objectstorage.Location) error {
	cfg, err := svc.Provider.GetConfigurationOptions()
	if err != nil {
		return fmt.Errorf("failed to get client options: %s", err.Error())
	}
	anon, found := cfg.Get("MetadataBucket")
	if !found || anon.(string) == "" {
		return fmt.Errorf("failed to get value of option 'MetadataBucket'")
	}
	_, err = location.CreateBucket(anon.(string))
	if err != nil {
		return err
	}
	return nil
}
