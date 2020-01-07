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
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"

	scribble "github.com/nanobox-io/golang-scribble"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
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
)

// RankDRF computes the Dominant Resource Fairness Rank of an host template
func RankDRF(t *resources.HostTemplate) float32 {
	fc := float32(t.Cores)
	fr := t.RAMSize
	fd := float32(t.DiskSize)
	return fc*CoreDRFWeight + fr*RAMDRFWeight + fd*DiskDRFWeight
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
	for {
		host, err = svc.InspectHost(host)
		if err != nil {
			return err
		}
		if host.LastState == state {
			return nil
		}
		if host.LastState == hoststate.ERROR {
			return scerr.NotAvailableError("host in error state")
		}
		select {
		case <-timer:
			return scerr.TimeoutError("Wait volume state timeout", timeout, nil)
		default:
			time.Sleep(1 * time.Second)
		}
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
	scannerTpls := map[string]bool{}
	if err != nil {
		return nil, err
	}

	// FIXME Prevent GPUs when user sends a 0
	askedForSpecificScannerInfo := sizing.MinGPU >= 0 || sizing.MinFreq != 0
	if askedForSpecificScannerInfo {
		_ = os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777)
		db, err := scribble.New(utils.AbsPathify("$HOME/.safescale/scanner/db"), nil)
		if err != nil {
			if force {
				log.Warnf("Problem creating / accessing Scanner database, ignoring GPU and Freq parameters for now...: %v", err)
			} else {
				var noHostError string
				if sizing.MinFreq <= 0 {
					noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs, problem accessing Scanner database: %v", sizing.MinGPU, err)
				} else {
					noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs and '%.01f' MHz clock frequency, problem accessing Scanner database: %v", sizing.MinGPU, sizing.MinFreq, err)
				}
				log.Error(noHostError)
				return nil, fmt.Errorf(noHostError)
			}
		} else {
			authOpts, err := svc.GetAuthenticationOptions()
			if err != nil {
				return nil, err
			}
			region, ok := authOpts.Get("Region")
			if !ok {
				return nil, fmt.Errorf("region value unset")
			}
			folder := fmt.Sprintf("images/%s/%s", svc.GetName(), region)

			imageList, err := db.ReadAll(folder)
			if err != nil {
				if force {
					log.Warnf("Problem creating / accessing Scanner database, ignoring GPU and Freq parameters for now...: %v", err)
				} else {
					var noHostError string
					if sizing.MinFreq <= 0 {
						noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs, problem accessing Scanner database: %v", sizing.MinGPU, err)
					} else {
						noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs and '%.01f' MHz clock frequency, problem accessing Scanner database: %v", sizing.MinGPU, sizing.MinFreq, err)
					}
					log.Error(noHostError)
					return nil, fmt.Errorf(noHostError)
				}
			} else {
				var images []resources.StoredCPUInfo
				for _, f := range imageList {
					imageFound := resources.StoredCPUInfo{}
					if err := json.Unmarshal([]byte(f), &imageFound); err != nil {
						log.Error(fmt.Sprintf("error unmarsalling image %s : %v", f, err))
					}

					// if the user asked explicitly no gpu
					if sizing.MinGPU == 0 && imageFound.GPU != 0 {
						continue
					}

					if imageFound.GPU < sizing.MinGPU {
						continue
					}

					if imageFound.CPUFrequency < float64(sizing.MinFreq) {
						continue
					}

					images = append(images, imageFound)
				}

				if !force && (len(images) == 0) {
					var noHostError string
					if sizing.MinFreq <= 0 {
						noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs, no images matching requirements", sizing.MinGPU)
					} else {
						noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs and a CPU clock frequencyof '%.01f MHz', no images matching requirements", sizing.MinGPU, sizing.MinFreq)
					}
					log.Error(noHostError)
					return nil, fmt.Errorf(noHostError)
				}

				for _, image := range images {
					scannerTpls[image.TemplateID] = true
				}
			}
		}
	}

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

	for _, t := range allTpls {
		msg := fmt.Sprintf("Discard machine template '%s' with : %d cores, %.01f GB of RAM, and %d GB of Disk:", t.Name, t.Cores, t.RAMSize, t.DiskSize)
		msg += " %s"
		if sizing.MinCores > 0 && t.Cores < sizing.MinCores {
			log.Debugf(msg, "not enough cores")
			continue
		}
		if sizing.MaxCores > 0 && t.Cores > sizing.MaxCores {
			log.Debugf(msg, "too many cores")
			continue
		}
		if sizing.MinRAMSize > 0.0 && t.RAMSize < sizing.MinRAMSize {
			log.Debugf(msg, "not enough RAM")
			continue
		}
		if sizing.MaxRAMSize > 0.0 && t.RAMSize > sizing.MaxRAMSize {
			log.Debugf(msg, "too many RAM")
			continue
		}
		if t.DiskSize > 0 && sizing.MinDiskSize > 0 && t.DiskSize < sizing.MinDiskSize {
			log.Debugf(msg, "not enough disk")
			continue
		}

		if _, ok := scannerTpls[t.ID]; ok || !askedForSpecificScannerInfo {
			newT := t
			selectedTpls = append(selectedTpls, &newT)
		}
	}

	sort.Sort(ByRankDRF(selectedTpls))
	return selectedTpls, nil
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

	imgs, err := svc.ListImages(false)
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
