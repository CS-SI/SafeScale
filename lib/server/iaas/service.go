/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	scribble "github.com/nanobox-io/golang-scribble"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/xrash/smetrics"

	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	imagefilters "github.com/CS-SI/SafeScale/lib/server/resources/abstract/filters/images"
	templatefilters "github.com/CS-SI/SafeScale/lib/server/resources/abstract/filters/templates"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
)

//go:generate mockgen -destination=mocks/mock_serviceapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/iaas Service

// Service consolidates Provider and ObjectStorage.Location interfaces in a single interface
// completed with higher-level methods
type Service interface {
	data.NullValue

	// --- from service ---
	CreateHostWithKeyPair(abstract.HostRequest) (*abstract.HostFull, *userdata.Content, *abstract.KeyPair, fail.Error)
	FilterImages(string) ([]abstract.Image, fail.Error)
	GetMetadataBucket() abstract.ObjectStorageBucket
	GetMetadataKey() (*crypt.Key, fail.Error)
	ListHostsByName(bool) (map[string]*abstract.HostFull, fail.Error)
	SearchImage(string) (*abstract.Image, fail.Error)
	SelectTemplatesBySize(abstract.HostSizingRequirements, bool) ([]*abstract.HostTemplate, fail.Error)
	SelectTemplateByName(string) (*abstract.HostTemplate, fail.Error)
	WaitHostState(string, hoststate.Enum, time.Duration) fail.Error
	WaitVolumeState(string, volumestate.Enum, time.Duration) (*abstract.Volume, fail.Error)

	TenantCleanup(bool) fail.Error // cleans up the data relative to SafeScale from tenant (not implemented yet)

	// --- from interface iaas.Providers ---
	providers.Provider

	LookupRuleInSecurityGroup(*abstract.SecurityGroup, abstract.SecurityGroupRule) (bool, fail.Error)

	// --- from interface objectstorage.Location ---
	objectstorage.Location
}

// GetService ...
type service struct {
	providers.Provider
	objectstorage.Location

	//	metadataBucket objectstorage.GetBucket
	metadataBucket abstract.ObjectStorageBucket
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
func RankDRF(t *abstract.HostTemplate) float32 {
	fc := float32(t.Cores)
	fr := t.RAMSize
	fd := float32(t.DiskSize)
	return fc*CoreDRFWeight + fr*RAMDRFWeight + fd*DiskDRFWeight
}

// ByRankDRF implements sort.Interface for []HostTemplate based on
// the Dominant Resource Fairness
type ByRankDRF []*abstract.HostTemplate

func (a ByRankDRF) Len() int           { return len(a) }
func (a ByRankDRF) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByRankDRF) Less(i, j int) bool { return RankDRF(a[i]) < RankDRF(a[j]) }

// NullService creates a service instance corresponding to null value
func NullService() *service {
	return &service{}
}

// IsNull tells if the instance is null value
func (svc *service) IsNull() bool {
	return svc == nil || svc.Provider == nil
}

// GetName ...
// Satisfies interface data.Identifiable
func (svc service) GetName() string {
	if svc.IsNull() {
		return ""
	}
	return svc.Provider.GetName()
}

// GetID ...
// Satisfies interface data.Identifiable
func (svc service) GetID() string {
	if svc.IsNull() {
		return ""
	}
	return svc.Provider.GetName()
}

// GetMetadataBucket returns the bucket instance describing metadata bucket
func (svc service) GetMetadataBucket() abstract.ObjectStorageBucket {
	if svc.IsNull() {
		return abstract.ObjectStorageBucket{}
	}
	return svc.metadataBucket
}

// GetMetadataKey returns the key used to crypt data in metadata bucket
func (svc service) GetMetadataKey() (*crypt.Key, fail.Error) {
	if svc.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if svc.metadataKey == nil {
		return nil, fail.NotFoundError("no crypt key defined for metadata content")
	}
	return svc.metadataKey, nil
}

// ChangeProvider allows to change provider interface of service object (mainly for test purposes)
func (svc *service) ChangeProvider(provider providers.Provider) fail.Error {
	if svc.IsNull() {
		return fail.InvalidInstanceError()
	}
	if provider == nil {
		return fail.InvalidParameterError("provider", "cannot be nil")
	}
	svc.Provider = provider
	return nil
}

// WaitHostState waits an host achieve state
// If host in error state, returns utils.ErrNotAvailable
// If timeout is reached, returns utils.ErrTimeout
func (svc service) WaitHostState(hostID string, state hoststate.Enum, timeout time.Duration) (rerr fail.Error) {
	if svc.IsNull() {
		return fail.InvalidInstanceError()
	}
	if hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}

	timer := time.After(timeout)
	host := abstract.NewHostFull()
	host.Core.ID = hostID
	for {
		host, rerr = svc.InspectHost(host)
		if rerr != nil {
			return rerr
		}
		if host.CurrentState == state {
			return nil
		}
		if host.CurrentState == hoststate.ERROR {
			return fail.NotAvailableError("host in error state")
		}
		select {
		case <-timer:
			return fail.TimeoutError(nil, timeout, "Wait volume state timeout")
		default:
			time.Sleep(1 * time.Second)
		}
	}
}

// WaitVolumeState waits an host achieve state
// If timeout is reached, returns utils.ErrTimeout
func (svc service) WaitVolumeState(volumeID string, state volumestate.Enum, timeout time.Duration) (*abstract.Volume, fail.Error) {
	if svc.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if volumeID == "" {
		return nil, fail.InvalidParameterError("volumeID", "cannot be empty string")
	}

	cout := make(chan int)
	next := make(chan bool)
	vc := make(chan *abstract.Volume)

	go pollVolume(svc, volumeID, state, cout, next, vc)
	for {
		select {
		case res := <-cout:
			if res == 0 {
				return nil, fail.NewError("error getting host state")
			}
			if res == 1 {
				return <-vc, nil
			}
			if res == 2 {
				next <- true
			}
		case <-time.After(timeout):
			next <- false
			return nil, fail.TimeoutError(nil, timeout, "Wait host state timeout")
		}
	}
}

func pollVolume(svc service, volumeID string, state volumestate.Enum, cout chan int, next chan bool, hostc chan *abstract.Volume) {
	for {
		v, err := svc.InspectVolume(volumeID)
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
func (svc service) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
	if svc.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

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
func (svc service) SelectTemplateByName(name string) (*abstract.HostTemplate, fail.Error) {
	if svc.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	allTemplates, err := svc.Provider.ListTemplates(true)
	if err != nil {
		return nil, err
	}
	for _, i := range allTemplates {
		if i.Name == name {
			return &i, nil
		}
	}
	return nil, fail.NotFoundError(fmt.Sprintf("template named '%s' not found", name))
}

func (svc service) reduceTemplates(tpls []abstract.HostTemplate) []abstract.HostTemplate {
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
	return func(tpl abstract.HostTemplate) bool {
		return re.Match([]byte(tpl.Name))
	}
}

// SelectTemplatesBySize select templates satisfying sizing requirements
// returned list is ordered by size fitting
func (svc service) SelectTemplatesBySize(sizing abstract.HostSizingRequirements, force bool) (selectedTpls []*abstract.HostTemplate, rerr fail.Error) {
	if svc.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true, "").Entering()
	defer tracer.Exiting()

	allTpls, rerr := svc.ListTemplates(false)
	scannerTpls := map[string]bool{}
	if rerr != nil {
		return nil, rerr
	}

	// FIXME: Prevent GPUs when user sends a 0
	askedForSpecificScannerInfo := sizing.MinGPU >= 0 || sizing.MinCPUFreq != 0
	if askedForSpecificScannerInfo {
		_ = os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777)
		db, err := scribble.New(utils.AbsPathify("$HOME/.safescale/scanner/db"), nil)
		if err != nil {
			if force {
				logrus.Warnf("Problem creating / accessing Scanner database, ignoring GPU and Freq parameters for now...: %v", err)
			} else {
				var noHostError string
				if sizing.MinCPUFreq <= 0 {
					noHostError = fmt.Sprintf("unable to create a host with '%d' GPUs, problem accessing Scanner database: %v", sizing.MinGPU, err)
				} else {
					noHostError = fmt.Sprintf("unable to create a host with '%d' GPUs and '%.01f' MHz clock frequency, problem accessing Scanner database: %v", sizing.MinGPU, sizing.MinCPUFreq, err)
				}
				return nil, fail.NewError(noHostError)
			}
		} else {
			authOpts, rerr := svc.GetAuthenticationOptions()
			if rerr != nil {
				return nil, rerr
			}
			region, ok := authOpts.Get("Region")
			if !ok {
				return nil, fail.SyntaxError("region value unset")
			}
			folder := fmt.Sprintf("images/%s/%s", svc.GetName(), region)

			imageList, err := db.ReadAll(folder)
			if err != nil {
				if force {
					logrus.Warnf("Problem creating / accessing Scanner database, ignoring GPU and Freq parameters for now...: %v", err)
				} else {
					var noHostError string
					if sizing.MinCPUFreq <= 0 {
						noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs, problem accessing Scanner database: %v", sizing.MinGPU, err)
					} else {
						noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs and '%.01f' MHz clock frequency, problem accessing Scanner database: %v", sizing.MinGPU, sizing.MinCPUFreq, err)
					}
					logrus.Error(noHostError)
					return nil, fail.NewError(noHostError)
				}
			} else {
				var images []abstract.StoredCPUInfo
				for _, f := range imageList {
					imageFound := abstract.StoredCPUInfo{}
					if err := json.Unmarshal([]byte(f), &imageFound); err != nil {
						return nil, fail.Wrap(err, "error unmarshalling image '%s'")
					}

					// if the user asked explicitly no gpu
					if sizing.MinGPU == 0 && imageFound.GPU != 0 {
						continue
					}

					if imageFound.GPU < sizing.MinGPU {
						continue
					}

					if imageFound.CPUFrequency < float64(sizing.MinCPUFreq) {
						continue
					}

					images = append(images, imageFound)
				}

				if !force && (len(images) == 0) {
					var noHostError string
					if sizing.MinCPUFreq <= 0 {
						noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs, no images matching requirements", sizing.MinGPU)
					} else {
						noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs and a CPU clock frequencyof '%.01f MHz', no images matching requirements", sizing.MinGPU, sizing.MinCPUFreq)
					}
					logrus.Error(noHostError)
					return nil, fail.NewError(noHostError)
				}

				for _, image := range images {
					scannerTpls[image.TemplateID] = true
				}
			}
		}
	}

	if sizing.MinCores == 0 && sizing.MaxCores == 0 && sizing.MinRAMSize == 0 && sizing.MaxRAMSize == 0 {
		logrus.Debugf("Looking for a host template as small as possible")
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
		gpuMsg := ""
		if sizing.MinGPU >= 0 {
			gpuMsg = fmt.Sprintf("%d GPU%s", sizing.MinGPU, strprocess.Plural(uint(sizing.MinGPU)))
		}
		logrus.Debugf(fmt.Sprintf("Looking for a host template with: %s cores, %s RAM, %s%s", coreMsg, ramMsg, gpuMsg, diskMsg))
	}

	for _, t := range allTpls {
		msg := fmt.Sprintf("Discarded host template '%s' with %d cores, %.01f GB of RAM, %d GPU and %d GB of Disk:", t.Name, t.Cores, t.RAMSize, t.GPUNumber, t.DiskSize)
		msg += " %s"
		if sizing.MinCores > 0 && t.Cores < sizing.MinCores {
			logrus.Debugf(msg, "not enough cores")
			continue
		}
		if sizing.MaxCores > 0 && t.Cores > sizing.MaxCores {
			logrus.Debugf(msg, "too many cores")
			continue
		}
		if sizing.MinRAMSize > 0.0 && t.RAMSize < sizing.MinRAMSize {
			logrus.Debugf(msg, "not enough RAM")
			continue
		}
		if sizing.MaxRAMSize > 0.0 && t.RAMSize > sizing.MaxRAMSize {
			logrus.Debugf(msg, "too many RAM")
			continue
		}
		if t.DiskSize > 0 && sizing.MinDiskSize > 0 && t.DiskSize < sizing.MinDiskSize {
			logrus.Debugf(msg, "not enough disk")
			continue
		}
		if (sizing.MinGPU <= 0 && t.GPUNumber > 0) || (sizing.MinGPU > 0 && t.GPUNumber > sizing.MinGPU) {
			logrus.Debugf(msg, "too many GPU")
			continue
		}

		if _, ok := scannerTpls[t.ID]; (ok || !askedForSpecificScannerInfo) && t.ID != "" {
			newT := t
			selectedTpls = append(selectedTpls, &newT)
		}
	}

	sort.Sort(ByRankDRF(selectedTpls))
	return selectedTpls, nil
}

type scoredImage struct {
	abstract.Image
	score float64
}

type scoredImages []scoredImage

func (a scoredImages) Len() int           { return len(a) }
func (a scoredImages) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a scoredImages) Less(i, j int) bool { return a[i].score < a[j].score }

// FilterImages search an images corresponding to OS Name
func (svc service) FilterImages(filter string) ([]abstract.Image, fail.Error) {
	if svc.IsNull() {
		return nil, fail.InvalidInstanceError()
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
	// fields := strings.Split(strings.ToUpper(osname), " ")
	for _, img := range imgs {
		// score := 1 / float64(smetrics.WagnerFischer(strings.ToUpper(img.Name), strings.ToUpper(osname), 1, 1, 2))
		score := smetrics.JaroWinkler(strings.ToUpper(img.Name), strings.ToUpper(filter), 0.7, 5)
		// score := matchScore(fields, strings.ToUpper(img.Name))
		// score := SimilarityScore(filter, img.Name)
		if score > 0.5 {
			simgs = append(simgs, scoredImage{
				Image: img,
				score: score,
			})
		}

	}
	var fimgs []abstract.Image
	sort.Sort(scoredImages(simgs))
	for _, simg := range simgs {
		fimgs = append(fimgs, simg.Image)
	}

	return fimgs, nil

}

func (svc service) reduceImages(imgs []abstract.Image) []abstract.Image {
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
	return func(img abstract.Image) bool {
		return re.Match([]byte(img.Name))
	}
}

// ListImages reduces the list of needed
func (svc service) ListImages(all bool) ([]abstract.Image, fail.Error) {
	if svc.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	imgs, err := svc.Provider.ListImages(all)
	if err != nil {
		return nil, err
	}
	return svc.reduceImages(imgs), nil
}

// SearchImage search an image corresponding to OS Name
func (svc service) SearchImage(osname string) (*abstract.Image, fail.Error) {
	if svc.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	imgs, err := svc.ListImages(false)
	if err != nil {
		return nil, err
	}

	maxscore := 0.0
	maxi := -1
	// fields := strings.Split(strings.ToUpper(osname), " ")
	for i, img := range imgs {
		// score := 1 / float64(smetrics.WagnerFischer(strings.ToUpper(img.Name), strings.ToUpper(osname), 1, 1, 2))
		score := smetrics.JaroWinkler(strings.ToUpper(img.Name), strings.ToUpper(osname), 0.7, 5)
		// score := matchScore(fields, strings.ToUpper(img.Name))
		// score := SimilarityScore(osname, img.Name)
		if score > maxscore {
			maxscore = score
			maxi = i
		}

	}
	// fmt.Println(fields, len(fields))
	// fmt.Println(len(fields))
	if maxscore < 0.5 || maxi < 0 || len(imgs) == 0 {
		return nil, fail.NotFoundError("unable to find an image matching '%s'", osname)
	}

	logrus.Infof("Selected image: '%s' (ID='%s')", imgs[maxi].Name, imgs[maxi].ID)
	return &imgs[maxi], nil
}

// CreateHostWithKeyPair creates an host
func (svc service) CreateHostWithKeyPair(request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, *abstract.KeyPair, fail.Error) {
	if svc.IsNull() {
		return nil, nil, nil, fail.InvalidInstanceError()
	}

	ah := abstract.NewHostCore()
	ah.Name = request.ResourceName
	_, rerr := svc.InspectHost(ah)
	if rerr == nil {
		return nil, nil, nil, abstract.ResourceDuplicateError("Host", request.ResourceName)
	}

	// Create temporary key pair
	kpNameuuid, err := uuid.NewV4()
	if err != nil {
		return nil, nil, nil, fail.ToError(err)
	}

	kpName := kpNameuuid.String()
	kp, rerr := svc.CreateKeyPair(kpName)
	if rerr != nil {
		return nil, nil, nil, rerr
	}

	// Create host
	hostReq := abstract.HostRequest{
		ResourceName:   request.ResourceName,
		HostName:       request.HostName,
		ImageID:        request.ImageID,
		KeyPair:        kp,
		PublicIP:       request.PublicIP,
		Subnets:        request.Subnets,
		DefaultRouteIP: request.DefaultRouteIP,
		// DefaultGateway: request.DefaultGateway,
		TemplateID: request.TemplateID,
	}
	host, userData, rerr := svc.CreateHost(hostReq)
	if rerr != nil {
		return nil, nil, nil, rerr
	}
	return host, userData, kp, nil
}

// ListHostsByName list hosts by name
func (svc service) ListHostsByName(details bool) (map[string]*abstract.HostFull, fail.Error) {
	if svc.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	hosts, err := svc.ListHosts(details)
	if err != nil {
		return nil, err
	}
	hostMap := make(map[string]*abstract.HostFull)
	for _, host := range hosts {
		hostMap[host.Core.Name] = host
	}
	return hostMap, nil
}

// TenantCleanup removes everything related to SafeScale from tenant (mainly metadata)
// if force equals false and there is metadata, returns an error
// WARNING: !!! this will make SafeScale unable to handle the resources !!!
func (svc service) TenantCleanup(force bool) fail.Error {
	if svc.IsNull() {
		return fail.InvalidInstanceError()
	}
	return fail.NotImplementedError("service.TenantCleanup() not yet implemented")
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
			{},
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

// SimilarityScore computes a similarity score between 2 strings
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
func InitializeBucket(svc service, location objectstorage.Location) fail.Error {
	if svc.IsNull() {
		return fail.InvalidParameterError("svc", "cannot be null value")
	}
	if location.IsNull() {
		return fail.InvalidParameterError("location", "cannot be nil")
	}

	cfg, err := svc.Provider.GetConfigurationOptions()
	if err != nil {
		return fail.Wrap(err, "failed to get client options: %s")
	}
	anon, found := cfg.Get("GetMetadataBucket")
	if !found || anon.(string) == "" {
		return fail.SyntaxError("failed to get value of option 'GetMetadataBucket'")
	}
	_, err = location.CreateBucket(anon.(string))
	if err != nil {
		return err
	}
	return nil
}

// LookupRuleInSecurityGroup checks if a rule is already in Security Group rules
func (svc service) LookupRuleInSecurityGroup(asg *abstract.SecurityGroup, rule abstract.SecurityGroupRule) (bool, fail.Error) {
	if asg.IsNull() {
		return false, fail.InvalidParameterError("asg", "cannot be null value of '*abstract.SecurityGroup'")
	}

	_, xerr := asg.Rules.IndexOfEquivalentRule(rule)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return false, nil
		default:
			return false, xerr
		}
	}
	return true, nil
}
