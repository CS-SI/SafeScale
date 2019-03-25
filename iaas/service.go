/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	scribble "github.com/nanobox-io/golang-scribble"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/iaas/objectstorage"
	api "github.com/CS-SI/SafeScale/iaas/providers"
	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/iaas/resources/enums/HostState"
	"github.com/CS-SI/SafeScale/iaas/resources/enums/VolumeState"
	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/crypt"
)

// Service ...
type Service struct {
	api.Provider
	objectstorage.Location
	MetadataBucket objectstorage.Bucket
	MetadataKey    *crypt.Key
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
type ByRankDRF []resources.HostTemplate

func (a ByRankDRF) Len() int           { return len(a) }
func (a ByRankDRF) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByRankDRF) Less(i, j int) bool { return RankDRF(&a[i]) < RankDRF(&a[j]) }

// HostAccess an host and the SSH Key Pair
type HostAccess struct {
	Host    *resources.Host
	Key     *resources.KeyPair
	User    string
	Gateway *HostAccess
}

// GetAccessIP returns the access IP
func (access *HostAccess) GetAccessIP() string {
	return access.Host.GetAccessIP()
}

// WaitHostState waits an host achieve state
func (svc *Service) WaitHostState(hostID string, state HostState.Enum, timeout time.Duration) error {
	if svc == nil {
		panic("Calling clt.WaitHostState with clt==nil!")
	}

	var err error

	timer := time.After(timeout)
	next := true
	host := resources.NewHost()
	host.ID = hostID
	for next {
		host, err = svc.InspectHost(host)
		if err != nil {
			return err
		}
		if host.LastState == state {
			return nil
		}
		if host.LastState == HostState.ERROR {
			return fmt.Errorf("host in error state")
		}
		select {
		case <-timer:
			return fmt.Errorf("timeout waiting host '%s' to reach state '%s'", host.Name, state.String())
		default:
			time.Sleep(1)
		}
	}
	return err
}

// WaitVolumeState waits an host achieve state
func (svc *Service) WaitVolumeState(volumeID string, state VolumeState.Enum, timeout time.Duration) (*resources.Volume, error) {
	if svc == nil {
		panic("Calling clt.WaitVolumeState with clt==nil!")
	}

	cout := make(chan int)
	next := make(chan bool)
	vc := make(chan *resources.Volume)

	go pollVolume(svc, volumeID, state, cout, next, vc)
	for {
		select {
		case res := <-cout:
			if res == 0 {
				//next <- false
				return nil, fmt.Errorf("Error getting host state")
			}
			if res == 1 {
				//next <- false
				return <-vc, nil
			}
			if res == 2 {
				next <- true
			}
		case <-time.After(timeout):
			next <- false
			return nil, &resources.ErrTimeout{Message: "Wait host state timeout"}
		}
	}
}

func pollVolume(svc *Service, volumeID string, state VolumeState.Enum, cout chan int, next chan bool, hostc chan *resources.Volume) {
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

// SelectTemplatesBySize select templates satisfying sizing requirements
// returned list is ordered by size fitting
func (svc *Service) SelectTemplatesBySize(sizing resources.SizingRequirements, force bool) ([]resources.HostTemplate, error) {
	if svc == nil {
		panic("Calling svc.SelectTemplatesBySize with svc==nil!")
	}

	templates, err := svc.ListTemplates(false)
	var selectedTpls []resources.HostTemplate
	scannerTemplates := map[string]bool{}
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
					noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs !, problem accessing Scanner database: %v", sizing.MinGPU, err)
				} else {
					noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs and '%f' GHz clock frequency !, problem accessing Scanner database: %v", sizing.MinGPU, sizing.MinFreq, err)
				}
				log.Error(noHostError)
				return nil, errors.New(noHostError)
			}
		} else {
			authOpts, err := svc.GetAuthOpts()
			if err != nil {
				return nil, err
			}
			region, ok := authOpts.Get("Region")
			if !ok {
				return nil, fmt.Errorf("Region value unset")
			}
			folder := fmt.Sprintf("images/%s/%s", svc.GetName(), region)

			imageList, err := db.ReadAll(folder)
			if err != nil {
				if force {
					log.Warnf("Problem creating / accessing Scanner database, ignoring GPU and Freq parameters for now...: %v", err)
				} else {
					var noHostError string
					if sizing.MinFreq <= 0 {
						noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs !, problem accessing Scanner database: %v", sizing.MinGPU, err)
					} else {
						noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs and '%f' GHz clock frequency !, problem accessing Scanner database: %v", sizing.MinGPU, sizing.MinFreq, err)
					}
					log.Error(noHostError)
					return nil, errors.New(noHostError)
				}
			} else {
				images := []resources.StoredCPUInfo{}
				for _, f := range imageList {
					imageFound := resources.StoredCPUInfo{}
					if err := json.Unmarshal([]byte(f), &imageFound); err != nil {
						fmt.Println("Error", err)
					}

					// if the user asked explicitly no gpu
					if int(sizing.MinGPU) == 0 && imageFound.GPU != 0 {
						continue
					}

					if imageFound.GPU < int(sizing.MinGPU) {
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
						noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs !, problem accessing Scanner database: %v", sizing.MinGPU, err)
					} else {
						noHostError = fmt.Sprintf("Unable to create a host with '%d' GPUs and '%f' GHz clock frequency !, problem accessing Scanner database: %v", sizing.MinGPU, sizing.MinFreq, err)
					}
					log.Error(noHostError)
					return nil, errors.New(noHostError)
				}

				for _, image := range images {
					scannerTemplates[image.TemplateID] = true
				}
			}
		}
	}

	log.Debugf("Looking for machine with: %d cores, %f RAM, and %d Disk", sizing.MinCores, sizing.MinRAMSize, sizing.MinDiskSize)

	for _, template := range templates {
		if template.Cores >= sizing.MinCores && (template.DiskSize == 0 || template.DiskSize >= sizing.MinDiskSize) && template.RAMSize >= sizing.MinRAMSize {
			if _, ok := scannerTemplates[template.ID]; ok || !askedForSpecificScannerInfo {
				selectedTpls = append(selectedTpls, template)
			}
		} else {
			log.Debugf("Discard machine template '%s' with : %d cores, %f RAM, and %d Disk", template.Name, template.Cores, template.RAMSize, template.DiskSize)
		}
	}

	sort.Sort(ByRankDRF(selectedTpls))
	return selectedTpls, nil
}

// FilterImages search an images corresponding to OS Name
func (svc *Service) FilterImages(filter string) ([]resources.Image, error) {
	if svc == nil {
		panic("Calling svc.FilterImages with svc==nil!")
	}

	imgs, err := svc.ListImages(false)
	if err != nil {
		return nil, err
	}
	if len(filter) == 0 {
		return imgs, nil
	}
	fimgs := []resources.Image{}
	//fields := strings.Split(strings.ToUpper(osname), " ")
	for _, img := range imgs {
		//score := 1 / float64(smetrics.WagnerFischer(strings.ToUpper(img.Name), strings.ToUpper(osname), 1, 1, 2))
		//score := smetrics.JaroWinkler(strings.ToUpper(img.Name), strings.ToUpper(osname), 0.7, 5)
		//score := matchScore(fields, strings.ToUpper(img.Name))
		score := SimilarityScore(filter, img.Name)
		if score > 0.5 {
			fimgs = append(fimgs, img)
		}

	}
	return fimgs, nil

}

// SearchImage search an image corresponding to OS Name
func (svc *Service) SearchImage(osname string) (*resources.Image, error) {
	if svc == nil {
		panic("Calling clt.SearchImage with clt==nil!")
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
		//score := smetrics.JaroWinkler(strings.ToUpper(img.Name), strings.ToUpper(osname), 0.7, 5)
		//score := matchScore(fields, strings.ToUpper(img.Name))
		score := SimilarityScore(osname, img.Name)
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

	log.Printf("Selected image: '%s' (ID='%s')", imgs[maxi].Name, imgs[maxi].ID)
	return &imgs[maxi], nil
}

// CreateHostWithKeyPair creates an host
func (svc *Service) CreateHostWithKeyPair(request resources.HostRequest) (*resources.Host, *resources.KeyPair, error) {
	if svc == nil {
		panic("Calling svc.CreateHostWithKeyPair svc==nil!")
	}

	_, err := svc.GetHostByName(request.ResourceName)
	if err == nil {
		return nil, nil, resources.ResourceDuplicateError("Host", request.ResourceName)
	}

	// Create temporary key pair
	kpNameuuid, err := uuid.NewV4()
	if err != nil {
		return nil, nil, err
	}

	kpName := kpNameuuid.String()
	kp, err := svc.CreateKeyPair(kpName)
	if err != nil {
		return nil, nil, err
	}

	password, err := utils.GeneratePassword(16)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate password: %s", err.Error())
	}

	// Create host
	hostReq := resources.HostRequest{
		ResourceName:   request.ResourceName,
		HostName:       request.HostName,
		ImageID:        request.ImageID,
		KeyPair:        kp,
		PublicIP:       request.PublicIP,
		Networks:       request.Networks,
		DefaultGateway: request.DefaultGateway,
		TemplateID:     request.TemplateID,
		Password:       password,
	}
	host, err := svc.CreateHost(hostReq)
	if err != nil {
		return nil, nil, err
	}
	return host, kp, nil
}

// ListHostsByName list hosts by name
func (svc *Service) ListHostsByName() (map[string]*resources.Host, error) {
	if svc == nil {
		panic("Calling svc.ListHostsByName() with svc==nil!")
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
	positions := []int{}
	for i, l := range s {
		if l == r {
			positions = append(positions, i)
		}
	}
	return positions

}

func runesIndexes(ref string, s string) [][]int {
	positions := [][]int{}
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
	newPathes := [][]int{}
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
func InitializeBucket(svc *Service, location objectstorage.Location) error {
	cfg, err := svc.GetCfgOpts()
	if err != nil {
		fmt.Printf("failed to get client options: %s\n", err.Error())
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
