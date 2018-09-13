/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package providers

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/api/enums/HostState"
	"github.com/CS-SI/SafeScale/providers/api/enums/VolumeState"
	uuid "github.com/satori/go.uuid"
)

// ResourceError resource error
type ResourceError struct {
	Name         string
	ResourceType string
}

// ResourceNotFound resource not found error
type ResourceNotFound struct {
	ResourceError
}

// ResourceNotFoundError creates a ResourceNotFound error
func ResourceNotFoundError(resource string, name string) ResourceNotFound {
	return ResourceNotFound{
		ResourceError{
			Name:         name,
			ResourceType: resource,
		},
	}
}
func (e ResourceNotFound) Error() string {
	return fmt.Sprintf("Unable to find %s '%s'", e.ResourceType, e.Name)
}

// ResourceAlreadyExists resource already exists error
type ResourceAlreadyExists struct {
	ResourceError
}

// ResourceAlreadyExistsError creates a ResourceAlreadyExists error
func ResourceAlreadyExistsError(resource string, name string) ResourceAlreadyExists {
	return ResourceAlreadyExists{
		ResourceError{
			Name:         name,
			ResourceType: resource,
		},
	}
}

func (e ResourceAlreadyExists) Error() string {
	return fmt.Sprintf("%s '%s' alredy exists", e.ResourceType, e.Name)
}

// Service Client High level service
type Service struct {
	api.ClientAPI
}

// FromClient contructs a Service instance from a ClientAPI
func FromClient(clt api.ClientAPI) *Service {
	return &Service{
		ClientAPI: clt,
	}
}

const (
	//CoreDRFWeight is the Dominant Resource Fairness weight of a core
	CoreDRFWeight float32 = 1.0
	//RAMDRFWeight is the Dominant Resource Fairness weight of 1 GB of RAM
	RAMDRFWeight float32 = 1.0 / 8.0
	//DiskDRFWeight is the Dominant Resource Fairness weight of 1 GB of Disk
	DiskDRFWeight float32 = 1.0 / 16.0
)

// RankDRF computes the Dominant Resource Fairness Rank of an host template
func RankDRF(t *api.HostTemplate) float32 {
	fc := float32(t.Cores)
	fr := t.RAMSize
	fd := float32(t.DiskSize)
	return fc*CoreDRFWeight + fr*RAMDRFWeight + fd*DiskDRFWeight
}

// ByRankDRF implements sort.Interface for []HostTemplate based on
// the Dominant Resource Fairness
type ByRankDRF []api.HostTemplate

func (a ByRankDRF) Len() int           { return len(a) }
func (a ByRankDRF) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByRankDRF) Less(i, j int) bool { return RankDRF(&a[i]) < RankDRF(&a[j]) }

// HostAccess an host and the SSH Key Pair
type HostAccess struct {
	Host    *api.Host
	Key     *api.KeyPair
	User    string
	Gateway *HostAccess
}

// GetAccessIP returns the access IP
func (access *HostAccess) GetAccessIP() string {
	ip := access.Host.AccessIPv4
	if len(ip) == 0 {
		ip = access.Host.AccessIPv6
	}
	return ip
}

// ServerRequest used to create a server
type ServerRequest struct {
	Name string `json:"name,omitempty"`
	// NetworksIDs list of the network IDs the host must be connected
	Networks []api.Network `json:"networks,omitempty"`
	// PublicIP a flg telling if the host must have a public IP is
	PublicIP bool `json:"public_ip,omitempty"`
	// TemplateID the UUID of the template used to size the host (see SelectTemplates)
	Template api.HostTemplate `json:"sizing,omitempty"`
	// ImageID  is the UUID of the image that contains the server's OS and initial state.
	OSName string `json:"os_name,omitempty"`
	// Gateway through which the server can be connected
	Gateway *HostAccess `json:"gateway,omitempty"`
}

//WaitHostState waits an host achieve state
func (srv *Service) WaitHostState(hostID string, state HostState.Enum, timeout time.Duration) (*api.Host, error) {
	var host *api.Host
	var err error
	timer := time.After(timeout)
	next := true
	for next {
		host, err = srv.GetHost(hostID)
		if host == nil {
			return nil, err
		} else if host.State == state {
			return host, err
		} else if host.State == HostState.ERROR {
			return host, fmt.Errorf("host in error state")
		}
		select {
		case <-timer:
			return host, fmt.Errorf("timeout waiting host '%s' to reach state '%s'", host.Name, state.String())
		default:
			time.Sleep(1)
		}
	}
	return host, err
}

//WaitHostState waits an host achieve state
// func (srv *Service) WaitHostState(hostID string, state HostState.Enum, timeout time.Duration) (*api.host, error) {
// 	cout := make(chan int)
// 	stop := make(chan bool)
// 	hostc := make(chan *api.Host)
// 	fmt.Println(timeout)
// 	var host *api.Host
// 	var err error
// 	go pollHost(srv, hostID, state, cout, stop, hostc)
// 	stop <- false
// 	timer := time.After(timeout)
// 	finish := false
// 	for !finish {
// 		select {
// 		case res := <-cout:
// 			if res == 0 {
// 				stop <- true
// 				err = fmt.Errorf("host in error state")
// 				finish = true
// 			}
// 			if res == 1 {
// 				fmt.Println("State achieved")
// 				stop <- true
// 				host = <-hostc
// 				fmt.Println("host received")
// 				finish = true
// 			}
// 			if res == 2 {
// 				stop <- false
// 			}
// 		case <-timer:
// 			stop <- true
// 			err = fmt.Errorf("Timeout")
// 			finish = true
// 		default:
// 		}
// 	}
// 	fmt.Println("receive result")
// 	<-cout
// 	fmt.Println("End of wait")
// 	return host, err
// }

// func sendResul(cout chan int, res int) {
// 	cout <- res
// 	fmt.Println("result sent ", res)
// }

// func pollHost(client api.ClientAPI, hostID string, state HostState.Enum, cout chan int, stop chan bool, hostc chan *api.Host) {
// 	finish := false
// 	fmt.Println("Start polling")
// 	for !finish {
// 		res := -1
// 		if finish {
// 			return
// 		}
// 		finish = <-stop

// 		fmt.Println("Get host")
// 		host, err := client.GetHost(hostID)
// 		if err != nil {
// 			log.Print(err)
// 			res = 0
// 		} else if host.State == state {
// 			res = 1
// 		} else if host.State == HostState.ERROR {
// 			res = 0
// 		} else {
// 			res = 2
// 		}
// 		fmt.Println(host.State)
// 		sendResul(cout, res)

// 		if res == 1 {
// 			fmt.Println("send host")
// 			hostc <- host
// 		}
// 		fmt.Println("end")
// 	}
// }

//WaitVolumeState waits an host achieve state
func (srv *Service) WaitVolumeState(volumeID string, state VolumeState.Enum, timeout time.Duration) (*api.Volume, error) {
	cout := make(chan int)
	next := make(chan bool)
	vc := make(chan *api.Volume)

	go pollVolume(srv, volumeID, state, cout, next, vc)
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
			return nil, &api.ErrTimeout{Message: "Wait host state timeout"}
		}
	}
}

func pollVolume(client api.ClientAPI, volumeID string, state VolumeState.Enum, cout chan int, next chan bool, hostc chan *api.Volume) {
	for {

		v, err := client.GetVolume(volumeID)
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

//SelectTemplatesBySize select templates satisfying sizing requirements
//returned list is ordered by size fitting
func (srv *Service) SelectTemplatesBySize(sizing api.SizingRequirements) ([]api.HostTemplate, error) {
	tpls, err := srv.ListTemplates(false)
	var selectedTpls []api.HostTemplate
	if err != nil {
		return nil, err
	}
	for _, tpl := range tpls {
		if tpl.Cores >= sizing.MinCores && (tpl.DiskSize == 0 || tpl.DiskSize >= sizing.MinDiskSize) && tpl.RAMSize >= sizing.MinRAMSize {
			selectedTpls = append(selectedTpls, tpl)
		}
	}
	sort.Sort(ByRankDRF(selectedTpls))
	return selectedTpls, nil
}

//FilterImages search an images corresponding to OS Name
func (srv *Service) FilterImages(filter string) ([]api.Image, error) {

	imgs, err := srv.ListImages(false)
	if err != nil {
		return nil, err
	}
	if len(filter) == 0 {
		return imgs, nil
	}
	fimgs := []api.Image{}
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

//SearchImage search an image corresponding to OS Name
func (srv *Service) SearchImage(osname string) (*api.Image, error) {

	imgs, err := srv.ListImages(false)
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
		return nil, fmt.Errorf("Unable to found and image matching %s", osname)
	}
	return &imgs[maxi], nil
}

//CreateHostWithKeyPair creates an host
func (srv *Service) CreateHostWithKeyPair(request api.HostRequest) (*api.Host, *api.KeyPair, error) {
	_, err := srv.GetHostByName(request.Name)
	if err == nil {
		return nil, nil, ResourceAlreadyExistsError("Host", request.Name)
	}

	//Create temporary key pair
	kpNameuuid, _ := uuid.NewV4()
	kpName := kpNameuuid.String()
	kp, err := srv.CreateKeyPair(kpName)
	if err != nil {
		return nil, nil, err
	}
	//defer srv.DeleteKeyPair(kpName)

	//Create host
	hostReq := api.HostRequest{
		Name:       request.Name,
		ImageID:    request.ImageID,
		KeyPair:    kp,
		PublicIP:   request.PublicIP,
		NetworkIDs: request.NetworkIDs,
		TemplateID: request.TemplateID,
	}
	host, err := srv.CreateHost(hostReq)
	if err != nil {
		return nil, nil, err
	}
	return host, kp, nil
}

//ListHostsByName list hosts by name
func (srv *Service) ListHostsByName() (map[string]api.Host, error) {
	hosts, err := srv.ListHosts(false)
	if err != nil {
		return nil, err
	}
	hostMap := make(map[string]api.Host)
	for _, host := range hosts {
		hostMap[host.Name] = host
	}
	return hostMap, nil
}

// GetHostByName returns host corresponding to name
func (srv *Service) GetHostByName(name string) (*api.Host, error) {
	hosts, err := srv.ListHostsByName()
	if err != nil {
		return nil, err
	}
	host, ok := hosts[name]
	if !ok {
		return nil, ResourceNotFoundError("host", name)
	}
	return &host, nil
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

//SimilarityScore computes a similariy score between 2 strings
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
