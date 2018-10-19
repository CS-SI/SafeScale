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

package main

import (
	"encoding/json"
	"fmt"
	"github.com/CS-SI/SafeScale/providers/enums/IPVersion"
	"io/ioutil"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"

	_ "github.com/CS-SI/SafeScale/broker/utils" // Imported to initialise tenants
)

const cmdNumberOfCPU string = "lscpu | grep 'CPU(s):' | grep -v 'NUMA' | tr -d '[:space:]' | cut -d: -f2"
const cmdNumberOfCorePerSocket string = "lscpu | grep 'Core(s) per socket' | tr -d '[:space:]' | cut -d: -f2"
const cmdNumberOfSocket string = "lscpu | grep 'Socket(s)' | tr -d '[:space:]' | cut -d: -f2"
const cmdArch string = "lscpu | grep 'Architecture' | tr -d '[:space:]' | cut -d: -f2"
const cmdHypervisor string = "lscpu | grep 'Hypervisor' | tr -d '[:space:]' | cut -d: -f2"

const cmdCPUFreq string = "lscpu | grep 'CPU MHz' | tr -d '[:space:]' | cut -d: -f2"
const cmdCPUModelName string = "lscpu | grep 'Model name' | cut -d: -f2 | sed -e 's/^[[:space:]]*//'"
const cmdTotalRAM string = "cat /proc/meminfo | grep MemTotal | cut -d: -f2 | sed -e 's/^[[:space:]]*//' | cut -d' ' -f1"
const cmdRAMFreq string = "sudo dmidecode -t memory | grep Speed | head -1 | cut -d' ' -f2"

const cmdGPU string = "lspci | egrep -i 'VGA|3D' | grep -i nvidia | cut -d: -f3 | sed 's/.*controller://g' | tr '\n' '%'"

var cmd = fmt.Sprintf("export LANG=C;echo $(%s)î$(%s)î$(%s)î$(%s)î$(%s)î$(%s)î$(%s)î$(%s)î$(%s)î$(%s)",
	cmdNumberOfCPU,
	cmdNumberOfCorePerSocket,
	cmdNumberOfSocket,
	cmdCPUFreq,
	cmdArch,
	cmdHypervisor,
	cmdCPUModelName,
	cmdTotalRAM,
	cmdRAMFreq,
	cmdGPU,
)

//CPUInfo stores CPU properties
type CPUInfo struct {
	TemplateID   string `json:"template_id,omitempty"`
	TemplateName string `json:"template_name,omitempty"`

	NumberOfCPU    int     `json:"number_of_cpu,omitempty"`
	NumberOfCore   int     `json:"number_of_core,omitempty"`
	NumberOfSocket int     `json:"number_of_socket,omitempty"`
	CPUFrequency   float64 `json:"cpu_frequency,omitempty"`
	CPUArch        string  `json:"cpu_arch,omitempty"`
	Hypervisor     string  `json:"hypervisor,omitempty"`
	CPUModel       string  `json:"cpu_model,omitempty"`
	RAMSize        float64 `json:"ram_size,omitempty"`
	RAMFreq        float64 `json:"ram_freq,omitempty"`
	GPU            int     `json:"gpu,omitempty"`
	GPUModel       string  `json:"gpu_model,omitempty"`
}

func parseOutput(output []byte) (*CPUInfo, error) {
	str := strings.TrimSpace(string(output))

	//	tokens := strings.Split(str, "\n")
	tokens := strings.Split(str, "î")
	if len(tokens) < 9 {
		return nil, fmt.Errorf("parsing error: '%s'", str)
	}
	info := CPUInfo{}
	var err error
	info.NumberOfCPU, err = strconv.Atoi(tokens[0])
	if err != nil {
		return nil, fmt.Errorf("Parsing error: NumberOfCPU='%s' (from '%s')", tokens[0], str)
	}
	info.NumberOfCore, err = strconv.Atoi(tokens[1])
	if err != nil {
		return nil, fmt.Errorf("Parsing error: NumberOfCore='%s' (from '%s')", tokens[1], str)
	}
	info.NumberOfSocket, err = strconv.Atoi(tokens[2])
	if err != nil {
		return nil, fmt.Errorf("Parsing error: NumberOfSocket='%s' (from '%s')", tokens[2], str)
	}
	info.NumberOfCore = info.NumberOfCore * info.NumberOfSocket
	info.CPUFrequency, err = strconv.ParseFloat(tokens[3], 64)
	if err != nil {
		return nil, fmt.Errorf("Parsing error: CpuFrequency='%s' (from '%s')", tokens[3], str)
	}
	info.CPUFrequency = math.Ceil(info.CPUFrequency/100) / 10

	info.CPUArch = tokens[4]
	info.Hypervisor = tokens[5]
	info.CPUModel = tokens[6]
	info.RAMSize, err = strconv.ParseFloat(tokens[7], 64)
	if err != nil {
		return nil, fmt.Errorf("Parsing error: RAMSize='%s' (from '%s')", tokens[7], str)
	}
	info.RAMSize = math.Ceil(info.RAMSize / 1024 / 1024)
	info.RAMFreq, err = strconv.ParseFloat(tokens[8], 64)
	if err != nil {
		info.RAMFreq = 0
	}
	fmt.Println(tokens[9])
	gpuTokens := strings.Split(tokens[9], "%")
	nb := len(gpuTokens)
	if nb > 1 {
		info.GPUModel = strings.TrimSpace(gpuTokens[0])
		info.GPU = nb - 1
	}

	return &info, nil
}

func scanImages(tenant string, service *providers.Service, c chan error) {
	images, err := service.ListImages(false)
	fmt.Println(tenant, "images:", len(images))
	if err != nil {
		c <- err
		return
	}
	type ImageList struct {
		Images []api.Image `json:"images,omitempty"`
	}
	content, err := json.Marshal(ImageList{
		Images: images,
	})
	if err != nil {
		c <- err
		return
	}
	f := fmt.Sprintf("%s/images.json", tenant)
	nerr := ioutil.WriteFile(f, content, 0666)
	if nerr != nil {
		log.Warnf("Error writing file: %v", nerr)
	}
	c <- nil
}

type getCPUInfoResult struct {
	Err     error
	CPUInfo *CPUInfo
}

func getCPUInfo(tenant string, service *providers.Service, tpl api.HostTemplate, img *api.Image, key *api.KeyPair, networkID string) (*CPUInfo, error) {
	//fmt.Printf("[%s] host %s: creating\n", tenant, tpl.Name)
	host, err := service.CreateHost(api.HostRequest{
		Name:       "scanhost",
		PublicIP:   true,
		ImageID:    img.ID,
		TemplateID: tpl.ID,
		KeyPair:    key,
		NetworkIDs: []string{networkID},
	})
	if err != nil {
		//fmt.Printf("[%s] host %s: error creation: %s\n", tenant, tpl.Name, err.Error())
		return nil, err
	}
	defer service.DeleteHost(host.ID)

	ssh, err := service.GetSSHConfig(host.ID)
	//fmt.Println("Reading SSH Config")
	if err != nil {
		fmt.Printf("[%s] host %s: error reading SSHConfig: %s\n", tenant, tpl.Name, err.Error())
		return nil, err
	}
	nerr := ssh.WaitServerReady(1 * time.Minute)
	if nerr != nil {
		log.Warnf("Error waiting for server ready: %v", nerr)
	}
	c, err := ssh.Command(cmd)

	//cmd, err := ssh.Command(cmd)
	//fmt.Println(">>> CMD", cmd)
	_, err = ssh.Command(cmd)
	if err != nil {
		fmt.Printf("[%s] host %s: error scanning: %s\n", tenant, tpl.Name, err.Error())
		return nil, err
	}
	out, err := c.CombinedOutput()
	//fmt.Println("parse: ", string(out), err)
	if err != nil {
		return nil, err
	}
	return parseOutput(out)
}

func scanTemplates(tenant string, service *providers.Service, c chan error) {
	tpls, err := service.ListTemplates(false)
	total := len(tpls)
	fmt.Println(tenant, "Templates:", total)
	if err != nil {
		c <- err
		return
	}

	info := []*CPUInfo{}
	nerr := service.DeleteKeyPair("key-scan")
	if nerr != nil {
		log.Warnf("Error deleting keypair: %v", nerr)
	}
	kp, err := service.CreateKeyPair("key-scan")
	if err != nil {
		c <- err
		return
	}

	net, err := service.CreateNetwork(api.NetworkRequest{
		CIDR:      "192.168.0.0/24",
		IPVersion: IPVersion.IPv4,
		Name:      "net-scan",
	})
	if err != nil {
		c <- err
		nerr := service.DeleteKeyPair("key-scan")
		if nerr != nil {
			log.Warnf("Error deleting keypair: %v", nerr)
		}
		return
	}

	img, err := service.SearchImage("Ubuntu 16.04")
	if err != nil {
		c <- err
		nerr := service.DeleteKeyPair("key-scan")
		if nerr != nil {
			log.Warnf("Error deleting keypair: %v", nerr)
		}
		return
	}

	ignored := 0
	succeeded := 0
	for _, tpl := range tpls {
		fmt.Printf("[%s] scanning template %s\n", tenant, tpl.Name)
		ci, err := getCPUInfo(tenant, service, tpl, img, kp, net.ID)
		if err == nil {
			ci.TemplateName = tpl.Name
			ci.TemplateID = tpl.ID
			info = append(info, ci)
			succeeded++
			fmt.Printf("[%s] scanning template %s: success: %v\n", tenant, tpl.Name, ci)
		} else {
			errStr := err.Error()
			if errStr == "exit status 255" {
				errStr = "SSH failed"
			}
			fmt.Printf("[%s] scanning template %s failure: %s\n", tenant, tpl.Name, errStr)
		}
	}

	fmt.Printf("[%s] ALL RESULTS: %v\n", tenant, info)
	fmt.Printf("[%s] total %d templaces scanned, %d succeeded, %d ignored, %d failed\n",
		tenant, total, succeeded, ignored, total-succeeded-ignored)
	type TplList struct {
		Templates []*CPUInfo `json:"templates,omitempty"`
	}
	content, err := json.Marshal(TplList{
		Templates: info,
	})

	f := fmt.Sprintf("%s/templates.json", tenant)
	nerr = ioutil.WriteFile(f, content, 0666)
	if nerr != nil {
		log.Warnf("Error writing file: %v", nerr)
	}

	nerr = service.DeleteNetwork(net.ID)
	if nerr != nil {
		log.Warnf("Error deleting network: %v", nerr)
	}
	nerr = service.DeleteKeyPair("key-scan")
	if nerr != nil {
		log.Warnf("Error deleting keypair: %v", nerr)
	}

	if err != nil {
		c <- err
		return
	}

	c <- nil
}

func scanService(tenant string, service *providers.Service, c chan error) {
	err := os.Remove(tenant)
	if err != nil {
		log.Warnf("Error removing file: %v", err)
	}
	err = os.Mkdir(tenant, 0777)
	if err != nil {
		log.Warnf("Error creating dir: %v", err)
	}
	cImage := make(chan error)
	go scanImages(tenant, service, cImage)
	cTpl := make(chan error)
	go scanTemplates(tenant, service, cTpl)
	errI := <-cImage
	errT := <-cTpl
	if errI != nil || errT != nil {
		c <- fmt.Errorf("[%s] Errors during scan: %v, %v", tenant, errI, errT)
	} else {
		c <- nil
	}
}

//Run runs the scan
func Run() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	channels := []chan error{}
	// TODO Fix check error
	the_providers, _ := providers.Tenants()
	for tenantname := range the_providers {
		service, err := providers.GetService(tenantname)
		if err != nil {
			fmt.Printf("Unable to get service for tenant '%s': %s", tenantname, err.Error())
		}
		c := make(chan error)
		go scanService(tenantname, service, c)
		channels = append(channels, c)
	}
	for _, c := range channels {
		err := <-c
		if err != nil {
			fmt.Printf("Error during scan: %s ", err.Error())
		}
	}
	fmt.Println("\nScanning done.")
}

func main() {
	Run()
}
