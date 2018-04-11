package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/SafeScale/providers/api/IPVersion"

	"github.com/SafeScale/providers/api"

	"github.com/SafeScale/providers"
	_ "github.com/SafeScale/providers/cloudwatt" // Imported to initialise tenants
	_ "github.com/SafeScale/providers/ovh"       // Imported to initialise tenants
)

const cmdNumberOfCPU string = "lscpu | grep 'CPU(s):' | grep -v 'NUMA' | tr -d '[:space:]' | cut -d: -f2"
const cmdNumberOfCorePerSocket string = "lscpu | grep 'Core(s) per socket' | tr -d '[:space:]' | cut -d: -f2"
const cmdNumberOfSocket string = "lscpu | grep 'Socket(s)' | tr -d '[:space:]' | cut -d: -f2"
const cmdArch string = "lscpu | grep 'Architecture' | tr -d '[:space:]' | cut -d: -f2"

const cmdCPUFreq string = "lscpu | grep 'CPU MHz' | tr -d '[:space:]' | cut -d: -f2"
const cmdCPUModelName string = "lscpu | grep 'Model name' | cut -d: -f2 | sed -e 's/^[[:space:]]*//'"
const cmdTotalRAM string = "cat /proc/meminfo | grep MemTotal | cut -d: -f2 | sed -e 's/^[[:space:]]*//' | cut -d' ' -f1"
const cmdRAMFreq string = "sudo dmidecode -t memory | grep Speed | head -1 | cut -d' ' -f2"
const cmdGPU string = "echo $(lspci | grep VGA | grep -i nvidia)"

var cmd = fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s",
	cmdNumberOfCPU,
	cmdNumberOfCorePerSocket,
	cmdNumberOfSocket,
	cmdCPUFreq,
	cmdArch,
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
	CPUModel       string  `json:"cpu_model,omitempty"`
	RAMSize        float64 `json:"ram_size,omitempty"`
	RAMFreq        float64 `json:"ram_freq,omitempty"`
	GPU            bool    `json:"gpu,omitempty"`
}

func parseOutput(output []byte) (*CPUInfo, error) {
	str := string(output)

	tokens := strings.Split(str, "\n")
	if len(tokens) < 9 {
		return nil, fmt.Errorf("Parsing error")
	}
	info := CPUInfo{}
	var err error
	info.NumberOfCPU, err = strconv.Atoi(tokens[0])
	if err != nil {
		return nil, fmt.Errorf("Parsing error")
	}
	info.NumberOfCore, err = strconv.Atoi(tokens[1])
	if err != nil {
		return nil, fmt.Errorf("Parsing error")
	}
	info.NumberOfSocket, err = strconv.Atoi(tokens[2])
	if err != nil {
		return nil, fmt.Errorf("Parsing error")
	}
	info.NumberOfCore = info.NumberOfCore * info.NumberOfSocket
	info.CPUFrequency, err = strconv.ParseFloat(tokens[3], 64)
	if err != nil {
		return nil, fmt.Errorf("Parsing error")
	}
	info.CPUFrequency = math.Ceil(info.CPUFrequency/100) / 10

	info.CPUArch = tokens[4]
	info.CPUModel = tokens[5]
	info.RAMSize, err = strconv.ParseFloat(tokens[6], 64)
	if err != nil {
		return nil, fmt.Errorf("Parsing error")
	}
	info.RAMSize = math.Ceil(info.RAMSize / 1024 / 1024)
	info.RAMFreq, err = strconv.ParseFloat(tokens[7], 64)
	if err != nil {
		info.RAMFreq = 0
	}
	info.GPU = len(strings.TrimSpace(tokens[8])) > 0

	return &info, nil

}

func scanImages(tenant string, service *providers.Service, c chan error) {
	images, err := service.ListImages()
	fmt.Println(tenant, len(images))
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
	ioutil.WriteFile(f, content, 0666)
	c <- nil
}

type getCPUInfoResult struct {
	Err     error
	CPUInfo *CPUInfo
}

func getCPUInfo(service *providers.Service, tpl api.VMTemplate, img *api.Image, key *api.KeyPair, networkID string) (*CPUInfo, error) {

	fmt.Println("Creating VM")
	vm, err := service.CreateVM(api.VMRequest{
		Name:       tpl.Name + "-scan",
		PublicIP:   true,
		ImageID:    img.ID,
		TemplateID: tpl.ID,
		KeyPair:    key,
	})
	if err != nil {
		fmt.Println("Error Creatting VM", err)
		return nil, err
	}
	defer service.DeleteVM(vm.ID)

	ssh, err := service.GetSSHConfig(vm.ID)
	fmt.Println("Reading SSH Config")
	if err != nil {
		fmt.Println("Error Reading SSHConfig", err)
		return nil, err
	}
	ssh.WaitServerReady(30 * time.Second)
	c, err := ssh.Command(cmd)

	//cmd, err := ssh.Command("whoami")
	fmt.Println(">>> CMD", cmd)
	if err != nil {
		fmt.Println("Error scanning VM", err)
		return nil, err
	}
	out, err := c.CombinedOutput()
	fmt.Println("parse: ", string(out), err)
	if err != nil {
		return nil, err
	}
	return parseOutput(out)

}
func scanTemplates(tenant string, service *providers.Service, c chan error) {
	tpls, err := service.ListTemplates()
	fmt.Println(tenant, len(tpls))
	if err != nil {
		c <- err
		return
	}

	info := []*CPUInfo{}
	service.DeleteKeyPair("key-scan")
	kp, err := service.CreateKeyPair("key-scan")
	if err != nil {
		c <- err
		return
	}
	defer service.DeleteKeyPair("key-scan")
	net, err := service.CreateNetwork(api.NetworkRequest{
		CIDR:      "192.168.0.0/24",
		IPVersion: IPVersion.IPv4,
		Name:      "net-scan",
	})
	if err != nil {
		c <- err
		return
	}
	img, err := service.SearchImage("Ubuntu 16.04")
	if err != nil {
		c <- err
		return
	}
	defer service.DeleteNetwork(net.ID)
	for _, tpl := range tpls {
		upperName := strings.ToUpper(tpl.Name)
		fmt.Println("scanning :", tpl.Name)
		if strings.Contains(upperName, "WIN") || strings.Contains(upperName, "FLEX") {
			continue
		}
		fmt.Println("scanning :", tpl.Name)
		ci, err := getCPUInfo(service, tpl, img, kp, net.ID)
		fmt.Println("INFO", ci)
		if err == nil {
			ci.TemplateName = tpl.Name
			ci.TemplateID = tpl.ID
			info = append(info, ci)
		}
	}
	fmt.Println("ALL INFO", info)
	type TplList struct {
		Templates []*CPUInfo `json:"templates,omitempty"`
	}
	content, err := json.Marshal(TplList{
		Templates: info,
	})
	if err != nil {
		c <- err
		return
	}
	f := fmt.Sprintf("%s/templates.json", tenant)
	ioutil.WriteFile(f, content, 0666)
	c <- nil
}

func scanService(tenant string, service *providers.Service, c chan error) {
	os.Remove(tenant)
	os.Mkdir(tenant, 0777)
	cImage := make(chan error)
	go scanImages(tenant, service, cImage)
	cTpl := make(chan error)
	go scanTemplates(tenant, service, cTpl)
	errI := <-cImage
	errT := <-cTpl
	c <- fmt.Errorf("Errors during scan: %v, %v", errI, errT)

}

//Run runs the scan
func Run() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	channels := []chan error{}
	for name, service := range providers.Services() {
		c := make(chan error)
		go scanService(name, service, c)
		channels = append(channels, c)
	}
	for _, c := range channels {
		err := <-c
		if err != nil {
			fmt.Printf("Error during scan %s", err.Error())
		}

	}
}
func main() {
	Run()
}
