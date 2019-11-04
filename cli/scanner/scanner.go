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

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/IPVersion"
	"github.com/CS-SI/SafeScale/lib/server/metadata"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"

	_ "github.com/CS-SI/SafeScale/lib/server" // Imported to initialise tenants
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
const cmdDiskSize string = "lsblk -b --output SIZE -n -d /dev/sda"
const cmdEphemeralDiskSize string = "lsblk -o name,type,mountpoint | grep disk | awk {'print $1'} | grep -v sda | xargs -i'{}' lsblk -b --output SIZE -n -d /dev/'{}'"
const cmdRotational string = "cat /sys/block/sda/queue/rotational"
const cmdDiskSpeed string = "sudo hdparm -t --direct /dev/sda | grep MB | awk '{print $11}'"
const cmdNetSpeed string = "URL=\"http://www.google.com\";curl -L --w \"$URL\nDNS %{time_namelookup}s conn %{time_connect}s time %{time_total}s\nSpeed %{speed_download}bps Size %{size_download}bytes\n\" -o/dev/null -s $URL | grep bps | awk '{ print $2}' | cut -d '.' -f 1"

var cmd = fmt.Sprintf("export LANG=C;echo $(%s)î$(%s)î$(%s)î$(%s)î$(%s)î$(%s)î$(%s)î$(%s)î$(%s)î$(%s)î$(%s)î$(%s)î$(%s)î$(%s)î$(%s)",
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
	cmdDiskSize,
	cmdEphemeralDiskSize,
	cmdDiskSpeed,
	cmdRotational,
	cmdNetSpeed,
)

//CPUInfo stores CPU properties
type CPUInfo struct {
	TenantName   string `json:"tenant_name,omitempty"`
	TemplateID   string `json:"template_id,omitempty"`
	TemplateName string `json:"template_name,omitempty"`
	ImageID      string `json:"image_id,omitempty"`
	ImageName    string `json:"image_name,omitempty"`
	LastUpdated  string `json:"last_updated,omitempty"`

	NumberOfCPU    int     `json:"number_of_cpu,omitempty"`
	NumberOfCore   int     `json:"number_of_core,omitempty"`
	NumberOfSocket int     `json:"number_of_socket,omitempty"`
	CPUFrequency   float64 `json:"cpu_frequency_Ghz,omitempty"`
	CPUArch        string  `json:"cpu_arch,omitempty"`
	Hypervisor     string  `json:"hypervisor,omitempty"`
	CPUModel       string  `json:"cpu_model,omitempty"`
	RAMSize        float64 `json:"ram_size_Gb,omitempty"`
	RAMFreq        float64 `json:"ram_freq,omitempty"`
	GPU            int     `json:"gpu,omitempty"`
	GPUModel       string  `json:"gpu_model,omitempty"`
	DiskSize       int64   `json:"disk_size_Gb,omitempty"`
	MainDiskType   string  `json:"main_disk_type"`
	MainDiskSpeed  float64 `json:"main_disk_speed_MBps"`
	SampleNetSpeed float64 `json:"sample_net_speed_KBps"`
	EphDiskSize    int64   `json:"eph_disk_size_Gb"`
	PricePerHour   float64 `json:"price_in_dollars_hour"`
}

func createCPUInfo(output string) (*CPUInfo, error) {
	str := strings.TrimSpace(output)

	tokens := strings.Split(str, "î")
	if len(tokens) < 9 {
		return nil, fmt.Errorf("parsing error: '%s'", str)
	}
	info := CPUInfo{}
	var err error
	info.NumberOfCPU, err = strconv.Atoi(tokens[0])
	if err != nil {
		return nil, fmt.Errorf("parsing error: NumberOfCPU='%s' (from '%s')", tokens[0], str)
	}
	info.NumberOfCore, err = strconv.Atoi(tokens[1])
	if err != nil {
		return nil, fmt.Errorf("parsing error: NumberOfCore='%s' (from '%s')", tokens[1], str)
	}
	info.NumberOfSocket, err = strconv.Atoi(tokens[2])
	if err != nil {
		return nil, fmt.Errorf("parsing error: NumberOfSocket='%s' (from '%s')", tokens[2], str)
	}
	info.NumberOfCore *= info.NumberOfSocket
	info.CPUFrequency, err = strconv.ParseFloat(tokens[3], 64)
	if err != nil {
		return nil, fmt.Errorf("parsing error: CpuFrequency='%s' (from '%s')", tokens[3], str)
	}
	info.CPUFrequency = math.Floor(info.CPUFrequency*100) / 100000

	info.CPUArch = tokens[4]
	info.Hypervisor = tokens[5]
	info.CPUModel = tokens[6]
	info.RAMSize, err = strconv.ParseFloat(tokens[7], 64)
	if err != nil {
		return nil, fmt.Errorf("parsing error: RAMSize='%s' (from '%s')", tokens[7], str)
	}

	memInGb := info.RAMSize / 1024 / 1024
	info.RAMSize = math.Floor(memInGb*100) / 100
	info.RAMFreq, err = strconv.ParseFloat(tokens[8], 64)
	if err != nil {
		info.RAMFreq = 0
	}
	gpuTokens := strings.Split(tokens[9], "%")
	nb := len(gpuTokens)
	if nb > 1 {
		info.GPUModel = strings.TrimSpace(gpuTokens[0])
		info.GPU = nb - 1
	}

	info.DiskSize, err = strconv.ParseInt(tokens[10], 10, 64)
	if err != nil {
		info.DiskSize = 0
	}
	info.DiskSize = info.DiskSize / 1024 / 1024 / 1024

	info.EphDiskSize, err = strconv.ParseInt(tokens[11], 10, 64)
	if err != nil {
		info.EphDiskSize = 0
	}
	info.EphDiskSize = info.EphDiskSize / 1024 / 1024 / 1024

	info.MainDiskSpeed, err = strconv.ParseFloat(tokens[12], 64)
	if err != nil {
		info.MainDiskSpeed = 0
	}

	rotational, err := strconv.ParseInt(tokens[13], 10, 64)
	if err != nil {
		info.MainDiskType = ""
	} else {
		if rotational == 1 {
			info.MainDiskType = "HDD"
		} else {
			info.MainDiskType = "SSD"
		}
	}

	nsp, err := strconv.ParseFloat(tokens[14], 64)
	if err != nil {
		info.SampleNetSpeed = 0
	} else {
		info.SampleNetSpeed = nsp / 1000 / 8
	}

	info.PricePerHour = 0

	return &info, nil
}

// RunScanner ...
func RunScanner(targetedTenant string) {
	var targetedProviders []string
	theProviders, err := iaas.GetTenants()
	if err != nil {
		panic(fmt.Sprintf("Unable to get Tenants %s", err.Error()))
	}

	for _, tenant := range theProviders {
		isScannable, err := isTenantScannable(tenant.(map[string]interface{}))
		if err != nil {
			panic(fmt.Sprint(err.Error()))
		}
		if isScannable {
			tenantName, found := tenant.(map[string]interface{})["name"].(string)
			if !found {
				panic(fmt.Sprintf("There is a scannable tenant without name"))
			}
			targetedProviders = append(targetedProviders, tenantName)
		}
	}

	if len(targetedProviders) < 1 {
		log.Warn("No scannable tenant found. Consider marking a tennant as Scannable as stated in documentation")
		return
	}

	if targetedTenant != "" {
		targetedTenantIsInTenantsList := false
		for _, tenant := range targetedProviders {
			if tenant == targetedTenant {
				targetedTenantIsInTenantsList = true
				break
			}
		}

		if !targetedTenantIsInTenantsList {
			log.Fatalf("Tenant %s not found.", targetedTenant)
		}
	}

	// TODO Enable when several safescaled instances can run in parallel
	/*
		var wtg sync.WaitGroup

		wtg.Add(len(targetedProviders))

		for _, tenantName := range targetedProviders {
			fmt.Printf("Working with tenant %s\n", tenantName)
			go analyzeTenant(&wtg, tenantName)
		}

		wtg.Wait()
	*/

	if targetedTenant != "" {
		fmt.Printf("Scanning only tenant %s", targetedTenant)
	}

	for _, tenantName := range targetedProviders {
		if targetedTenant != "" {
			if targetedTenant != tenantName {
				continue
			}
		}

		fmt.Printf("Working with tenant %s\n", tenantName)
		err := analyzeTenant(nil, tenantName)
		if err != nil {
			fmt.Printf("Error working with tenant %s\n", tenantName)
		}
		if err := collect(tenantName); err != nil {
			log.Warn(fmt.Printf("failed to save scanned info from tenant %s", tenantName))
		}
	}
}

// isTenantScannable will return true if a tennant could be used by the scanner and false otherwise
func isTenantScannable(tenant map[string]interface{}) (isScannable bool, err error) {
	tenantCompute, found := tenant["compute"].(map[string]interface{})
	if !found {
		return false, fmt.Errorf("malformed tenant structure")
	}
	isScannable, found = tenantCompute["Scannable"].(bool)
	if !found {
		return false, fmt.Errorf("malformed tenant structure")
	}
	return isScannable, nil
}

func analyzeTenant(group *sync.WaitGroup, theTenant string) (err error) {
	if group != nil {
		defer group.Done()
	}

	tenantCmd := exec.Command("safescale", "tenant", "set", theTenant)
	if err := tenantCmd.Run(); err != nil {
		return err
	}

	serviceProvider, err := iaas.UseService(theTenant)
	if err != nil {
		log.Warnf("Unable to get serviceProvider for tenant '%s': %s", theTenant, err.Error())
		return err
	}

	err = dumpImages(serviceProvider, theTenant)
	if err != nil {
		return err
	}

	err = dumpTemplates(serviceProvider, theTenant)
	if err != nil {
		return err
	}

	templates, err := serviceProvider.ListTemplates(true)
	if err != nil {
		return err
	}
	img, err := serviceProvider.SearchImage("Ubuntu 18.04")
	if err != nil {
		log.Warnf("No image here...")
		return err
	}

	// Prepare network

	there := true
	var network *resources.Network

	netName := "net-safescale" // FIXME Hardcoded string
	if network, err = serviceProvider.GetNetwork(netName); network != nil && err == nil {
		log.Warnf("Network '%s' already there", netName)
	} else {
		there = false
	}

	if !there {
		network, err = serviceProvider.CreateNetwork(resources.NetworkRequest{
			CIDR:      "192.168.0.0/24",
			IPVersion: IPVersion.IPv4,
			Name:      netName,
		})
		if err != nil {
			return err
		}
		if network == nil {
			return fmt.Errorf("failure creating network '%s'", netName)
		}

		defer func() {
			delerr := serviceProvider.DeleteNetwork(network.ID)
			if delerr != nil {
				log.Warnf("Error deleting network '%s'", network.ID)
			}
			err = scerr.AddConsequence(err, delerr)
		}()

		_, err = metadata.SaveNetwork(serviceProvider, network)
		if err != nil {
			return err
		}
	}

	err = os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup

	concurrency := math.Min(4, float64(len(templates)/2))
	sem := make(chan bool, int(concurrency))

	hostAnalysis := func(template resources.HostTemplate) error {
		defer wg.Done()
		if network != nil {

			// Limit scanner tests for integration test purposes
			testSubset := ""

			if testSubsetCandidate := os.Getenv("SCANNER_SUBSET"); testSubsetCandidate != "" {
				testSubset = testSubsetCandidate
			}

			if len(testSubset) > 0 {
				if !strings.Contains(template.Name, testSubset) {
					return nil
				}
			}

			// TODO If there is a file with today's date, skip it...
			fileCandidate := utils.AbsPathify("$HOME/.safescale/scanner/" + theTenant + "#" + template.Name + ".json")
			if _, err := os.Stat(fileCandidate); !os.IsNotExist(err) {
				return nil
			}

			log.Printf("Checking template %s\n", template.Name)

			hostName := "scanhost-" + template.Name
			hostHandler := handlers.NewHostHandler(serviceProvider)

			host, err := hostHandler.Create(context.Background(), hostName, network.Name, "Ubuntu 18.04", true, template.Name, false)
			if err != nil {
				log.Warnf("template [%s] host '%s': error creation: %v\n", template.Name, hostName, err.Error())
				return err
			}

			defer func() {
				log.Infof("Trying to delete host '%s' with ID '%s'", hostName, host.ID)
				delerr := hostHandler.Delete(context.Background(), host.ID)
				if delerr != nil {
					log.Warnf("Error deleting host '%s'", host.ID)
				}
			}()

			sshSvc := handlers.NewSSHHandler(serviceProvider)
			ssh, err := sshSvc.GetConfig(context.Background(), host.ID)
			if err != nil {
				log.Warnf("template [%s] host '%s': error reading SSHConfig: %v\n", template.Name, hostName, err.Error())
				return err
			}
			_, nerr := ssh.WaitServerReady("ready", time.Duration(6+concurrency-1)*time.Minute)
			if nerr != nil {
				log.Warnf("template [%s]: Error waiting for server ready: %v", template.Name, nerr)
				return nerr
			}
			c, err := ssh.Command(cmd)
			if err != nil {
				log.Warnf("template [%s]: Problem creating ssh command: %v", template.Name, err)
				return err
			}
			_, cout, _, err := c.RunWithTimeout(nil, 8*time.Minute) // FIXME Hardcoded timeout
			if err != nil {
				log.Warnf("template [%s]: Problem running ssh command: %v", template.Name, err)
				return err
			}

			daCPU, err := createCPUInfo(cout)
			if err != nil {
				log.Warnf("template [%s]: Problem building cpu info: %v", template.Name, err)
				return err
			}

			daCPU.TemplateName = template.Name
			daCPU.TemplateID = template.ID
			daCPU.ImageID = img.ID
			daCPU.ImageName = img.Name
			daCPU.TenantName = theTenant
			daCPU.LastUpdated = time.Now().Format(time.RFC850)

			daOut, err := json.MarshalIndent(daCPU, "", "\t")
			if err != nil {
				log.Warnf("template [%s] : Problem marshaling json data: %v", template.Name, err)
				return err
			}

			nerr = ioutil.WriteFile(utils.AbsPathify("$HOME/.safescale/scanner/"+theTenant+"#"+template.Name+".json"), daOut, 0666)
			if nerr != nil {
				log.Warnf("template [%s] : Error writing file: %v", template.Name, nerr)
				return nerr
			}
			log.Infof("template [%s] : Stored in file: %s", template.Name, "$HOME/.safescale/scanner/"+theTenant+"#"+template.Name+".json")
		} else {
			return fmt.Errorf("no gateway network")
		}

		return nil
	}

	wg.Add(len(templates))

	for _, target := range templates {
		sem <- true
		localTarget := target
		go func(inner resources.HostTemplate) {
			defer func() { <-sem }()
			lerr := hostAnalysis(inner)
			if lerr != nil {
				log.Warnf("Error running scanner: %+v", lerr)
			}
		}(localTarget)
	}

	for i := 0; i < cap(sem); i++ {
		sem <- true
	}

	wg.Wait()

	return nil
}

func dumpTemplates(service iaas.Service, tenant string) (err error) {
	err = os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777)
	if err != nil {
		return err
	}

	type TemplateList struct {
		Templates []resources.HostTemplate `json:"templates,omitempty"`
	}

	templates, err := service.ListTemplates(false)
	if err != nil {
		return err
	}

	content, err := json.Marshal(TemplateList{
		Templates: templates,
	})
	if err != nil {
		return err
	}

	f := fmt.Sprintf("$HOME/.safescale/scanner/%s-templates.json", tenant)
	f = utils.AbsPathify(f)

	err = ioutil.WriteFile(f, content, 0666)
	if err != nil {
		return err
	}

	return nil
}

func dumpImages(service iaas.Service, tenant string) (err error) {
	err = os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777)
	if err != nil {
		return err
	}

	type ImageList struct {
		Images []resources.Image `json:"images,omitempty"`
	}

	images, err := service.ListImages(false)
	if err != nil {
		return err
	}

	content, err := json.Marshal(ImageList{
		Images: images,
	})
	if err != nil {
		return err
	}

	f := fmt.Sprintf("$HOME/.safescale/scanner/%s-images.json", tenant)
	f = utils.AbsPathify(f)

	err = ioutil.WriteFile(f, content, 0666)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	log.Printf("%s version %s\n", os.Args[0], VERSION+", build "+REV+" ("+BUILD_DATE+")")

	safescaledPort := 50051

	if portCandidate := os.Getenv("SAFESCALED_PORT"); portCandidate != "" {
		num, err := strconv.Atoi(portCandidate)
		if err == nil {
			safescaledPort = num
		}
	}

	timeout := time.Duration(1 * time.Second)
	_, err := net.DialTimeout("tcp", "localhost:"+strconv.Itoa(safescaledPort), timeout)
	if err != nil {
		log.Fatalf("You must run safescaled first...")
	}

	cmd := exec.Command("safescale", "help")
	if err := cmd.Run(); err != nil {
		log.Fatalf("You must have safescale in your $PATH")
	}

	if len(os.Args) == 1 {
		fmt.Println("Scanner will create one instance of each available template for ALL your tenants marked as 'Scannable' in your tenants.toml file")
	} else {
		fmt.Printf("Scanner will create one instance of each available template for the tenant '%s' of your tenants.toml file\n", os.Args[1])
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Are you sure ? [y]es [N]o: ")
	text, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("failed to read the input : ", err.Error())
		text = "n"
	}
	if strings.TrimRight(text, "\n") != "y" {
		os.Exit(0)
	}

	fmt.Println("Scanner will start in 10 sec, this is your last chance to cancel with Control+C")
	time.Sleep(time.Duration(10) * time.Second)

	log.Info("Starting scanner...")
	if len(os.Args) > 1 {
		RunScanner(os.Args[1])
	} else {
		RunScanner("")
	}
}
