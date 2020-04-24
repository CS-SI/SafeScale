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

package handlers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	scribble "github.com/nanobox-io/golang-scribble"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	networkfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/network"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

//go:generate mockgen -destination=../mocks/mock_imageapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers ScannerHandler

// PriceInfo stores price information
type PriceInfo struct {
	Devise        string  `json:"device"`                   // contains the device of the price info
	DurationLabel string  `json:"duration_label,omitempty"` // contains a label for the duration "Per Hour" for example
	Duration      uint    `json:"duration"`                 // number of seconds of the duration
	Price         float64 `json:"price"`                    // price in the devise for the duration
}

// CPUInfo stores CPU properties
type CPUInfo struct {
	TenantName     string      `json:"tenant_name,omitempty"`
	TemplateID     string      `json:"template_id,omitempty"`
	TemplateName   string      `json:"template_name,omitempty"`
	ImageID        string      `json:"image_id,omitempty"`
	ImageName      string      `json:"image_name,omitempty"`
	LastUpdated    string      `json:"last_updated,omitempty"`
	NumberOfCPU    int         `json:"number_of_cpu,omitempty"`
	NumberOfCore   int         `json:"number_of_core,omitempty"`
	NumberOfSocket int         `json:"number_of_socket,omitempty"`
	CPUFrequency   float64     `json:"cpu_frequency_Ghz,omitempty"`
	CPUArch        string      `json:"cpu_arch,omitempty"`
	Hypervisor     string      `json:"hypervisor,omitempty"`
	CPUModel       string      `json:"cpu_model,omitempty"`
	RAMSize        float64     `json:"ram_size_Gb,omitempty"`
	RAMFreq        float64     `json:"ram_freq,omitempty"`
	GPU            int         `json:"gpu,omitempty"`
	GPUModel       string      `json:"gpu_model,omitempty"`
	DiskSize       int64       `json:"disk_size_Gb,omitempty"`
	MainDiskType   string      `json:"main_disk_type"`
	MainDiskSpeed  float64     `json:"main_disk_speed_MBps"`
	SampleNetSpeed float64     `json:"sample_net_speed_KBps"`
	EphDiskSize    int64       `json:"eph_disk_size_Gb"`
	PricePerSecond float64     `json:"price_in_dollars_second"` // DEPRECATED, use field Prices
	PricePerHour   float64     `json:"price_in_dollars_hour"`   // DEPRECATED, use field Prices
	Prices         []PriceInfo `json:"prices,omitempty"`
}

// StoredCPUInfo ...
type StoredCPUInfo struct {
	ID string `bow:"key"`
	CPUInfo
}

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

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// ScannerHandler defines API to manipulate images
type ScannerHandler interface {
	Scan() error
}

// scannerHandler service
type scannerHandler struct {
	job server.Job
}

// NewScannerHandler creates a scanner service
func NewScannerHandler(job server.Job) ScannerHandler {
	return &scannerHandler{job: job}
}

// Scan scans the tenant and update the database
func (handler *scannerHandler) Scan() (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	tracer := concurrency.NewTracer(handler.job.SafeGetTask(), debug.ShouldTrace("handlers.tenant")).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)

	svc := handler.job.SafeGetService()

	// FIXME: Check if tenant is scannable

	// for _, tenant := range theProviders {
	// 	isScannable, err := isTenantScannable(tenant.(map[string]interface{}))
	// 	if err != nil {
	// 		panic(fmt.Sprint(err.Error()))
	// 	}
	// 	if isScannable {
	// 		tenantName, found := tenant.(map[string]interface{})["name"].(string)
	// 		if !found {
	// 			panic(fmt.Sprintf("There is a scannable tenant without name"))
	// 		}
	// 		targetedProviders = append(targetedProviders, tenantName)
	// 	}
	// }

	if err := handler.analyze(); err != nil {
		return err
	}
	if err := handler.collect(); err != nil {
		return scerr.Wrap(err, "failed to save scanned info for tenant '%s'", svc.SafeGetName())
	}
	return nil
}

func (handler *scannerHandler) analyze() (err error) {
	svc := handler.job.SafeGetService()
	tenantName := svc.SafeGetName()

	err = handler.dumpImages()
	if err != nil {
		return err
	}

	err = handler.dumpTemplates()
	if err != nil {
		return err
	}

	templates, err := svc.ListTemplates(true)
	if err != nil {
		return err
	}
	img, err := svc.SearchImage("Ubuntu 18.04")
	if err != nil {
		logrus.Warnf("No image here...")
		return err
	}

	// Prepare network if needed
	task := handler.job.SafeGetTask()
	netName := "net-safescale" // FIXME: Hardcoded string
	network, err := networkfactory.Load(task, svc, netName)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return err
		}
		network, err := networkfactory.New(svc)
		if err != nil {
			return err
		}
		req := abstract.NetworkRequest{
			Name:      netName,
			IPVersion: ipversion.IPv4,
			CIDR:      "192.168.0.0/24",
		}
		err = network.Create(task, req, "", nil)
		if err != nil {
			return err
		}

		defer func() {
			derr := network.Delete(task)
			if derr != nil {
				logrus.Warnf("Error deleting network '%s'", network.SafeGetID())
			}
			err = scerr.AddConsequence(err, derr)
		}()
	}

	err = os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup

	concurrency := math.Min(4, float64(len(templates)/2))
	sem := make(chan bool, int(concurrency))

	hostAnalysis := func(template abstract.HostTemplate) error {
		defer wg.Done()
		if network != nil {
			// Limit scanner tests for integration test purposes
			testSubset := ""

			// FIXME: move SCANNER_SUBSET to safescale CLI and pass the value by protobuf to the handler
			if testSubsetCandidate := os.Getenv("SCANNER_SUBSET"); testSubsetCandidate != "" {
				testSubset = testSubsetCandidate
			}

			if len(testSubset) > 0 {
				if !strings.Contains(template.Name, testSubset) {
					return nil
				}
			}

			// TODO: If there is a file with today's date, skip it...
			fileCandidate := utils.AbsPathify("$HOME/.safescale/scanner/" + tenantName + "#" + template.Name + ".json")
			if _, err := os.Stat(fileCandidate); !os.IsNotExist(err) {
				return nil
			}

			logrus.Infof("Checking template %s", template.Name)

			var an *abstract.Network
			err = network.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
				var ok bool
				an, ok = clonable.(*abstract.Network)
				if !ok {
					return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return nil
			})
			if err != nil {
				return err
			}
			hostName := "scanhost-" + template.Name
			host, err := hostfactory.New(svc)
			if err != nil {
				return err
			}

			req := abstract.HostRequest{
				ResourceName: hostName,
				Networks:     []*abstract.Network{an},
				PublicIP:     false,
				TemplateID:   template.ID,
			}
			def := abstract.HostSizingRequirements{
				Image: "Ubuntu 18.04",
			}
			_, err = host.Create(task, req, def)
			if err != nil {
				return scerr.Wrap(err, "template [%s] host '%s': error creation", template.Name, hostName)
			}

			defer func() {
				logrus.Infof("Trying to delete host '%s' with ID '%s'", hostName, host.SafeGetID())
				derr := host.Delete(task)
				if derr != nil {
					logrus.Warnf("Error deleting host '%s'", hostName)
				}
			}()

			// sshSvc := handlers.NewSSHHandler(job)
			// ssh, err := sshSvc.GetConfig(host.SafeGetID())
			// if err != nil {
			// 	logrus.Warnf("template [%s] host '%s': error reading SSHConfig: %v", template.Name, hostName, err.Error())
			// 	return err
			// }
			// _, nerr := ssh.WaitServerReady(job.SafeGetTask(), "ready", time.Duration(6+concurrency-1)*time.Minute)
			// if nerr != nil {
			// 	logrus.Warnf("template [%s]: Error waiting for server ready: %v", template.Name, nerr)
			// 	return nerr
			// }

			// c, err := ssh.Command(job.SafeGetTask(), cmd)
			// if err != nil {
			// 	logrus.Warnf("template [%s]: Problem creating ssh command: %v", template.Name, err)
			// 	return err
			// }
			// _, cout, _, err := c.RunWithTimeout(nil, outputs.COLLECT, 8*time.Minute) // FIXME Hardcoded timeout
			// if err != nil {
			// 	logrus.Warnf("template [%s]: Problem running ssh command: %v", template.Name, err)
			// 	return err
			// }
			_, cout, _, err := host.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), 8*time.Minute) // FIXME: hardcoded timeout
			if err != nil {
				return scerr.Wrap(err, "template [%s] host '%s': failed to run collection script", template.Name, hostName)
			}
			daCPU, err := createCPUInfo(cout)
			if err != nil {
				return scerr.Wrap(err, "template [%s]: Problem building cpu info", template.Name)
			}

			daCPU.TemplateName = template.Name
			daCPU.TemplateID = template.ID
			daCPU.ImageID = img.ID
			daCPU.ImageName = img.Name
			daCPU.TenantName = tenantName
			daCPU.LastUpdated = time.Now().Format(time.RFC850)

			daOut, err := json.MarshalIndent(daCPU, "", "\t")
			if err != nil {
				logrus.Warnf("tenant '%s', template '%s' : Problem marshaling json data: %v", tenantName, template.Name, err)
				return err
			}

			nerr := ioutil.WriteFile(utils.AbsPathify("$HOME/.safescale/scanner/"+tenantName+"#"+template.Name+".json"), daOut, 0666)
			if nerr != nil {
				logrus.Warnf("tenant '%s', template '%s' : Error writing file: %v", tenantName, template.Name, nerr)
				return nerr
			}
			logrus.Infof("tenant '%s', template '%s': Stored in file: %s", tenantName, template.Name, "$HOME/.safescale/scanner/"+tenantName+"#"+template.Name+".json")
		} else {
			return fmt.Errorf("no gateway network")
		}

		return nil
	}

	wg.Add(len(templates))

	for _, target := range templates {
		sem <- true
		localTarget := target
		go func(inner abstract.HostTemplate) {
			defer func() { <-sem }()
			lerr := hostAnalysis(inner)
			if lerr != nil {
				logrus.Warnf("Error running scanner: %+v", lerr)
			}
		}(localTarget)
	}

	for i := 0; i < cap(sem); i++ {
		sem <- true
	}

	wg.Wait()

	return nil
}

func (handler *scannerHandler) dumpTemplates() (err error) {
	err = os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777)
	if err != nil {
		return err
	}

	type TemplateList struct {
		Templates []abstract.HostTemplate `json:"templates,omitempty"`
	}

	svc := handler.job.SafeGetService()
	templates, err := svc.ListTemplates(false)
	if err != nil {
		return err
	}

	content, err := json.Marshal(TemplateList{
		Templates: templates,
	})
	if err != nil {
		return err
	}

	f := fmt.Sprintf("$HOME/.safescale/scanner/%s-templates.json", svc.SafeGetName())
	f = utils.AbsPathify(f)

	err = ioutil.WriteFile(f, content, 0666)
	if err != nil {
		return err
	}

	return nil
}

func (handler *scannerHandler) dumpImages() (err error) {
	err = os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777)
	if err != nil {
		return err
	}

	type ImageList struct {
		Images []abstract.Image `json:"images,omitempty"`
	}

	svc := handler.job.SafeGetService()
	images, err := svc.ListImages(false)
	if err != nil {
		return err
	}

	content, err := json.Marshal(ImageList{
		Images: images,
	})
	if err != nil {
		return err
	}

	f := fmt.Sprintf("$HOME/.safescale/scanner/%s-images.json", svc.SafeGetName())
	f = utils.AbsPathify(f)

	err = ioutil.WriteFile(f, content, 0666)
	if err != nil {
		return err
	}

	return nil
}

func createCPUInfo(output string) (_ *CPUInfo, err error) {
	str := strings.TrimSpace(output)

	tokens := strings.Split(str, "î")
	if len(tokens) < 9 {
		return nil, scerr.SyntaxError("parsing error: '%s'", str)
	}
	info := CPUInfo{}
	info.NumberOfCPU, err = strconv.Atoi(tokens[0])
	if err != nil {
		return nil, scerr.SyntaxError("parsing error: NumberOfCPU='%s' (from '%s')", tokens[0], str)
	}
	info.NumberOfCore, err = strconv.Atoi(tokens[1])
	if err != nil {
		return nil, scerr.SyntaxError("parsing error: NumberOfCore='%s' (from '%s')", tokens[1], str)
	}
	info.NumberOfSocket, err = strconv.Atoi(tokens[2])
	if err != nil {
		return nil, scerr.SyntaxError("parsing error: NumberOfSocket='%s' (from '%s')", tokens[2], str)
	}
	info.NumberOfCore *= info.NumberOfSocket
	info.CPUFrequency, err = strconv.ParseFloat(tokens[3], 64)
	if err != nil {
		return nil, scerr.SyntaxError("parsing error: CpuFrequency='%s' (from '%s')", tokens[3], str)
	}
	info.CPUFrequency = math.Floor(info.CPUFrequency*100) / 100000

	info.CPUArch = tokens[4]
	info.Hypervisor = tokens[5]
	info.CPUModel = tokens[6]
	info.RAMSize, err = strconv.ParseFloat(tokens[7], 64)
	if err != nil {
		return nil, scerr.SyntaxError("parsing error: RAMSize='%s' (from '%s')", tokens[7], str)
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

func (handler *scannerHandler) collect() (err error) {
	svc := handler.job.SafeGetService()

	authOpts, err := svc.GetAuthenticationOptions()
	if err != nil {
		return err
	}
	region, ok := authOpts.Get("Region")
	if !ok {
		return scerr.InvalidRequestError("'Region' not set in tenant 'compute' section")
	}

	folder := fmt.Sprintf("images/%s/%s", svc.SafeGetName(), region)

	err = os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777)
	if err != nil {
		return err
	}

	db, err := scribble.New(utils.AbsPathify("$HOME/.safescale/scanner/db"), nil)
	if err != nil {
		return err
	}

	files, err := ioutil.ReadDir(utils.AbsPathify("$HOME/.safescale/scanner"))
	if err != nil {
		return err
	}

	for _, file := range files {
		acpu := StoredCPUInfo{}
		theFile := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/scanner/%s", file.Name()))
		if strings.Contains(file.Name(), svc.SafeGetName()+"#") {
			logrus.Infof("Storing: %s", file.Name())

			byteValue, err := ioutil.ReadFile(theFile)
			if err != nil {
				return err
			}

			err = json.Unmarshal(byteValue, &acpu)
			if err != nil {
				return err
			}

			acpu.ID = acpu.ImageID

			err = db.Write(folder, acpu.TemplateName, acpu)
			if err != nil {
				return err
			}
		}
		if !file.IsDir() {
			err := os.Remove(theFile)
			if err != nil {
				logrus.Infof("Error Supressing %s : %s", file.Name(), err.Error())
			}
		}
	}
	return nil
}
