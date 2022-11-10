/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/oscarpicas/scribble"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/host"
	networkfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/network"
	subnetfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/subnet"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// PriceInfo stores price information
type PriceInfo struct {
	Currency      string  `json:"currency"`                 // contains the currency of the price info
	DurationLabel string  `json:"duration_label,omitempty"` // contains a label for the duration "Per Hour" for example
	Duration      uint    `json:"duration"`                 // number of seconds of the duration
	Price         float64 `json:"price"`                    // price in the given currency for the duration
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
	PricePerSecond float64     `json:"price_in_dollars_second"` // DEPRECATED: use field Prices
	PricePerHour   float64     `json:"price_in_dollars_hour"`   // DEPRECATED: use field Prices
	Prices         []PriceInfo `json:"prices,omitempty"`
}

// StoredCPUInfo ...
type StoredCPUInfo struct {
	ID string `bow:"key"`
	CPUInfo
}

const (
	scanNetworkName   string  = "safescale-scan-network"
	scanNetworkCIDR   string  = "192.168.20.0/24"
	scanSubnetName    string  = "safescale-scan-subnet"
	scanSubnetCIDR    string  = "192.168.20.0/26"
	defaultScanImage  string  = "Ubuntu 20.04"
	scannedHostPrefix string  = "scanhost-"
	maxParallelScans  float64 = 4.0
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

// FIXME: some disks are vda (instead of sda)
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

// NOTICE: At service level, we need to log before returning, because it's the last chance to track the real issue in server side, so we should catch panics here

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/handlers.TenantHandler -o mocks/mock_tenant.go

// TenantHandler defines API to manipulate tenants
type TenantHandler interface {
	Scan(string, bool, []string) (*protocol.ScanResultList, fail.Error)
	Inspect(string) (*protocol.TenantInspectResponse, fail.Error)
}

// tenantHandler service
type tenantHandler struct {
	job              jobapi.Job
	abstractSubnet   *abstract.Subnet
	scannedHostImage *abstract.Image
}

// NewTenantHandler creates a scanner service
func NewTenantHandler(job jobapi.Job) TenantHandler {
	return &tenantHandler{job: job}
}

// Inspect displays tenant configuration
// FIXME: job now knows the tenant to inspect, not more needed to pass tenantName as parameter...
func (handler *tenantHandler) Inspect(tenantName string) (_ *protocol.TenantInspectResponse, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if tenantName == "" {
		return nil, fail.InvalidParameterError("tenant name", "cannot be empty string")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.tenant")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	svc := handler.job.Service()
	// currentName, err := svc.GetName()
	// if err != nil {
	// 	return nil, err
	// }
	// if tenantName != currentName {
	// 	return nil, fail.NewError("we only inspect current tenant right now")
	// }

	ctx := handler.job.Context()

	fromParams := func(in map[string]interface{}, key1 string, key2 string) string {
		if val, ok := in[key1]; ok {
			if adict, ok := val.(map[string]interface{}); ok {
				if val2, ok := adict[key2]; ok {
					if val3, ok := val2.(string); ok {
						return val3
					}
				}
			}
		}
		return ""
	}

	fromParamsWithSynonims := func(in map[string]interface{}, keylist []string, synons []string) string {
		for _, key1 := range keylist {
			if val, ok := in[key1]; ok {
				if adict, ok := val.(map[string]interface{}); ok {
					for _, key2 := range synons {
						if val2, ok := adict[key2]; ok {
							if val3, ok := val2.(string); ok {
								if val3 != "" {
									return val3
								}
							}
						}
					}
				}
			}
		}

		return ""
	}

	skipEmpty := func(in *protocol.KeyValue) *protocol.KeyValue {
		if in == nil {
			return nil
		}
		if in.Value == "" {
			return nil
		}

		return in
	}

	authOpts, xerr := svc.AuthenticationOptions()
	if xerr != nil {
		return nil, fail.Wrap(xerr, "unable to recover driver authentication options")
	}

	configOpts, xerr := svc.ConfigurationOptions()
	if xerr != nil {
		return nil, fail.Wrap(xerr, "unable to recover driver configuration options")
	}

	params, err := svc.TenantParameters()
	if err != nil {
		return nil, err
	}

	svcName, err := svc.GetName()
	if err != nil {
		return nil, err
	}

	provName, err := svc.GetProviderName()
	if err != nil {
		return nil, err
	}

	bucket, err := svc.GetMetadataBucket(ctx)
	if err != nil {
		return nil, err
	}

	var (
		whitelistTemplateRegexp string
		blacklistTemplateRegexp string
		whitelistImageRegexp    string
		blacklistImageRegexp    string
	)
	if configOpts.WhitelistTemplateRegexp != nil {
		whitelistTemplateRegexp = configOpts.WhitelistTemplateRegexp.String()
	}
	if configOpts.BlacklistTemplateRegexp != nil {
		blacklistTemplateRegexp = configOpts.BlacklistTemplateRegexp.String()
	}
	if configOpts.WhitelistImageRegexp != nil {
		whitelistImageRegexp = configOpts.WhitelistImageRegexp.String()
	}
	if configOpts.BlacklistImageRegexp != nil {
		blacklistImageRegexp = configOpts.BlacklistImageRegexp.String()
	}

	out := &protocol.TenantInspectResponse{
		Name:     svcName,
		Provider: provName,
		Identity: &protocol.TenantIdentity{
			User: skipEmpty(&protocol.KeyValue{
				Key:   "Username",
				Value: fromParams(params, "identity", "Username"),
			}),
			AppKey: nil, // secret
			Domain: skipEmpty(&protocol.KeyValue{
				Key:   "DomainName",
				Value: fromParamsWithSynonims(params, []string{"objectstorage", "compute", "identity"}, []string{"DomainName", "Domain"}),
			}),
		},
		Compute: &protocol.TenantCompute{
			Region:                 fromParams(params, "compute", "Region"),
			SubRegion:              authOpts.SubRegion,
			AvailabilityZone:       fromParams(params, "compute", "Zone"),
			Context:                nil,
			ApiKey:                 nil, // secret
			WhitelistTemplateRegex: whitelistTemplateRegexp,
			BlacklistTemplateRegex: blacklistTemplateRegexp,
			DefaultImage:           configOpts.DefaultImage,
			DnsList:                configOpts.DNSServers,
			OperatorUsername:       fromParams(params, "compute", "OperatorUsername"),
			WhitelistImageRegex:    whitelistImageRegexp,
			BlacklistImageRegex:    blacklistImageRegexp,
		},
		ObjectStorage: &protocol.TenantObjectStorage{
			Type:           fromParams(params, "objectstorage", "Type"),
			Endpoint:       fromParams(params, "objectstorage", "Endpoint"),
			AuthUrl:        fromParams(params, "objectstorage", "AuthURL"),
			AccessKey:      "", // secret
			Region:         fromParams(params, "objectstorage", "Region"),
			ProjectName:    fromParams(params, "objectstorage", "ProjectName"),
			ApplicationKey: "", // secret
			Username:       fromParams(params, "objectstorage", "Username"),
			Password:       "", // secret
		},
		Metadata: &protocol.TenantMetadata{
			BucketName: bucket.GetName(),
			Crypt:      fromParams(params, "metadata", "CryptKey") != "",
		},
	}
	return out, nil
}

// Scan scans the tenant and updates the database
// FIXME: job now knows the tenant to scan, no need to pass it as parameter
func (handler *tenantHandler) Scan(tenantName string, isDryRun bool, templateNamesToScan []string) (_ *protocol.ScanResultList, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if tenantName == "" {
		return nil, fail.InvalidParameterError("tenant name", "cannot be empty string")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.tenant")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	svc := handler.job.Service()
	ctx := handler.job.Context()

	isScannable, err := handler.checkScannable()
	if err != nil {
		return nil, err
	}
	if !isScannable {
		return nil, fail.ForbiddenError("tenant is not defined as scannable")
	}

	if isDryRun {
		return handler.dryRun(ctx, templateNamesToScan)
	}

	var templatesToScan []abstract.HostTemplate
	if templateNamesToScan != nil { // nolint
		for _, templateName := range templateNamesToScan {
			template, err := svc.FindTemplateByName(ctx, templateName)
			if err != nil {
				return nil, fail.AbortedError(err)
			}
			templatesToScan = append(templatesToScan, *template)
		}
	} else {
		if xerr := handler.dumpImages(ctx); xerr != nil {
			return nil, xerr
		}

		if xerr := handler.dumpTemplates(ctx); xerr != nil {
			return nil, xerr
		}

		templatesToScan, xerr := svc.ListTemplates(ctx, false)
		if xerr != nil {
			return nil, xerr
		}

		for _, template := range templatesToScan {
			templateNamesToScan = append(templateNamesToScan, template.Name)
		}
	}

	logrus.Infof("Starting scan of tenant %q with templates: %v", tenantName, templateNamesToScan)
	logrus.Infof("Using %q image", defaultScanImage)

	var xerr fail.Error
	handler.scannedHostImage, xerr = svc.SearchImage(ctx, defaultScanImage)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "could not find needed image in given service")
	}

	logrus.Infof("Creating scan network: %q", scanNetworkName)
	network, xerr := handler.getScanNetwork()
	if xerr != nil {
		return nil, fail.Wrap(xerr, "could not get/create the scan network")
	}

	nid, aerr := network.GetID()
	if aerr != nil {
		return nil, fail.ConvertError(aerr)
	}

	defer func() {
		derr := network.Delete(context.Background())
		if derr != nil {
			logrus.Warnf("Error deleting network '%s'", nid)
			_ = ferr.AddConsequence(derr)
		}
	}()

	logrus.Infof("Creating scan subnet: %q", scanSubnetName)
	subnet, xerr := handler.getScanSubnet(nid)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "could not get/create the scan subnet")
	}

	snid, aerr := subnet.GetID()
	if aerr != nil {
		return nil, fail.ConvertError(aerr)
	}

	defer func() {
		if derr := subnet.Delete(context.Background()); derr != nil {
			logrus.Warnf("Error deleting subnet '%s'", snid)
			_ = ferr.AddConsequence(derr)
		}
	}()

	xerr = subnet.Inspect(context.Background(), func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, innerErr := lang.Cast[*abstract.Subnet](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		handler.abstractSubnet = as
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	var scanResultList []*protocol.ScanResult

	var scanWaitGroup sync.WaitGroup
	scanChannel := make(chan bool, int(math.Min(maxParallelScans, float64(len(templatesToScan)))))

	scanWaitGroup.Add(len(templatesToScan))

	for _, targetTemplate := range templatesToScan {
		scanChannel <- true
		localTarget := targetTemplate

		fileCandidate := utils.AbsPathify("$HOME/.safescale/scanner/" + tenantName + "#" + localTarget.Name + ".json")
		if _, err := os.Stat(fileCandidate); err != nil {
			if !os.IsNotExist(err) {
				break
			}
		}

		go func(innerTemplate abstract.HostTemplate) {
			var crash error
			defer fail.SilentOnPanic(&crash)

			logrus.Infof("Started scan for template %q", innerTemplate.Name)
			lerr := handler.analyzeTemplate(innerTemplate)
			if lerr != nil {
				logrus.Warnf("Error running scanner for template %q: %+v", innerTemplate.Name, lerr)
				scanResultList = append(scanResultList, &protocol.ScanResult{
					TemplateName: innerTemplate.Name,
					ScanSuccess:  false,
				})
			} else {
				scanResultList = append(scanResultList, &protocol.ScanResult{
					TemplateName: innerTemplate.Name,
					ScanSuccess:  true,
				})
			}
			<-scanChannel
			scanWaitGroup.Done()
		}(localTarget)
	}

	for i := 0; i < cap(scanChannel); i++ {
		scanChannel <- true
	}

	scanWaitGroup.Wait()

	svcName, xerr := svc.GetName()
	if xerr != nil {
		return nil, xerr
	}
	if err := handler.collect(ctx); err != nil {
		return nil, fail.Wrap(err, "failed to save scanned info for tenant '%s'", svcName)
	}
	return &protocol.ScanResultList{Results: scanResultList}, nil
}

func (handler *tenantHandler) analyzeTemplate(template abstract.HostTemplate) (ferr fail.Error) {
	svc := handler.job.Service()
	task := handler.job.Task()
	tenantName, xerr := svc.GetName()
	if xerr != nil {
		return xerr
	}

	hostName := scannedHostPrefix + template.Name
	host, xerr := hostfactory.New(handler.job.Context())
	if xerr != nil {
		return xerr
	}

	// FIXME: Fix hardcoded flexible engine host name regex
	if tenantName == "flexibleengine" {
		hostName = strings.ReplaceAll(hostName, ".", "_")
	}

	req := abstract.HostRequest{
		ResourceName: hostName,
		Subnets:      []*abstract.Subnet{handler.abstractSubnet},
		PublicIP:     false,
		TemplateID:   template.ID,
	}
	def := abstract.HostSizingRequirements{
		Image: defaultScanImage,
	}

	if _, xerr = host.Create(handler.job.Context(), req, def); xerr != nil {
		return fail.Wrap(xerr, "template [%s] host '%s': error creation", template.Name, hostName)
	}

	hid, err := host.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	defer func() {
		logrus.Infof("Deleting host '%s' with ID '%s'", hostName, hid)
		ctx := jobapi.NewContextPropagatingJob(handler.job.Context())
		derr := host.Delete(ctx)
		if derr != nil {
			switch derr.(type) {
			case *fail.ErrNotFound:
				// missing Host is considered a successful deletion, continue
			default:
				logrus.Warnf("Error deleting host '%s'", hostName)
			}
		}
	}()

	_, cout, _, xerr := host.Run(task.Context(), cmd, outputs.COLLECT, temporal.ConnectionTimeout(), 5*temporal.ContextTimeout())
	if xerr != nil {
		return fail.Wrap(xerr, "template [%s] host '%s': failed to run collection script", template.Name, hostName)
	}

	daCPU, xerr := createCPUInfo(cout)
	if xerr != nil {
		return fail.Wrap(xerr, "template [%s]: Problem building cpu info", template.Name)
	}

	daCPU.TemplateName = template.Name
	daCPU.TemplateID = template.ID
	daCPU.ImageID = handler.scannedHostImage.ID
	daCPU.ImageName = handler.scannedHostImage.Name
	daCPU.TenantName = tenantName
	daCPU.LastUpdated = time.Now().Format(time.RFC850)

	daOut, err := json.MarshalIndent(daCPU, "", "\t")
	if err != nil {
		logrus.Warnf("tenant '%s', template '%s' : Problem marshaling json data: %v", tenantName, template.Name, err)
		return fail.ConvertError(err)
	}

	nerr := os.WriteFile(utils.AbsPathify("$HOME/.safescale/scanner/"+tenantName+"#"+template.Name+".json"), daOut, 0600)
	if nerr != nil {
		logrus.Warnf("tenant '%s', template '%s' : Error writing file: %v", tenantName, template.Name, nerr)
		return fail.ConvertError(nerr)
	}
	logrus.Infof("tenant '%s', template '%s': Stored in file: %s", tenantName, template.Name, "$HOME/.safescale/scanner/"+tenantName+"#"+template.Name+".json")

	return nil
}

func (handler *tenantHandler) dryRun(ctx context.Context, templateNamesToScan []string) (_ *protocol.ScanResultList, ferr fail.Error) {
	svc := handler.job.Service()

	var resultList []*protocol.ScanResult

	templates, xerr := svc.ListTemplates(ctx, false)
	if xerr != nil {
		return nil, xerr
	}

	for _, template := range templates {
		if templateNamesToScan != nil { // nolint
			for _, givenName := range templateNamesToScan {
				if givenName == template.Name {
					resultList = append(resultList, &protocol.ScanResult{
						TemplateName: template.Name,
						ScanSuccess:  false,
					})
				}
			}
		}
		resultList = append(resultList, &protocol.ScanResult{
			TemplateName: template.Name,
			ScanSuccess:  false,
		})
	}

	return &protocol.ScanResultList{Results: resultList}, xerr
}

func (handler *tenantHandler) checkScannable() (isScannable bool, ferr fail.Error) {
	svc := handler.job.Service()

	params, xerr := svc.TenantParameters()
	if xerr != nil {
		return false, xerr
	}

	compute, ok1 := params["compute"].(map[string]interface{})
	isScannable, ok2 := compute["Scannable"].(bool)

	if !(ok1 && ok2) {
		return false, fail.InvalidParameterError("scannable", "not set")
	}

	return isScannable, xerr
}

func (handler *tenantHandler) dumpTemplates(ctx context.Context) (ferr fail.Error) {
	err := os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777)
	if err != nil {
		return fail.ConvertError(err)
	}

	type TemplateList struct {
		Templates []*abstract.HostTemplate `json:"templates,omitempty"`
	}

	svc := handler.job.Service()
	templates, xerr := svc.ListTemplates(ctx, false)
	if xerr != nil {
		return xerr
	}

	content, err := json.Marshal(TemplateList{
		Templates: templates,
	})
	if err != nil {
		return fail.ConvertError(err)
	}

	svcName, xerr := svc.GetName()
	if xerr != nil {
		return xerr
	}
	f := fmt.Sprintf("$HOME/.safescale/scanner/%s-templates.json", svcName)
	f = utils.AbsPathify(f)

	if err = os.WriteFile(f, content, 0600); err != nil {
		return fail.ConvertError(err)
	}

	return nil
}

func (handler *tenantHandler) dumpImages(ctx context.Context) (ferr fail.Error) {
	if err := os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777); err != nil {
		return fail.ConvertError(err)
	}

	type ImageList struct {
		Images []*abstract.Image `json:"images,omitempty"`
	}

	svc := handler.job.Service()
	images, xerr := svc.ListImages(ctx, false)
	if xerr != nil {
		return xerr
	}

	content, err := json.Marshal(ImageList{
		Images: images,
	})
	if err != nil {
		return fail.ConvertError(err)
	}

	svcName, xerr := svc.GetName()
	if xerr != nil {
		return xerr
	}

	f := fmt.Sprintf("$HOME/.safescale/scanner/%s-images.json", svcName)
	f = utils.AbsPathify(f)

	if err := os.WriteFile(f, content, 0600); err != nil {
		return fail.ConvertError(err)
	}

	return nil
}

func (handler *tenantHandler) getScanNetwork() (network resources.Network, ferr fail.Error) {
	var xerr fail.Error
	network, xerr = networkfactory.Load(handler.job.Context(), scanNetworkName)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok || valid.IsNil(xerr) {
			return nil, xerr
		}

		network, xerr = networkfactory.New(handler.job.Context())
		if xerr != nil {
			return nil, xerr
		}
		req := abstract.NetworkRequest{
			Name: scanNetworkName,
			CIDR: scanNetworkCIDR,
		}
		if xerr = network.Create(handler.job.Context(), req); xerr != nil {
			return nil, xerr
		}
		return network, xerr
	}
	return network, xerr
}

func (handler *tenantHandler) getScanSubnet(networkID string) (_ resources.Subnet, ferr fail.Error) {
	subnet, xerr := subnetfactory.Load(handler.job.Context(), scanNetworkName, scanSubnetName)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok || valid.IsNil(xerr) {
			return nil, xerr
		}
		subnet, xerr = subnetfactory.New(handler.job.Context())
		if xerr != nil {
			return nil, xerr
		}
		req := abstract.SubnetRequest{
			Name:           scanSubnetName,
			NetworkID:      networkID,
			IPVersion:      ipversion.IPv4,
			CIDR:           scanSubnetCIDR,
			DefaultSSHPort: 22,
		}

		subnetHostSizing := abstract.HostSizingRequirements{
			MinGPU: -1,
		}
		xerr = subnet.Create(handler.job.Context(), req, "", &subnetHostSizing)
		if xerr != nil {
			return nil, xerr
		}
	}

	return subnet, nil
}

func createCPUInfo(output string) (_ *CPUInfo, ferr fail.Error) {
	str := strings.TrimSpace(output)

	tokens := strings.Split(str, "î")
	if len(tokens) < 9 {
		return nil, fail.SyntaxError("parsing error: '%s'", str)
	}
	info := CPUInfo{}
	var err error
	if info.NumberOfCPU, err = strconv.Atoi(tokens[0]); err != nil {
		return nil, fail.SyntaxError("parsing error: NumberOfCPU='%s' (from '%s')", tokens[0], str)
	}
	if info.NumberOfCore, err = strconv.Atoi(tokens[1]); err != nil {
		return nil, fail.SyntaxError("parsing error: NumberOfCore='%s' (from '%s')", tokens[1], str)
	}
	if info.NumberOfSocket, err = strconv.Atoi(tokens[2]); err != nil {
		return nil, fail.SyntaxError("parsing error: NumberOfSocket='%s' (from '%s')", tokens[2], str)
	}
	info.NumberOfCore *= info.NumberOfSocket
	if info.CPUFrequency, err = strconv.ParseFloat(tokens[3], 64); err != nil {
		return nil, fail.SyntaxError("parsing error: CpuFrequency='%s' (from '%s')", tokens[3], str)
	}
	info.CPUFrequency = math.Floor(info.CPUFrequency*100) / 100000

	info.CPUArch = tokens[4]
	info.Hypervisor = tokens[5]
	info.CPUModel = tokens[6]
	if info.RAMSize, err = strconv.ParseFloat(tokens[7], 64); err != nil {
		return nil, fail.SyntaxError("parsing error: RAMSize='%s' (from '%s')", tokens[7], str)
	}

	memInGb := info.RAMSize / 1024 / 1024
	info.RAMSize = math.Floor(memInGb*100) / 100
	if info.RAMFreq, err = strconv.ParseFloat(tokens[8], 64); err != nil {
		info.RAMFreq = 0
	}
	gpuTokens := strings.Split(tokens[9], "%")
	nb := len(gpuTokens)
	if nb > 1 {
		info.GPUModel = strings.TrimSpace(gpuTokens[0])
		info.GPU = nb - 1
	}

	if info.DiskSize, err = strconv.ParseInt(tokens[10], 10, 64); err != nil {
		info.DiskSize = 0
	}
	info.DiskSize = info.DiskSize / 1024 / 1024 / 1024

	if info.EphDiskSize, err = strconv.ParseInt(tokens[11], 10, 64); err != nil {
		info.EphDiskSize = 0
	}
	info.EphDiskSize = info.EphDiskSize / 1024 / 1024 / 1024

	if info.MainDiskSpeed, err = strconv.ParseFloat(tokens[12], 64); err != nil {
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

func (handler *tenantHandler) collect(ctx context.Context) (ferr fail.Error) {
	svc := handler.job.Service()

	authOpts, xerr := svc.AuthenticationOptions()
	if xerr != nil {
		return xerr
	}

	region := authOpts.Region
	svcName, xerr := svc.GetName()
	if xerr != nil {
		return xerr
	}
	folder := fmt.Sprintf("images/%s/%s", svcName, region)

	if err := os.MkdirAll(utils.AbsPathify("$HOME/.safescale/scanner"), 0777); err != nil {
		return fail.ConvertError(err)
	}

	db, err := scribble.New(utils.AbsPathify("$HOME/.safescale/scanner/db"), nil)
	if err != nil {
		return fail.ConvertError(err)
	}

	files, err := ioutil.ReadDir(utils.AbsPathify("$HOME/.safescale/scanner"))
	if err != nil {
		return fail.ConvertError(err)
	}

	for _, file := range files {
		acpu := StoredCPUInfo{}
		theFile := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/scanner/%s", file.Name()))

		svcName, xerr := svc.GetName()
		if xerr != nil {
			return xerr
		}

		if strings.Contains(file.Name(), svcName+"#") {
			logrus.Infof("Storing: %s", file.Name())

			byteValue, err := os.ReadFile(theFile)
			if err != nil {
				return fail.ConvertError(err)
			}

			if err = json.Unmarshal(byteValue, &acpu); err != nil {
				return fail.ConvertError(err)
			}

			acpu.ID = acpu.ImageID

			if err = db.Write(folder, acpu.TemplateName, acpu); err != nil {
				return fail.ConvertError(err)
			}
		}
		if !file.IsDir() {
			if err = os.Remove(theFile); err != nil {
				logrus.WithContext(handler.job.Context()).Debugf("Error Suppressing %s : %s", file.Name(), err.Error())
			}
		}
	}
	return nil
}
