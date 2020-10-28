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

package outscale

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/antihax/optional"
	"github.com/sirupsen/logrus"

	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

func normalizeImageName(name string) string {
	if len(name) == 0 {
		return name
	}

	n := strings.Replace(name, "-", " ", 1)
	n = strings.Replace(n, "-", " (", 1)
	n = strings.Replace(n, ".", ",", 1)
	n = strings.ReplaceAll(n, ".", "")
	n = strings.Replace(n, ",", ".", 1)
	n = strings.ReplaceAll(n, "-0", ")")
	tok := strings.Split(n, " (")

	if len(tok) == 0 {
		return name
	}

	return tok[0]
}

// ListImages lists available OS images
func (s stack) ListImages() (_ []abstract.Image, xerr fail.Error) {
	var emptySlice []abstract.Image
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.compute") || tracing.ShouldTrace("stack.outscale")*/).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	var resp osc.ReadImagesResponse
	xerr = stacks.RetryableRemoteCall(
		func() (innerErr error) {
			resp, _, innerErr = s.client.ImageApi.ReadImages(s.auth, nil)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return emptySlice, xerr
	}
	var images []abstract.Image
	for _, omi := range resp.Images {
		images = append(images, abstract.Image{
			Description: omi.Description,
			ID:          omi.ImageId,
			Name:        normalizeImageName(omi.ImageName),
			URL:         omi.FileLocation,
			StorageType: omi.RootDeviceType,
		})
	}
	return images, nil
}

func intRange(start, stop, step int) []int {
	var r []int
	for i := start; i <= stop; i += step {
		r = append(r, i)
	}
	return r
}

func gpuTemplateName(version, cpu, ram, perf, gpu int, gpuType string) (name string) {
	if version == 0 {
		name = fmt.Sprintf("tina.c%dr%dp%d", cpu, ram, perf)
		return
	}
	name = fmt.Sprintf("tinav%d.c%dr%dp%d.g%dt%s", version, cpu, ram, perf, gpu, gpuType)
	return
}

func (s stack) cpuFreq(perf int) float32 {
	freq := float32(2.0)
	if f, ok := s.CPUPerformanceMap[perf]; ok {
		freq = f
	}
	return freq
}

func parseSizing(s string) (cpus, ram, perf int, xerr fail.Error) {
	tokens := strings.FieldsFunc(s, func(r rune) bool {
		return r == 'c' || r == 'r' || r == 'p' || r == 'g'
	})

	if len(tokens) < 2 {
		return 0, 0, 0, fail.InconsistentError("error parsing sizing string")
	}

	var err error
	cpus, err = strconv.Atoi(tokens[0])
	if err != nil {
		return 0, 0, 0, fail.ToError(err)
	}
	ram, err = strconv.Atoi(tokens[1])
	if err != nil {
		return 0, 0, 0, fail.ToError(err)
	}
	perf = 2
	if len(tokens) < 3 {
		return
	}
	perf, err = strconv.Atoi(tokens[2])
	if err != nil {
		return 0, 0, 0, fail.ToError(err)
	}

	return
}

func parseGPU(s string) (gpus int, gpuType string, xerr fail.Error) {
	tokens := strings.FieldsFunc(s, func(r rune) bool {
		return r == 'g' || r == 't'
	})
	if len(tokens) < 2 {
		return 0, "", fail.InvalidParameterError("id", "malformed id")
	}
	var err error
	gpus, err = strconv.Atoi(tokens[0])
	if err != nil {
		return 0, "", fail.ToError(err)
	}
	gpuType = tokens[1]
	return
}

func (s stack) parseTemplateID(id string) (*abstract.HostTemplate, fail.Error) {
	tokens := strings.Split(id, ".")
	if len(tokens) < 2 || !strings.HasPrefix(id, "tina") {
		return nil, fail.InvalidParameterError("id", "invalid template id")
	}

	cpus, ram, perf, err := parseSizing(tokens[1])
	if err != nil {
		return nil, fail.InvalidParameterError("id", "invalid template id")
	}
	gpus := 0
	gpuType := ""
	if len(tokens) > 2 {
		gpus, gpuType, err = parseGPU(tokens[2])
		if err != nil {
			return nil, fail.InvalidParameterError("id", "invalid template id")
		}
	}
	return &abstract.HostTemplate{
		Cores:     cpus,
		CPUFreq:   s.cpuFreq(perf),
		GPUNumber: gpus,
		GPUType:   gpuType,
		RAMSize:   float32(ram),
		DiskSize:  0,
		Name:      id,
		ID:        id,
	}, nil
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (s stack) ListTemplates() (_ []abstract.HostTemplate, xerr fail.Error) {
	var emptySlice []abstract.HostTemplate
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.compute") || tracing.ShouldTrace("stack.outscale")*/).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	// without GPU
	cpus := intRange(1, 78, 1)
	ramPerCore := intRange(1, 16, 1)
	perfLevels := []int{1, 2, 3}
	var templates []abstract.HostTemplate
	for _, cpu := range cpus {
		for _, ramCore := range ramPerCore {
			for _, perf := range perfLevels {
				ram := cpu * ramCore
				// Outscale maximum memory size
				if ram > 1039 {
					break
				}
				name := gpuTemplateName(0, cpu, ram, perf, 0, "")
				templates = append(templates, abstract.HostTemplate{
					DiskSize: 0,
					Name:     name,
					Cores:    cpu,
					RAMSize:  float32(ram),
					ID:       name,

					CPUFreq:   s.cpuFreq(perf),
					GPUNumber: 0,
				})
			}

		}
	}
	// instances with gpu https://wiki.outscale.net/pages/viewpage.action?pageId=49023126
	// with nvidia-k2 GPU
	gpus := intRange(1, 8, 2)
	for _, gpu := range gpus {
		for _, cpu := range cpus {
			for _, ramCore := range ramPerCore {
				for _, perf := range perfLevels {
					ram := cpu * ramCore
					// Outscale maximum memory size
					if ram > 1039 {
						break
					}
					//
					name := gpuTemplateName(3, cpu, ram, perf, gpu, "nvidia-k2")
					templates = append(templates, abstract.HostTemplate{
						DiskSize:  0,
						Name:      name,
						Cores:     cpu,
						RAMSize:   float32(ram),
						CPUFreq:   s.cpuFreq(perf),
						ID:        name,
						GPUNumber: gpu,
						GPUType:   "nvidia-k2",
					})
				}

			}
		}
	}

	// with nvidia-p6 gpu
	for _, gpu := range gpus {
		for _, cpu := range cpus {
			for _, ramCore := range ramPerCore {
				for _, perf := range perfLevels {
					ram := cpu * ramCore
					// Outscale maximum memory size
					if ram > 1039 {
						break
					}
					//
					name := gpuTemplateName(5, cpu, ram, perf, gpu, "nvidia-p6")
					templates = append(templates, abstract.HostTemplate{
						DiskSize:  0,
						Name:      name,
						Cores:     cpu,
						RAMSize:   float32(ram),
						CPUFreq:   s.cpuFreq(perf),
						ID:        name,
						GPUNumber: gpu,
						GPUType:   "nvidia-p6",
					})
				}
			}
		}
	}

	// with nvidia-p100 gpu
	for _, gpu := range gpus {
		for _, cpu := range cpus {
			for _, ramCore := range ramPerCore {
				for _, perf := range perfLevels {
					ram := cpu * ramCore
					// Outscale maximum memory size
					if ram > 1039 {
						break
					}
					//
					name := gpuTemplateName(5, cpu, ram, perf, gpu, "nvidia-p100")
					templates = append(templates, abstract.HostTemplate{
						DiskSize:  0,
						Name:      name,
						Cores:     cpu,
						RAMSize:   float32(ram),
						CPUFreq:   s.cpuFreq(perf),
						ID:        name,
						GPUNumber: gpu,
						GPUType:   "nvidia-p100",
					})
				}
			}
		}
	}

	return templates, nil
}

// InspectImage returns the Image referenced by id
func (s stack) InspectImage(id string) (_ *abstract.Image, xerr fail.Error) {
	nullImage := &abstract.Image{}
	if s.IsNull() {
		return nullImage, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullImage, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.compute") || tracing.ShouldTrace("stack.outscale")*/).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	defer func() {
		if xerr != nil {
			xerr = fail.Wrap(xerr, fmt.Sprintf("failed to get image '%s'", id))
		}
	}()

	readImagesOpts := osc.ReadImagesOpts{
		ReadImagesRequest: optional.NewInterface(osc.ReadImagesRequest{
			DryRun: false,
			Filters: osc.FiltersImage{
				ImageIds: []string{id},
			},
		}),
	}
	var resp osc.ReadImagesResponse
	xerr = stacks.RetryableRemoteCall(
		func() (innerErr error) {
			resp, _, innerErr = s.client.ImageApi.ReadImages(s.auth, &readImagesOpts)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return nullImage, xerr
	}
	if len(resp.Images) != 1 {
		return nullImage, fail.InconsistentError("more than one image with the same id")
	}
	img := resp.Images[0]
	out := &abstract.Image{
		Description: img.Description,
		ID:          img.ImageId,
		Name:        img.ImageName,
		StorageType: img.RootDeviceType,
		URL:         img.FileLocation,
	}
	return out, nil
}

// InspectTemplate returns the Template referenced by id
func (s stack) InspectTemplate(id string) (_ *abstract.HostTemplate, xerr fail.Error) {
	nullHT := &abstract.HostTemplate{}
	if s.IsNull() {
		return nullHT, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.compute") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	return s.parseTemplateID(id)
}

func (s stack) getOrCreatePassword(request abstract.HostRequest) (string, fail.Error) {
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return "", fail.Wrap(err, "failed to generate password")
		}
		return password, nil
	}
	return request.Password, nil
}

func (s stack) prepareUserData(request abstract.HostRequest, ud *userdata.Content) fail.Error {
	cidr := func() string {
		if len(request.Subnets) == 0 {
			return ""
		}
		return request.Subnets[0].CIDR
	}()
	if xerr := ud.Prepare(*s.configurationOptions, request, cidr, ""); xerr != nil {
		msg := "failed to prepare user data content"
		logrus.Debugf(strprocess.Capitalize(msg + ": " + xerr.Error()))
		return fail.Wrap(xerr, msg)
	}
	return nil
}

func (s stack) createNIC(request *abstract.HostRequest, subnet *abstract.Subnet) (osc.Nic, fail.Error) {
	resp, xerr := s.rpcCreateNic(subnet.ID, request.ResourceName)
	if xerr != nil {
		return osc.Nic{}, xerr
	}
	// primary := deviceNumber == 0
	return resp, nil
}

func (s stack) createNICs(request *abstract.HostRequest) (nics []osc.Nic, xerr fail.Error) {
	nics = []osc.Nic{}

	// first network is the default network
	nics, xerr = s.tryCreateNICS(request, nics)
	if xerr != nil { // if error delete created NICS
		for _, v := range nics {
			xerr := s.rpcDeleteNic(v)
			if xerr != nil {
				logrus.Errorf("impossible to delete NIC '%s': %v", v.NicId, xerr)
			}
		}
	}
	return nics, xerr
}

func (s stack) tryCreateNICS(request *abstract.HostRequest, nics []osc.Nic) ([]osc.Nic, fail.Error) {
	for _, n := range request.Subnets[1:] {
		nic, xerr := s.createNIC(request, n)
		if xerr != nil {
			return nics, xerr
		}
		nics = append(nics, nic)
	}
	return nics, nil
}

func (s stack) deleteNICs(nics []osc.Nic) fail.Error {
	for _, nic := range nics {
		if xerr := s.rpcDeleteNic(nic); xerr != nil {
			return xerr
		}
	}
	return nil
}

func hostState(state string) hoststate.Enum {
	if state == "pending" {
		return hoststate.STARTING
	}
	if state == "running" {
		return hoststate.STARTED
	}
	if state == "stopping" || state == "shutting-down" {
		return hoststate.STOPPING
	}
	if state == "stopped" {
		return hoststate.STOPPED
	}
	if state == "terminated" {
		return hoststate.TERMINATED
	}
	if state == "quarantine" {
		return hoststate.ERROR
	}
	return hoststate.UNKNOWN
}

func (s stack) hostState(id string) (hoststate.Enum, fail.Error) {
	vm, xerr := s.rpcReadVmByID(id)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return hoststate.TERMINATED, retry.StopRetryError(xerr)
		default:
			return hoststate.ERROR, xerr
		}
	}
	return hostState(vm.State), nil
}

// WaitHostReady waits an host achieve ready state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return an utils.ErrInvalidParameter
func (s stack) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	if s.IsNull() {
		return abstract.NewHostCore(), fail.InvalidInstanceError()
	}

	return s.WaitHostState(hostParam, hoststate.STARTED, timeout)
}

// WaitHostState wait for host to be in the specified state
// On exit, xerr may be of type:
// - *retry.ErrTimeout: when the timeout is reached
// - *retry.ErrStopRetry: when a breaking error arises; xerr.Cause() contains the real error encountered
// - fail.Error: any other errors
func (s stack) WaitHostState(hostParam stacks.HostParameter, state hoststate.Enum, timeout time.Duration) (_ *abstract.HostCore, xerr fail.Error) {
	nullAHC := abstract.NewHostCore()
	if s.IsNull() {
		return nullAHC, fail.InvalidInstanceError()
	}

	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAHC, xerr
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.compute") || tracing.ShouldTrace("stack.outscale")*/, "(%s, %s, %v)", hostRef, state.String(), timeout).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	xerr = retry.WhileUnsuccessfulDelay5SecondsTimeout(
		func() error {
			st, innerXErr := s.hostState(ahf.Core.ID)
			if innerXErr != nil {
				return innerXErr
			}

			switch st {
			case hoststate.ERROR:
				return retry.StopRetryError(fail.NewError("host in 'error' state"))
			case hoststate.TERMINATED:
				return retry.StopRetryError(fail.NewError("host in 'terminated' state"))
			case state:
				ahf.Core.LastState = st
				return nil
			default:
				return fail.NewError("wrong state")
			}
		},
		timeout,
	)
	if xerr != nil {
		return nullAHC, xerr
	}
	return ahf.Core, nil
}

func outscaleTemplateID(id string) (string, fail.Error) {
	tokens := strings.Split(id, ".")
	if len(tokens) < 2 {
		return "", fail.InvalidParameterError("id", "malformed template id")
	}
	if len(tokens) == 2 {
		return id, nil
	}
	return fmt.Sprintf("%s.%s", tokens[0], tokens[1]), nil
}

func (s stack) addNICs(request *abstract.HostRequest, vmID string) ([]osc.Nic, fail.Error) {
	if len(request.Subnets) > 1 {
		nics, xerr := s.createNICs(request)
		if xerr != nil {
			return nil, xerr
		}
		for i, nic := range nics {
			xerr = s.rpcLinkNic(vmID, nic.NicId, int32(i+1))
			if xerr != nil {
				logrus.Errorf("failed to attach NIC %s to Host %s: %v", nic.NicId, vmID, xerr)
				return nil, xerr
			}
		}
		return nics, nil
	}
	return nil, nil
}

func (s stack) addGPUs(request *abstract.HostRequest, tpl abstract.HostTemplate, vmID string) (xerr fail.Error) {
	//tpl, xerr := s.InspectTemplate(request.TemplateID)
	//if xerr != nil {
	//	return xerr
	//}
	//if tpl == nil {
	//	return fail.InvalidParameterError("request.TemplateID", "Template does not exists")
	//}
	if tpl.GPUNumber <= 0 {
		return nil
	}

	var (
		flexibleGpus []osc.FlexibleGpu
		createErr    fail.Error
	)
	for gpu := 0; gpu < tpl.GPUNumber; gpu++ {
		resp, xerr := s.rpcCreateFlexibleGpu(tpl.GPUType)
		if xerr != nil {
			createErr = xerr
			break
		}
		flexibleGpus = append(flexibleGpus, resp)

		xerr = s.rpcLinkFlexibleGpu(vmID, resp.FlexibleGpuId)
		if xerr != nil {
			break
		}
	}
	if xerr != nil {
		for _, gpu := range flexibleGpus {
			if derr := s.rpcDeleteFlexibleGpu(gpu.FlexibleGpuId); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Flexible GPU"))
			}
		}
	}
	return createErr
}

func (s stack) addVolume(request *abstract.HostRequest, vmID string) (xerr fail.Error) {
	if request.DiskSize == 0 {
		return nil
	}

	v, xerr := s.CreateVolume(abstract.VolumeRequest{
		Name:  fmt.Sprintf("vol-%s", request.HostName),
		Size:  request.DiskSize,
		Speed: s.Options.Compute.DefaultVolumeSpeed,
	})
	if xerr != nil {
		return xerr
	}
	defer func() {
		if xerr != nil {
			derr := s.DeleteVolume(v.ID)
			if derr != nil {
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	_, xerr = s.rpcCreateTags(v.ID, map[string]string{
		"DeleteWithVM": "true",
	})
	if xerr != nil {
		return xerr
	}

	_, xerr = s.CreateVolumeAttachment(abstract.VolumeAttachmentRequest{
		HostID:   vmID,
		VolumeID: v.ID,
	})
	return xerr
}

// VPL: obsolete
//func (s stack) getNICs(vmID string) ([]osc.Nic, fail.Error) {
//	resp, xerr := s.rpcReadNics("", vmID)
//	if xerr != nil {
//		return nil, xerr
//	}
//	return resp, nil
//}

func (s stack) addPublicIP(nic osc.Nic) (*osc.PublicIp, fail.Error) {
	// Allocate Public IP
	var resp osc.CreatePublicIpResponse
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			resp, _, innerErr = s.client.PublicIpApi.CreatePublicIp(s.auth, nil)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	defer func() {
		if xerr != nil {
			deletePublicIpRequest := osc.DeletePublicIpRequest{
				PublicIpId: resp.PublicIp.PublicIpId,
			}
			derr := stacks.RetryableRemoteCall(
				func() error {
					_, _, innerErr := s.client.PublicIpApi.DeletePublicIp(s.auth, &osc.DeletePublicIpOpts{
						DeletePublicIpRequest: optional.NewInterface(deletePublicIpRequest),
					})
					return innerErr
				},
				normalizeError,
			)
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete public ip %s", resp.PublicIp.PublicIpId))
			}
		}
	}()

	// Attach public ip
	linkPublicIpRequest := osc.LinkPublicIpRequest{
		NicId:      nic.NicId,
		PublicIpId: resp.PublicIp.PublicIpId,
	}
	xerr = stacks.RetryableRemoteCall(
		func() error {
			_, _, innerErr := s.client.PublicIpApi.LinkPublicIp(s.auth, &osc.LinkPublicIpOpts{
				LinkPublicIpRequest: optional.NewInterface(linkPublicIpRequest)},
			)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	return &resp.PublicIp, nil
}

func (s stack) setHostProperties(host *abstract.HostFull, subnets []*abstract.Subnet, vm osc.Vm, nics []osc.Nic) fail.Error {
	vmType, xerr := s.InspectTemplate(vm.VmType)
	if xerr != nil {
		return xerr
	}

	// Updates Host Property propsv1.HostDescription
	host.Description.Created = time.Now()
	host.Description.Updated = host.Description.Created

	// Updates Host Property propsv1.HostSizing
	host.Sizing.Cores = vmType.Cores
	host.Sizing.CPUFreq = vmType.CPUFreq
	host.Sizing.DiskSize = vmType.DiskSize
	host.Sizing.GPUNumber = vmType.GPUNumber
	host.Sizing.GPUType = vmType.GPUType
	host.Sizing.RAMSize = vmType.RAMSize

	// Updates Host Property propsv1.HostNetworking
	// subnets contains network names, but hostproperty.NetworkV1.IPxAddresses has to be
	// indexed on network ID. Tries to convert if possible, if we already have correspondance
	// between network ID and network Name in Host definition
	subnetsByID := map[string]string{}
	subnetsByName := map[string]string{}
	ipv4Addresses := map[string]string{}
	ipv6Addresses := map[string]string{}
	for i, net := range subnets {
		nic := nics[i]
		subnetsByID[net.ID] = net.Name
		subnetsByName[net.Name] = net.ID
		ipv4Addresses[net.ID] = func() string {
			for _, addr := range nic.PrivateIps {
				if addr.IsPrimary {
					return addr.PrivateIp
				}
			}
			return ""
		}()
	}
	host.Networking.SubnetsByID = subnetsByID
	host.Networking.SubnetsByName = subnetsByName
	// IPvxAddresses are here indexed by names... At least we have them...
	host.Networking.IPv4Addresses = ipv4Addresses
	host.Networking.IPv6Addresses = ipv6Addresses
	host.Networking.PublicIPv4 = vm.PublicIp

	return nil
}

func (s stack) initHostProperties(request *abstract.HostRequest, host *abstract.HostFull) fail.Error {
	defaultSubnet := func() *abstract.Subnet {
		if len(request.Subnets) == 0 {
			return nil
		}
		return request.Subnets[0]
	}()

	isGateway := request.IsGateway // && defaultSubnet != nil && defaultSubnet.Name != abstract.SingleHostNetworkName
	// defaultGatewayID := func() string {
	//	if request.DefaultGateway != nil {
	//		return request.DefaultGateway.ID
	//	}
	//	return ""
	// }()
	template, err := s.InspectTemplate(request.TemplateID)
	if err != nil {
		return err
	}
	if template == nil {
		return fail.InvalidParameterError("request.TemplateID", "Invalid template ID")
	}

	host.Core.PrivateKey = request.KeyPair.PrivateKey // Add PrivateKey to host definition
	host.Core.Password = request.Password

	host.Networking.DefaultSubnetID = func() string {
		if defaultSubnet == nil {
			return ""
		}
		return defaultSubnet.ID
	}()
	// host.Networking.DefaultGatewayID = defaultGatewayID
	// host.Networking.DefaultGatewayPrivateIP = request.DefaultRouteIP
	host.Networking.IsGateway = isGateway

	// Adds Host property SizingV1
	host.Sizing.Cores = template.Cores
	host.Sizing.CPUFreq = template.CPUFreq
	host.Sizing.RAMSize = template.RAMSize
	host.Sizing.DiskSize = template.DiskSize
	host.Sizing.GPUNumber = template.GPUNumber
	host.Sizing.GPUType = template.GPUType
	return nil
}

func (s stack) addPublicIPs(primaryNIC osc.Nic, otherNICs []osc.Nic) (*osc.PublicIp, fail.Error) {
	ip, xerr := s.addPublicIP(primaryNIC)
	if xerr != nil {
		return nil, xerr
	}

	for _, nic := range otherNICs {
		_, xerr = s.addPublicIP(nic)
		if xerr != nil {
			return nil, xerr
		}
	}
	return ip, nil
}

// CreateHost creates an host that fulfils the request
func (s stack) CreateHost(request abstract.HostRequest) (ahf *abstract.HostFull, udc *userdata.Content, xerr fail.Error) {
	nullAHF := abstract.NewHostFull()
	nullUDC := userdata.NewContent()
	if s.IsNull() {
		return nullAHF, nullUDC, fail.InvalidInstanceError()
	}
	if request.KeyPair == nil {
		return nullAHF, nullUDC, fail.InvalidRequestError("request.KeyPair", "cannot be nil")
	}
	if len(request.Subnets) == 0 && !request.PublicIP {
		return nullAHF, nullUDC, abstract.ResourceInvalidRequestError("host creation", "cannot create a host without public IP or without attached subnet")
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.compute") || tracing.ShouldTrace("stack.outscale")*/, "(%v)", request).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	// Get or create password
	password, xerr := s.getOrCreatePassword(request)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	request.Password = password

	// gather default subnet ID
	subnetID, xerr := s.getDefaultSubnetID(request)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}

	// Import keypair to create host
	creationKeyPair, xerr := abstract.NewKeyPair(request.ResourceName + "_install")
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	xerr = s.ImportKeyPair(creationKeyPair)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	defer func() {
		derr := s.DeleteKeyPair(creationKeyPair.Name)
		if derr != nil {
			logrus.Errorf("failed to delete creation keypair: %v", derr)
		}
	}()
	request.KeyPair = creationKeyPair

	// Configure userdata content
	udc = userdata.NewContent()
	xerr = s.prepareUserData(request, udc)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	ahf = abstract.NewHostFull()
	if xerr = s.initHostProperties(&request, ahf); xerr != nil {
		return nullAHF, nullUDC, xerr
	}

	// prepare userdata phase1 execution
	userDataPhase1, xerr := udc.Generate(userdata.PHASE1_INIT)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	vmType, xerr := outscaleTemplateID(request.TemplateID)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	//op := s.Options.Compute.OperatorUsername
	//patchSSH := fmt.Sprintf("\nchown -R %s:%s /home/%s", op, op, op)
	buf := bytes.NewBuffer(userDataPhase1)
	//buf.WriteString(patchSSH)

	// create host
	vmsRequest := osc.CreateVmsRequest{
		ImageId:  request.ImageID,
		UserData: base64.StdEncoding.EncodeToString(buf.Bytes()),
		VmType:   vmType,
		SubnetId: subnetID,
		Placement: osc.Placement{
			SubregionName: s.Options.Compute.Subregion,
			Tenancy:       s.Options.Compute.DefaultTenancy,
		},
		KeypairName: creationKeyPair.Name,
	}

	tpl, xerr := s.InspectTemplate(request.TemplateID)
	if xerr != nil {
		return nil, nil, xerr
	}

	var diskSize int = tpl.DiskSize
	if request.DiskSize > diskSize {
		diskSize = request.DiskSize
	}
	if diskSize < 10 {
		diskSize = 10
	}

	vmsRequest.BlockDeviceMappings = []osc.BlockDeviceMappingVmCreation{
		{
			Bsu: osc.BsuToCreate{
				DeleteOnVmDeletion: true,
				SnapshotId:         "",
				VolumeSize:         int32(diskSize),
				VolumeType:         s.volumeType(s.Options.Compute.DefaultVolumeSpeed),
			},
			NoDevice:   "true",
			DeviceName: "/dev/sda1",
		},
	}

	var resp osc.CreateVmsResponse
	xerr = stacks.RetryableRemoteCall(
		func() (innerErr error) {
			resp, _, innerErr = s.client.VmApi.CreateVms(s.auth, &osc.CreateVmsOpts{
				CreateVmsRequest: optional.NewInterface(vmsRequest),
			})
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}

	if len(resp.Vms) == 0 {
		return nullAHF, nullUDC, fail.InconsistentError("after creation submission, virtual machine list is empty")
	}
	vm := resp.Vms[0]

	defer func() {
		if xerr != nil {
			if derr := s.DeleteHost(vm.VmId); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Host"))
			}
		}
	}()

	if _, xerr = s.WaitHostState(vm.VmId, hoststate.STARTED, temporal.GetHostTimeout()); xerr != nil {
		return nullAHF, nullUDC, xerr
	}

	// Retrieve default Nic use to create public ip
	nics, xerr := s.rpcReadNics("", vm.VmId)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	if len(nics) == 0 {
		return nullAHF, nullUDC, fail.InconsistentError("No network interface associated to vm")
	}
	defaultNic := nics[0]

	nics, xerr = s.addNICs(&request, vm.VmId)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	if request.PublicIP {
		ip, xerr := s.addPublicIPs(defaultNic, nics)
		if xerr != nil {
			return nullAHF, nullUDC, xerr
		}
		if ip != nil {
			udc.PublicIP = ip.PublicIp
			vm.PublicIp = udc.PublicIP
		}
	}

	if xerr = s.addGPUs(&request, *tpl, vm.VmId); xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	_, xerr = s.rpcCreateTags(vm.VmId, map[string]string{
		"name": request.ResourceName,
	})
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}

	if _, xerr = s.WaitHostState(vm.VmId, hoststate.STARTED, temporal.GetHostTimeout()); xerr != nil {
		return nullAHF, nullUDC, xerr
	}

	ahf = abstract.NewHostFull()
	ahf.Core.ID = vm.VmId
	ahf.Core.Name = request.ResourceName
	ahf.Core.Password = request.Password
	ahf.Core.PrivateKey = request.KeyPair.PrivateKey
	ahf.Core.LastState = hoststate.STARTED
	nics = append(nics, defaultNic)
	xerr = s.setHostProperties(ahf, request.Subnets, vm, nics)
	return ahf, udc, xerr
}

func (s stack) getDefaultSubnetID(request abstract.HostRequest) (string, fail.Error) {
	if len(request.Subnets) == 0 {
		return "", nil
	}
	return request.Subnets[0].ID, nil
}

func (s stack) deleteHost(id string) fail.Error {
	if xerr := s.rpcDeleteHosts([]string{id}); xerr != nil {
		return xerr
	}
	_, xerr := s.WaitHostState(id, hoststate.TERMINATED, temporal.GetHostCreationTimeout())
	return xerr
}

// DeleteHost deletes the host identified by id
func (s stack) DeleteHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostLabel, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.compute") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", hostLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	readPublicIpsRequest := osc.ReadPublicIpsRequest{
		Filters: osc.FiltersPublicIp{VmIds: []string{ahf.Core.ID}},
	}
	var resp osc.ReadPublicIpsResponse
	xerr = stacks.RetryableRemoteCall(
		func() (innerErr error) {
			resp, _, innerErr = s.client.PublicIpApi.ReadPublicIps(s.auth, &osc.ReadPublicIpsOpts{
				ReadPublicIpsRequest: optional.NewInterface(readPublicIpsRequest),
			})
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to read public IPs of Host %s", ahf.Core.ID)
	}

	// list attached volumes
	volumes, xerr := s.ListVolumeAttachments(ahf.Core.ID)
	if xerr != nil {
		volumes = []abstract.VolumeAttachment{}
	}

	// delete host
	if xerr = s.deleteHost(ahf.Core.ID); xerr != nil {
		return xerr
	}

	// delete public IPs
	if len(resp.PublicIps) == 0 {
		return nil
	}
	var lastErr fail.Error
	for _, ip := range resp.PublicIps {
		deletePublicIpRequest := osc.DeletePublicIpRequest{
			PublicIpId: ip.PublicIpId,
		}
		xerr = stacks.RetryableRemoteCall(
			func() error {
				_, _, innerErr := s.client.PublicIpApi.DeletePublicIp(s.auth, &osc.DeletePublicIpOpts{
					DeletePublicIpRequest: optional.NewInterface(deletePublicIpRequest),
				})
				return innerErr
			},
			normalizeError,
		)
		if xerr != nil { // continue to delete even if error
			lastErr = xerr
			logrus.Errorf("failed to delete public IP %s of Host %s: %v", ip.PublicIpId, ahf.Core.ID, xerr)
		}
	}

	// delete volumes
	for _, v := range volumes {
		tags, xerr := s.rpcReadTags(v.VolumeID)
		if xerr != nil {
			continue
		}
		del := func() string {
			if del, ok := tags["DeleteWithVM"]; ok {
				return del
			}
			return "false"
		}()
		if del == "true" {
			if xerr = s.DeleteVolume(v.VolumeID); xerr != nil { // continue to delete even if error
				logrus.Errorf("Unable to delete Volume %s of Host %s", v.VolumeID, ahf.Core.ID)
			}
		}
	}

	return lastErr
}

// InspectHost returns the host identified by id or updates content of a *abstract.Host
func (s stack) InspectHost(hostParam stacks.HostParameter) (ahf *abstract.HostFull, xerr fail.Error) {
	nullAHF := abstract.NewHostFull()
	if s.IsNull() {
		return nullAHF, fail.InvalidInstanceError()
	}
	var hostLabel string
	ahf, hostLabel, xerr = stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAHF, xerr
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.compute") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", hostLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	vm, xerr := s.rpcReadVmByID(ahf.Core.ID)
	if xerr != nil {
		return nullAHF, xerr
	}

	if ahf.Core.Name == "" {
		tags, xerr := s.rpcReadTags(vm.VmId)
		if xerr != nil {
			return nullAHF, xerr
		}
		if tag, ok := tags["name"]; ok {
			ahf.Core.Name = tag
		}
	}
	subnets, nics, err := s.listSubnetsByHost(vm.VmId)
	if err != nil {
		return nullAHF, err
	}

	ahf = abstract.NewHostFull()
	ahf.Core.ID = vm.VmId
	ahf.Core.LastState = hostState(vm.State)
	xerr = s.setHostProperties(ahf, subnets, vm, nics)
	return ahf, xerr
}

// InspectHostByName returns the host identified by name
func (s stack) InspectHostByName(name string) (ahf *abstract.HostFull, xerr fail.Error) {
	nullAHF := abstract.NewHostFull()
	if s.IsNull() {
		return nullAHF, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.compute") || tracing.ShouldTrace("stack.outscale")*/, "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	vm, xerr := s.rpcReadVmByName(name)
	if xerr != nil {
		return nullAHF, xerr
	}

	ahf = abstract.NewHostFull()
	ahf.Core.ID = vm.VmId
	ahf.Core.Name = name
	ahf.Core.LastState = hostState(vm.State)
	return ahf, nil
}

// GetHostState returns the current state of the host identified by id
func (s stack) GetHostState(hostParam stacks.HostParameter) (_ hoststate.Enum, xerr fail.Error) {
	if s.IsNull() {
		return hoststate.UNKNOWN, fail.InvalidInstanceError()
	}
	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.compute") || tracing.ShouldTrace("stack.outscale")*/).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return hoststate.UNKNOWN, xerr
	}

	return s.hostState(ahf.Core.ID)
}

// ListHosts lists all hosts
func (s stack) ListHosts(details bool) (_ abstract.HostList, xerr fail.Error) {
	emptyList := abstract.HostList{}
	if s.IsNull() {
		return emptyList, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.compute") || tracing.ShouldTrace("stack.outscale")*/).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	var resp osc.ReadVmsResponse
	xerr = stacks.RetryableRemoteCall(
		func() (innerErr error) {
			resp, _, innerErr = s.client.VmApi.ReadVms(s.auth, nil)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return emptyList, xerr
	}

	var hosts abstract.HostList
	for _, vm := range resp.Vms {
		if hostState(vm.State) == hoststate.TERMINATED {
			continue
		}

		ahf := abstract.NewHostFull()
		ahf.Core.ID = vm.VmId
		ahf.Core.LastState = hostState(vm.State)
		if details {
			ahf, xerr = s.InspectHost(ahf)
			if xerr != nil {
				return nil, xerr
			}
		} else {
			tags, xerr := s.rpcReadTags(vm.VmId)
			if xerr != nil {
				return emptyList, xerr
			}
			if tag, ok := tags["name"]; ok {
				ahf.Core.Name = tag
			}
		}
		hosts = append(hosts, ahf)
	}
	return hosts, nil
}

// StopHost stops the host identified by id
func (s stack) StopHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.compute") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	request := osc.StopVmsOpts{
		StopVmsRequest: optional.NewInterface(osc.StopVmsRequest{
			VmIds:     []string{ahf.Core.ID},
			ForceStop: true,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, innerErr := s.client.VmApi.StopVms(s.auth, &request)
			return innerErr
		},
		normalizeError,
	)
}

// StartHost starts the host identified by id
func (s stack) StartHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.compute") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	request := osc.StartVmsOpts{
		StartVmsRequest: optional.NewInterface(osc.StartVmsRequest{
			VmIds: []string{ahf.Core.ID},
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, innerErr := s.client.VmApi.StartVms(s.auth, &request)
			return innerErr
		},
		normalizeError,
	)
}

// RebootHost Reboot host
func (s stack) RebootHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.compute") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	request := osc.RebootVmsOpts{
		RebootVmsRequest: optional.NewInterface(osc.RebootVmsRequest{
			VmIds: []string{ahf.Core.ID},
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, innerErr := s.client.VmApi.RebootVms(s.auth, &request)
			return innerErr
		},
		normalizeError,
	)
}

func (s stack) perfFromFreq(freq float32) int {
	var perfList sort.IntSlice
	for k := range s.CPUPerformanceMap {
		perfList = append(perfList, k)
	}
	sort.Sort(sort.Reverse(perfList))
	for _, perf := range perfList {
		if freq < s.CPUPerformanceMap[perf] {
			return perf
		}
	}
	return 1
}

// ResizeHost Resize host
func (s stack) ResizeHost(hostParam stacks.HostParameter, sizing abstract.HostSizingRequirements) (ahf *abstract.HostFull, xerr fail.Error) {
	nullAHF := abstract.NewHostFull()
	if s.IsNull() {
		return nullAHF, fail.InvalidInstanceError()
	}

	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAHF, xerr
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.compute") || tracing.ShouldTrace("stack.outscale")*/, "(%s, %v)", hostRef, sizing).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	perf := s.perfFromFreq(sizing.MinCPUFreq)
	t := gpuTemplateName(0, sizing.MaxCores, int(sizing.MaxRAMSize), perf, 0, "")

	request := osc.UpdateVmOpts{
		UpdateVmRequest: optional.NewInterface(osc.UpdateVmRequest{
			VmId:   ahf.Core.ID,
			VmType: t,
		}),
	}
	xerr = stacks.RetryableRemoteCall(
		func() error {
			_, _, innerErr := s.client.VmApi.UpdateVm(s.auth, &request)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	return s.InspectHost(ahf.Core.ID)
}

// BindSecurityGroupToHost ...
func (s stack) BindSecurityGroupToHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg.ID)
		if xerr != nil {
			return xerr
		}
	}

	ahf, hostLabel, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	vm, xerr := s.rpcReadVmByID(ahf.Core.ID)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to query information of Host %s", hostLabel)
	}

	found := false
	sgs := make([]string, 0, len(vm.SecurityGroups)+1)
	for _, v := range vm.SecurityGroups {
		if v.SecurityGroupId == asg.ID {
			found = true
			break
		}
		sgs = append(sgs, v.SecurityGroupId)
	}
	if found {
		// Security Group already bound to Host
		return nil
	}

	// Add new SG to Host
	sgs = append(sgs, asg.ID)
	updateVmRequest := osc.UpdateVmRequest{
		VmId:             ahf.Core.ID,
		SecurityGroupIds: sgs,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, innerErr := s.client.VmApi.UpdateVm(s.auth, &osc.UpdateVmOpts{
				UpdateVmRequest: optional.NewInterface(updateVmRequest),
			})
			return innerErr
		},
		normalizeError,
	)
}

// UnbindSecurityGroupFromHost ...
func (s stack) UnbindSecurityGroupFromHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	ahf, hostLabel, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	vm, xerr := s.rpcReadVmByID(ahf.Core.ID)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to query information of Host %s", hostLabel)
	}

	found := false
	sgs := make([]string, 0, len(vm.SecurityGroups))
	for _, v := range vm.SecurityGroups {
		if v.SecurityGroupId != asg.ID {
			sgs = append(sgs, v.SecurityGroupId)
		} else {
			found = true
		}
	}
	if !found {
		// Security Group not bound to Host, exit gracefully
		return nil
	}

	// Update Security Groups of Host
	updateVmRequest := osc.UpdateVmRequest{
		VmId:             ahf.Core.ID,
		SecurityGroupIds: sgs,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, innerErr := s.client.VmApi.UpdateVm(s.auth, &osc.UpdateVmOpts{
				UpdateVmRequest: optional.NewInterface(updateVmRequest),
			})
			return innerErr
		},
		normalizeError,
	)
}
