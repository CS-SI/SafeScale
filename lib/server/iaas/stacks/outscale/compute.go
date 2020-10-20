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

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"

	"github.com/antihax/optional"
	"github.com/sirupsen/logrus"

	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
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
func (s *Stack) ListImages(all bool) (_ []abstract.Image, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	res, _, err := s.client.ImageApi.ReadImages(s.auth, nil)
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), "failed to list images")
	}
	var images []abstract.Image
	for _, omi := range res.Images {
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

func (s *Stack) cpuFreq(perf int) float32 {
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

func (s *Stack) parseTemplateID(id string) (*abstract.HostTemplate, fail.Error) {
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
func (s *Stack) ListTemplates(all bool) (_ []abstract.HostTemplate, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%v)", all).WithStopwatch().Entering()
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
	// instances wit gpu https://wiki.outscale.net/pages/viewpage.action?pageId=49023126
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
func (s *Stack) InspectImage(id string) (_ *abstract.Image, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	defer func() {
		if xerr != nil {
			xerr = fail.Wrap(xerr, fmt.Sprintf("failed to get image '%s'", id))
		}
	}()

	res, _, err := s.client.ImageApi.ReadImages(s.auth, &osc.ReadImagesOpts{
		ReadImagesRequest: optional.NewInterface(osc.ReadImagesRequest{
			DryRun: false,
			Filters: osc.FiltersImage{
				ImageIds: []string{id},
			},
		}),
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(res.Images) != 1 {
		return nil, fail.InconsistentError("more than one image with the same id")
	}
	img := res.Images[0]
	return &abstract.Image{
		Description: img.Description,
		ID:          img.ImageId,
		Name:        img.ImageName,
		StorageType: img.RootDeviceType,
		URL:         img.FileLocation,
	}, nil
}

// InspectTemplate returns the Template referenced by id
func (s *Stack) InspectTemplate(id string) (_ *abstract.HostTemplate, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	return s.parseTemplateID(id)
}

// VPL: obsolete
// func (s *Stack) getOrCreateKeypair(request abstract.HostRequest) (*abstract.KeyPair, error) {
//	id, err := uuid.NewV4()
//	if err != nil {
//		msg := fmt.Sprintf("failed to create host UUID: %+v", err)
//		logrus.Debugf(utils.Capitalize(msg))
//		return nil, fmt.Errorf(msg)
//	}
//	if request.KeyPair == nil {
//		name := fmt.Sprintf("%s_%s", request.ResourceName, id)
//		kp, err := s.CreateKeyPair(name)
//		if err != nil {
//			msg := fmt.Sprintf("Failed to create host key pair: %+v", err)
//			logrus.Errorf(msg)
//			return nil, fmt.Errorf(msg)
//		}
//		return kp, nil
//	}
//	return request.KeyPair, nil
// }

func (s *Stack) getOrCreatePassword(request abstract.HostRequest) (string, fail.Error) {
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return "", fail.Wrap(err, "failed to generate password")
		}
		return password, nil
	}
	return request.Password, nil
}

func (s *Stack) prepareUserData(request abstract.HostRequest, ud *userdata.Content) fail.Error {
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

func (s *Stack) createNIC(request *abstract.HostRequest, subnet *abstract.Subnet) (*osc.Nic, fail.Error) {
	//groups, xerr := s.listSecurityGroupIDs(subnet.Networking)
	//if xerr != nil {
	//	return nil, xerr
	//}

	nicRequest := osc.CreateNicRequest{
		Description: request.ResourceName,
		SubnetId:    subnet.ID,
		//SecurityGroupIds: groups,
	}
	res, _, err := s.client.NicApi.CreateNic(s.auth, &osc.CreateNicOpts{
		CreateNicRequest: optional.NewInterface(nicRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	// primary := deviceNumber == 0
	return &res.Nic, nil
}

func (s *Stack) createNICs(request *abstract.HostRequest) (nics []osc.Nic, xerr fail.Error) {
	nics = []osc.Nic{}

	// first network is the default network
	nics, xerr = s.tryCreateNICS(request, nics)
	if xerr != nil { // if error delete created NICS
		for _, v := range nics {
			xerr := s.deleteNIC(v)
			if xerr != nil {
				logrus.Errorf("impossible to delete NIC '%s': %v", v.NicId, xerr)
			}
		}
	}
	return nics, xerr
}

func (s Stack) tryCreateNICS(request *abstract.HostRequest, nics []osc.Nic) ([]osc.Nic, fail.Error) {
	for _, n := range request.Subnets[1:] {
		nic, xerr := s.createNIC(request, n)
		if xerr != nil {
			return nics, xerr
		}
		nics = append(nics, *nic)
	}
	return nics, nil
}

func (s Stack) deleteNICs(nics []osc.Nic) fail.Error {
	for _, nic := range nics {
		xerr := s.deleteNIC(nic)
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

func (s Stack) deleteNIC(nic osc.Nic) fail.Error {
	request := osc.DeleteNicRequest{
		NicId: nic.NicId,
	}
	_, _, err := s.client.NicApi.DeleteNic(s.auth, &osc.DeleteNicOpts{
		DeleteNicRequest: optional.NewInterface(request),
	})
	return normalizeError(err)
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

func (s Stack) hostState(id string) (hoststate.Enum, fail.Error) {
	vm, xerr := s.getVM(id)
	if xerr != nil {
		return hoststate.ERROR, xerr
	}
	if vm == nil {
		return hoststate.TERMINATED, retry.StopRetryError(fail.NotFoundError("vm '%s' does not exist", id))
	}
	return hostState(vm.State), nil
}

// WaitHostReady waits an host achieve ready state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return an utils.ErrInvalidParameter
func (s Stack) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	//if s == nil {
	//	return abstract.NewHostCore(), fail.InvalidInstanceError()
	//}

	return s.WaitHostState(hostParam, hoststate.STARTED, timeout)
}

// WaitHostState wait for host to be in the specified state
// On exit, xerr may be of type:
// - *retry.ErrTimeout: when the timeout is reached
// - *retry.ErrStopRetry: when a breaking error arises; xerr.Cause() contains the real error encountered
// - fail.Error: any other errors
func (s Stack) WaitHostState(hostParam stacks.HostParameter, state hoststate.Enum, timeout time.Duration) (_ *abstract.HostCore, xerr fail.Error) {
	nullAhc := abstract.NewHostCore()
	//if s == nil {
	//	return nullAhc, fail.InvalidInstanceError()
	//}

	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAhc, xerr
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s, %s, %v)", hostRef, state.String(), timeout).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	xerr = retry.WhileUnsuccessfulDelay5SecondsTimeout(
		func() error {
			st, innerXErr := s.hostState(ahf.Core.ID)
			if innerXErr != nil {
				return innerXErr
			}
			if st != state {
				return fail.NewError("wrong st")
			}
			if st == hoststate.ERROR {
				return retry.StopRetryError(fail.NewError("host in error state"))
			}
			ahf.Core.LastState = st
			return nil
		},
		timeout,
	)
	if xerr != nil {
		return nullAhc, xerr
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

func (s Stack) addNICS(request *abstract.HostRequest, vmID string) ([]osc.Nic, fail.Error) {
	if len(request.Subnets) > 1 {
		nics, xerr := s.createNICs(request)
		if xerr != nil {
			return nil, xerr
		}
		for i, nic := range nics {
			nicRequest := osc.LinkNicRequest{
				VmId:         vmID,
				NicId:        nic.NicId,
				DeviceNumber: int32(i + 1),
			}
			_, _, err := s.client.NicApi.LinkNic(s.auth, &osc.LinkNicOpts{
				LinkNicRequest: optional.NewInterface(nicRequest),
			})
			if err != nil {
				logrus.Errorf("Error attaching NIC %s to VM %s: %v", nic.NicId, vmID, err)
				return nil, normalizeError(err)
			}
		}
		return nics, nil
	}
	return nil, nil
}

func (s Stack) addGPUs(request *abstract.HostRequest, vmID string) fail.Error {
	tpl, xerr := s.InspectTemplate(request.TemplateID)
	if xerr != nil {
		return xerr
	}
	if tpl == nil {
		return fail.InvalidParameterError("request.TemplateID", "Template does not exists")
	}
	if tpl.GPUNumber <= 0 {
		return nil
	}

	var (
		flexibleGpus []osc.FlexibleGpu
		createErr    fail.Error
	)
	for gpu := 0; gpu < tpl.GPUNumber; gpu++ {
		resCreate, _, err := s.client.FlexibleGpuApi.CreateFlexibleGpu(s.auth, &osc.CreateFlexibleGpuOpts{
			CreateFlexibleGpuRequest: optional.NewInterface(osc.CreateFlexibleGpuRequest{
				DeleteOnVmDeletion: true,
				Generation:         "",
				ModelName:          tpl.GPUType,
				SubregionName:      s.Options.Compute.Subregion,
			}),
		})
		if err != nil {
			createErr = normalizeError(err)
			break
		}
		flexibleGpus = append(flexibleGpus, resCreate.FlexibleGpu)
		_, _, err = s.client.FlexibleGpuApi.LinkFlexibleGpu(s.auth, &osc.LinkFlexibleGpuOpts{
			LinkFlexibleGpuRequest: optional.NewInterface(osc.LinkFlexibleGpuRequest{
				DryRun:        false,
				FlexibleGpuId: resCreate.FlexibleGpu.FlexibleGpuId,
				VmId:          vmID,
			}),
		})
		if err != nil {
			createErr = normalizeError(err)
			break
		}
	}
	if createErr != nil {
		for _, gpu := range flexibleGpus {
			// FIXME: handle error
			_, _, _ = s.client.FlexibleGpuApi.DeleteFlexibleGpu(s.auth, &osc.DeleteFlexibleGpuOpts{
				DeleteFlexibleGpuRequest: optional.NewInterface(osc.DeleteFlexibleGpuRequest{
					DryRun:        false,
					FlexibleGpuId: gpu.FlexibleGpuId,
				}),
			})
		}
	}
	return createErr
}

func (s Stack) addVolume(request *abstract.HostRequest, vmID string) (xerr fail.Error) {
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

	xerr = s.setResourceTags(v.ID, map[string]string{
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

func (s Stack) getNICS(vmID string) ([]osc.Nic, fail.Error) {
	request := osc.ReadNicsRequest{
		Filters: osc.FiltersNic{
			LinkNicVmIds: []string{vmID},
		},
	}
	res, _, err := s.client.NicApi.ReadNics(s.auth, &osc.ReadNicsOpts{ReadNicsRequest: optional.NewInterface(request)})
	if err != nil {
		return nil, normalizeError(err)
	}
	return res.Nics, nil
}

func (s Stack) addPublicIP(nic osc.Nic) (*osc.PublicIp, fail.Error) {
	resIP, _, err := s.client.PublicIpApi.CreatePublicIp(s.auth, nil)
	if err != nil {
		return nil, normalizeError(err)
	}
	linkPublicIpRequest := osc.LinkPublicIpRequest{
		NicId:      nic.NicId,
		PublicIpId: resIP.PublicIp.PublicIpId,
	}
	_, _, err = s.client.PublicIpApi.LinkPublicIp(s.auth, &osc.LinkPublicIpOpts{
		LinkPublicIpRequest: optional.NewInterface(linkPublicIpRequest)},
	)
	if err != nil {
		deletePublicIpRequest := osc.DeletePublicIpRequest{
			PublicIpId: resIP.PublicIp.PublicIpId,
		}
		_, _, err := s.client.PublicIpApi.DeletePublicIp(s.auth, &osc.DeletePublicIpOpts{
			DeletePublicIpRequest: optional.NewInterface(deletePublicIpRequest),
		})
		if err != nil {
			logrus.Warnf(fmt.Sprintf("Cannot delete public ip '%s': %v", resIP.PublicIp.PublicIpId, err))
			return nil, normalizeError(err)
		}
	}
	return &resIP.PublicIp, nil
}

func (s Stack) setHostProperties(host *abstract.HostFull, subnets []*abstract.Subnet, vm *osc.Vm, nics []osc.Nic) fail.Error {
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
	return nil
}

func (s Stack) initHostProperties(request *abstract.HostRequest, host *abstract.HostFull) fail.Error {
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

func (s Stack) addPublicIPs(primaryNIC osc.Nic, otherNICs []osc.Nic) (*osc.PublicIp, fail.Error) {
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
func (s Stack) CreateHost(request abstract.HostRequest) (ahf *abstract.HostFull, udc *userdata.Content, xerr fail.Error) {
	nullAHF := abstract.NewHostFull()
	nullUDC := userdata.NewContent()

	//if s == nil {
	//	return nullAHF, nullUDC, fail.InvalidInstanceError()
	//}
	if request.KeyPair == nil {
		return nullAHF, nullUDC, fail.InvalidRequestError("request.KeyPair", "cannot be nil")
	}
	if len(request.Subnets) == 0 && !request.PublicIP {
		return nullAHF, nullUDC, abstract.ResourceInvalidRequestError("host creation", "cannot create a host without public IP or without attached subnet")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stack.outscale"), "(%v)", request).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	password, xerr := s.getOrCreatePassword(request)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	request.Password = password

	subnetID, xerr := s.getDefaultSubnetID(request)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}

	xerr = s.prepareUserData(request, udc)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	if xerr = s.initHostProperties(&request, ahf); xerr != nil {
		return nullAHF, nullUDC, xerr
	}

	userDataPhase1, xerr := udc.Generate("phase1")
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	vmType, xerr := outscaleTemplateID(request.TemplateID)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	op := s.Options.Compute.OperatorUsername
	patchSSH := fmt.Sprintf("\nchown -R %s:%s /home/%s", op, op, op)
	buf := bytes.NewBuffer(userDataPhase1)
	buf.WriteString(patchSSH)

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
	resVM, _, err := s.client.VmApi.CreateVms(s.auth, &osc.CreateVmsOpts{
		CreateVmsRequest: optional.NewInterface(vmsRequest),
	})
	if err != nil {
		return nullAHF, nullUDC, fail.Wrap(normalizeError(err), fmt.Sprintf("failed to create host '%s'", request.ResourceName))
	}

	if len(resVM.Vms) == 0 {
		return nullAHF, nullUDC, fail.InconsistentError("virtual machine list empty")
	}

	vm := resVM.Vms[0]
	defer func() {
		if xerr != nil {
			derr := s.DeleteHost(vm.VmId)
			if derr != nil {
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	_, xerr = s.WaitHostState(vm.VmId, hoststate.STARTED, time.Duration(0))
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	// Retrieve default Nic use to create public ip
	nics, xerr := s.getNICS(vm.VmId)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	if len(nics) == 0 {
		return nullAHF, nullUDC, fail.InconsistentError("No network interface associated to vm")
	}
	defaultNic := nics[0]

	nics, xerr = s.addNICS(&request, vm.VmId)
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

	xerr = s.addVolume(&request, vm.VmId)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}

	xerr = s.addGPUs(&request, vm.VmId)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	xerr = s.setResourceTags(vm.VmId, map[string]string{
		"name": request.ResourceName,
	})
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}

	_, xerr = s.WaitHostState(vm.VmId, hoststate.STARTED, time.Duration(0))
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}

	ahf = abstract.NewHostFull()
	ahf.Core.ID = vm.VmId
	ahf.Core.Name = request.ResourceName
	ahf.Core.Password = request.Password
	ahf.Core.PrivateKey = request.KeyPair.PrivateKey
	ahf.Core.LastState = hoststate.STARTED
	nics = append(nics, defaultNic)
	xerr = s.setHostProperties(ahf, request.Subnets, &vm, nics)
	return ahf, udc, xerr
}

func (s *Stack) getDefaultSubnetID(request abstract.HostRequest) (string, fail.Error) {
	if s == nil {
		return "", fail.InvalidInstanceError()
	}
	if len(request.Subnets) == 0 {
		return "", nil
	}
	defaultSubnet := request.Subnets[0]
	return defaultSubnet.ID, nil
	//subnet, err := s.InspectSubnet(defaultSubet.Networking, defaultSubnet.ID)
	//if err != nil {
	//	return "", err
	//}
	//if subnet == nil {
	//	return "", abstract.ResourceInvalidRequestError("request.Networks", "Invalid network, no subnet found")
	//}
	//return subnet.SubnetId, nil
}

func (s *Stack) getVM(vmID string) (*osc.Vm, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	readVmsRequest := osc.ReadVmsRequest{
		Filters: osc.FiltersVm{
			VmIds: []string{vmID},
		},
	}
	vm, _, err := s.client.VmApi.ReadVms(s.auth, &osc.ReadVmsOpts{
		ReadVmsRequest: optional.NewInterface(readVmsRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(vm.Vms) == 0 {
		return nil, nil
	}
	return &vm.Vms[0], nil
}

func (s *Stack) deleteHost(id string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	request := osc.DeleteVmsRequest{
		VmIds: []string{id},
	}
	_, _, err := s.client.VmApi.DeleteVms(s.auth, &osc.DeleteVmsOpts{
		DeleteVmsRequest: optional.NewInterface(request),
	})
	if err != nil {
		return normalizeError(err)
	}
	_, xerr := s.WaitHostState(id, hoststate.TERMINATED, time.Duration(0))
	return xerr
}

// DeleteHost deletes the host identified by id
func (s *Stack) DeleteHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%vs)", hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	readPublicIpsRequest := osc.ReadPublicIpsRequest{
		Filters: osc.FiltersPublicIp{VmIds: []string{ahf.Core.ID}},
	}
	resp, _, err := s.client.PublicIpApi.ReadPublicIps(s.auth, &osc.ReadPublicIpsOpts{
		ReadPublicIpsRequest: optional.NewInterface(readPublicIpsRequest),
	})
	if err != nil {
		logrus.Errorf("Unable to read public IPs of vm %s", ahf.Core.ID)
	}
	volumes, xerr := s.ListVolumeAttachments(ahf.Core.ID)
	if xerr != nil {
		volumes = []abstract.VolumeAttachment{}
	}
	xerr = s.deleteHost(ahf.Core.ID)
	if xerr != nil {
		return xerr
	}
	if len(resp.PublicIps) == 0 {
		return nil
	}
	var lastErr fail.Error
	for _, ip := range resp.PublicIps {
		deletePublicIpRequest := osc.DeletePublicIpRequest{
			PublicIpId: ip.PublicIpId,
		}
		_, _, err = s.client.PublicIpApi.DeletePublicIp(s.auth, &osc.DeletePublicIpOpts{
			DeletePublicIpRequest: optional.NewInterface(deletePublicIpRequest),
		})
		if err != nil { // continue to delete even if error
			lastErr = normalizeError(err)
			logrus.Errorf("Unable to delete public IP %s of vm %s", ip.PublicIpId, ahf.Core.ID)
		}
	}

	for _, v := range volumes {
		tags, xerr := s.getResourceTags(v.VolumeID)
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
			xerr = s.DeleteVolume(v.VolumeID)
			if xerr != nil { // continue to delete even if error
				logrus.Errorf("Unable to delete volume %s of vm %s", v.VolumeID, ahf.Core.ID)
			}
		}

	}

	return lastErr
}

// InspectHost returns the host identified by id or updates content of a *abstract.Host
func (s *Stack) InspectHost(hostParam stacks.HostParameter) (ahf *abstract.HostFull, xerr fail.Error) {
	ahf = abstract.NewHostFull()
	if s == nil {
		return ahf, fail.InvalidInstanceError()
	}
	var hostRef string
	ahf, hostRef, xerr = stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return ahf, xerr
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	vm, xerr := s.getVM(ahf.Core.ID)
	if xerr != nil {
		return nil, xerr
	}
	if ahf.Core.Name == "" {
		tags, xerr := s.getResourceTags(vm.VmId)
		if xerr != nil {
			return ahf, xerr
		}
		if tag, ok := tags["name"]; ok {
			ahf.Core.Name = tag
		}
	}
	subnets, nics, err := s.listSubnetsByHost(vm.VmId)
	if err != nil {
		return nil, err
	}
	ahf.Core.ID = vm.VmId
	ahf.Core.LastState = hostState(vm.State)
	xerr = s.setHostProperties(ahf, subnets, vm, nics)
	return ahf, xerr

}

// InspectHostByName returns the host identified by name
func (s *Stack) InspectHostByName(name string) (ahc *abstract.HostCore, xerr fail.Error) {
	nullAhc := abstract.NewHostCore()
	if s == nil {
		return nullAhc, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	res, _, err := s.client.VmApi.ReadVms(s.auth, &osc.ReadVmsOpts{
		ReadVmsRequest: optional.NewInterface(osc.ReadVmsRequest{
			DryRun: false,
			Filters: osc.FiltersVm{
				Tags: []string{fmt.Sprintf("name=%s", name)},
			},
		}),
	})
	if err != nil {
		return nullAhc, normalizeError(err)
	}
	if len(res.Vms) == 0 {
		return nullAhc, fail.NotFoundError("failed to find a host named '%s'", name)
	}

	vm := res.Vms[0]
	ahc = abstract.NewHostCore()
	ahc.ID = vm.VmId
	ahc.Name = name
	ahc.LastState = hostState(vm.State)
	return ahc, nil
}

// GetHostState returns the current state of the host identified by id
func (s *Stack) GetHostState(hostParam stacks.HostParameter) (_ hoststate.Enum, xerr fail.Error) {
	if s == nil {
		return hoststate.UNKNOWN, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return hoststate.UNKNOWN, xerr
	}

	return s.hostState(ahf.Core.ID)
}

// ListHosts lists all hosts
func (s *Stack) ListHosts(details bool) (_ abstract.HostList, xerr fail.Error) {
	emptyList := abstract.HostList{}
	if s == nil {
		return emptyList, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	res, _, err := s.client.VmApi.ReadVms(s.auth, nil)
	if err != nil {
		return emptyList, normalizeError(err)
	}

	var hosts abstract.HostList
	for _, vm := range res.Vms {
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
			tags, xerr := s.getResourceTags(vm.VmId)
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
func (s *Stack) StopHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	stopVmsRequest := osc.StopVmsRequest{
		VmIds:     []string{ahf.Core.ID},
		ForceStop: true,
	}
	_, _, err := s.client.VmApi.StopVms(s.auth, &osc.StopVmsOpts{
		StopVmsRequest: optional.NewInterface(stopVmsRequest),
	})
	return normalizeError(err)
}

// StartHost starts the host identified by id
func (s *Stack) StartHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	startVmsRequest := osc.StartVmsRequest{
		VmIds: []string{ahf.Core.ID},
	}
	_, _, err := s.client.VmApi.StartVms(s.auth, &osc.StartVmsOpts{
		StartVmsRequest: optional.NewInterface(startVmsRequest),
	})
	return normalizeError(err)
}

// RebootHost Reboot host
func (s *Stack) RebootHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	rebootVmsRequest := osc.RebootVmsRequest{
		VmIds: []string{ahf.Core.ID},
	}
	_, _, err := s.client.VmApi.RebootVms(s.auth, &osc.RebootVmsOpts{
		RebootVmsRequest: optional.NewInterface(rebootVmsRequest),
	})
	return normalizeError(err)
}

func (s *Stack) perfFromFreq(freq float32) int {
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
func (s *Stack) ResizeHost(hostParam stacks.HostParameter, request abstract.HostSizingRequirements) (ahf *abstract.HostFull, xerr fail.Error) {
	nullAhf := abstract.NewHostFull()
	if s == nil {
		return ahf, fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAhf, xerr
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s, %v)", hostRef, request).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	perf := s.perfFromFreq(request.MinCPUFreq)
	t := gpuTemplateName(0, request.MaxCores, int(request.MaxRAMSize), perf, 0, "")
	updateVmRequest := osc.UpdateVmRequest{
		VmId:   ahf.Core.ID,
		VmType: t,
		// VmType: request.,
	}
	_, _, err := s.client.VmApi.UpdateVm(s.auth, &osc.UpdateVmOpts{
		UpdateVmRequest: optional.NewInterface(updateVmRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}

	return s.InspectHost(ahf.Core.ID)
}

// BindSecurityGroupToHost ...
func (s *Stack) BindSecurityGroupToHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	return fail.NotImplementedError("not yet implemented")
}

// UnbindSecurityGroupFromHost ...
func (s *Stack) UnbindSecurityGroupFromHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	return fail.NotImplementedError("not yet implemented")
}
