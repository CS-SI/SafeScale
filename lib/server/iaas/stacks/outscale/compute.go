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
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/antihax/optional"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/outscale-dev/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hoststate"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/iaas/abstract/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/userdata"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
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
func (s *Stack) ListImages(bool) ([]abstract.Image, fail.Error) {
	res, _, err := s.client.ImageApi.ReadImages(s.auth, nil)
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), "failed to list images")
	}
	var images []abstract.Image
	for _, omi := range res.Images {
		images = append(
			images, abstract.Image{
				Description: omi.Description,
				ID:          omi.ImageId,
				Name:        normalizeImageName(omi.ImageName),
				URL:         omi.FileLocation,
				StorageType: omi.RootDeviceType,
			},
		)
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
	tokens := strings.FieldsFunc(
		s, func(r rune) bool {
			return r == 'c' || r == 'r' || r == 'p' || r == 'g'
		},
	)

	if len(tokens) < 2 {
		return 0, 0, 0, fail.InconsistentError("error parsing sizing string")
	}

	cpus, xerr = strconv.Atoi(tokens[0])
	if xerr != nil {
		return
	}
	ram, xerr = strconv.Atoi(tokens[1])
	if xerr != nil {
		return
	}
	perf = 2
	if len(tokens) < 3 {
		return
	}
	perf, xerr = strconv.Atoi(tokens[2])
	if xerr != nil {
		return
	}

	return
}

func parseGPU(s string) (gpus int, gpuType string, xerr fail.Error) {
	tokens := strings.FieldsFunc(
		s, func(r rune) bool {
			return r == 'g' || r == 't'
		},
	)
	if len(tokens) < 2 {
		xerr = fail.InvalidParameterError("id", "malformed id")
		return
	}
	gpus, xerr = strconv.Atoi(tokens[0])
	if xerr != nil {
		return
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
func (s *Stack) ListTemplates(bool) ([]abstract.HostTemplate, fail.Error) {
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
				templates = append(
					templates, abstract.HostTemplate{
						DiskSize: 0,
						Name:     name,
						Cores:    cpu,
						RAMSize:  float32(ram),
						ID:       name,

						CPUFreq:   s.cpuFreq(perf),
						GPUNumber: 0,
					},
				)
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
					templates = append(
						templates, abstract.HostTemplate{
							DiskSize:  0,
							Name:      name,
							Cores:     cpu,
							RAMSize:   float32(ram),
							CPUFreq:   s.cpuFreq(perf),
							ID:        name,
							GPUNumber: gpu,
							GPUType:   "nvidia-k2",
						},
					)
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
					templates = append(
						templates, abstract.HostTemplate{
							DiskSize:  0,
							Name:      name,
							Cores:     cpu,
							RAMSize:   float32(ram),
							CPUFreq:   s.cpuFreq(perf),
							ID:        name,
							GPUNumber: gpu,
							GPUType:   "nvidia-p6",
						},
					)
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
					templates = append(
						templates, abstract.HostTemplate{
							DiskSize:  0,
							Name:      name,
							Cores:     cpu,
							RAMSize:   float32(ram),
							CPUFreq:   s.cpuFreq(perf),
							ID:        name,
							GPUNumber: gpu,
							GPUType:   "nvidia-p100",
						},
					)
				}
			}
		}
	}

	return templates, nil
}

// GetImage returns the Image referenced by id
func (s *Stack) GetImage(id string) (_ *abstract.Image, xerr fail.Error) {
	defer func() {
		if xerr != nil {
			xerr = fail.Wrap(xerr, fmt.Sprintf("failed to get image '%s'", id))
		}
	}()

	res, _, err := s.client.ImageApi.ReadImages(
		s.auth, &osc.ReadImagesOpts{
			ReadImagesRequest: optional.NewInterface(
				osc.ReadImagesRequest{
					DryRun: false,
					Filters: osc.FiltersImage{
						ImageIds: []string{id},
					},
				},
			),
		},
	)
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), fmt.Sprintf("failed to get image '%s'", id))
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

// GetTemplate returns the Template referenced by id
func (s *Stack) GetTemplate(id string) (*abstract.HostTemplate, fail.Error) {
	return s.parseTemplateID(id)
}

func (s *Stack) getOrCreatePassword(request abstract.HostRequest) (string, fail.Error) {
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return "", fmt.Errorf("failed to generate password: %s", err.Error())
		}
		return password, nil
	}
	return request.Password, nil
}

func (s *Stack) prepareUserData(request abstract.HostRequest, ud *userdata.Content) error {
	cidr := func() string {
		if len(request.Networks) == 0 {
			return ""
		}
		return request.Networks[0].CIDR
	}()
	err := ud.Prepare(*s.configurationOptions, request, cidr, "")
	if err != nil {
		msg := fmt.Sprintf("failed to prepare user data content: %+v", err)
		logrus.Debugf(utils.Capitalize(msg))
		return fmt.Errorf(msg)
	}
	return nil
}

func (s *Stack) createNIC(request *abstract.HostRequest, net *abstract.Network) (*osc.Nic, fail.Error) {

	group, err := s.getNetworkSecurityGroup(s.Options.Network.VPCID)
	if err != nil {
		return nil, err
	}
	nicRequest := osc.CreateNicRequest{
		Description:      request.ResourceName,
		SubnetId:         net.ID,
		SecurityGroupIds: []string{group.SecurityGroupId},
	}
	res, _, err := s.client.NicApi.CreateNic(
		s.auth, &osc.CreateNicOpts{
			CreateNicRequest: optional.NewInterface(nicRequest),
		},
	)
	if err != nil {
		return nil, normalizeError(err)
	}
	// primary := deviceNumber == 0
	return &res.Nic, nil
}

func (s *Stack) createNICS(request *abstract.HostRequest) ([]osc.Nic, fail.Error) {
	var nics []osc.Nic
	var err error
	// first network is the default network
	nics, err = s.tryCreateNICS(request, nics)
	if err != nil { // if error delete created NICS
		for _, ni := range nics {
			theNic := ni
			err := s.deleteNic(&theNic)
			if err != nil {
				logrus.Errorf("impossible to delete NIC %v", theNic.NicId)
			}
		}
	}
	return nics, err
}

func (s *Stack) tryCreateNICS(request *abstract.HostRequest, nics []osc.Nic) ([]osc.Nic, fail.Error) {
	for _, n := range request.Networks[1:] {
		nic, err := s.createNIC(request, n)
		if err != nil {
			return nics, err
		}
		nics = append(nics, *nic)
	}
	return nics, nil
}

func (s *Stack) deleteNics(nics []osc.Nic) error {
	for _, nic := range nics {
		theNic := nic
		err := s.deleteNic(&theNic)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Stack) deleteNic(nic *osc.Nic) error {
	request := osc.DeleteNicRequest{
		NicId: nic.NicId,
	}
	_, _, err := s.client.NicApi.DeleteNic(
		s.auth, &osc.DeleteNicOpts{
			DeleteNicRequest: optional.NewInterface(request),
		},
	)
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

func (s *Stack) hostState(id string) (hoststate.Enum, fail.Error) {
	vm, err := s.getVM(id)
	if err != nil {
		return hoststate.ERROR, err
	}
	if vm == nil {
		return hoststate.TERMINATED, fail.AbortedError("", fmt.Errorf("vm %s does not exist", id))
	}
	return hostState(vm.State), nil
}

// WaitForHostState wait for host to be in the specified state
func (s *Stack) WaitForHostState(hostID string, state hoststate.Enum) error {
	err := retry.WhileUnsuccessfulDelay5SecondsTimeout(
		func() error {
			hostState, err := s.hostState(hostID)
			if err != nil {
				return fail.Errorf("", err)
			}
			if state != hostState {
				return fail.Errorf("wrong state", nil)
			}
			if state == hoststate.ERROR {
				return fail.AbortedError("host in error state", err)
			}
			return nil
		}, temporal.GetHostCreationTimeout(),
	)
	return err
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

func (s *Stack) addNICS(request *abstract.HostRequest, vmID string) ([]osc.Nic, fail.Error) {
	if len(request.Networks) > 1 {
		nics, err := s.createNICS(request)
		if err != nil {
			return nil, err
		}
		for i, nic := range nics {
			nicRequest := osc.LinkNicRequest{
				VmId:         vmID,
				NicId:        nic.NicId,
				DeviceNumber: int32(i + 1),
			}
			_, _, err := s.client.NicApi.LinkNic(
				s.auth, &osc.LinkNicOpts{
					LinkNicRequest: optional.NewInterface(nicRequest),
				},
			)
			if err != nil {
				logrus.Errorf("Error attaching NIC %s to VM %s: %v", nic.NicId, vmID, err)
				return nil, err
			}
		}
		return nics, err
	}
	return nil, nil
}

func (s *Stack) addGPUs(request *abstract.HostRequest, vmID string) error {
	tpl, err := s.GetTemplate(request.TemplateID)
	if err != nil {
		return err
	}
	if tpl == nil {
		return fail.InvalidParameterError("request.TemplateID", "Template does not exists")
	}
	if tpl.GPUNumber <= 0 {
		return nil
	}
	var flexibleGpus []osc.FlexibleGpu
	var createErr error
	for gpu := 0; gpu < tpl.GPUNumber; gpu++ {
		resCreate, _, err := s.client.FlexibleGpuApi.CreateFlexibleGpu(
			s.auth, &osc.CreateFlexibleGpuOpts{
				CreateFlexibleGpuRequest: optional.NewInterface(
					osc.CreateFlexibleGpuRequest{
						DeleteOnVmDeletion: true,
						Generation:         "",
						ModelName:          tpl.GPUType,
						SubregionName:      s.Options.Compute.Subregion,
					},
				),
			},
		)
		if err != nil {
			createErr = err
			break
		}
		flexibleGpus = append(flexibleGpus, resCreate.FlexibleGpu)
		_, _, err = s.client.FlexibleGpuApi.LinkFlexibleGpu(
			s.auth, &osc.LinkFlexibleGpuOpts{
				LinkFlexibleGpuRequest: optional.NewInterface(
					osc.LinkFlexibleGpuRequest{
						DryRun:        false,
						FlexibleGpuId: resCreate.FlexibleGpu.FlexibleGpuId,
						VmId:          vmID,
					},
				),
			},
		)
		if err != nil {
			createErr = normalizeError(err)
			break
		}
	}
	if createErr != nil {
		for _, gpu := range flexibleGpus {
			_, _, _ = s.client.FlexibleGpuApi.DeleteFlexibleGpu(
				s.auth, &osc.DeleteFlexibleGpuOpts{
					DeleteFlexibleGpuRequest: optional.NewInterface(
						osc.DeleteFlexibleGpuRequest{
							DryRun:        false,
							FlexibleGpuId: gpu.FlexibleGpuId,
						},
					),
				},
			)
		}
	}
	return createErr
}

func (s *Stack) addVolume(request *abstract.HostRequest, vmID string) (err error) {
	if request.DiskSize == 0 {
		return nil
	}
	v, err := s.CreateVolume(
		abstract.VolumeRequest{
			Name:  fmt.Sprintf("vol-%s", request.HostName),
			Size:  request.DiskSize,
			Speed: s.Options.Compute.DefaultVolumeSpeed,
		},
	)
	if err != nil {
		return normalizeError(err)
	}
	defer func() {
		if err != nil {
			if !fail.ImplementsCauser(err) {
				err = fail.Wrap(err, "")
			}
			derr := s.DeleteVolume(v.ID)
			if derr != nil {
				err = fail.AddConsequence(err, derr)
			}
		}
	}()

	err = s.setResourceTags(
		v.ID, map[string]string{
			"DeleteWithVM": "true",
		},
	)
	if err != nil {
		return err
	}
	_, err = s.CreateVolumeAttachment(
		abstract.VolumeAttachmentRequest{
			HostID:   vmID,
			VolumeID: v.ID,
		},
	)
	return err
}

func (s *Stack) getNICS(vmID string) ([]osc.Nic, fail.Error) {
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

func (s *Stack) addPublicIP(nic *osc.Nic) (*osc.PublicIp, fail.Error) {

	resIP, _, err := s.client.PublicIpApi.CreatePublicIp(s.auth, nil)
	if err != nil {
		return nil, normalizeError(err)
	}
	linkPublicIpRequest := osc.LinkPublicIpRequest{
		NicId:      nic.NicId,
		PublicIpId: resIP.PublicIp.PublicIpId,
	}
	_, _, err = s.client.PublicIpApi.LinkPublicIp(
		s.auth, &osc.LinkPublicIpOpts{
			LinkPublicIpRequest: optional.NewInterface(linkPublicIpRequest),
		},
	)
	if err != nil {
		deletePublicIpRequest := osc.DeletePublicIpRequest{
			PublicIpId: resIP.PublicIp.PublicIpId,
		}
		_, _, err := s.client.PublicIpApi.DeletePublicIp(
			s.auth, &osc.DeletePublicIpOpts{
				DeletePublicIpRequest: optional.NewInterface(deletePublicIpRequest),
			},
		)
		if err != nil {
			logrus.Warnf("Cannot delete public ip %s: %v", resIP.PublicIp.PublicIpId, normalizeError(err))
			return nil, normalizeError(err)
		}
	}
	return &resIP.PublicIp, nil
}

func (s *Stack) setHostProperties(host *abstract.Host, networks []*abstract.Network, vm *osc.Vm, nics []osc.Nic) error {
	// Updates Host Property propsv1.HostDescription
	err := host.Properties.LockForWrite(hostproperty.DescriptionV1).ThenUse(
		func(clonable data.Clonable) error {
			hpDescriptionV1 := clonable.(*propertiesv1.HostDescription)
			hpDescriptionV1.Created = time.Now()
			hpDescriptionV1.Updated = time.Now()
			return nil
		},
	)
	if err != nil {
		return err
	}

	// Updates Host Property propsv1.HostSizing
	err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(
		func(clonable data.Clonable) error {
			hpSizingV1 := clonable.(*propertiesv1.HostSizing)
			vmType, err := s.GetTemplate(vm.VmType)
			if err != nil {
				return err
			}
			if hpSizingV1.AllocatedSize == nil {
				hpSizingV1.AllocatedSize = &propertiesv1.HostSize{
					Cores:     vmType.Cores,
					CPUFreq:   vmType.CPUFreq,
					DiskSize:  vmType.DiskSize,
					GPUNumber: vmType.GPUNumber,
					GPUType:   vmType.GPUType,
					RAMSize:   vmType.RAMSize,
				}
			}
			return nil
		},
	)
	if err != nil {
		return err
	}

	// Updates Host Property propsv1.HostNetwork
	return host.Properties.LockForWrite(hostproperty.NetworkV1).ThenUse(
		func(clonable data.Clonable) error {
			hostNetworkV1 := clonable.(*propertiesv1.HostNetwork)
			hostNetworkV1.PublicIPv4 = vm.PublicIp
			// networks contains network names, but hostproperty.NetworkV1.IPxAddresses has to be
			// indexed on network ID. Tries to convert if possible, if we already have correspondance
			// between network ID and network Name in Host definition
			networksByID := map[string]string{}
			networksByName := map[string]string{}
			ipv4Addresses := map[string]string{}
			ipv6Addresses := map[string]string{}
			for i, net := range networks {
				nic := nics[i]
				networksByID[net.ID] = net.Name
				networksByName[net.Name] = net.ID
				ipv4Addresses[net.ID] = func() string {
					for _, addr := range nic.PrivateIps {
						if addr.IsPrimary {
							return addr.PrivateIp
						}
					}
					return ""
				}()
			}

			hostNetworkV1.NetworksByID = networksByID
			hostNetworkV1.NetworksByName = networksByName
			// IPvxAddresses are here indexed by names... At least we have them...
			hostNetworkV1.IPv4Addresses = ipv4Addresses
			hostNetworkV1.IPv6Addresses = ipv6Addresses

			return nil
		},
	)
}

func (s *Stack) initHostProperties(request *abstract.HostRequest, host *abstract.Host) error {
	defaultNet := func() *abstract.Network {
		if len(request.Networks) == 0 {
			return nil
		}
		return request.Networks[0]
	}()
	isGateway := request.DefaultGateway == nil && defaultNet != nil && defaultNet.Name != abstract.SingleHostNetworkName
	defaultGatewayID := func() string {
		if request.DefaultGateway != nil {
			return request.DefaultGateway.ID
		}
		return ""
	}()
	template, err := s.GetTemplate(request.TemplateID)
	if err != nil {
		return err
	}
	if template == nil {
		return fail.InvalidParameterError("request.TemplateID", "Invalid template ID")
	}

	host.PrivateKey = request.KeyPair.PrivateKey // Add PrivateKey to host definition
	host.Password = request.Password

	err = host.Properties.LockForWrite(hostproperty.NetworkV1).ThenUse(
		func(clonable data.Clonable) error {
			hostNetworkV1 := clonable.(*propertiesv1.HostNetwork)
			hostNetworkV1.DefaultNetworkID = func() string {
				if defaultNet == nil {
					return ""
				}
				return defaultNet.ID
			}()
			hostNetworkV1.DefaultGatewayID = defaultGatewayID
			hostNetworkV1.DefaultGatewayPrivateIP = request.DefaultRouteIP
			hostNetworkV1.IsGateway = isGateway
			return nil
		},
	)
	if err != nil {
		return err
	}

	// Adds Host property SizingV1
	return host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(
		func(clonable data.Clonable) error {
			hostSizingV1 := clonable.(*propertiesv1.HostSizing)
			// Note: from there, no idea what was the RequestedSize; caller will have to complement this information
			hostSizingV1.Template = request.TemplateID
			hostSizingV1.AllocatedSize = &propertiesv1.HostSize{
				Cores:     template.Cores,
				CPUFreq:   template.CPUFreq,
				RAMSize:   template.RAMSize,
				DiskSize:  template.DiskSize,
				GPUNumber: template.GPUNumber,
				GPUType:   template.GPUType,
			}
			return nil
		},
	)
}

func (s *Stack) addPublicIPs(primaryNIC *osc.Nic, otherNICs []osc.Nic) (*osc.PublicIp, fail.Error) {
	ip, err := s.addPublicIP(primaryNIC)
	if err != nil {
		return nil, err
	}

	for _, nic := range otherNICs {
		theNic := nic
		_, err = s.addPublicIP(&theNic)
		if err != nil {
			return nil, err
		}
	}
	return ip, nil
}

// CreateHost creates an host that fulfills the request
func (s *Stack) CreateHost(request abstract.HostRequest) (_ *abstract.Host, _ *userdata.Content, xerr fail.Error) {
	userData := userdata.NewContent()
	if request.DefaultGateway == nil && !request.PublicIP {
		return nil, userData, abstract.ResourceInvalidRequestError(
			"host creation", "cannot create a host without public IP or without attached network",
		)
	}

	password, err := s.getOrCreatePassword(request)
	request.Password = password
	if err != nil {
		return nil, userData, err
	}

	subnetID, err := s.getSubnetID(request)
	if err != nil {
		return nil, userData, err
	}

	err = s.prepareUserData(request, userData)
	if err != nil {
		return nil, userData, err
	}
	host := abstract.NewHost()
	err = s.initHostProperties(&request, host)
	if err != nil {
		return nil, userData, err
	}

	userDataPhase1, err := userData.Generate("phase1")
	if err != nil {
		return nil, userData, err
	}
	vmType, err := outscaleTemplateID(request.TemplateID)
	if err != nil {
		return nil, userData, err
	}
	op := s.Options.Compute.OperatorUsername
	patchSSH := fmt.Sprintf("\nchown -R %s:%s /home/%s", op, op, op)
	buf := bytes.NewBuffer(userDataPhase1)
	buf.WriteString(patchSSH)

	// Import keypair to create host
	creationKeyPair, err := abstract.NewKeyPair(request.ResourceName + "_install")
	if err != nil {
		return nil, nil, err
	}
	err = s.ImportKeyPair(creationKeyPair)
	if err != nil {
		return nil, nil, err
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

	if request.DiskSize > 0 {

		tpl, err := s.GetTemplate(request.TemplateID)
		if err != nil {
			return nil, nil, err
		}
		if tpl == nil {
			return nil, nil, fail.InvalidParameterError("request.TemplateID", "Template does not exist")
		}

		var diskSize int
		diskSize = tpl.DiskSize

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
	}

	resVM, _, err := s.client.VmApi.CreateVms(
		s.auth, &osc.CreateVmsOpts{
			CreateVmsRequest: optional.NewInterface(vmsRequest),
		},
	)
	if err != nil {
		return nil, userData, fail.Wrap(
			normalizeError(err), fmt.Sprintf("failed to create host '%s'", request.ResourceName),
		)
	}

	if len(resVM.Vms) == 0 {
		return nil, userData, fail.InconsistentError("virtual machine list empty")
	}

	vm := resVM.Vms[0]
	defer func() {
		if err != nil {
			if !fail.ImplementsCauser(err) {
				err = fail.Wrap(err, "")
			}
			derr := s.DeleteHost(vm.VmId)
			if derr != nil {
				err = fail.AddConsequence(err, derr)
			}
		}
	}()

	err = s.WaitForHostState(vm.VmId, hoststate.STARTED)
	if err != nil {
		return nil, userData, err
	}
	// Retrieve default Nic use to create public ip
	nics, err := s.getNICS(vm.VmId)
	if err != nil {
		return nil, userData, err
	}
	if len(nics) == 0 {
		return nil, userData, fail.InconsistentError("No network interface associated to vm")
	}
	defaultNic := nics[0]

	nics, err = s.addNICS(&request, vm.VmId)
	if err != nil {
		return nil, userData, err
	}
	if request.PublicIP {
		ip, err := s.addPublicIPs(&defaultNic, nics)
		if ip != nil {
			userData.PublicIP = ip.PublicIp
			vm.PublicIp = userData.PublicIP
		}
		if err != nil {
			return nil, userData, err
		}
	}

	err = s.addGPUs(&request, vm.VmId)
	if err != nil {
		return nil, userData, err
	}

	// FIXME: Add resource tags here
	tags := make(map[string]string)
	tags["name"] = request.ResourceName

	tags["ManagedBy"] = "safescale"
	tags["DeclaredInBucket"] = s.configurationOptions.MetadataBucket
	tags["CreationDate"] = time.Now().Format(time.RFC3339)

	err = s.setResourceTags(
		vm.VmId, tags,
	)
	if err != nil {
		return nil, userData, err
	}

	err = s.WaitForHostState(vm.VmId, hoststate.STARTED)
	if err != nil {
		return nil, userData, err
	}

	host.ID = vm.VmId
	host.Name = request.ResourceName
	host.Password = request.Password
	host.PrivateKey = request.KeyPair.PrivateKey
	host.LastState = hoststate.STARTED
	nics = append(nics, defaultNic)
	err = s.setHostProperties(host, request.Networks, &vm, nics)
	return host, userData, err
}

func (s *Stack) getSubnetID(request abstract.HostRequest) (string, fail.Error) {
	if len(request.Networks) == 0 {
		return "", nil
	}
	defautNet := request.Networks[0]
	subnet, err := s.getSubnet(defautNet.ID)
	if err != nil {
		return "", err
	}
	if subnet == nil {
		return "", abstract.ResourceInvalidRequestError("request.Networks", "Invalid network, no subnet found")
	}
	return subnet.SubnetId, nil
}

func (s *Stack) getVM(vmID string) (*osc.Vm, fail.Error) {
	readVmsRequest := osc.ReadVmsRequest{
		Filters: osc.FiltersVm{
			VmIds: []string{vmID},
		},
	}
	vm, _, err := s.client.VmApi.ReadVms(
		s.auth, &osc.ReadVmsOpts{
			ReadVmsRequest: optional.NewInterface(readVmsRequest),
		},
	)

	if err != nil {
		return nil, normalizeError(err)
	}
	if len(vm.Vms) == 0 {
		return nil, nil
	}
	return &vm.Vms[0], nil
}

func (s *Stack) deleteHost(id string) error {
	request := osc.DeleteVmsRequest{
		VmIds: []string{id},
	}
	_, _, err := s.client.VmApi.DeleteVms(
		s.auth, &osc.DeleteVmsOpts{
			DeleteVmsRequest: optional.NewInterface(request),
		},
	)
	if err != nil {
		return normalizeError(err)
	}
	return s.WaitForHostState(id, hoststate.TERMINATED)
}

// DeleteHost deletes the host identified by id
func (s *Stack) DeleteHost(id string) error {
	readPublicIpsRequest := osc.ReadPublicIpsRequest{
		Filters: osc.FiltersPublicIp{VmIds: []string{id}},
	}
	res, _, err := s.client.PublicIpApi.ReadPublicIps(
		s.auth, &osc.ReadPublicIpsOpts{
			ReadPublicIpsRequest: optional.NewInterface(readPublicIpsRequest),
		},
	)
	if err != nil {
		logrus.Errorf("Unable to read public IPs of vm %s", id)
	}
	volumes, err := s.ListVolumeAttachments(id)
	if err != nil {
		volumes = []abstract.VolumeAttachment{}
	}
	err = s.deleteHost(id)
	if err != nil {
		return err
	}
	if len(res.PublicIps) == 0 {
		return nil
	}
	var lastErr error
	for _, ip := range res.PublicIps {
		deletePublicIpRequest := osc.DeletePublicIpRequest{
			PublicIpId: ip.PublicIpId,
		}
		_, _, err = s.client.PublicIpApi.DeletePublicIp(
			s.auth, &osc.DeletePublicIpOpts{
				DeletePublicIpRequest: optional.NewInterface(deletePublicIpRequest),
			},
		)
		if err != nil { // continue to delete even if error
			lastErr = nil
			logrus.Errorf("Unable to delete public IP %s of vm %s", ip.PublicIpId, id)
		}
	}

	for _, v := range volumes {
		tags, err := s.getResourceTags(v.VolumeID)
		if err != nil {
			continue
		}
		del := func() string {
			if del, ok := tags["DeleteWithVM"]; ok {
				return del
			}
			return "false"
		}()
		if del == "true" {
			err = s.DeleteVolume(v.VolumeID)
			if err != nil { // continue to delete even if error
				logrus.Errorf("Unable to delete volume %s of vm %s", v.VolumeID, id)
			}
		}

	}

	return lastErr

}

// InspectHost returns the host identified by id or updates content of a *abstract.Host
func (s *Stack) InspectHost(hostParam interface{}) (*abstract.Host, fail.Error) {
	var host *abstract.Host
	hostName := ""
	switch hostParam := hostParam.(type) {
	case string:
		if hostParam == "" {
			return nil, fail.InvalidParameterError("hostParam", "cannot be an empty string")
		}
		host = abstract.NewHost()
		host.ID = hostParam
	case *abstract.Host:
		if hostParam == nil {
			return nil, fail.InvalidParameterError("hostParam", "cannot be nil")
		}
		host = hostParam
		hostName = host.Name
	default:
		return nil, fail.InvalidParameterError("hostParam", "must be a string or a *abstract.Host")
	}

	vm, err := s.getVM(host.ID)
	if err != nil {
		return nil, err
	}

	if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
		// FIXME: Get creation time and/or metadata
		logrus.Warn(spew.Sdump(vm))
	}

	if hostName == "" {
		tags, err := s.getResourceTags(vm.VmId)
		if err != nil {
			return nil, err
		}
		if tag, ok := tags["name"]; ok {
			hostName = tag
		}
	}

	nets, nics, err := s.listNetworksByHost(vm.VmId)
	if err != nil {
		return nil, err
	}
	host.ID = vm.VmId
	host.Name = hostName
	host.LastState = hostState(vm.State)
	err = s.setHostProperties(host, nets, vm, nics)
	return host, err

}

// GetHostByName returns the host identified by name
func (s *Stack) GetHostByName(name string) (*abstract.Host, fail.Error) {
	res, _, err := s.client.VmApi.ReadVms(
		s.auth, &osc.ReadVmsOpts{
			ReadVmsRequest: optional.NewInterface(
				osc.ReadVmsRequest{
					DryRun: false,
					Filters: osc.FiltersVm{
						Tags: []string{fmt.Sprintf("name=%s", name)},
					},
				},
			),
		},
	)
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(res.Vms) == 0 {
		return nil, fail.NotFoundError(fmt.Sprintf("No host named %s", name))
	}
	return s.InspectHost(res.Vms[0].VmId)
}

// GetHostByID returns the host identified by name
func (s *Stack) GetHostByID(name string) (*abstract.Host, fail.Error) {
	res, _, err := s.client.VmApi.ReadVms(
		s.auth, &osc.ReadVmsOpts{
			ReadVmsRequest: optional.NewInterface(
				osc.ReadVmsRequest{
					DryRun: false,
					Filters: osc.FiltersVm{
						Tags: []string{fmt.Sprintf("id=%s", name)},
					},
				},
			),
		},
	)
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(res.Vms) == 0 {
		return nil, fail.NotFoundError(fmt.Sprintf("No host with id %s", name))
	}
	return s.InspectHost(res.Vms[0].VmId)
}

// GetHostState returns the current state of the host identified by id
func (s *Stack) GetHostState(hostParam interface{}) (hoststate.Enum, fail.Error) {
	var host *abstract.Host
	switch hostParam := hostParam.(type) {
	case string:
		if hostParam == "" {
			return hoststate.UNKNOWN, fail.InvalidParameterError("hostParam", "cannot be an empty string")
		}
		host = abstract.NewHost()
		host.ID = hostParam
	case *abstract.Host:
		if hostParam == nil {
			return hoststate.UNKNOWN, fail.InvalidParameterError("hostParam", "cannot be nil")
		}
		host = hostParam
	default:
		return hoststate.UNKNOWN, fail.InvalidParameterError("hostParam", "must be a string or a *abstract.Host")
	}

	return s.hostState(host.ID)
}

// ListHosts lists all hosts
func (s *Stack) ListHosts() ([]*abstract.Host, fail.Error) {
	res, _, err := s.client.VmApi.ReadVms(s.auth, nil)
	if err != nil {
		return nil, normalizeError(err)
	}
	var hosts []*abstract.Host
	for _, vm := range res.Vms {
		if hostState(vm.State) == hoststate.TERMINATED {
			continue
		}
		h, err := s.InspectHost(vm.VmId)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, nil

}

// StopHost stops the host identified by id
func (s *Stack) StopHost(id string) error {
	stopVmsRequest := osc.StopVmsRequest{
		VmIds:     []string{id},
		ForceStop: true,
	}
	_, _, err := s.client.VmApi.StopVms(
		s.auth, &osc.StopVmsOpts{
			StopVmsRequest: optional.NewInterface(stopVmsRequest),
		},
	)
	return normalizeError(err)
}

// StartHost starts the host identified by id
func (s *Stack) StartHost(id string) error {
	startVmsRequest := osc.StartVmsRequest{
		VmIds: []string{id},
	}
	_, _, err := s.client.VmApi.StartVms(
		s.auth, &osc.StartVmsOpts{
			StartVmsRequest: optional.NewInterface(startVmsRequest),
		},
	)
	return normalizeError(err)
}

// RebootHost Reboot host
func (s *Stack) RebootHost(id string) error {
	rebootVmsRequest := osc.RebootVmsRequest{
		VmIds: []string{id},
	}
	_, _, err := s.client.VmApi.RebootVms(
		s.auth, &osc.RebootVmsOpts{
			RebootVmsRequest: optional.NewInterface(rebootVmsRequest),
		},
	)
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
func (s *Stack) ResizeHost(id string, request abstract.SizingRequirements) (*abstract.Host, fail.Error) {
	perf := s.perfFromFreq(request.MinFreq)
	t := gpuTemplateName(0, request.MaxCores, int(request.MaxRAMSize), perf, 0, "")
	updateVmRequest := osc.UpdateVmRequest{
		VmId:   id,
		VmType: t,
		// VmType: request.,
	}
	_, _, err := s.client.VmApi.UpdateVm(
		s.auth, &osc.UpdateVmOpts{
			UpdateVmRequest: optional.NewInterface(updateVmRequest),
		},
	)
	if err != nil {
		return nil, normalizeError(err)
	}

	return s.InspectHost(id)
}
