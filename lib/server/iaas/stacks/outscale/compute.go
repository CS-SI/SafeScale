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

package outscale

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hoststate"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
	"github.com/outscale/osc-sdk-go/oapi"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

func normalizeImageName(name string) string {
	n := strings.Replace(name, "-", " ", 1)
	n = strings.Replace(n, "-", " (", 1)
	n = strings.Replace(n, ".", ",", 1)
	n = strings.ReplaceAll(n, ".", "")
	n = strings.Replace(n, ",", ".", 1)
	n = strings.ReplaceAll(n, "-0", ")")
	tok := strings.Split(n, " (")

	return tok[0]
}

// ListImages lists available OS images
func (s *Stack) ListImages(all bool) ([]resources.Image, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	res, err := s.client.POST_ReadImages(oapi.ReadImagesRequest{})
	if err != nil {
		return nil, err
	}
	var images []resources.Image
	for _, omi := range res.OK.Images {
		images = append(images, resources.Image{
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

func parseSizing(s string) (cpus, ram, perf int, err error) {
	tokens := strings.FieldsFunc(s, func(r rune) bool {
		return r == 'c' || r == 'r' || r == 'p' || r == 'g'
	})
	cpus, err = strconv.Atoi(tokens[0])
	if err != nil {
		return
	}
	ram, err = strconv.Atoi(tokens[1])
	if err != nil {
		return
	}
	perf = 2
	if len(tokens) < 3 {
		return
	}
	perf, err = strconv.Atoi(tokens[2])
	if err != nil {
		return
	}

	return
}

func parseGPU(s string) (gpus int, gpuType string, err error) {
	tokens := strings.FieldsFunc(s, func(r rune) bool {
		return r == 'g' || r == 't'
	})
	if len(tokens) < 2 {
		err = scerr.InvalidParameterError("id", "malformed id")
		return
	}
	gpus, err = strconv.Atoi(tokens[0])
	if err != nil {
		return
	}
	gpuType = tokens[1]
	return
}

func (s *Stack) parseTemplateID(id string) (*resources.HostTemplate, error) {
	tokens := strings.Split(id, ".")
	if len(tokens) < 2 || !strings.HasPrefix(id, "tina") {
		return nil, scerr.InvalidParameterError("id", "invalid template id")
	}

	cpus, ram, perf, err := parseSizing(tokens[1])
	if err != nil {
		return nil, scerr.InvalidParameterError("id", "invalid template id")
	}
	gpus := 0
	gpuType := ""
	if len(tokens) > 2 {
		gpus, gpuType, err = parseGPU(tokens[2])
		if err != nil {
			return nil, scerr.InvalidParameterError("id", "invalid template id")
		}
	}
	return &resources.HostTemplate{
		Cores:     cpus,
		CPUFreq:   s.cpuFreq(perf),
		GPUNumber: gpus,
		GPUType:   gpuType,
		RAMSize:   float32(ram),
		DiskSize:  16000,
		Name:      id,
		ID:        id,
	}, nil
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
// TODO manage performance instance
func (s *Stack) ListTemplates(all bool) ([]resources.HostTemplate, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	//without GPU
	cpus := intRange(1, 78, 1)
	ramPerCore := intRange(1, 16, 1)
	perfs := []int{1, 2, 3}
	var templates []resources.HostTemplate
	for _, cpu := range cpus {
		for _, ramCore := range ramPerCore {
			for _, perf := range perfs {
				ram := cpu * ramCore
				//Outscale maximum memory size
				if ram > 1039 {
					break
				}
				name := gpuTemplateName(0, cpu, ram, perf, 0, "")
				templates = append(templates, resources.HostTemplate{
					DiskSize: 16000,
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
	//instances wit gpu https://wiki.outscale.net/pages/viewpage.action?pageId=49023126
	//with nvidia-k2 GPU
	gpus := intRange(1, 8, 2)
	for _, gpu := range gpus {
		for _, cpu := range cpus {
			for _, ramCore := range ramPerCore {
				for _, perf := range perfs {
					ram := cpu * ramCore
					//Outscale maximum memory size
					if ram > 1039 {
						break
					}
					//
					name := gpuTemplateName(3, cpu, ram, perf, gpu, "nvidia-k2")
					templates = append(templates, resources.HostTemplate{
						DiskSize:  16000,
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

	//with nvidia-p6 gpu
	for _, gpu := range gpus {
		for _, cpu := range cpus {
			for _, ramCore := range ramPerCore {
				for _, perf := range perfs {
					ram := cpu * ramCore
					//Outscale maximum memory size
					if ram > 1039 {
						break
					}
					//
					name := gpuTemplateName(5, cpu, ram, perf, gpu, "nvidia-p6")
					templates = append(templates, resources.HostTemplate{
						DiskSize:  16000,
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

	//with nvidia-p100 gpu
	for _, gpu := range gpus {
		for _, cpu := range cpus {
			for _, ramCore := range ramPerCore {
				for _, perf := range perfs {
					ram := cpu * ramCore
					//Outscale maximum memory size
					if ram > 1039 {
						break
					}
					//
					name := gpuTemplateName(5, cpu, ram, perf, gpu, "nvidia-p100")
					templates = append(templates, resources.HostTemplate{
						DiskSize:  16000,
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

// GetImage returns the Image referenced by id
func (s *Stack) GetImage(id string) (*resources.Image, error) {
	res, err := s.client.POST_ReadImages(oapi.ReadImagesRequest{
		Filters: oapi.FiltersImage{
			ImageIds: []string{id},
		},
	})
	if err != nil {
		return nil, err
	}
	if len(res.OK.Images) != 1 {
		return nil, scerr.InconsistentError("more than one image with the same id")
	}
	img := res.OK.Images[0]
	return &resources.Image{
		Description: img.Description,
		ID:          img.ImageId,
		Name:        img.ImageName,
		StorageType: img.RootDeviceType,
		URL:         img.FileLocation,
	}, nil
}

// GetTemplate returns the Template referenced by id
func (s *Stack) GetTemplate(id string) (*resources.HostTemplate, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	return s.parseTemplateID(id)
}

func (s *Stack) getOrCreateKeypair(request resources.HostRequest) (*resources.KeyPair, error) {
	id, err := uuid.NewV4()
	if err != nil {
		msg := fmt.Sprintf("failed to create host UUID: %+v", err)
		logrus.Debugf(utils.Capitalize(msg))
		return nil, fmt.Errorf(msg)
	}
	if request.KeyPair == nil {
		name := fmt.Sprintf("%s_%s", request.ResourceName, id)
		kp, err := s.CreateKeyPair(name)
		if err != nil {
			msg := fmt.Sprintf("Failed to create host key pair: %+v", err)
			logrus.Errorf(msg)
			return nil, fmt.Errorf(msg)
		}
		return kp, nil
	}
	return request.KeyPair, nil
}

func (s *Stack) getOrCreatePassword(request resources.HostRequest) (string, error) {
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return "", fmt.Errorf("failed to generate password: %s", err.Error())
		}
		return password, nil
	}
	return request.Password, nil
}

func (s *Stack) prepareUserData(request resources.HostRequest, ud *userdata.Content) error {
	err := ud.Prepare(*s.configrationOptions, request, request.Networks[0].CIDR, "")
	if err != nil {
		msg := fmt.Sprintf("failed to prepare user data content: %+v", err)
		logrus.Debugf(utils.Capitalize(msg))
		return fmt.Errorf(msg)
	}
	return nil
}

func (s *Stack) createNIC(request *resources.HostRequest, net *resources.Network) (*oapi.Nic, error) {

	group, err := s.getNetworkSecurityGroup(s.Options.Network.VPCID)
	if err != nil {
		return nil, err
	}
	res, err := s.client.POST_CreateNic(oapi.CreateNicRequest{
		Description:      request.ResourceName,
		SubnetId:         net.ID,
		SecurityGroupIds: []string{group.SecurityGroupId},
	})

	if err != nil {
		return nil, err
	}
	if res == nil || res.OK == nil {
		return nil, scerr.InconsistentError("Inconsistent provider response")
	}
	//primary := deviceNumber == 0
	return &res.OK.Nic, nil
}

func (s *Stack) createNICS(request *resources.HostRequest) ([]oapi.Nic, error) {
	var nics []oapi.Nic
	var err error
	//first network is the default network
	for _, n := range request.Networks[1:] {
		nic, err := s.createNIC(request, n)
		if err != nil {
			break
		}
		nics = append(nics, *nic)
	}
	if err != nil {
		for _, ni := range nics {
			err := s.deleteNic(&ni)
			if err != nil {
				logrus.Errorf("impossible to delete NIC %v", ni.NicId)
			}
		}
	}

	return nics, err
}

func (s *Stack) deleteNics(nics []oapi.Nic) error {
	for _, nic := range nics {
		err := s.deleteNic(&nic)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Stack) deleteNic(nic *oapi.Nic) error {
	_, err := s.client.POST_DeleteNic(oapi.DeleteNicRequest{
		NicId: nic.NicId,
	})
	return err
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

func (s *Stack) hostState(id string) (hoststate.Enum, error) {
	vm, err := s.getVM(id)
	if err != nil {
		return hoststate.ERROR, err
	}
	if vm == nil {
		return hoststate.TERMINATED, scerr.AbortedError("", fmt.Errorf("vm %s does not exist", id))
	}
	return hostState(vm.State), nil
}

//WaitForHostState wait for host to be in the specifed state
func (s *Stack) WaitForHostState(hostID string, state hoststate.Enum) error {
	err := retry.WhileUnsuccessfulDelay5SecondsTimeout(func() error {
		hstate, err := s.hostState(hostID)
		println("host", hstate.String())
		if err != nil {
			return scerr.AbortedError("", err)
		}
		if state != hstate {
			return fmt.Errorf("wrong state")
		}
		if state == hoststate.ERROR {
			return scerr.AbortedError("host in error state", err)
		}
		return nil
	}, temporal.GetHostCreationTimeout())
	return err
}

func outscaleTemplateID(id string) (string, error) {
	tokens := strings.Split(id, ".")
	if len(tokens) < 2 {
		return "", scerr.InvalidParameterError("id", "malformed template id")
	}
	if len(tokens) == 2 {
		return id, nil
	}
	return fmt.Sprintf("%s.%s", tokens[0], tokens[1]), nil
}

func (s *Stack) addNICS(request *resources.HostRequest, vmID string) ([]oapi.Nic, error) {
	if len(request.Networks) > 1 {
		nics, err := s.createNICS(request)
		if err != nil {
			return nil, err
		}
		for i, nic := range nics {
			_, err := s.client.POST_LinkNic(oapi.LinkNicRequest{
				VmId:         vmID,
				NicId:        nic.NicId,
				DeviceNumber: int64(i + 1),
			})
			if err != nil {
				logrus.Errorf("Error attaching NIC %s to VM %s: %v", nic.NicId, vmID, err)
				return nil, err
			}
		}
		return nics, err
	}
	return nil, nil
}

func (s *Stack) addGPUs(request *resources.HostRequest, vmID string) error {
	tpl, err := s.GetTemplate(request.TemplateID)
	if err != nil {
		return err
	}
	if tpl == nil {
		return scerr.InvalidParameterError("request.TemplateID", "Template does not exists")
	}
	if tpl.GPUNumber <= 0 {
		return nil
	}
	for gpu := 1; gpu < tpl.GPUNumber; gpu++ {
		//TODO complet when v1 ready
	}
	return nil
}

func (s *Stack) addVolume(request *resources.HostRequest, vmID string) error {
	if request.DiskSize == 0 {
		return nil
	}
	v, err := s.CreateVolume(resources.VolumeRequest{
		Name:  fmt.Sprintf("vol-%s", request.HostName),
		Size:  request.DiskSize,
		Speed: s.Options.Compute.DefaultVolumeSpeed,
	})
	if err != nil {
		return err
	}
	_, err = s.CreateVolumeAttachment(resources.VolumeAttachmentRequest{
		HostID:   vmID,
		VolumeID: v.ID,
	})
	if err != nil {
		err2 := s.DeleteVolume(v.ID)
		return scerr.Wrap(err, err2.Error())
	}
	return nil
}

func (s *Stack) getNICS(vmID string) ([]oapi.Nic, error) {
	res, err := s.client.POST_ReadNics(oapi.ReadNicsRequest{
		Filters: oapi.FiltersNic{
			LinkNicVmIds: []string{vmID},
		},
	})
	if err != nil {
		return nil, err
	}
	if res == nil || res.OK == nil {
		return nil, scerr.InconsistentError("Inconsistent provider response")
	}
	return res.OK.Nics, nil
}

func (s *Stack) addPublicIP(nic *oapi.Nic) (*oapi.PublicIp, error) {

	resIP, err := s.client.POST_CreatePublicIp(oapi.CreatePublicIpRequest{})
	if err != nil {
		return nil, err
	}
	if resIP.OK == nil {
		return nil, scerr.InconsistentError("Provider inconstent response")
	}

	_, err = s.client.POST_LinkPublicIp(oapi.LinkPublicIpRequest{
		NicId:      nic.NicId,
		PublicIpId: resIP.OK.PublicIp.PublicIpId,
	})
	if err != nil {
		_, err := s.client.POST_DeletePublicIp(oapi.DeletePublicIpRequest{
			PublicIpId: resIP.OK.PublicIp.PublicIpId,
		})
		if err != nil {
			logrus.Warnf("Cannot delete public ip %s: %v", resIP.OK.PublicIp.PublicIpId, err)
			return nil, err
		}
	}
	return &resIP.OK.PublicIp, nil
}

func (s *Stack) setHostProperties(host *resources.Host, networks []*resources.Network, vm *oapi.Vm, nics []oapi.Nic) error {
	// Updates Host Property propsv1.HostDescription
	err := host.Properties.LockForWrite(hostproperty.DescriptionV1).ThenUse(func(clonable data.Clonable) error {
		hpDescriptionV1 := clonable.(*propertiesv1.HostDescription)
		hpDescriptionV1.Created = time.Now()
		hpDescriptionV1.Updated = time.Now()
		return nil
	})
	if err != nil {
		return err
	}

	// Updates Host Property propsv1.HostSizing
	err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(func(clonable data.Clonable) error {
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
	})
	if err != nil {
		return err
	}

	// Updates Host Property propsv1.HostNetwork
	return host.Properties.LockForWrite(hostproperty.NetworkV1).ThenUse(func(clonable data.Clonable) error {
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
	})
}

func (s *Stack) initHostProperties(request *resources.HostRequest, host *resources.Host) error {
	defaultNet := request.Networks[0]
	isGateway := request.DefaultGateway == nil && defaultNet.Name != resources.SingleHostNetworkName
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
		return scerr.InvalidParameterError("request.TemplateID", "Invalid template ID")
	}

	host.PrivateKey = request.KeyPair.PrivateKey // Add PrivateKey to host definition
	host.Password = request.Password

	err = host.Properties.LockForWrite(hostproperty.NetworkV1).ThenUse(func(clonable data.Clonable) error {
		hostNetworkV1 := clonable.(*propertiesv1.HostNetwork)
		hostNetworkV1.DefaultNetworkID = defaultNet.ID
		hostNetworkV1.DefaultGatewayID = defaultGatewayID
		hostNetworkV1.DefaultGatewayPrivateIP = request.DefaultRouteIP
		hostNetworkV1.IsGateway = isGateway
		return nil
	})
	if err != nil {
		return err
	}

	// Adds Host property SizingV1
	return host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(func(clonable data.Clonable) error {
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
	})
}

func (s *Stack) deleteHostOnError(err error, vm *oapi.Vm) error {
	err2 := s.DeleteHost(vm.VmId)
	if err2 != nil {
		return scerr.Wrap(err, err2.Error())
	}
	return err
}

// CreateHost creates an host that fulfils the request
func (s *Stack) CreateHost(request resources.HostRequest) (*resources.Host, *userdata.Content, error) {
	if s == nil {
		return nil, nil, scerr.InvalidInstanceError()
	}

	userData := userdata.NewContent()
	if request.DefaultGateway == nil && !request.PublicIP {
		return nil, userData, resources.ResourceInvalidRequestError("host creation", "cannot create a host without public IP or without attached network")
	}

	keyPair, err := s.getOrCreateKeypair(request)
	if err != nil {
		return nil, userData, err
	}
	defer func() {
		_ = s.DeleteKeyPair(keyPair.ID)
	}()
	request.KeyPair = keyPair
	password, err := s.getOrCreatePassword(request)
	request.Password = password
	if err != nil {
		return nil, userData, err
	}

	defautNet := request.Networks[0]
	subnet, err := s.getSubnet(defautNet.ID)
	if err != nil {
		return nil, userData, err
	}
	if subnet == nil {
		return nil, userData, resources.ResourceInvalidRequestError("request.Networks", "Invalid network, no subnet found")
	}
	subnetID := subnet.SubnetId

	err = s.prepareUserData(request, userData)
	if err != nil {
		return nil, userData, err
	}
	host := resources.NewHost()
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

	resVM, err := s.client.POST_CreateVms(oapi.CreateVmsRequest{
		ImageId:  request.ImageID,
		UserData: base64.StdEncoding.EncodeToString(buf.Bytes()),
		VmType:   vmType,
		SubnetId: subnetID,
		Placement: oapi.Placement{
			SubregionName: s.Options.Compute.Subregion,
			Tenancy:       s.Options.Compute.DefaultTenancy,
		},
		KeypairName: keyPair.ID,
	})
	if err != nil {
		return nil, userData, err
	}
	if resVM.OK == nil || len(resVM.OK.Vms) != 1 {
		return nil, userData, scerr.InconsistentError("Inconsistent provider response")
	}
	vm := resVM.OK.Vms[0]
	err = s.WaitForHostState(vm.VmId, hoststate.STARTED)
	if err != nil {
		return nil, userData, s.deleteHostOnError(err, &vm)
	}
	//Retrieve default Nic use to create public ip
	nics, err := s.getNICS(vm.VmId)
	if err != nil {
		return nil, userData, s.deleteHostOnError(err, &vm)
	}
	if len(nics) == 0 {
		return nil, userData, s.deleteHostOnError(scerr.InconsistentError("No network interface associated to vm"), &vm)
	}
	defaultNic := nics[0]

	nics, err = s.addNICS(&request, vm.VmId)
	if err != nil {
		return nil, userData, s.deleteHostOnError(err, &vm)
	}
	if request.PublicIP {
		ip, err := s.addPublicIP(&defaultNic)
		if err != nil {
			return nil, userData, s.deleteHostOnError(err, &vm)
		}
		if ip != nil {
			userData.PublicIP = ip.PublicIp
			vm.PublicIp = userData.PublicIP
		}

		for _, nic := range nics {
			_, err = s.addPublicIP(&nic)
			if err != nil {
				return nil, userData, s.deleteHostOnError(err, &vm)
			}
		}
	}

	err = s.addVolume(&request, vm.VmId)
	if err != nil {
		return nil, userData, s.deleteHostOnError(err, &vm)
	}

	err = s.setResourceTags(vm.VmId, map[string]string{
		"name": request.ResourceName,
	})
	if err != nil {
		return nil, userData, s.deleteHostOnError(err, &vm)
	}

	err = s.WaitForHostState(vm.VmId, hoststate.STARTED)
	if err != nil {
		return nil, userData, s.deleteHostOnError(err, &vm)
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

func (s *Stack) getVM(vmID string) (*oapi.Vm, error) {
	vm, err := s.client.POST_ReadVms(oapi.ReadVmsRequest{
		Filters: oapi.FiltersVm{
			VmIds: []string{vmID},
		},
	})
	if err != nil {
		return nil, err
	}
	if len(vm.OK.Vms) == 0 {
		return nil, nil
	}
	return &vm.OK.Vms[0], nil
}

func (s *Stack) deleteHost(id string) error {
	_, err := s.client.POST_DeleteVms(oapi.DeleteVmsRequest{
		VmIds: []string{id},
	})
	if err != nil {
		return err
	}
	return s.WaitForHostState(id, hoststate.TERMINATED)
}

// DeleteHost deletes the host identified by id
func (s *Stack) DeleteHost(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "must not be empty")
	}
	res, err := s.client.POST_ReadPublicIps(oapi.ReadPublicIpsRequest{
		Filters: oapi.FiltersPublicIp{VmIds: []string{id}},
	})
	if err != nil {
		logrus.Errorf("Unable to read public IPs of vm %s", id)
	}
	err = s.deleteHost(id)
	if err != nil {
		return err
	}
	if res.OK == nil || len(res.OK.PublicIps) == 0 {
		return nil
	}
	var lastErr error
	for _, ip := range res.OK.PublicIps {
		_, err = s.client.POST_DeletePublicIp(oapi.DeletePublicIpRequest{
			PublicIpId: ip.PublicIpId,
		})
		if err != nil { //continue to delete even if error
			lastErr = nil
			logrus.Errorf("Unable to delete public IP %s of vm %s", ip.PublicIpId, id)
		}
	}
	return lastErr

}

//InspectHost returns the host identified by id or updates content of a *resources.Host
func (s *Stack) InspectHost(hostParam interface{}) (*resources.Host, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	var host *resources.Host
	hostName := ""
	switch hostParam := hostParam.(type) {
	case string:
		if hostParam == "" {
			return nil, scerr.InvalidParameterError("hostParam", "cannot be an empty string")
		}
		host = resources.NewHost()
		host.ID = hostParam
	case *resources.Host:
		if hostParam == nil {
			return nil, scerr.InvalidParameterError("hostParam", "cannot be nil")
		}
		host = hostParam
		hostName = host.Name
	default:
		return nil, scerr.InvalidParameterError("hostParam", "must be a string or a *resources.Host")
	}

	vm, err := s.getVM(host.ID)
	if err != nil {
		return nil, err
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
func (s *Stack) GetHostByName(name string) (*resources.Host, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	hosts, err := s.ListHosts()
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if h.Name == name {
			return s.InspectHost(h.ID)
		}
	}
	return nil, scerr.NotFoundError(fmt.Sprintf("No host named %s", name))
	//TODO try in with v1
	// res, err := s.client.POST_ReadVms(oapi.ReadVmsRequest{
	// 	Filters: oapi.FiltersVm{
	// 		SubregionNames: []string{s.Options.Compute.Subregion},
	// 		Tags:           []string{fmt.Sprintf("name=%s", name)},
	// 	},
	// })
	// if err != nil {
	// 	return nil, err
	// }
	// if res == nil || res.OK == nil || len(res.OK.Vms) > 1 {
	// 	return nil, scerr.InconsistentError("Inconsistent provider response")
	// }
	// if len(res.OK.Vms) == 0 {
	// 	return nil, nil
	// }
	// return s.InspectHost(res.OK.Vms[0].VmId)

}

// GetHostState returns the current state of the host identified by id
func (s *Stack) GetHostState(hostParam interface{}) (hoststate.Enum, error) {
	if s == nil {
		return hoststate.UNKNOWN, scerr.InvalidInstanceError()
	}
	var host *resources.Host
	switch hostParam := hostParam.(type) {
	case string:
		if hostParam == "" {
			return hoststate.UNKNOWN, scerr.InvalidParameterError("hostParam", "cannot be an empty string")
		}
		host = resources.NewHost()
		host.ID = hostParam
	case *resources.Host:
		if hostParam == nil {
			return hoststate.UNKNOWN, scerr.InvalidParameterError("hostParam", "cannot be nil")
		}
		host = hostParam
	default:
		return hoststate.UNKNOWN, scerr.InvalidParameterError("hostParam", "must be a string or a *resources.Host")
	}

	return s.hostState(host.ID)
}

// ListHosts lists all hosts
func (s *Stack) ListHosts() ([]*resources.Host, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	res, err := s.client.POST_ReadVms(oapi.ReadVmsRequest{
		Filters: oapi.FiltersVm{
			SubregionNames: []string{s.Options.Compute.Subregion},
		},
	})
	if err != nil {
		return nil, err
	}
	if res == nil || res.OK == nil {
		return nil, scerr.InconsistentError("Inconsistent provider response")
	}
	var hosts []*resources.Host
	for _, vm := range res.OK.Vms {
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
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "must not be empty")
	}
	_, err := s.client.POST_StopVms(oapi.StopVmsRequest{
		VmIds:     []string{id},
		ForceStop: true,
	})
	return err
}

// StartHost starts the host identified by id
func (s *Stack) StartHost(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "must not be empty")
	}
	_, err := s.client.POST_StartVms(oapi.StartVmsRequest{
		VmIds: []string{id},
	})
	return err
}

//RebootHost Reboot host
func (s *Stack) RebootHost(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "must not be empty")
	}
	_, err := s.client.POST_RebootVms(oapi.RebootVmsRequest{
		VmIds: []string{id},
	})
	return err
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

//ResizeHost Resize host
func (s *Stack) ResizeHost(id string, request resources.SizingRequirements) (*resources.Host, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if id == "" {
		return nil, scerr.InvalidParameterError("id", "must not be empty")
	}
	perf := s.perfFromFreq(request.MinFreq)
	t := gpuTemplateName(0, request.MaxCores, int(request.MaxRAMSize), perf, 0, "")
	_, err := s.client.POST_UpdateVm(oapi.UpdateVmRequest{
		VmId:   id,
		VmType: t,
		// VmType: request.,
	})
	if err != nil {
		return nil, err
	}

	return s.InspectHost(id)
}
