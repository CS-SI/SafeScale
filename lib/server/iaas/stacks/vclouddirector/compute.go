// +build vcloud,!ignore

/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package vclouddirector

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vmware/go-vcloud-director/types/v56"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/vmware/go-vcloud-director/govcd"
)

// -------------IMAGES---------------------------------------------------------------------------------------------------

// ListImages lists available OS images
func (s *stack) ListImages(all bool) (list []abstract.Image, xerr fail.Error) {
	var nullImage []abstract.Image
	if s == nil {
		return nullImage, fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debug(">>> stacks.vclouddirector::ListImages()")
	defer logrus.Debug("<<< stacks.vclouddirector::ListImages()")

	org, err := govcd.GetOrgByName(s.EbrcService, s.AuthOptions.ProjectName)
	if err != nil {
		return nullImage, fail.Wrap(normalizeError(err), "Error listing images")
	}

	catalogName := ""
	list = nullImage
	for _, item := range org.Org.Link {
		// Retrieve the first catalog name for further usage
		if item.Type == "application/vnd.vmware.vcloud.catalog+xml" {
			catalogName = item.Name
		} else {
			continue
		}

		if catalogName != "" {
			cat, err := org.FindCatalog(catalogName)
			if err != nil {
				continue
			}
			if !all && !strings.Contains(catalogName, "Linux") {
				continue
			}
			for _, item := range cat.Catalog.CatalogItems {
				for _, deepItem := range item.CatalogItem {
					list = append(list, abstract.Image{ID: deepItem.ID, Name: deepItem.Name})
				}
			}
		}
	}

	return list, nil
}

// GetImage returns the Image referenced by id
func (s *stack) GetImage(id string) (*abstract.Image, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	images, xerr := s.ListImages(true)
	if xerr != nil {
		return nil, xerr
	}
	for _, image := range images {
		if image.ID == id {
			return &image, nil
		}
	}

	return nil, nil
}

// -------------TEMPLATES------------------------------------------------------------------------------------------------

// ListTemplates overload OpenStackEbrc ListTemplate method to filter wind and flex instance and add GPU configuration
func (s *stack) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
	var nullTemplate []abstract.HostTemplate
	if s == nil {
		return nullTemplate, fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debug(">>> stacks.vclouddirector::ListTemplates()")
	defer logrus.Debug("<<< stacks.vclouddirector::ListTemplates()")

	list := nullTemplate
	list = append(list, abstract.HostTemplate{Name: "Default", Cores: 1, DiskSize: 20, ID: "None...", RAMSize: 2})
	return list, nil
}

// ListTemplates overload OpenStackEbrc ListTemplate method to filter wind and flex instance and add GPU configuration
func (s *stack) ListTemplatesSpecial(all bool) ([]abstract.HostTemplate, fail.Error) {
	var nullTemplateSlice []abstract.HostTemplate

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debug(">>> stacks.vclouddirector::ListTemplates()")
	defer logrus.Debug("<<< stacks.vclouddirector::ListTemplates()")

	org, err := govcd.GetOrgByName(s.EbrcService, s.AuthOptions.ProjectName)
	if err != nil {
		return nullTemplateSlice, fail.Wrap(normalizeError(err), "error listing templates")
	}

	catalogName := ""
	list := nullTemplateSlice
	for _, item := range org.Org.Link {
		// Retrieve the first catalog name for further usage
		if item.Type == "application/vnd.vmware.vcloud.catalog+xml" {
			catalogName = item.Name
		} else {
			continue
		}

		if catalogName != "" {
			cat, err := org.FindCatalog(catalogName)
			if err != nil {
				continue
			}
			if !all && !strings.Contains(catalogName, "Linux") {
				continue
			}
			for _, item := range cat.Catalog.CatalogItems {
				for _, deepItem := range item.CatalogItem {
					catalogitem, cerr := cat.FindCatalogItem(deepItem.Name)
					if cerr != nil {
						continue
					}

					vapptemplate, cerr := catalogitem.GetVAppTemplate()
					if cerr != nil {
						continue
					}

					ms, cerr := vapptemplate.GetMemorySize()
					if cerr != nil {
						continue
					}

					ds, cerr := vapptemplate.GetTemplateDiskSize()
					if cerr != nil {
						continue
					}

					ht := abstract.HostTemplate{
						Cores:    1,
						RAMSize:  float32(ms),
						DiskSize: ds,
						ID:       vapptemplate.VAppTemplate.ID,
						Name:     vapptemplate.VAppTemplate.Name,
					}
					list = append(list, ht)
				}
			}
		}
	}

	return nullTemplateSlice, nil
}

// GetTemplate overload OpenStackEbrc GetTemplate method to add GPU configuration
func (s *stack) GetTemplate(id string) (*abstract.HostTemplate, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debugf(">>> stacks.vclouddirector::InspectTemplate(%s)", id)
	defer logrus.Debugf("<<< stacks.vclouddirector::InspectTemplate(%s)", id)

	// "Cores:%d,Disk:%d,Memory:%d"
	if strings.HasPrefix(id, "Cores:") {
		items := strings.Split(id, ",")
		cores, _ := strconv.Atoi(strings.Split(items[0], ":")[1])
		disk, _ := strconv.Atoi(strings.Split(items[1], ":")[1])
		memory, _ := strconv.Atoi(strings.Split(items[2], ":")[1])
		hot := &abstract.HostTemplate{
			Cores:    cores,
			DiskSize: disk,
			RAMSize:  float32(memory),
		}

		return hot, nil
	}

	return nil, nil
}

// -------------SSH KEYS-------------------------------------------------------------------------------------------------

// CreateKeyPair creates and import a key pair
func (s *stack) CreateKeyPair(name string) (_ *abstract.KeyPair, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.vclouddirector"), "(%s)", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	return abstract.NewKeyPair(name)
}

// GetKeyPair returns the key pair identified by id
func (s *stack) GetKeyPair(id string) (*abstract.KeyPair, fail.Error) {
	return nil, fail.NotImplementedError("")
}

// ListKeyPairs lists available key pairs
func (s *stack) ListKeyPairs() ([]abstract.KeyPair, fail.Error) {
	return nil, fail.NotImplementedError("")
}

// DeleteKeyPair deletes the key pair identified by id
func (s *stack) DeleteKeyPair(id string) fail.Error {
	return fail.NotImplementedError("")
}

// CreateHost creates an host satisfying request
func (s *stack) CreateHost(request abstract.HostRequest) (hostFull *abstract.HostFull, content *userdata.Content, xerr fail.Error) {
	nullAhf := abstract.NewHostFull()
	if s == nil {
		return nullAhf, nil, fail.InvalidInstanceError()
	}
	if request.KeyPair == nil {
		return nullAhf, nil, fail.InvalidParameterCannotBeNilError("request.KeyPair")
	}

	// TODO: use concurrency.Tracer
	logrus.Debug("vclouddirector.Client.CreateHost() called")
	defer logrus.Debug("vclouddirector.Client.CreateHost() done")

	userData := userdata.NewContent()

	resourceName := request.ResourceName
	networks := request.Networks
	hostMustHavePublicIP := request.PublicIP
	defaultGateway := request.DefaultGateway
	keyPair := request.KeyPair

	if networks == nil || len(networks) == 0 {
		return nullAhf, userData, fail.InvalidRequestError("the hostFull %s must be on at least one network (even if public)", resourceName)
	}
	if defaultGateway == nil && !hostMustHavePublicIP {
		return nullAhf, userData, fail.InvalidRequestError("The hostFull %s must have a gateway or be public", resourceName)
	}

	org, vdc, xerr := s.getOrgVdc()
	if err != nil {
		return nullAhf, userData, fail.Wrap(xerr, "error getting hostFull by name")
	}

	catalogName := ""
	itemName := ""

	// Recover catalog name
	for _, item := range org.Org.Link {
		catalogName := ""
		if item.Type == "application/vnd.vmware.vcloud.catalog+xml" {
			catalogName = item.Name
		} else {
			continue
		}

		if catalogName != "" {
			cat, err := org.FindCatalog(catalogName)
			if err != nil {
				continue
			}
			for _, item := range cat.Catalog.CatalogItems {
				for _, deepItem := range item.CatalogItem {
					if deepItem.ID == request.ImageRef {
						itemName = deepItem.Name
					}
				}
			}
		}
	}

	logrus.Warningf("Selected catalog: [%s]", catalogName)

	catalog, err := org.FindCatalog(catalogName)
	if err != nil {
		return nullAhf, userData, fail.Wrap(normalizeError(err), "failed to find catalog")
	}
	if utils.IsEmpty(catalog) {
		return nullAhf, userData, fail.NewError("no catalog found")
	}

	logrus.Warningf("Selected image: [%s]", request.ImageRef)

	catalogitem, err := catalog.FindCatalogItem(itemName)
	if err != nil {
		return nullAhf, userData, fail.Wrap(normalizeError(err), "failed to search catalog item")
	}
	if utils.IsEmpty(catalogitem) {
		return nullAhf, userData, fail.NewError("failed to find item '%s' in the catalog", itemName)
	}

	// Determine system disk size based on vcpus count
	template, xerr := s.GetTemplate(request.TemplateRef)
	if xerr != nil {
		return nullAhf, userData, fail.Wrap(xerr, "failed to get image: %s", request.TemplateRef)
	}
	_ = template

	vapptemplate, err := catalogitem.GetVAppTemplate()
	if err != nil {
		return nullAhf, userData, fail.Wrap(normalizeError(err), "error getting VAppTemplate")
	}
	if utils.IsEmpty(vapptemplate) {
		return nullAhf, userData, fail.NewError("VAppTemplate not found")
	}

	log.Printf("[DEBUG] VAppTemplate: %#v", vapptemplate)

	net, err := vdc.FindVDCNetwork(request.Networks[0].Name)
	if err != nil {
		return nil, userData, fail.Wrap(normalizeError(err), "failed to find OrgVCD Networking")
	}
	nets := []*types.OrgVDCNetwork{net.OrgVDCNetwork}

	storageProfileReference := types.Reference{}
	for _, sps := range vdc.Vdc.VdcStorageProfiles {
		for _, sp := range sps.VdcStorageProfile {
			storageProfileReference, err = vdc.FindStorageProfileReference(sp.Name)
			if err != nil {
				return nullAhf, userData, fail.NewError("failed to find storage profile '%s'", sp.Name)
			}
		}
	}

	//	log.Printf("storage_profile %s", storageProfileReference)

	vapp, err := vdc.FindVAppByName(request.ResourceName)
	if err != nil {
		retryErr := retry.WhileUnsuccessfulDelay5Seconds(
			func() error {
				// FIXME: vdc.ComposeVAppWithDHCP doesn't exist anymore; use of vdc.ComposeVapp + another call ?
				task, innerErr := vdc.ComposeVAppWithDHCP(nets, vapptemplate, storageProfileReference, request.ResourceName, fmt.Sprintf("%s description", request.ResourceName), true)
				if innerErr != nil {
					logrus.Warning(normalizeError(innerErr))
					return normalizeError(innerErr)
				}
				innerXErr := task.WaitTaskCompletion()
				logrus.Warning(innerXErr)
				return innerXErr
			},
			10*time.Minute,
		)
		if retryErr != nil {
			return nullAhf, userData, fail.Wrap(retryErr, "error creating vapp")
		}
		vapp, err = vdc.FindVAppByName(request.ResourceName)
		if err != nil {
			return nullAhf, userData, fail.Wrap(normalizeError(err), "error creating vapp")
		}
	}

	// FIXME: Defer vapp creation
	defer func() {
		if xerr != nil {
			vapp, derr := vdc.FindVAppByName(request.ResourceName)
			if derr != nil {
				logrus.Errorf("Error deleting deferred hostFull")
				xerr.AddConsequence(derr)
				return
			}

			undepTask, derr := vapp.Undeploy()
			if derr != nil {
				logrus.Errorf("Error deleting deferred hostFull")
				xerr.AddConsequence(derr)
				return
			}

			derr = undepTask.WaitTaskCompletion()
			if derr != nil {
				logrus.Errorf("Error deleting deferred hostFull")
				xerr.AddConsequence(derr)
				return
			}

			dtask, derr := vapp.Delete()
			if derr != nil {
				logrus.Errorf("Error deleting deferred hostFull")
				xerr.AddConsequence(derr)
				return
			}

			derr = dtask.WaitTaskCompletion()
			if derr != nil {
				logrus.Errorf("Error deleting deferred hostFull")
				xerr.AddConsequence(derr)
				return
			}
		}
	}()

	log.Printf("Renaming vapp to %s", request.ResourceName)

	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			task, innerErr := vapp.ChangeVMName(request.ResourceName)
			if innerErr != nil {
				return normalizeError(innerErr)
			}
			return normalizeError(task.WaitTaskCompletion())
		},
		10*time.Minute,
	)
	if retryErr != nil {
		return nullAhf, userData, fail.Wrap(retryErr, "error changing vmname")
	}

	// ----Initialize----
	if request.Password == "" {
		password, xerr := utils.GeneratePassword(16)
		if xerr != nil {
			return nullAhf, userData, fail.Wrap(xerr, "failed to generate password")
		}
		request.Password = password
	}

	defaultNetwork := request.Networks[0]

	// Constructs userdata content
	xerr = userData.Prepare(*s.Config, request, defaultNetwork.CIDR, "")
	if xerr != nil {
		msg := fmt.Sprintf("failed to prepare user data content: %+v", retryErr)
		logrus.Debugf(strprocess.Capitalize(msg))
		return nullAhf, userData, fail.Wrap(xerr, msg)
	}

	phase1Content, xerr := userData.Generate("phase1")
	if xerr != nil {
		return nullAhf, userData, xerr
	}

	retryErr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			task, innerErr := vapp.RunCustomizationScript(request.ResourceName, string(phase1Content))
			if innerErr != nil {
				return normalizeError(innerErr)
			}
			return task.WaitTaskCompletion()
		},
		10*time.Minute,
	)
	if retryErr != nil {
		return nullAhf, userData, fail.Wrap(retryErr, "error running customization script'")
	}

	retryErr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			task, innerErr := vapp.PowerOn()
			if innerErr != nil {
				return normalizeError(innerErr)
			}
			return normalizeError(task.WaitTaskCompletion())
		},
		10*time.Minute,
	)
	if retryErr != nil {
		return nullAhf, userData, fail.Wrap(retryErr, "error powering on the hostFull")
	}

	capturedIP := ""

	retryErr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			vm, innerErr := vdc.FindVMByName(vapp, vapp.VApp.Name)
			if innerErr != nil {
				return normalizeError(innerErr)
			}
			innerErr = vm.Refresh()
			if innerErr != nil {
				return normalizeError(innerErr)
			}

			cose, innerErr := vm.GetNetworkConnectionSection()
			if innerErr != nil {
				return normalizeError(innerErr)
			}

			PublicIPv4 := cose.NetworkConnection[0].IPAddress
			if PublicIPv4 == "" {
				return fail.NewError("no IP detected")
			} else {
				logrus.Warningf("IP Detected: [%s]", PublicIPv4)
				capturedIP = PublicIPv4
			}

			return nil
		},
		3*time.Minute,
	)
	if retryErr != nil {
		return nullAhf, userData, fail.Wrap(retryErr, "error getting machine ip")
	}

	// FIXME: Populate this
	hostFull = abstract.NewHostFull()
	hostFull.Core = &abstract.HostCore{
		ID:         vapp.VApp.ID,
		Name:       vapp.VApp.Name,
		PrivateKey: keyPair.PrivateKey,
		Password:   request.Password,
	}

	publicIPs, xerr := s.getPublicIPs()
	if xerr != nil {
		return nullAhf, userData, xerr
	}

	selectedIP := publicIPs.IPRange[0].StartAddress

	hostIsAGateway := false

	// TODO: adapt in abstract.HostFull.HostNetworking
	hostFull.Networking.DefaultNetworkID = defaultNetwork.ID
	hostFull.Networking.IsGateway = request.IsGateway
	if hostFull.Networking.IsGateway {
		hostFull.Networking.PublicIPv4 = selectedIP
	} else {
		hostFull.Networking.PublicIPv4 = capturedIP
	}
	// retryErr = hostFull.Properties.LockForWrite(hostproperty.NetworkV1).ThenUse(func(clonable data.Clonable) error {
	//	hostNetworkV1 := clonable.(*propsv1.HostNetworking)
	//	hostNetworkV1.DefaultSubnetID = defaultNetwork.ID
	//
	//	hostNetworkV1.IsGateway = request.DefaultGateway == nil && request.Networks[0].Name != abstract.SingleHostNetworkName
	//	if request.DefaultGateway != nil {
	//		hostNetworkV1.DefaultGatewayID = request.DefaultGateway.ID
	//
	//		gateway, err := s.InspectHost(request.DefaultGateway)
	//		if err != nil {
	//			return fail.Errorf(fmt.Sprintf("Failed to get gateway hostFull : %s", err.Error()), err)
	//		}
	//
	//		hostNetworkV1.DefaultGatewayPrivateIP = gateway.GetPrivateIP()
	//	}
	//
	//	hostIsAGateway = hostNetworkV1.IsGateway
	//
	//	if hostNetworkV1.IsGateway {
	//		hostNetworkV1.PublicIPv4 = selectedIP
	//	} else {
	//		hostNetworkV1.PublicIPv4 = capturedIP
	//	}
	//	return nil
	// })
	// if retryErr != nil {
	//	return nil, userData, retryErr
	// }

	dsize, _ := vapptemplate.GetTemplateDiskSize()
	memory, _ := vapptemplate.GetMemorySize()

	// FIXME: Extract true info
	// TODO: adapt in abstract.HostFull.HostSizing
	hostFull.Sizing.RAMSize = float32(memory / 1024)
	hostFull.Sizing.Cores = 1
	hostFull.Sizing.DiskSize = dsize / 1024 / 1024 / 1024
	hostFull.Sizing.GPUNumber = 1
	// xerr = hostFull.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(func(clonable data.Clonable) error {
	//	hostSizingV1 := clonable.(*propsv1.HostSizing)
	//
	//	hostSizingV1.RequestedSize.RAMSize = float32(memory / 1024)
	//	hostSizingV1.RequestedSize.Cores = 1
	//	hostSizingV1.RequestedSize.DiskSize = dsize / 1024 / 1024 / 1024
	//	hostSizingV1.RequestedSize.GPUNumber = 1
	//
	//	return nil
	// })
	// if xerr != nil {
	//	return nil, userData, fail.Errorf(fmt.Sprintf("Failed to update HostProperty.SizingV1 : %s", xerr.Error()), xerr)
	// }

	// FIXME: Edge gateway smart tunnel only if public or gateway
	if hostMustHavePublicIP || hostIsAGateway {
		gateways, xerr := s.findEdgeGatewayNames()
		if xerr != nil {
			return nullAhf, userData, fail.Wrap(xerr, "failed to find edge gateways")
		}
		if utils.IsEmpty(gateways) {
			return nil, userData, fail.NewError("no edge gateways found")
		}

		edgeGateway, err := vdc.FindEdgeGateway(gateways[0])
		if err != nil {
			return nullAhf, userData, normalizeError(err)
		}
		egt, err := edgeGateway.Create1to1Mapping(capturedIP, selectedIP, fmt.Sprintf("SmartTunnel-%s", hostFull.Core.Name))
		if err != nil {
			return nullAhf, userData, normalizeError(err)
		}
		err = egt.WaitTaskCompletion()
		if err != nil {
			return nullAhf, userData, normalizeError(err)
		}
	}

	return hostFull, userData, nil
}

// ClearHostStartupScript clears the userdata startup script for Host instance (metadata service)
// FIXME: determine if anything is needed (does nothing for now)
func (s stack) ClearHostStartupScript(hostParam stacks.HostParameter) fail.Error {
	return nil
}

// InspectHost returns the host identified by ref (name or id) or by a *abstract.IPAddress containing an id
func (s *stack) InspectHost(hostParam stacks.HostParameter) (ahf *abstract.HostFull, xerr fail.Error) {
	ahf = &abstract.HostFull{}
	if s == nil {
		return ahf, fail.InvalidInstanceError()
	}
	var hostRef string
	ahf, hostRef, xerr = stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return ahf, xerr
	}

	logrus.Debug("vclouddirector.compute.InspectHost() called")
	defer logrus.Debug("vclouddirector.compute.InspectHost() done")

	_, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return nil, xerr
	}

	vapp, err := vdc.FindVAppByID(hostRef)
	if err != nil {
		vapp, err = vdc.FindVAppByName(hostRef)
		if err != nil {
			xerr = fail.NotFoundErrorWithCause(normalizeError(err), "error inspecting host")
			return ahf, xerr
		}
	}

	err = vapp.Refresh()
	if err != nil {
		return nil, abstract.ResourceNotFoundError("host", ahf.Core.Name)
	}

	// FIXME: Populate this
	newHost := abstract.NewHostFull()
	newHost.Core = &abstract.HostCore{
		ID:        vapp.VApp.ID,
		Name:      vapp.VApp.Name,
		LastState: stateConvert(vapp.VApp.Status),
	}

	if xerr = s.complementHost(ahf, newHost); xerr != nil {
		return ahf, xerr
	}

	return ahf, nil
}

func (s *stack) complementHost(host *abstract.HostFull, newHost *abstract.HostFull) fail.Error {
	host.Core.ID = newHost.Core.ID
	if host.Core.Name == "" {
		host.Core.Name = newHost.Core.Name
	}
	host.Core.LastState = newHost.Core.LastState

	// TODO: adapt to abstract.HostFull.HostNetworking
	// err := host.Properties.LockForWrite(hostproperty.NetworkV1).ThenUse(func(clonable data.Clonable) error {
	//	newHostNetworkV1 := propsv1.NewHostSubnet()
	//	hostNetworkV1 := clonable.(*propsv1.HostNetworking)
	//	hostNetworkV1.IPv4Addresses = newHostNetworkV1.IPv4Addresses
	//	hostNetworkV1.IPv6Addresses = newHostNetworkV1.IPv6Addresses
	//	hostNetworkV1.SubnetsByID = newHostNetworkV1.SubnetsByID
	//	hostNetworkV1.SubnetsByName = newHostNetworkV1.SubnetsByName
	//	return nil
	// })
	// if err != nil {
	//	return fail.Errorf(fmt.Sprintf("Failed to update HostProperty.NetworkV1 : %s", err.Error()), err)
	// }

	// TODO: adapt to abstract.HostFull.HostSizing
	// err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(func(clonable data.Clonable) error {
	//	newHostSizingV1 := propsv1.NewHostSizing()
	//	hostSizingV1 := clonable.(*propsv1.HostSizing)
	//	hostSizingV1.AllocatedSize.Cores = newHostSizingV1.AllocatedSize.Cores
	//	hostSizingV1.AllocatedSize.RAMSize = newHostSizingV1.AllocatedSize.RAMSize
	//	hostSizingV1.AllocatedSize.DiskSize = newHostSizingV1.AllocatedSize.DiskSize
	//	return nil
	// })
	// if err != nil {
	//	return fail.Errorf(fmt.Sprintf("Failed to update HostProperty.SizingV1 : %s", err.Error()), err)
	// }

	return nil
}

// stateConvert convert vcd state to a HostState.Enum
func stateConvert(stateVcd int) hoststate.Enum {
	switch stateVcd {
	case 4, 5:
		return hoststate.STARTED
	case 19:
		return hoststate.STARTING
	case 18, 8:
		return hoststate.STOPPED
	default:
		return hoststate.ERROR
	}
}

// InspectHostByName returns the host identified by ref (name or id)
func (s *stack) InspectHostByName(name string) (*abstract.HostFull, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debug("vclouddirector.Client.InspectHostByName() called")
	defer logrus.Debug("vclouddirector.Client.InspectHostByName() done")

	_, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return nil, xerr
	}

	vapp, err := vdc.FindVAppByName(name)
	if err != nil {
		return nil, abstract.ResourceNotFoundError("host", name)
	}

	err = vapp.Refresh()
	if err != nil {
		return nil, abstract.ResourceNotFoundError("host", name)
	}

	ahf := abstract.NewHostFull()
	ahf.Core.ID = vapp.VApp.ID
	ahf.Core.Name = vapp.VApp.Name
	ahf.Core.LastState = stateConvert(vapp.VApp.Status)

	return ahf, nil
}

// DeleteHost deletes the host identified by id
func (s *stack) DeleteHost(hostParam stacks.HostParameter) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}
	if ahf.Core.ID == "" {
		return fail.InvalidParameterError("hostParam", "must be an ID as a string, or an *abstract.HostCore or an *abstract.HostFull")
	}

	// TODO: use concurrency.Tracer
	logrus.Debug("vclouddirector.Client.DeleteHost() called")
	defer logrus.Debug("vclouddirector.Client.DeleteHost() done")

	_, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return xerr
	}

	vapp, err := vdc.FindVAppByID(ahf.Core.ID)
	if err != nil {
		return normalizeError(err)
	}

	undepTask, err := vapp.Undeploy()
	if err != nil {
		return normalizeError(err)
	}

	err = undepTask.WaitTaskCompletion()
	if err != nil {
		return normalizeError(err)
	}

	dtask, err := vapp.Delete()
	if err != nil {
		return normalizeError(err)
	}

	// FIXME: Remove firewall and NAT rules

	err = dtask.WaitTaskCompletion()
	return normalizeError(err)
}

// ResizeHost change the template used by an host
func (s *stack) ResizeHost(hostParam stacks.HostParameter, request abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	return nil, fail.NotImplementedError("ResizeHost() not implemented yet")
}

// ListHosts lists available hosts
func (s *stack) ListHosts() ([]*abstract.HostCore, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debug("vclouddirector.Client.ListHosts() called")
	defer logrus.Debug("vclouddirector.Client.ListHosts() done")

	org, err := govcd.GetOrgByName(s.EbrcService, s.AuthOptions.ProjectName)
	if err != nil {
		return nil, normalizeError(err)
	}

	refs, xerr := getLinks(org, "vnd.vmware.vcloud.vApp")
	if xerr != nil {
		return nil, xerr
	}

	var hosts []*abstract.HostCore
	for _, ref := range refs {
		hosts = append(hosts, &abstract.HostCore{Name: ref.Name})
	}

	return hosts, nil
}

// StopHost stops the host identified by id
func (s *stack) StopHost(hostParam stacks.HostParameter, gracefully bool) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}
	if ahf.Core.ID == "" {
		return fail.InvalidParameterError("hostParam", "must be an ID as a string, or an *abstract.HostCore or an *abstract.HostFull")
	}

	// TODO: use concurrency.Tracer
	logrus.Debug("vclouddirector.compute.StopHost() called")
	defer logrus.Debug("vclouddirector.compute.StopHost() done")

	_, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return xerr
	}

	vapp, err := vdc.FindVAppByID(id)
	if err != nil {
		return normalizeError(err)
	}

	dtask, err := vapp.Shutdown()
	if err != nil {
		return normalizeError(err)
	}

	err = dtask.WaitTaskCompletion()
	return normalizeError(err)
}

// StartHost starts the host identified by id
func (s *stack) StartHost(hostParam interface{}) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}
	if ahf.Core.ID == "" {
		return fail.InvalidParameterError("hostParam", "must be an ID as a string, or an *abstract.HostCore or an *abstract.HostFull")
	}

	// TODO: use concurrency.Tracer
	logrus.Debug("vclouddirector.Client.StartHost() called")
	defer logrus.Debug("vclouddirector.Client.StartHost() done")

	_, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return xerr
	}

	vapp, err := vdc.FindVAppByID(ahf.Core.ID)
	if err != nil {
		return normalizeError(err)
	}

	dtask, err := vapp.PowerOn()
	if err != nil {
		return normalizeError(err)
	}

	err = dtask.WaitTaskCompletion()
	return normalizeError(err)
}

// RebootHost reboot the host identified by id
func (s *stack) RebootHost(hostParam stacks.HostParameter) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}
	if ahf.Core.ID == "" {
		return fail.InvalidParameterError("hostParam", "must be an ID as a string, or an *abstract.HostCore or an *abstract.HostFull")
	}

	// TODO: use concurrency.Tracer
	logrus.Debug("vclouddirector.Client.RebootHost() called")
	defer logrus.Debug("vclouddirector.Client.RebootHost() done")

	_, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return xerr
	}

	vapp, err := vdc.FindVAppByID(ahf.Core.ID)
	if err != nil {
		return normalizeError(err)
	}

	dtask, err := vapp.Reboot()
	if err != nil {
		return normalizeError(err)
	}

	err = dtask.WaitTaskCompletion()
	return normalizeError(err)
}

// GetHostState returns the host identified by id
func (s *stack) GetHostState(hostParam stacks.HostParameter) (hoststate.Enum, fail.Error) {
	if s == nil {
		return hoststate.ERROR, fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debug("vclouddirector.Client.RebootHost() called")
	defer logrus.Debug("vclouddirector.Client.RebootHost() done")

	ahf, xerr := s.InspectHost(hostParam)
	if xerr != nil {
		return hoststate.ERROR, xerr
	}
	return ahf.CurrentState, nil
}

// -------------Provider Infos-------------------------------------------------------------------------------------------

// ListAvailabilityZones lists the usable AvailabilityZones
func (s *stack) ListAvailabilityZones() (map[string]bool, fail.Error) {
	return map[string]bool{"local": true}, nil
}

func (s *stack) ListRegions() ([]string, fail.Error) {
	return nil, fail.NotImplementedError("ListRegions() not implemented yet") // FIXME: Technical debt
}

// BindSecurityGroupToHost ...
func (s *stack) BindSecurityGroupToHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	return fail.NotImplementedError("not yet implemented")
}

// UnbindSecurityGroupFromHost ...
func (s *stack) UnbindSecurityGroupFromHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	return fail.NotImplementedError("not yet implemented")
}
