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

package ebrc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vmware/go-vcloud-director/govcd"
	"github.com/vmware/go-vcloud-director/types/v56"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"time"

	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
)

//-------------IMAGES---------------------------------------------------------------------------------------------------

// ListImages lists available OS images
func (s *StackEbrc) ListImages(all bool) ([]resources.Image, error) {
	logrus.Debug(">>> stacks.ebrc::ListImages()")
	defer logrus.Debug("<<< stacks.ebrc::ListImages()")

	if s == nil {
		panic("Calling stacks.ebrc::ListImage from nil pointer!")
	}

	var empty []resources.Image

	org, err := govcd.GetOrgByName(s.EbrcService, s.AuthOptions.ProjectName)
	if err != nil {
		return empty, errors.Wrap(err, fmt.Sprintf("Error listing images"))
	}

	catalog_name := ""
	for _, item := range org.Org.Link {
		// Retrieve the first catalog name for further usage
		if item.Type == "application/vnd.vmware.vcloud.catalog+xml" {
			catalog_name = item.Name
		} else {
			continue
		}

		if catalog_name != "" {
			cat, err := org.FindCatalog(catalog_name)
			if err != nil {
				continue
			}
			if !all && !strings.Contains(catalog_name, "Linux") {
				continue
			}
			for _, item := range cat.Catalog.CatalogItems {
				for _, deepItem := range item.CatalogItem {
					empty = append(empty, resources.Image{ID: deepItem.ID, Name: deepItem.Name})
				}
			}
		}
	}

	return empty, nil
}

// GetImage returns the Image referenced by id
func (s *StackEbrc) GetImage(id string) (*resources.Image, error) {
	if s == nil {
		panic("Calling s.GetImage with s==nil!")
	}

	images, err := s.ListImages(true)
	if err != nil {
		return nil, err
	}
	for _, image := range images {
		if image.ID == id {
			return &image, nil
		}
	}

	return nil, nil
}

//-------------TEMPLATES------------------------------------------------------------------------------------------------

// ListTemplates overload OpenStackEbrc ListTemplate method to filter wind and flex instance and add GPU configuration
func (s *StackEbrc) ListTemplates(all bool) ([]resources.HostTemplate, error) {
	logrus.Debug(">>> stacks.ebrc::ListTemplates()")
	defer logrus.Debug("<<< stacks.ebrc::ListTemplates()")

	if s == nil {
		panic("Calling stacks.ebrc::ListImage from nil pointer!")
	}

	var empty []resources.HostTemplate
	empty = append(empty, resources.HostTemplate{Name: "Default", Cores: 1, DiskSize: 20, ID: "None...", RAMSize: 2})

	return empty, nil
}

// ListTemplates overload OpenStackEbrc ListTemplate method to filter wind and flex instance and add GPU configuration
func (s *StackEbrc) ListTemplatesSpecial(all bool) ([]resources.HostTemplate, error) {
	logrus.Debug(">>> stacks.ebrc::ListTemplates()")
	defer logrus.Debug("<<< stacks.ebrc::ListTemplates()")

	if s == nil {
		panic("Calling stacks.ebrc::ListTemplates from nil pointer!")
	}

	var empty []resources.HostTemplate

	org, err := govcd.GetOrgByName(s.EbrcService, s.AuthOptions.ProjectName)
	if err != nil {
		return empty, errors.Wrap(err, fmt.Sprintf("Error listing templates"))
	}

	catalog_name := ""
	for _, item := range org.Org.Link {
		// Retrieve the first catalog name for further usage
		if item.Type == "application/vnd.vmware.vcloud.catalog+xml" {
			catalog_name = item.Name
		} else {
			continue
		}

		if catalog_name != "" {
			cat, err := org.FindCatalog(catalog_name)
			if err != nil {
				continue
			}
			if !all && !strings.Contains(catalog_name, "Linux") {
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

					ht := resources.HostTemplate{
						Cores:    1,
						RAMSize:  float32(ms),
						DiskSize: ds,
						ID:       vapptemplate.VAppTemplate.ID,
						Name:     vapptemplate.VAppTemplate.Name,
					}
					empty = append(empty, ht)
				}
			}
		}
	}

	return empty, nil
}

//GetTemplate overload OpenStackEbrc GetTemplate method to add GPU configuration
func (s *StackEbrc) GetTemplate(id string) (*resources.HostTemplate, error) {
	logrus.Debugf(">>> stacks.ebrc::GetTemplate(%s)", id)
	defer logrus.Debugf("<<< stacks.ebrc::GetTemplate(%s)", id)

	if s == nil {
		panic("Calling method GetTemplate from nil!")
	}

	// "Cores:%d,Disk:%d,Memory:%d"
	if strings.HasPrefix(id, "Cores:") {
		items := strings.Split(id, ",")
		cores, _ := strconv.Atoi(strings.Split(items[0], ":")[1])
		disk, _ := strconv.Atoi(strings.Split(items[1], ":")[1])
		memory, _ := strconv.Atoi(strings.Split(items[2], ":")[1])
		hot := &resources.HostTemplate{
			Cores:    cores,
			DiskSize: disk,
			RAMSize:  float32(memory),
		}

		return hot, nil
	}

	return nil, nil
}

//-------------SSH KEYS-------------------------------------------------------------------------------------------------

// CreateKeyPair creates and import a key pair
func (s *StackEbrc) CreateKeyPair(name string) (*resources.KeyPair, error) {
	logrus.Debugf(">>> stacks.ebrc::CreateKeyPair(%s)", name)
	defer logrus.Debugf("<<< stacks.ebrc::CreateKeyPair(%s)", name)

	if s == nil {
		panic("Calling method CreateKeyPair from nil!")
	}

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := privateKey.PublicKey
	pub, _ := ssh.NewPublicKey(&publicKey)
	pubBytes := ssh.MarshalAuthorizedKey(pub)
	pubKey := string(pubBytes)

	priBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	priKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: priBytes,
		},
	)
	priKey := string(priKeyPem)
	return &resources.KeyPair{
		ID:         name,
		Name:       name,
		PublicKey:  pubKey,
		PrivateKey: priKey,
	}, nil
}

// GetKeyPair returns the key pair identified by id
func (s *StackEbrc) GetKeyPair(id string) (*resources.KeyPair, error) {
	return nil, scerr.Errorf(fmt.Sprintf("Not implemented"), nil)
}

// ListKeyPairs lists available key pairs
func (s *StackEbrc) ListKeyPairs() ([]resources.KeyPair, error) {
	return nil, scerr.Errorf(fmt.Sprintf("Not implemented"), nil)
}

// DeleteKeyPair deletes the key pair identified by id
func (s *StackEbrc) DeleteKeyPair(id string) error {
	return scerr.Errorf(fmt.Sprintf("Not implemented"), nil)
}

// CreateHost creates an host satisfying request
func (s *StackEbrc) CreateHost(request resources.HostRequest) (host *resources.Host, content *userdata.Content, err error) {
	logrus.Debug("ebrc.Client.CreateHost() called")
	defer logrus.Debug("ebrc.Client.CreateHost() done")

	if s == nil {
		panic("Calling s.CreateHost with s==nil!")
	}

	userData := userdata.NewContent()

	resourceName := request.ResourceName
	networks := request.Networks
	hostMustHavePublicIP := request.PublicIP
	defaultGateway := request.DefaultGateway
	keyPair := request.KeyPair

	if networks == nil || len(networks) == 0 {
		return nil, userData, scerr.Errorf(fmt.Sprintf("The host %s must be on at least one network (even if public)", resourceName), nil)
	}
	if defaultGateway == nil && !hostMustHavePublicIP {
		return nil, userData, scerr.Errorf(fmt.Sprintf("The host %s must have a gateway or be public", resourceName), nil)
	}

	org, vdc, err := s.getOrgVdc()
	if err != nil {
		return nil, userData, errors.Wrap(err, fmt.Sprintf("Error getting host by name"))
	}

	catalogName := ""
	itemName := ""

	// Recover catalog name
	for _, item := range org.Org.Link {
		catalog_name := ""
		if item.Type == "application/vnd.vmware.vcloud.catalog+xml" {
			catalog_name = item.Name
		} else {
			continue
		}

		if catalog_name != "" {
			cat, err := org.FindCatalog(catalog_name)
			if err != nil {
				continue
			}
			for _, item := range cat.Catalog.CatalogItems {
				for _, deepItem := range item.CatalogItem {
					if deepItem.ID == request.ImageID {
						catalogName = catalog_name
						itemName = deepItem.Name
					}
				}
			}
		}
	}

	logrus.Warningf("Selected catalog: [%s]", catalogName)

	catalog, err := org.FindCatalog(catalogName)
	if err != nil || utils.IsEmpty(catalog) {
		return nil, userData, scerr.Errorf(fmt.Sprintf("error finding catalog: %#v", err), err)
	}

	logrus.Warningf("Selected image: [%s]", request.ImageID)

	catalogitem, err := catalog.FindCatalogItem(itemName)
	if err != nil || utils.IsEmpty(catalogitem) {
		return nil, userData, scerr.Errorf(fmt.Sprintf("error finding catalog item: %#v", err), err)
	}

	// FIXME Use template

	// Determine system disk size based on vcpus count
	template, err := s.GetTemplate(request.TemplateID)
	if err != nil {
		return nil, userData, scerr.Errorf(fmt.Sprintf("failed to get image: %s", request.TemplateID), err)
	}
	_ = template

	vapptemplate, err := catalogitem.GetVAppTemplate()
	if err != nil || utils.IsEmpty(vapptemplate) {
		return nil, userData, scerr.Errorf(fmt.Sprintf("error finding VAppTemplate: %#v", err), err)
	}

	log.Printf("[DEBUG] VAppTemplate: %#v", vapptemplate)

	net, err := vdc.FindVDCNetwork(request.Networks[0].Name)
	if err != nil {
		return nil, userData, scerr.Errorf(fmt.Sprintf("error finding OrgVCD Network: %#v", err), err)
	}
	nets := []*types.OrgVDCNetwork{net.OrgVDCNetwork}

	storage_profile_reference := types.Reference{}

	for _, sps := range vdc.Vdc.VdcStorageProfiles {
		for _, sp := range sps.VdcStorageProfile {
			storage_profile_reference, err = vdc.FindStorageProfileReference(sp.Name)
			if err != nil {
				return nil, userData, scerr.Errorf(fmt.Sprintf("error finding storage profile %s", sp.Name), err)
			}
		}
	}

	log.Printf("storage_profile %s", storage_profile_reference)
	// FIXME Remove this
	// logrus.Warningf("Request [%s]", spew.Sdump(request))

	vapp, err := vdc.FindVAppByName(request.ResourceName)

	if err != nil {
		retryErr := retry.WhileUnsuccessfulDelay5Seconds(
			func() error {
				task, err := vdc.ComposeVAppWithDHCP(nets, vapptemplate, storage_profile_reference, request.ResourceName, fmt.Sprintf("%s description", request.ResourceName), true)
				if err != nil {
					logrus.Warning(err)
					return err
				}
				err = task.WaitTaskCompletion()
				logrus.Warning(err)
				return err
			},
			10*time.Minute,
		)

		if retryErr != nil {
			return nil, userData, scerr.Errorf(fmt.Sprintf("error creating vapp: %#v", err), retryErr)
		}
		vapp, err = vdc.FindVAppByName(request.ResourceName)
		if err != nil {
			return nil, userData, scerr.Errorf(fmt.Sprintf("error creating vapp: %#v", err), err)
		}
	}

	// FIXME Defer vapp creation
	defer func() {
		if err != nil {
			vapp, derr := vdc.FindVAppByName(request.ResourceName)
			if derr != nil {
				logrus.Errorf("Error deleting deferred host")
				return
			}

			undepTask, derr := vapp.Undeploy()
			if derr != nil {
				logrus.Errorf("Error deleting deferred host")
				return
			}

			derr = undepTask.WaitTaskCompletion()
			if derr != nil {
				logrus.Errorf("Error deleting deferred host")
				return
			}

			dtask, derr := vapp.Delete()
			if derr != nil {
				logrus.Errorf("Error deleting deferred host")
				return
			}

			derr = dtask.WaitTaskCompletion()
			if derr != nil {
				logrus.Errorf("Error deleting deferred host")
				return
			}
		}
	}()

	log.Printf("Renaming vapp to %s", request.ResourceName)

	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			task, err := vapp.ChangeVMName(request.ResourceName)
			if err != nil {
				return err
			}
			return task.WaitTaskCompletion()
		},
		10*time.Minute,
	)
	if err != nil {
		return nil, userData, scerr.Errorf(fmt.Sprintf("error changing vmname: %#v", err), err)
	}

	//----Initialize----
	if keyPair == nil {
		var err error
		keyPair, err = s.CreateKeyPair(fmt.Sprintf("key_%s", resourceName))
		if err != nil {
			return nil, userData, scerr.Errorf(fmt.Sprintf("KeyPair creation failed : %s", err.Error()), err)
		}
		request.KeyPair = keyPair
	}
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return nil, userData, scerr.Errorf(fmt.Sprintf("failed to generate password: %s", err.Error()), err)
		}
		request.Password = password
	}

	defaultNetwork := request.Networks[0]

	// Constructs userdata content
	err = userData.Prepare(*s.Config, request, defaultNetwork.CIDR, "")
	if err != nil {
		msg := fmt.Sprintf("failed to prepare user data content: %+v", err)
		logrus.Debugf(utils.Capitalize(msg))
		return nil, userData, scerr.Errorf(fmt.Sprintf(msg), err)
	}

	phase1Content, err := userData.Generate("phase1")
	if err != nil {
		return nil, userData, err
	}

	// FIXME Remove this
	userdataFileName := "/tmp/userdata.sh"
	err = ioutil.WriteFile(userdataFileName, phase1Content, 0644)
	if err != nil {
		return nil, userData, scerr.Errorf(fmt.Sprintf("Failed to write userData locally : %s", err.Error()), err)
	}

	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			task, err := vapp.RunCustomizationScript(request.ResourceName, string(phase1Content))
			if err != nil {
				return err
			}
			return task.WaitTaskCompletion()
		},
		10*time.Minute,
	)
	if err != nil {
		return nil, userData, scerr.Errorf(fmt.Sprintf("error running customization script: %#v", err), err)
	}

	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			task, err := vapp.PowerOn()
			if err != nil {
				return err
			}
			return task.WaitTaskCompletion()
		},
		10*time.Minute,
	)
	if err != nil {
		return nil, userData, scerr.Errorf(fmt.Sprintf("error powering on machine: %#v", err), err)
	}

	capturedIP := ""

	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			vm, err := vdc.FindVMByName(vapp, vapp.VApp.Name)
			if err != nil {
				return err
			}
			err = vm.Refresh()
			if err != nil {
				return err
			}

			cose, err := vm.GetNetworkConnectionSection()
			if err != nil {
				return err
			}

			PublicIPv4 := cose.NetworkConnection[0].IPAddress
			if PublicIPv4 == "" {
				return scerr.Errorf(fmt.Sprintf("No IP detected"), nil)
			} else {
				logrus.Warningf("IP Detected: [%s]", PublicIPv4)
				capturedIP = PublicIPv4
			}

			return nil
		},
		3*time.Minute,
	)
	if err != nil {
		return nil, userData, scerr.Errorf(fmt.Sprintf("error getting machine ip: %#v", err), err)
	}

	// FIXME Populate this
	host = resources.NewHost()
	host.ID = vapp.VApp.ID
	host.Name = vapp.VApp.Name
	host.PrivateKey = keyPair.PrivateKey
	host.Password = request.Password

	publicIPs, err := s.getPublicIPs()
	if err != nil {
		return nil, userData, err
	}

	selectedIP := publicIPs.IPRange[0].StartAddress

	hostIsAGateway := false

	err = host.Properties.LockForWrite(hostproperty.NetworkV1).ThenUse(func(clonable data.Clonable) error {
		hostNetworkV1 := clonable.(*propsv1.HostNetwork)
		hostNetworkV1.DefaultNetworkID = defaultNetwork.ID

		hostNetworkV1.IsGateway = request.DefaultGateway == nil && request.Networks[0].Name != resources.SingleHostNetworkName
		if request.DefaultGateway != nil {
			hostNetworkV1.DefaultGatewayID = request.DefaultGateway.ID

			gateway, err := s.InspectHost(request.DefaultGateway)
			if err != nil {
				return scerr.Errorf(fmt.Sprintf("Failed to get gateway host : %s", err.Error()), err)
			}

			hostNetworkV1.DefaultGatewayPrivateIP = gateway.GetPrivateIP()
		}

		hostIsAGateway = hostNetworkV1.IsGateway

		if hostNetworkV1.IsGateway {
			hostNetworkV1.PublicIPv4 = selectedIP
		} else {
			hostNetworkV1.PublicIPv4 = capturedIP
		}
		return nil
	})
	if err != nil {
		return nil, userData, err
	}

	dsize, _ := vapptemplate.GetTemplateDiskSize()
	memory, _ := vapptemplate.GetMemorySize()

	// FIXME Extract true info
	err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(func(clonable data.Clonable) error {
		hostSizingV1 := clonable.(*propsv1.HostSizing)

		hostSizingV1.RequestedSize.RAMSize = float32(memory / 1024)
		hostSizingV1.RequestedSize.Cores = 1
		hostSizingV1.RequestedSize.DiskSize = dsize / 1024 / 1024 / 1024
		hostSizingV1.RequestedSize.GPUNumber = 1

		return nil
	})
	if err != nil {
		return nil, userData, scerr.Errorf(fmt.Sprintf("Failed to update HostProperty.SizingV1 : %s", err.Error()), err)
	}

	// FIXME Edge gateway smart tunnel only if public or gateway
	if hostMustHavePublicIP || hostIsAGateway {
		gateways, err := s.findEdgeGatewayNames()
		if err != nil || utils.IsEmpty(gateways) {
			if err != nil {
				return nil, userData, scerr.Errorf(fmt.Sprintf("Unable to find edge gateways : %s", err.Error()), err)
			}
			return nil, userData, scerr.Errorf(fmt.Sprintf("Unable to find edge gateways"), err)
		}

		edgeGateway, err := vdc.FindEdgeGateway(gateways[0])
		if err != nil {
			return nil, userData, err
		}
		egt, err := edgeGateway.Create1to1Mapping(capturedIP, selectedIP, fmt.Sprintf("SmartTunnel-%s", host.Name))
		if err != nil {
			return nil, userData, err
		}
		err = egt.WaitTaskCompletion()
		if err != nil {
			return nil, userData, err
		}
	}

	// FIXME Remove this
	// logrus.Warningf(spew.Sdump(host.Properties))

	return host, userData, nil
}

// GetHost returns the host identified by ref (name or id) or by a *resources.Host containing an id
func (s *StackEbrc) InspectHost(hostParam interface{}) (*resources.Host, error) {
	logrus.Debug("ebrc.Client.InspectHost() called")
	defer logrus.Debug("ebrc.Client.InspectHost() done")

	if s == nil {
		panic("Calling s.InspectHost with s==nil!")
	}

	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting host by name"))
	}

	var host *resources.Host
	switch hostParam.(type) {
	case string:
		host := resources.NewHost()
		host.ID = hostParam.(string)
	case *resources.Host:
		host = hostParam.(*resources.Host)
	default:
		return nil, fmt.Errorf("erbc.Stack::InspectHost(): parameter 'hostParam' must be a string or a *resources.Host!")
	}

	if host == nil {
		return nil, fmt.Errorf("host cannot be nil")
	}

	byName := true
	hostRef := host.Name
	if hostRef == "" {
		byName = false
		hostRef = host.ID
	}

	var vapp govcd.VApp

	if byName {
		vapp, err = vdc.FindVAppByName(hostRef)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("Error getting host by name"))
		}
	} else {
		vapp, err = vdc.FindVAppByID(hostRef)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("Error getting host by id"))
		}
	}

	err = vapp.Refresh()
	if err != nil {
		return nil, resources.ResourceNotFoundError("host", host.Name)
	}

	// FIXME Populate this
	newHost := &resources.Host{
		ID:         vapp.VApp.ID,
		Name:       vapp.VApp.Name,
		LastState:  stateConvert(vapp.VApp.Status),
		Properties: nil,
	}

	if err := s.complementHost(host, newHost); err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("Failed to complement the host : %s", err.Error()), err)
	}

	return host, nil
}

func (s *StackEbrc) complementHost(host *resources.Host, newHost *resources.Host) error {
	if host == nil || newHost == nil {
		return scerr.Errorf(fmt.Sprintf("host and newHost have to been set"), nil)
	}

	if s == nil {
		panic("Calling s.complementHost with s==nil!")
	}

	host.ID = newHost.ID
	if host.Name == "" {
		host.Name = newHost.Name
	}
	host.LastState = newHost.LastState

	err := host.Properties.LockForWrite(hostproperty.NetworkV1).ThenUse(func(clonable data.Clonable) error {
		newHostNetworkV1 := propsv1.NewHostNetwork()
		hostNetworkV1 := clonable.(*propsv1.HostNetwork)
		hostNetworkV1.IPv4Addresses = newHostNetworkV1.IPv4Addresses
		hostNetworkV1.IPv6Addresses = newHostNetworkV1.IPv6Addresses
		hostNetworkV1.NetworksByID = newHostNetworkV1.NetworksByID
		hostNetworkV1.NetworksByName = newHostNetworkV1.NetworksByName
		return nil
	})
	if err != nil {
		return scerr.Errorf(fmt.Sprintf("Failed to update HostProperty.NetworkV1 : %s", err.Error()), err)
	}

	err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(func(clonable data.Clonable) error {
		newHostSizingV1 := propsv1.NewHostSizing()
		hostSizingV1 := clonable.(*propsv1.HostSizing)
		hostSizingV1.AllocatedSize.Cores = newHostSizingV1.AllocatedSize.Cores
		hostSizingV1.AllocatedSize.RAMSize = newHostSizingV1.AllocatedSize.RAMSize
		hostSizingV1.AllocatedSize.DiskSize = newHostSizingV1.AllocatedSize.DiskSize
		return nil
	})
	if err != nil {
		return scerr.Errorf(fmt.Sprintf("Failed to update HostProperty.SizingV1 : %s", err.Error()), err)
	}

	return nil
}

//stateConvert convert vcd state to a HostState.Enum
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

// GetHostByName returns the host identified by ref (name or id)
func (s *StackEbrc) GetHostByName(name string) (*resources.Host, error) {
	logrus.Debug("ebrc.Client.GetHostByName() called")
	defer logrus.Debug("ebrc.Client.GetHostByName() done")

	if s == nil {
		panic("Calling s.GetHostByName with s==nil!")
	}

	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting host by name"))
	}

	vapp, err := vdc.FindVAppByName(name)
	if err != nil {
		return nil, resources.ResourceNotFoundError("host", name)
	}

	err = vapp.Refresh()
	if err != nil {
		return nil, resources.ResourceNotFoundError("host", name)
	}

	// FIXME Populate this
	hr := &resources.Host{
		ID:         vapp.VApp.ID,
		Name:       vapp.VApp.Name,
		LastState:  stateConvert(vapp.VApp.Status),
		PrivateKey: "", // FIXME Recover pk and pass
		Password:   "",
		Properties: nil,
	}

	return hr, nil
}

// DeleteHost deletes the host identified by id
func (s *StackEbrc) DeleteHost(id string) error {
	logrus.Debug("ebrc.Client.DeleteHost() called")
	defer logrus.Debug("ebrc.Client.DeleteHost() done")

	if s == nil {
		panic("Calling s.DeleteHost with s==nil!")
	}

	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error deleting host"))
	}

	vapp, err := vdc.FindVAppByID(id)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error deleting host"))
	}

	undepTask, err := vapp.Undeploy()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error deleting host"))
	}

	err = undepTask.WaitTaskCompletion()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error deleting host"))
	}

	dtask, err := vapp.Delete()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error deleting host"))
	}

	// FIXME Delete firewall and NAT rules

	err = dtask.WaitTaskCompletion()

	return err
}

// ResizeHost change the template used by an host
func (s *StackEbrc) ResizeHost(id string, request resources.SizingRequirements) (*resources.Host, error) {
	return nil, scerr.Errorf(fmt.Sprintf("Not implemented yet"), nil)
}

// ListHosts lists available hosts
func (s *StackEbrc) ListHosts() ([]*resources.Host, error) {
	logrus.Debug("ebrc.Client.ListHosts() called")
	defer logrus.Debug("ebrc.Client.ListHosts() done")

	if s == nil {
		panic("Calling s.ListHosts with s==nil!")
	}

	org, err := govcd.GetOrgByName(s.EbrcService, s.AuthOptions.ProjectName)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error listing hosts"))
	}

	refs, err := getLinks(org, "vnd.vmware.vcloud.vApp")
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error listing hosts"))
	}

	var nets []*resources.Host
	for _, ref := range refs {
		nets = append(nets, &resources.Host{Name: ref.Name})
	}

	return nets, nil
}

// StopHost stops the host identified by id
func (s *StackEbrc) StopHost(id string) error {
	logrus.Debug("ebrc.Client.StopHost() called")
	defer logrus.Debug("ebrc.Client.StopHost() done")

	if s == nil {
		panic("Calling s.StopHost with s==nil!")
	}

	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error stopping host"))
	}

	vapp, err := vdc.FindVAppByID(id)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error stopping host"))
	}

	dtask, err := vapp.Shutdown()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error stopping host"))
	}

	err = dtask.WaitTaskCompletion()

	return err
}

// StartHost starts the host identified by id
func (s *StackEbrc) StartHost(id string) error {
	logrus.Debug("ebrc.Client.StartHost() called")
	defer logrus.Debug("ebrc.Client.StartHost() done")

	if s == nil {
		panic("Calling s.StartHost with s==nil!")
	}

	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error starting host"))
	}

	vapp, err := vdc.FindVAppByID(id)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error starting host"))
	}

	dtask, err := vapp.PowerOn()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error starting host"))
	}

	err = dtask.WaitTaskCompletion()

	return err
}

// RebootHost reboot the host identified by id
func (s *StackEbrc) RebootHost(id string) error {
	logrus.Debug("ebrc.Client.RebootHost() called")
	defer logrus.Debug("ebrc.Client.RebootHost() done")

	if s == nil {
		panic("Calling s.RebootHost with s==nil!")
	}

	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error rebooting host"))
	}

	vapp, err := vdc.FindVAppByID(id)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error rebooting host"))
	}

	dtask, err := vapp.Reboot()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error rebooting host"))
	}

	err = dtask.WaitTaskCompletion()

	return err
}

// GetHostState returns the host identified by id
func (s *StackEbrc) GetHostState(hostParam interface{}) (hoststate.Enum, error) {
	logrus.Debug("ebrc.Client.RebootHost() called")
	defer logrus.Debug("ebrc.Client.RebootHost() done")

	if s == nil {
		panic("Calling s.GetHostState with s==nil!")
	}

	host, err := s.InspectHost(hostParam)
	if err != nil {
		return hoststate.ERROR, err
	}
	return host.LastState, nil
}

//-------------Provider Infos-------------------------------------------------------------------------------------------

// ListAvailabilityZones lists the usable AvailabilityZones
func (s *StackEbrc) ListAvailabilityZones() (map[string]bool, error) {
	return map[string]bool{"local": true}, nil
}

func (s *StackEbrc) ListRegions() ([]string, error) {
	panic("implement me")
}

func (s *StackEbrc) CreateVIP(s1 string, s2 string) (*resources.VirtualIP, error) {
	panic("implement me")
}

func (s *StackEbrc) AddPublicIPToVIP(ip *resources.VirtualIP) error {
	panic("implement me")
}

func (s *StackEbrc) BindHostToVIP(ip *resources.VirtualIP, s2 string) error {
	panic("implement me")
}

func (s *StackEbrc) UnbindHostFromVIP(ip *resources.VirtualIP, s2 string) error {
	panic("implement me")
}

func (s *StackEbrc) DeleteVIP(ip *resources.VirtualIP) error {
	panic("implement me")
}

func (s *StackEbrc) GetCapabilities() providers.Capabilities {
	panic("implement me")
}

func (s *StackEbrc) GetTenantParameters() map[string]interface{} {
	panic("implement me")
}
