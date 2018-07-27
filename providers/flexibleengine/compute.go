/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package flexibleengine

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/pengux/check"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/api/HostState"
	"github.com/CS-SI/SafeScale/providers/api/IPVersion"
	metadata "github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/system"
	"github.com/CS-SI/SafeScale/utils/retry"
	"github.com/CS-SI/SafeScale/utils/retry/Verdict"

	uuid "github.com/satori/go.uuid"

	"github.com/gophercloud/gophercloud"
	nics "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/attachinterfaces"
	exbfv "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/bootfromvolume"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/pagination"
)

type gpuCfg struct {
	GPUNumber int
	GPUType   string
}

var gpuMap = map[string]gpuCfg{
	"g1.xlarge": gpuCfg{
		GPUNumber: 1,
		GPUType:   "UNKNOW",
	},
	"g1.2xlarge": gpuCfg{
		GPUNumber: 1,
		GPUType:   "UNKNOW",
	},
	"g1.2xlarge.8": gpuCfg{
		GPUNumber: 1,
		GPUType:   "NVIDIA 1080 TI",
	},
}

type blockDevice struct {
	// SourceType must be one of: "volume", "snapshot", "image", or "blank".
	SourceType exbfv.SourceType `json:"source_type" required:"true"`

	// UUID is the unique identifier for the existing volume, snapshot, or
	// image (see above).
	UUID string `json:"uuid,omitempty"`

	// BootIndex is the boot index. It defaults to 0.
	BootIndex string `json:"boot_index,omitempty"`

	// DeleteOnTermination specifies whether or not to delete the attached volume
	// when the server is deleted. Defaults to `false`.
	DeleteOnTermination bool `json:"delete_on_termination"`

	// DestinationType is the type that gets created. Possible values are "volume"
	// and "local".
	DestinationType exbfv.DestinationType `json:"destination_type,omitempty"`

	// GuestFormat specifies the format of the block device.
	GuestFormat string `json:"guest_format,omitempty"`

	// VolumeSize is the size of the volume to create (in gigabytes). This can be
	// omitted for existing volumes.
	VolumeSize int `json:"volume_size,omitempty"`

	// Type of volume
	VolumeType string `json:"volume_type,omitempty"`
}

// CreateOptsExt is a structure that extends the server `CreateOpts` structure
// by allowing for a block device mapping.
type bootdiskCreateOptsExt struct {
	servers.CreateOptsBuilder
	BlockDevice []blockDevice `json:"block_device_mapping_v2,omitempty"`
}

// ToServerCreateMap adds the block device mapping option to the base server
// creation options.
func (opts bootdiskCreateOptsExt) ToServerCreateMap() (map[string]interface{}, error) {
	base, err := opts.CreateOptsBuilder.ToServerCreateMap()
	if err != nil {
		return nil, err
	}

	if len(opts.BlockDevice) == 0 {
		err := gophercloud.ErrMissingInput{}
		err.Argument = "bootfromvolume.CreateOptsExt.BlockDevice"
		return nil, err
	}

	serverMap := base["server"].(map[string]interface{})

	blkDevices := make([]map[string]interface{}, len(opts.BlockDevice))

	for i, bd := range opts.BlockDevice {
		b, err := gophercloud.BuildRequestBody(bd, "")
		if err != nil {
			return nil, err
		}
		blkDevices[i] = b
	}
	serverMap["block_device_mapping_v2"] = blkDevices

	return base, nil
}

type serverCreateOpts struct {
	// Name is the name to assign to the newly launched server.
	Name string `json:"name" required:"true"`

	// ImageRef [optional; required if ImageName is not provided] is the ID or
	// full URL to the image that contains the server's OS and initial state.
	// Also optional if using the boot-from-volume extension.
	ImageRef string `json:"imageRef,omitempty"`

	// ImageName [optional; required if ImageRef is not provided] is the name of
	// the image that contains the server's OS and initial state.
	// Also optional if using the boot-from-volume extension.
	ImageName string `json:"-,omitempty"`

	// FlavorRef [optional; required if FlavorName is not provided] is the ID or
	// full URL to the flavor that describes the server's specs.
	FlavorRef string `json:"flavorRef"`

	// FlavorName [optional; required if FlavorRef is not provided] is the name of
	// the flavor that describes the server's specs.
	FlavorName string `json:"-"`

	// SecurityGroups lists the names of the security groups to which this server
	// should belong.
	SecurityGroups []string `json:"-"`

	// UserData contains configuration information or scripts to use upon launch.
	// Create will base64-encode it for you, if it isn't already.
	UserData []byte `json:"-"`

	// AvailabilityZone in which to launch the server.
	AvailabilityZone string `json:"availability_zone,omitempty"`

	// Networks dictates how this server will be attached to available networks.
	// By default, the server will be attached to all isolated networks for the
	// tenant.
	Networks []servers.Network `json:"-"`

	// Metadata contains key-value pairs (up to 255 bytes each) to attach to the
	// server.
	Metadata map[string]string `json:"metadata,omitempty"`

	// Personality includes files to inject into the server at launch.
	// Create will base64-encode file contents for you.
	Personality servers.Personality `json:"personality,omitempty"`

	// ConfigDrive enables metadata injection through a configuration drive.
	ConfigDrive *bool `json:"config_drive,omitempty"`

	// AdminPass sets the root user password. If not set, a randomly-generated
	// password will be created and returned in the response.
	AdminPass string `json:"adminPass,omitempty"`

	// AccessIPv4 specifies an IPv4 address for the instance.
	AccessIPv4 string `json:"accessIPv4,omitempty"`

	// AccessIPv6 pecifies an IPv6 address for the instance.
	AccessIPv6 string `json:"accessIPv6,omitempty"`

	// ServiceClient will allow calls to be made to retrieve an image or
	// flavor ID by name.
	ServiceClient *gophercloud.ServiceClient `json:"-"`
}

// ToServerCreateMap assembles a request body based on the contents of a
// CreateOpts.
func (opts serverCreateOpts) ToServerCreateMap() (map[string]interface{}, error) {
	sc := opts.ServiceClient
	opts.ServiceClient = nil
	b, err := gophercloud.BuildRequestBody(opts, "")
	if err != nil {
		return nil, err
	}

	if opts.UserData != nil {
		var userData string
		if _, err := base64.StdEncoding.DecodeString(string(opts.UserData)); err != nil {
			userData = base64.StdEncoding.EncodeToString(opts.UserData)
		} else {
			userData = string(opts.UserData)
		}
		b["user_data"] = &userData
	}

	if len(opts.SecurityGroups) > 0 {
		securityGroups := make([]map[string]interface{}, len(opts.SecurityGroups))
		for i, groupName := range opts.SecurityGroups {
			securityGroups[i] = map[string]interface{}{"name": groupName}
		}
		b["security_groups"] = securityGroups
	}

	if len(opts.Networks) > 0 {
		networks := make([]map[string]interface{}, len(opts.Networks))
		for i, net := range opts.Networks {
			networks[i] = make(map[string]interface{})
			if net.UUID != "" {
				networks[i]["uuid"] = net.UUID
			}
			if net.Port != "" {
				networks[i]["port"] = net.Port
			}
			if net.FixedIP != "" {
				networks[i]["fixed_ip"] = net.FixedIP
			}
		}
		b["networks"] = networks
	}

	// If FlavorRef isn't provided, use FlavorName to ascertain the flavor ID.
	if opts.FlavorRef == "" {
		if opts.FlavorName == "" {
			err := servers.ErrNeitherFlavorIDNorFlavorNameProvided{}
			err.Argument = "FlavorRef/FlavorName"
			return nil, err
		}
		if sc == nil {
			err := servers.ErrNoClientProvidedForIDByName{}
			err.Argument = "ServiceClient"
			return nil, err
		}
		flavorID, err := flavors.IDFromName(sc, opts.FlavorName)
		if err != nil {
			return nil, err
		}
		b["flavorRef"] = flavorID
	}

	return map[string]interface{}{"server": b}, nil
}

// CreateVM creates a new VM
func (client *Client) CreateVM(request api.VMRequest) (*api.VM, error) {
	return client.createVM(request, false)
}

// createVM creates a new VM and configure it as gateway for the network if isGateway is true
func (client *Client) createVM(request api.VMRequest, isGateway bool) (*api.VM, error) {
	if isGateway && !request.PublicIP {
		return nil, fmt.Errorf("can't create a gateway without public IP")
	}

	// Validating name of the VM
	if ok, err := validateVMName(request); !ok {
		return nil, fmt.Errorf("name '%s' is invalid for a FlexibleEngine VM: %s", request.Name, providerError(err))
	}

	//Eventual network gateway
	var gw *api.VM
	// If the VM is not public it has to be created on a network owning a Gateway
	if !request.PublicIP {
		m, err := metadata.LoadGateway(providers.FromClient(client), request.NetworkIDs[0])
		if err != nil {
			return nil, err
		}
		if m != nil {
			gw = m.Get()
		}
	}

	var nets []servers.Network
	//Add private networks
	for _, n := range request.NetworkIDs {
		nets = append(nets, servers.Network{
			UUID: n,
		})
	}

	//Prepare key pair
	kp := request.KeyPair
	var err error
	//If no key pair is supplied create one
	if kp == nil {
		id, _ := uuid.NewV4()
		name := fmt.Sprintf("%s_%s", request.Name, id)
		kp, err = client.CreateKeyPair(name)
		if err != nil {
			return nil, fmt.Errorf("Error creating key pair for VM '%s': %s", request.Name, providerError(err))
		}
	}

	userData, err := client.osclt.PrepareUserData(request, isGateway, kp, gw)

	// Determine system disk size based on vcpus count
	template, err := client.GetTemplate(request.TemplateID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get image: %s", providerError(err))
	}

	var diskSize int
	if template.VMSize.DiskSize > 0 {
		diskSize = template.VMSize.DiskSize
	} else if template.VMSize.Cores < 16 {
		diskSize = 100
	} else if template.VMSize.Cores < 32 {
		diskSize = 200
	} else {
		diskSize = 400
	}

	// Defines boot disk
	bootdiskOpts := blockDevice{
		SourceType:          exbfv.SourceImage,
		DestinationType:     exbfv.DestinationVolume,
		BootIndex:           "0",
		DeleteOnTermination: true,
		UUID:                request.ImageID,
		VolumeType:          "SSD",
		VolumeSize:          diskSize,
	}
	// Defines server
	srvOpts := serverCreateOpts{
		Name:           request.Name,
		SecurityGroups: []string{client.SecurityGroup.Name},
		Networks:       nets,
		FlavorRef:      request.TemplateID,
		UserData:       userData,
	}
	// Defines VM "Extension bootfromvolume" options
	bdOpts := bootdiskCreateOptsExt{
		CreateOptsBuilder: srvOpts,
		BlockDevice:       []blockDevice{bootdiskOpts},
	}
	b, err := bdOpts.ToServerCreateMap()
	if err != nil {
		return nil, fmt.Errorf("Failed to build query to create VM '%s': %s", request.Name, providerError(err))
	}
	r := servers.CreateResult{}
	var httpResp *http.Response
	httpResp, r.Err = client.osclt.Compute.Post(client.osclt.Compute.ServiceURL("servers"), b, &r.Body, &gophercloud.RequestOpts{
		OkCodes: []int{200, 202},
	})
	server, err := r.Extract()
	if err != nil {
		if server != nil {
			servers.Delete(client.osclt.Compute, server.ID)
		}
		return nil, fmt.Errorf("Query to create VM '%s' failed: %s (HTTP return code: %d)", request.Name, providerError(err), httpResp.StatusCode)
	}

	// Wait that VM is started
	vm, err := client.waitVMReady(server.ID, time.Minute*5)
	if err != nil {
		client.DeleteVM(server.ID)
		return nil, fmt.Errorf("Timeout waiting VM '%s' ready: %s", request.Name, providerError(err))
	}

	// Fixes the size of bootdisk, FlexibleEngine is used to not give one...
	vm.Size.DiskSize = diskSize
	vm.PrivateKey = kp.PrivateKey
	//Add gateway ID to VM definition
	var gwID string
	if gw != nil {
		gwID = gw.ID
	}
	vm.GatewayID = gwID

	if request.PublicIP {
		fip, err := client.attachFloatingIP(vm)
		if err != nil {
			client.DeleteVM(vm.ID)
			return nil, fmt.Errorf("Error attaching public IP for VM '%s': %s", request.Name, providerError(err))
		}
		if isGateway {
			err = client.enableVMRouterMode(vm)
			if err != nil {
				client.DeleteVM(vm.ID)
				client.DeleteFloatingIP(fip.ID)
				return nil, fmt.Errorf("Error enabling gateway mode of VM '%s': %s", request.Name, providerError(err))
			}
		}
	}

	if isGateway {
		err = metadata.SaveGateway(providers.FromClient(client), vm, request.NetworkIDs[0])
	} else {
		err = metadata.SaveHost(providers.FromClient(client), vm, request.NetworkIDs[0])
	}
	if err != nil {
		client.DeleteVM(vm.ID)
		return nil, fmt.Errorf("failed to create VM: %s", providerError(err))
	}

	return vm, nil
}

// validateVMName validates the name of a VM based on known FlexibleEngine requirements
func validateVMName(req api.VMRequest) (bool, error) {
	s := check.Struct{
		"Name": check.Composite{
			check.NonEmpty{},
			check.Regex{Constraint: `^[a-zA-Z0-9_-]+$`},
			check.MaxChar{Constraint: 64},
		},
	}

	e := s.Validate(req)
	if e.HasErrors() {
		errors, _ := e.GetErrorsByKey("Name")
		var errs []string
		for _, msg := range errors {
			errs = append(errs, msg.Error())
		}
		return false, fmt.Errorf(strings.Join(errs, " + "))
	}
	return true, nil
}

// WaitVMReady waits a vm achieve ready state
func (client *Client) waitVMReady(vmID string, timeout time.Duration) (*api.VM, error) {
	var server *servers.Server
	var err error

	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			server, err = servers.Get(client.osclt.Compute, vmID).Extract()
			if err != nil {
				return err
			}
			if server.Status != "ACTIVE" {
				return fmt.Errorf("host in '%s' state", server.Status)
			}
			return nil
		},
		timeout,
	)
	if retryErr != nil {
		return nil, retryErr
	}
	return client.toVM(server), nil
}

// GetVM returns the VM identified by id
func (client *Client) GetVM(id string) (*api.VM, error) {
	server, err := servers.Get(client.osclt.Compute, id).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting VM: %s", providerError(err))
	}
	vm := client.toVM(server)
	return vm, nil
}

// ListVMs lists available VMs
func (client *Client) ListVMs(all bool) ([]api.VM, error) {
	if all {
		return client.listAllVMs()
	}
	return client.listMonitoredVMs()
}

// listAllVMs lists available VMs
func (client *Client) listAllVMs() ([]api.VM, error) {
	pager := servers.List(client.osclt.Compute, servers.ListOpts{})
	var vms []api.VM
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := servers.ExtractServers(page)
		if err != nil {
			return false, err
		}
		for _, srv := range list {
			vms = append(vms, *client.toVM(&srv))
		}
		return true, nil
	})
	if len(vms) == 0 && err != nil {
		return nil, fmt.Errorf("Error listing vms : %s", providerError(err))
	}
	return vms, nil
}

// listMonitoredVMs lists available VMs created by SafeScale (ie registered in object storage)
// This code seems to be the same than openstack provider, but it HAS TO BE DUPLICARED
// because client.ListObjects() is different (Swift for openstack, S3 for flexibleengine).
func (client *Client) listMonitoredVMs() ([]api.VM, error) {
	var vms []api.VM
	m, err := metadata.NewHost(providers.FromClient(client))
	if err != nil {
		return vms, err
	}
	err = m.Browse(func(vm *api.VM) error {
		vms = append(vms, *vm)
		return nil
	})
	if len(vms) == 0 && err != nil {
		return nil, fmt.Errorf("Error listing vms : %s", providerError(err))
	}
	return vms, nil
}

// DeleteVM deletes the VM identified by id
func (client *Client) DeleteVM(id string) error {
	// Retrieve the list of attached volumes before deleting the VM
	volumeAttachments, err := client.ListVolumeAttachments(id)
	if err != nil {
		return err
	}
	vm, err := client.GetVM(id)
	if err != nil {
		return err
	}
	if client.Cfg.UseFloatingIP {
		fip, err := client.getFloatingIPOfVM(id)
		if err == nil {
			if fip != nil {
				err = floatingips.DisassociateInstance(client.osclt.Compute, id, floatingips.DisassociateOpts{
					FloatingIP: fip.IP,
				}).ExtractErr()
				if err != nil {
					return fmt.Errorf("Error deleting VM %s : %s", id, providerError(err))
				}
				err = floatingips.Delete(client.osclt.Compute, fip.ID).ExtractErr()
				if err != nil {
					return fmt.Errorf("Error deleting VM %s : %s", id, providerError(err))
				}
			}
		}
	}
	err = servers.Delete(client.osclt.Compute, id).ExtractErr()
	if err != nil {
		return fmt.Errorf("error deleting VM %s : %s", vm.Name, providerError(err))
	}

	// In FlexibleEngine, volumes may not be always automatically removed, so take care of them
	for _, va := range volumeAttachments {
		volume, err := client.GetVolume(va.VolumeID)
		if err != nil {
			continue
		}
		client.DeleteVolume(volume.ID)
	}

	metadata.RemoveHost(providers.FromClient(client), vm)

	// FlexibleEngine may take time to remove VM, preventing for example DeleteNetwork to work if called to soon
	// So we wait VM is effectively removed before returning
	return client.waitVMRemoved(id, 120*time.Second)
}

// waitVMDeleted waits
func (client *Client) waitVMRemoved(vmID string, timeout time.Duration) error {
	return retry.WhileSuccessfulDelay1SecondWithNotify(
		func() error {
			_, err := servers.Get(client.osclt.Compute, vmID).Extract()
			return err
		},
		timeout,
		func(try retry.Try, verdict Verdict.Enum) {
			log.Printf("Client.waitVMRemoved(%s): try #%d: verdict=%s, err=%v", vmID, try.Count, verdict.String(), try.Err)
		},
	)
}

// GetSSHConfig creates SSHConfig to connect a VM by its ID
func (client *Client) GetSSHConfig(id string) (*system.SSHConfig, error) {
	vm, err := client.GetVM(id)
	if err != nil {
		return nil, err
	}
	return client.getSSHConfig(vm)
}

func (client *Client) getSSHConfig(vm *api.VM) (*system.SSHConfig, error) {
	ip := vm.GetAccessIP()
	sshConfig := system.SSHConfig{
		PrivateKey: vm.PrivateKey,
		Port:       22,
		Host:       ip,
		User:       api.DefaultUser,
	}
	if vm.GatewayID != "" {
		gw, err := client.GetVM(vm.GatewayID)
		if err != nil {
			return nil, err
		}
		ip := gw.GetAccessIP()
		GatewayConfig := system.SSHConfig{
			PrivateKey: gw.PrivateKey,
			Port:       22,
			User:       api.DefaultUser,
			Host:       ip,
		}
		sshConfig.GatewayConfig = &GatewayConfig
	}

	return &sshConfig, nil
}

// getFloatingIP returns the floating IP associated with the VM identified by vmID
// By convention only one floating IP is allocated to a VM
func (client *Client) getFloatingIPOfVM(vmID string) (*floatingips.FloatingIP, error) {
	pager := floatingips.List(client.osclt.Compute)
	var fips []floatingips.FloatingIP
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := floatingips.ExtractFloatingIPs(page)
		if err != nil {
			return false, err
		}

		for _, fip := range list {
			if fip.InstanceID == vmID {
				fips = append(fips, fip)
			}
		}
		return true, nil
	})
	if len(fips) == 0 {
		if err != nil {
			return nil, fmt.Errorf("No floating IP found for VM %s: %s", vmID, providerError(err))
		}
		return nil, fmt.Errorf("No floating IP found for VM %s", vmID)

	}
	if len(fips) > 1 {
		return nil, fmt.Errorf("Configuration error, more than one Floating IP associated to VM %s", vmID)
	}
	return &fips[0], nil
}

// attachFloatingIP creates a Floating IP and attaches it to a VM
func (client *Client) attachFloatingIP(vm *api.VM) (*FloatingIP, error) {
	fip, err := client.CreateFloatingIP()
	if err != nil {
		return nil, fmt.Errorf("Failed to attach Floating IP on VM '%s': %s", vm.Name, providerError(err))
	}

	err = client.AssociateFloatingIP(vm, fip.ID)
	if err != nil {
		client.DeleteFloatingIP(fip.ID)
		return nil, fmt.Errorf("Failed to attach Floating IP to VM '%s': %s", vm.Name, providerError(err))
	}

	updateAccessIPsOfVM(vm, fip.PublicIPAddress)

	return fip, nil
}

// updateAccessIPsOfVM updates the IP address(es) to use to access the VM
func updateAccessIPsOfVM(vm *api.VM, ip string) {
	if IPVersion.IPv4.Is(ip) {
		vm.AccessIPv4 = ip
	} else if IPVersion.IPv6.Is(ip) {
		vm.AccessIPv6 = ip
	}
}

// EnableVMRouterMode enables the VM to act as a router/gateway.
func (client *Client) enableVMRouterMode(vm *api.VM) error {
	portID, err := client.getOpenstackPortID(vm)
	if err != nil {
		return fmt.Errorf("Failed to enable Router Mode on VM '%s': %s", vm.Name, providerError(err))
	}

	pairs := []ports.AddressPair{
		{
			IPAddress: "1.1.1.1/0",
		},
	}
	opts := ports.UpdateOpts{AllowedAddressPairs: &pairs}
	_, err = ports.Update(client.osclt.Network, *portID, opts).Extract()
	if err != nil {
		return fmt.Errorf("Failed to enable Router Mode on VM '%s': %s", vm.Name, providerError(err))
	}
	return nil
}

// DisableVMRouterMode disables the VM to act as a router/gateway.
func (client *Client) disableVMRouterMode(vm *api.VM) error {
	portID, err := client.getOpenstackPortID(vm)
	if err != nil {
		return fmt.Errorf("Failed to disable Router Mode on VM '%s': %s", vm.Name, providerError(err))
	}

	opts := ports.UpdateOpts{AllowedAddressPairs: nil}
	_, err = ports.Update(client.osclt.Network, *portID, opts).Extract()
	if err != nil {
		return fmt.Errorf("Failed to disable Router Mode on VM '%s': %s", vm.Name, providerError(err))
	}
	return nil
}

// listInterfaces returns a pager of the interfaces attached to VM identified by 'serverID'
func (client *Client) listInterfaces(vmID string) pagination.Pager {
	url := client.osclt.Compute.ServiceURL("servers", vmID, "os-interface")
	return pagination.NewPager(client.osclt.Compute, url, func(r pagination.PageResult) pagination.Page {
		return nics.InterfacePage{SinglePageBase: pagination.SinglePageBase(r)}
	})
}

// getOpenstackPortID returns the port ID corresponding to the first private IP address of the VM
// returns nil,nil if not found
func (client *Client) getOpenstackPortID(vm *api.VM) (*string, error) {
	ip := vm.PrivateIPsV4[0]
	found := false
	nic := nics.Interface{}
	pager := client.listInterfaces(vm.ID)
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := nics.ExtractInterfaces(page)
		if err != nil {
			return false, err
		}
		for _, i := range list {
			for _, iip := range i.FixedIPs {
				if iip.IPAddress == ip {
					found = true
					nic = i
					return false, nil
				}
			}
		}
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error browsing Openstack Interfaces of VM '%s': %s", vm.Name, providerError(err))
	}
	if found {
		return &nic.PortID, nil
	}
	return nil, nil
}

// toVMSize converts flavor attributes returned by OpenStack driver into api.VM
func (client *Client) toVMSize(flavor map[string]interface{}) api.VMSize {
	if i, ok := flavor["id"]; ok {
		fid := i.(string)
		tpl, _ := client.GetTemplate(fid)
		return tpl.VMSize
	}
	if _, ok := flavor["vcpus"]; ok {
		return api.VMSize{
			Cores:    flavor["vcpus"].(int),
			DiskSize: flavor["disk"].(int),
			RAMSize:  flavor["ram"].(float32) / 1000.0,
		}
	}
	return api.VMSize{}
}

// toHostState converts VM status returned by FlexibleEngine driver into HostState enum
func toHostState(status string) HostState.Enum {
	switch status {
	case "BUILD", "build", "BUILDING", "building":
		return HostState.STARTING
	case "ACTIVE", "active":
		return HostState.STARTED
	case "RESCUED", "rescued":
		return HostState.STOPPING
	case "STOPPED", "stopped", "SHUTOFF", "shutoff":
		return HostState.STOPPED
	default:
		return HostState.ERROR
	}
}

// convertAdresses converts adresses returned by the FlexibleEngine driver and arranges them by version in a map
func (client *Client) convertAdresses(addresses map[string]interface{}) map[IPVersion.Enum][]string {
	addrs := make(map[IPVersion.Enum][]string)
	for _, obj := range addresses {
		for _, networkAddresses := range obj.([]interface{}) {
			address := networkAddresses.(map[string]interface{})
			version := address["version"].(float64)
			fixedIP := address["addr"].(string)
			switch version {
			case 4:
				addrs[IPVersion.IPv4] = append(addrs[IPVersion.IPv4], fixedIP)
			case 6:
				addrs[IPVersion.IPv6] = append(addrs[IPVersion.IPv4], fixedIP)
			}
		}
	}
	return addrs
}

// toVM converts a FlexibleEngine (almost OpenStack...) server into api VM
func (client *Client) toVM(server *servers.Server) *api.VM {
	//	adresses, ipv4, ipv6 := client.convertAdresses(server.Addresses)
	adresses := client.convertAdresses(server.Addresses)

	vm := api.VM{
		ID:           server.ID,
		Name:         server.Name,
		PrivateIPsV4: adresses[IPVersion.IPv4],
		PrivateIPsV6: adresses[IPVersion.IPv6],
		AccessIPv4:   server.AccessIPv4,
		AccessIPv6:   server.AccessIPv6,
		Size:         client.toVMSize(server.Flavor),
		State:        toHostState(server.Status),
	}
	m, err := metadata.LoadHost(providers.FromClient(client), server.ID)
	if err == nil && m != nil {
		vmDef := m.Get()
		vm.GatewayID = vmDef.GatewayID
		vm.PrivateKey = vmDef.PrivateKey
		//Floating IP management
		if vm.AccessIPv4 == "" {
			vm.AccessIPv4 = vmDef.AccessIPv4
		}
		if vm.AccessIPv6 == "" {
			vm.AccessIPv6 = vmDef.AccessIPv6
		}
	}
	return &vm
}

// CreateKeyPair creates and import a key pair
func (client *Client) CreateKeyPair(name string) (*api.KeyPair, error) {
	return client.osclt.CreateKeyPair(name)
}

// GetKeyPair returns the key pair identified by id
func (client *Client) GetKeyPair(id string) (*api.KeyPair, error) {
	return client.osclt.GetKeyPair(id)
}

// ListKeyPairs lists available key pairs
func (client *Client) ListKeyPairs() ([]api.KeyPair, error) {
	return client.osclt.ListKeyPairs()
}

// DeleteKeyPair deletes the key pair identified by id
func (client *Client) DeleteKeyPair(id string) error {
	return client.osclt.DeleteKeyPair(id)
}

// GetImage returns the Image referenced by id
func (client *Client) GetImage(id string) (*api.Image, error) {
	return client.osclt.GetImage(id)
}

// ListImages lists available OS images
func (client *Client) ListImages() ([]api.Image, error) {
	return client.osclt.ListImages()
}

func addGPUCfg(tpl *api.VMTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

// GetTemplate returns the Template referenced by id
func (client *Client) GetTemplate(id string) (*api.VMTemplate, error) {
	tpl, err := client.osclt.GetTemplate(id)
	if tpl != nil {
		addGPUCfg(tpl)
	}
	return tpl, err
}

// ListTemplates lists available VM templates
// VM templates are sorted using Dominant Resource Fairness Algorithm
func (client *Client) ListTemplates() ([]api.VMTemplate, error) {
	allTemplates, err := client.osclt.ListTemplates()
	if err != nil {
		return nil, err
	}
	var tpls []api.VMTemplate
	for _, tpl := range allTemplates {
		addGPUCfg(&tpl)
		tpls = append(tpls, tpl)
	}

	return tpls, nil
}

// StopVM stops the VM identified by id
func (client *Client) StopVM(id string) error {
	return client.osclt.StopVM(id)
}

// StartVM starts the VM identified by id
func (client *Client) StartVM(id string) error {
	return client.osclt.StartVM(id)
}
