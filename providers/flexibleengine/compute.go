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
	"github.com/CS-SI/SafeScale/providers/enums/HostState"
	"github.com/CS-SI/SafeScale/providers/enums/IPVersion"
	filters "github.com/CS-SI/SafeScale/providers/filters/images"
	metadata "github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/openstack"
	"github.com/CS-SI/SafeScale/providers/userdata"

	"github.com/CS-SI/SafeScale/system"

	"github.com/CS-SI/SafeScale/utils/retry"

	uuid "github.com/satori/go.uuid"

	gc "github.com/gophercloud/gophercloud"
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
		err := gc.ErrMissingInput{}
		err.Argument = "bootfromvolume.CreateOptsExt.BlockDevice"
		return nil, err
	}

	serverMap := base["server"].(map[string]interface{})

	blkDevices := make([]map[string]interface{}, len(opts.BlockDevice))

	for i, bd := range opts.BlockDevice {
		b, err := gc.BuildRequestBody(bd, "")
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
	ServiceClient *gc.ServiceClient `json:"-"`
}

// ToServerCreateMap assembles a request body based on the contents of a
// CreateOpts.
func (opts serverCreateOpts) ToServerCreateMap() (map[string]interface{}, error) {
	sc := opts.ServiceClient
	opts.ServiceClient = nil
	b, err := gc.BuildRequestBody(opts, "")
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

// CreateHost creates a new host
func (client *Client) CreateHost(request api.HostRequest) (*api.Host, error) {
	host, err := client.createHost(request, false)
	if err != nil {
		return nil, err
	}
	err = metadata.SaveHost(providers.FromClient(client), host, request.NetworkIDs[0])
	if err != nil {
		client.DeleteHost(host.ID)
		return nil, fmt.Errorf("failed to create Host: %s", openstack.ProviderErrorToString(err))
	}
	return host, nil
}

// CreateHost creates a new host and configure it as gateway for the network if isGateway is true
func (client *Client) createHost(request api.HostRequest, isGateway bool) (*api.Host, error) {
	if isGateway && !request.PublicIP {
		return nil, fmt.Errorf("can't create a gateway without public IP")
	}

	// Validating name of the host
	if ok, err := validatehostName(request); !ok {
		return nil, fmt.Errorf("name '%s' is invalid for a FlexibleEngine Host: %s", request.Name, openstack.ProviderErrorToString(err))
	}

	// Check name availability
	m, err := metadata.LoadHost(providers.FromClient(client), request.Name)
	if err != nil {
		return nil, err
	}
	if m != nil {
		return nil, providers.ResourceAlreadyExistsError("Host", request.Name)
	}

	// Network gateway
	var gw *api.Host
	// If the host is not public it has to be created on a network owning a Gateway
	if !request.PublicIP {
		m, err := metadata.LoadGateway(providers.FromClient(client), request.NetworkIDs[0])
		if err != nil {
			return nil, err
		}
		if m != nil {
			gw = m.Get()
		}
	}
	// If a gateway is created, we need the CIDR for the userdata
	var cidr string
	if isGateway {
		m, err := metadata.LoadNetwork(providers.FromClient(client), request.NetworkIDs[0])
		if err != nil {
			return nil, err
		}
		if m == nil {
			return nil, fmt.Errorf("failed to load metadata of network '%s'", request.NetworkIDs[0])
		}
		network := m.Get()
		cidr = network.CIDR
	}

	var nets []servers.Network
	// Add private networks
	for _, n := range request.NetworkIDs {
		nets = append(nets, servers.Network{
			UUID: n,
		})
	}

	// Prepare key pair
	kp := request.KeyPair
	// If no key pair is supplied create one
	if kp == nil {
		id, _ := uuid.NewV4()
		name := fmt.Sprintf("%s_%s", request.Name, id)
		kp, err = client.CreateKeyPair(name)
		if err != nil {
			return nil, fmt.Errorf("error creating key pair for host '%s': %s", request.Name, openstack.ProviderErrorToString(err))
		}
	}

	userData, err := userdata.Prepare(client, request, isGateway, kp, gw, cidr)
	if err != nil {
		return nil, err
	}

	// Determine system disk size based on vcpus count
	template, err := client.GetTemplate(request.TemplateID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get image: %s", openstack.ProviderErrorToString(err))
	}

	var diskSize int
	if template.HostSize.DiskSize > 0 {
		diskSize = template.HostSize.DiskSize
	} else if template.HostSize.Cores < 16 {
		diskSize = 100
	} else if template.HostSize.Cores < 32 {
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
	// Defines host "Extension bootfromvolume" options
	bdOpts := bootdiskCreateOptsExt{
		CreateOptsBuilder: srvOpts,
		BlockDevice:       []blockDevice{bootdiskOpts},
	}
	b, err := bdOpts.ToServerCreateMap()
	if err != nil {
		return nil, fmt.Errorf("failed to build query to create host '%s': %s", request.Name, openstack.ProviderErrorToString(err))
	}
	r := servers.CreateResult{}
	var httpResp *http.Response
	httpResp, r.Err = client.osclt.Compute.Post(client.osclt.Compute.ServiceURL("servers"), b, &r.Body, &gc.RequestOpts{
		OkCodes: []int{200, 202},
	})
	server, err := r.Extract()
	if err != nil {
		if server != nil {
			servers.Delete(client.osclt.Compute, server.ID)
		}
		return nil, fmt.Errorf("query to create host '%s' failed: %s (HTTP return code: %d)", request.Name, openstack.ProviderErrorToString(err), httpResp.StatusCode)
	}

	// Wait that host is ready, not just that the build is started
	host, err := client.WaitHostReady(server.ID, time.Minute*5)
	if err != nil {
		client.DeleteHost(server.ID)
		return nil, fmt.Errorf("timeout waiting host '%s' ready: %s", request.Name, openstack.ProviderErrorToString(err))
	}

	// Fixes the size of bootdisk, FlexibleEngine is used to not give one...
	host.Size.DiskSize = diskSize
	host.PrivateKey = kp.PrivateKey
	//Add gateway ID to host definition
	var gwID string
	if gw != nil {
		gwID = gw.ID
	}
	host.GatewayID = gwID

	if request.PublicIP {
		fip, err := client.attachFloatingIP(host)
		if err != nil {
			client.DeleteHost(host.ID)
			return nil, fmt.Errorf("error attaching public IP for host '%s': %s", request.Name, openstack.ProviderErrorToString(err))
		}
		if isGateway {
			err = client.enableHostRouterMode(host)
			if err != nil {
				client.DeleteHost(host.ID)
				client.DeleteFloatingIP(fip.ID)
				return nil, fmt.Errorf("error enabling gateway mode of host '%s': %s", request.Name, openstack.ProviderErrorToString(err))
			}
		}
	}

	return host, nil
}

// validatehostName validates the name of an host based on known FlexibleEngine requirements
func validatehostName(req api.HostRequest) (bool, error) {
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

// GetHost returns the host identified by ref (id or name)
func (client *Client) GetHost(ref string) (*api.Host, error) {
	// We first try looking for host from metadata
	m, err := metadata.LoadHost(providers.FromClient(client), ref)
	if err != nil {
		return nil, err
	}
	if m != nil {
		return m.Get(), nil
	}

	// If not found, we look for any host from provider
	// 1st try with id
	server, err := servers.Get(client.osclt.Compute, ref).Extract()
	if err != nil {
		if _, ok := err.(gc.ErrDefault404); !ok {
			return nil, fmt.Errorf("Error getting Host '%s': %s", ref, openstack.ProviderErrorToString(err))
		}
	}
	if server != nil && server.ID != "" {
		return client.toHost(server), nil
	}

	// Last chance, we look at all network
	hosts, err := client.listAllHosts()
	if err != nil {
		return nil, err
	}
	for _, host := range hosts {
		if host.ID == ref || host.Name == ref {
			return &host, err
		}
	}

	// At this point, no network has been found with given reference
	return nil, nil
}

// ListHosts lists available hosts
func (client *Client) ListHosts(all bool) ([]api.Host, error) {
	if all {
		return client.listAllHosts()
	}
	return client.listMonitoredHosts()
}

// listallhosts lists available hosts
func (client *Client) listAllHosts() ([]api.Host, error) {
	pager := servers.List(client.osclt.Compute, servers.ListOpts{})
	var hosts []api.Host
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := servers.ExtractServers(page)
		if err != nil {
			return false, err
		}
		for _, srv := range list {
			hosts = append(hosts, *client.toHost(&srv))
		}
		return true, nil
	})
	if len(hosts) == 0 && err != nil {
		return nil, fmt.Errorf("error listing hosts : %s", openstack.ProviderErrorToString(err))
	}
	return hosts, nil
}

// listMonitoredHosts lists available hosts created by SafeScale (ie registered in object storage)
// This code seems to be the same than openstack provider, but it HAS TO BE DUPLICATED
// because client.ListObjects() is different (Swift for openstack, S3 for flexibleengine).
func (client *Client) listMonitoredHosts() ([]api.Host, error) {
	var hosts []api.Host
	m := metadata.NewHost(providers.FromClient(client))
	err := m.Browse(func(host *api.Host) error {
		hosts = append(hosts, *host)
		return nil
	})
	if len(hosts) == 0 && err != nil {
		return nil, fmt.Errorf("Error listing hosts : %s", openstack.ProviderErrorToString(err))
	}
	return hosts, nil
}

// DeleteHost deletes the host identified by id
func (client *Client) DeleteHost(ref string) error {
	m, err := metadata.LoadHost(providers.FromClient(client), ref)
	if err != nil {
		return err
	}
	if m == nil {
		return providers.ResourceNotFoundError("host", ref)
	}

	host := m.Get()
	id := host.ID
	// Retrieve the list of attached volumes before deleting the host
	volumeAttachments, err := client.ListVolumeAttachments(id)
	if err != nil {
		return err
	}

	err = client.oscltDeleteHost(id)
	if err != nil {
		return err
	}
	err = metadata.RemoveHost(providers.FromClient(client), host)
	if err != nil {
		return err
	}

	// In FlexibleEngine, volumes may not be always automatically removed, so take care of them
	for _, va := range volumeAttachments {
		volume, err := client.GetVolume(va.VolumeID)
		if err != nil {
			continue
		}
		client.DeleteVolume(volume.ID)
	}

	return err
}

func (client *Client) oscltDeleteHost(id string) error {
	if client.osclt.Cfg.UseFloatingIP {
		fip, err := client.getFloatingIPOfHost(id)
		if err == nil {
			if fip != nil {
				err = floatingips.DisassociateInstance(client.osclt.Compute, id, floatingips.DisassociateOpts{
					FloatingIP: fip.IP,
				}).ExtractErr()
				if err != nil {
					return fmt.Errorf("error deleting host %s : %s", id, openstack.ProviderErrorToString(err))
				}
				err = floatingips.Delete(client.osclt.Compute, fip.ID).ExtractErr()
				if err != nil {
					return fmt.Errorf("error deleting host %s : %s", id, openstack.ProviderErrorToString(err))
				}
			}
		}
	}

	var err error
	// Try to remove host for 3 minutes
	outerRetryErr := retry.WhileUnsuccessful(
		func() error {
			resourcePresent := true
			// 1st, send delete host order
			err = servers.Delete(client.osclt.Compute, id).ExtractErr()
			if err != nil {
				switch err.(type) {
				case gc.ErrDefault404:
					// Resource not found, consider deletion succeeded (if the entry doesn't exist at all,
					// metadata deletion will return an error)
					return nil
				default:
					return fmt.Errorf("failed to submit host '%s' deletion: %s", id, openstack.ProviderErrorToString(err))
				}
			}
			// 2nd, check host status every 5 seconds until check failed.
			// If check succeeds but state is Error, retry the deletion.
			// If check fails and error isn't 'resource not found', retry
			innerRetryErr := retry.WhileUnsuccessfulDelay5Seconds(
				func() error {
					host, err := servers.Get(client.osclt.Compute, id).Extract()
					if err == nil {
						if toHostState(host.Status) == HostState.ERROR {
							return nil
						}
						return fmt.Errorf("host '%s' state is '%s'", host.Name, host.Status)
					}
					switch err.(type) {
					case gc.ErrDefault404:
						resourcePresent = false
						return nil
					}
					return err
				},
				1*time.Minute,
			)
			if innerRetryErr != nil {
				switch innerRetryErr.(type) {
				case retry.ErrTimeout:
					// retry deletion...
					return fmt.Errorf("failed to acknowledge host '%s' deletion! %s", id, err.Error())
				default:
					return innerRetryErr
				}
			}
			if !resourcePresent {
				return nil
			}
			return fmt.Errorf("host '%s' in state 'ERROR', retrying to delete", id)
		},
		0,
		3*time.Minute,
	)
	if outerRetryErr != nil {
		log.Printf("failed to remove host '%s': %s", id, err.Error())
		return err
	}
	return nil
}

// GetSSHConfig creates SSHConfig to connect an host by its ID
func (client *Client) GetSSHConfig(id string) (*system.SSHConfig, error) {
	host, err := client.GetHost(id)
	if err != nil {
		return nil, err
	}
	return client.getSSHConfig(host)
}

func (client *Client) getSSHConfig(host *api.Host) (*system.SSHConfig, error) {
	ip := host.GetAccessIP()
	sshConfig := system.SSHConfig{
		PrivateKey: host.PrivateKey,
		Port:       22,
		Host:       ip,
		User:       api.DefaultUser,
	}
	if host.GatewayID != "" {
		gw, err := client.GetHost(host.GatewayID)
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

// getFloatingIP returns the floating IP associated with the host identified by hostID
// By convention only one floating IP is allocated to an host
func (client *Client) getFloatingIPOfHost(hostID string) (*floatingips.FloatingIP, error) {
	pager := floatingips.List(client.osclt.Compute)
	var fips []floatingips.FloatingIP
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := floatingips.ExtractFloatingIPs(page)
		if err != nil {
			return false, err
		}

		for _, fip := range list {
			if fip.InstanceID == hostID {
				fips = append(fips, fip)
			}
		}
		return true, nil
	})
	if len(fips) == 0 {
		if err != nil {
			return nil, fmt.Errorf("no floating IP found for host '%s': %s", hostID, openstack.ProviderErrorToString(err))
		}
		return nil, fmt.Errorf("no floating IP found for host '%s'", hostID)

	}
	if len(fips) > 1 {
		return nil, fmt.Errorf("Configuration error, more than one Floating IP associated to host '%s'", hostID)
	}
	return &fips[0], nil
}

// attachFloatingIP creates a Floating IP and attaches it to an host
func (client *Client) attachFloatingIP(host *api.Host) (*FloatingIP, error) {
	fip, err := client.CreateFloatingIP()
	if err != nil {
		return nil, fmt.Errorf("failed to attach Floating IP on host '%s': %s", host.Name, openstack.ProviderErrorToString(err))
	}

	err = client.AssociateFloatingIP(host, fip.ID)
	if err != nil {
		client.DeleteFloatingIP(fip.ID)
		return nil, fmt.Errorf("failed to attach Floating IP to host '%s': %s", host.Name, openstack.ProviderErrorToString(err))
	}

	updateAccessIPsOfHost(host, fip.PublicIPAddress)

	return fip, nil
}

// updateAccessIPsOfHost updates the IP address(es) to use to access the host
func updateAccessIPsOfHost(host *api.Host, ip string) {
	if IPVersion.IPv4.Is(ip) {
		host.AccessIPv4 = ip
	} else if IPVersion.IPv6.Is(ip) {
		host.AccessIPv6 = ip
	}
}

// EnableHostRouterMode enables the host to act as a router/gateway.
func (client *Client) enableHostRouterMode(host *api.Host) error {
	portID, err := client.getOpenstackPortID(host)
	if err != nil {
		return fmt.Errorf("failed to enable Router Mode on host '%s': %s", host.Name, openstack.ProviderErrorToString(err))
	}

	pairs := []ports.AddressPair{
		{
			IPAddress: "1.1.1.1/0",
		},
	}
	opts := ports.UpdateOpts{AllowedAddressPairs: &pairs}
	_, err = ports.Update(client.osclt.Network, *portID, opts).Extract()
	if err != nil {
		return fmt.Errorf("Failed to enable Router Mode on host '%s': %s", host.Name, openstack.ProviderErrorToString(err))
	}
	return nil
}

// DisableHostRouterMode disables the host to act as a router/gateway.
func (client *Client) disableHostRouterMode(host *api.Host) error {
	portID, err := client.getOpenstackPortID(host)
	if err != nil {
		return fmt.Errorf("Failed to disable Router Mode on host '%s': %s", host.Name, openstack.ProviderErrorToString(err))
	}

	opts := ports.UpdateOpts{AllowedAddressPairs: nil}
	_, err = ports.Update(client.osclt.Network, *portID, opts).Extract()
	if err != nil {
		return fmt.Errorf("Failed to disable Router Mode on host '%s': %s", host.Name, openstack.ProviderErrorToString(err))
	}
	return nil
}

// listInterfaces returns a pager of the interfaces attached to host identified by 'serverID'
func (client *Client) listInterfaces(hostID string) pagination.Pager {
	url := client.osclt.Compute.ServiceURL("servers", hostID, "os-interface")
	return pagination.NewPager(client.osclt.Compute, url, func(r pagination.PageResult) pagination.Page {
		return nics.InterfacePage{SinglePageBase: pagination.SinglePageBase(r)}
	})
}

// getOpenstackPortID returns the port ID corresponding to the first private IP address of the host
// returns nil,nil if not found
func (client *Client) getOpenstackPortID(host *api.Host) (*string, error) {
	ip := host.PrivateIPsV4[0]
	found := false
	nic := nics.Interface{}
	pager := client.listInterfaces(host.ID)
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
		return nil, fmt.Errorf("error browsing Openstack Interfaces of host '%s': %s", host.Name, openstack.ProviderErrorToString(err))
	}
	if found {
		return &nic.PortID, nil
	}
	return nil, nil
}

// toHostSize converts flavor attributes returned by OpenStack driver into api.Host
func (client *Client) toHostSize(flavor map[string]interface{}) api.HostSize {
	if i, ok := flavor["id"]; ok {
		fid := i.(string)
		tpl, _ := client.GetTemplate(fid)
		return tpl.HostSize
	}
	if _, ok := flavor["vcpus"]; ok {
		return api.HostSize{
			Cores:    flavor["vcpus"].(int),
			DiskSize: flavor["disk"].(int),
			RAMSize:  flavor["ram"].(float32) / 1000.0,
		}
	}
	return api.HostSize{}
}

// toHostState converts host status returned by FlexibleEngine driver into HostState enum
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

// toHost converts a FlexibleEngine (almost OpenStack...) server into api host
func (client *Client) toHost(server *servers.Server) *api.Host {
	//	adresses, ipv4, ipv6 := client.convertAdresses(server.Addresses)
	adresses := client.convertAdresses(server.Addresses)

	host := api.Host{
		ID:           server.ID,
		Name:         server.Name,
		PrivateIPsV4: adresses[IPVersion.IPv4],
		PrivateIPsV6: adresses[IPVersion.IPv6],
		AccessIPv4:   server.AccessIPv4,
		AccessIPv6:   server.AccessIPv6,
		Size:         client.toHostSize(server.Flavor),
		State:        toHostState(server.Status),
	}
	m, err := metadata.LoadHost(providers.FromClient(client), server.ID)
	if err == nil && m != nil {
		hostDef := m.Get()
		host.GatewayID = hostDef.GatewayID
		host.PrivateKey = hostDef.PrivateKey
		//Floating IP management
		if host.AccessIPv4 == "" {
			host.AccessIPv4 = hostDef.AccessIPv4
		}
		if host.AccessIPv6 == "" {
			host.AccessIPv6 = hostDef.AccessIPv6
		}
	}
	return &host
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

func isWindowsImage(image api.Image) bool {
	return strings.Contains(strings.ToLower(image.Name), "windows")
}
func isBMSImage(image api.Image) bool {
	return strings.HasPrefix(strings.ToUpper(image.Name), "OBS-BMS") ||
		strings.HasPrefix(strings.ToUpper(image.Name), "OBS_BMS")
}

// ListImages lists available OS images
func (client *Client) ListImages(all bool) ([]api.Image, error) {
	images, err := client.osclt.ListImages(all)
	if err != nil {
		return nil, err
	}
	if all {
		return images, nil
	}

	imageFilter := filters.NewFilter(isWindowsImage).Not().And(filters.NewFilter(isBMSImage).Not())
	return filters.FilterImages(images, imageFilter), nil

}

func addGPUCfg(tpl *api.HostTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

// GetTemplate returns the Template referenced by id
func (client *Client) GetTemplate(id string) (*api.HostTemplate, error) {
	tpl, err := client.osclt.GetTemplate(id)
	if tpl != nil {
		addGPUCfg(tpl)
	}
	return tpl, err
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (client *Client) ListTemplates(all bool) ([]api.HostTemplate, error) {
	allTemplates, err := client.osclt.ListTemplates(all)
	if err != nil {
		return nil, err
	}
	var tpls []api.HostTemplate
	for _, tpl := range allTemplates {
		addGPUCfg(&tpl)
		tpls = append(tpls, tpl)
	}

	return tpls, nil
}

// StopHost stops the host identified by id
func (client *Client) StopHost(id string) error {
	return client.osclt.StopHost(id)
}

// StartHost starts the host identified by id
func (client *Client) StartHost(id string) error {
	return client.osclt.StartHost(id)
}

// WaitHostReady waits an host achieve ready state
func (client *Client) WaitHostReady(hostID string, timeout time.Duration) (*api.Host, error) {
	var (
		server *servers.Server
		err    error
		broken bool
	)

	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			server, err = servers.Get(client.osclt.Compute, hostID).Extract()
			if err != nil {
				return err
			}
			if server.Status == "ERROR" {
				broken = true
				return nil
			}
			if server.Status != "ACTIVE" {
				return fmt.Errorf("host '%s' is in state '%s'", server.Name, server.Status)
			}
			return nil
		},
		timeout,
	)
	if retryErr != nil {
		return nil, retryErr
	}
	if broken {
		return nil, fmt.Errorf("host '%s' is in '%s' state", server.Name, server.Status)
	}
	return client.toHost(server), nil
}
