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
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pengux/check"

	filters "github.com/CS-SI/SafeScale/providers/filters/images"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostState"
	"github.com/CS-SI/SafeScale/providers/model/enums/IPVersion"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/providers/openstack"
	"github.com/CS-SI/SafeScale/providers/userdata"
	"github.com/CS-SI/SafeScale/utils"
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
func (client *Client) CreateHost(request model.HostRequest) (*model.Host, error) {
	//msgFail := "Failed to create Host resource: %s"
	msgSuccess := fmt.Sprintf("Host resource '%s' created successfully", request.ResourceName)

	if request.DefaultGateway == nil && !request.PublicIP {
		return nil, model.ResourceInvalidRequestError("host creation", "can't create a host without network and without public access (would be unreachable)")
	}

	// Validating name of the host
	if ok, err := validatehostName(request); !ok {
		return nil, fmt.Errorf("name '%s' is invalid for a FlexibleEngine Host: %s", request.ResourceName, openstack.ProviderErrorToString(err))
	}

	// The Default Network is the first of the provided list, by convention
	defaultNetwork := request.Networks[0]
	defaultNetworkID := defaultNetwork.ID
	defaultGateway := request.DefaultGateway
	isGateway := defaultGateway == nil && defaultNetwork.Name != model.SingleHostNetworkName
	defaultGatewayID := ""
	defaultGatewayPrivateIP := ""
	if defaultGateway != nil {
		hostNetworkV1 := propsv1.NewHostNetwork()
		err := defaultGateway.Properties.Get(HostProperty.NetworkV1, hostNetworkV1)
		if err != nil {
			return nil, err
		}
		defaultGatewayPrivateIP = hostNetworkV1.IPv4Addresses[defaultNetworkID]
		defaultGatewayID = defaultGateway.ID
	}

	var nets []servers.Network
	// Add private networks
	for _, n := range request.Networks {
		nets = append(nets, servers.Network{
			UUID: n.ID,
		})
	}

	// If no key pair is supplied create one
	if request.KeyPair == nil {
		id, err := uuid.NewV4()
		if err != nil {
			return nil, fmt.Errorf("error creating UID : %v", err)
		}

		name := fmt.Sprintf("%s_%s", request.ResourceName, id)
		request.KeyPair, err = client.CreateKeyPair(name)
		if err != nil {
			msg := fmt.Sprintf("failed to create host key pair: %+v", err)
			log.Debugf(utils.TitleFirst(msg))
		}
	}

	// --- prepares data structures for Provider usage ---

	// Constructs userdata content
	userData, err := userdata.Prepare(client, request, request.KeyPair, defaultNetwork.CIDR)
	if err != nil {
		msg := fmt.Sprintf("failed to prepare user data content: %+v", err)
		log.Debugf(utils.TitleFirst(msg))
		return nil, fmt.Errorf(msg)
	}

	// Determine system disk size based on vcpus count
	template, err := client.GetTemplate(request.TemplateID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get image: %s", openstack.ProviderErrorToString(err))
	}

	// Determines appropriate disk size
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

	// Select useable availability zone, the first one in the list
	azList, err := client.ListAvailabilityZones(false)
	if err != nil {
		return nil, err
	}
	var az string
	for az = range azList {
		break
	}
	log.Debugf("Selected Availability Zone: '%s'", az)

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
		Name:             request.ResourceName,
		SecurityGroups:   []string{client.SecurityGroup.Name},
		Networks:         nets,
		FlavorRef:        request.TemplateID,
		UserData:         userData,
		AvailabilityZone: az,
	}
	// Defines host "Extension bootfromvolume" options
	bdOpts := bootdiskCreateOptsExt{
		CreateOptsBuilder: srvOpts,
		BlockDevice:       []blockDevice{bootdiskOpts},
	}
	b, err := bdOpts.ToServerCreateMap()
	if err != nil {
		return nil, fmt.Errorf("failed to build query to create host '%s': %s", request.ResourceName, openstack.ProviderErrorToString(err))
	}

	// --- Initializes model.Host ---

	host := model.NewHost()
	host.PrivateKey = request.KeyPair.PrivateKey // Add PrivateKey to host definition

	hostNetworkV1 := propsv1.NewHostNetwork()
	hostNetworkV1.IsGateway = isGateway
	hostNetworkV1.DefaultNetworkID = defaultNetworkID
	hostNetworkV1.DefaultGatewayID = defaultGatewayID
	hostNetworkV1.DefaultGatewayPrivateIP = defaultGatewayPrivateIP

	// Updates Host property NetworkV1
	err = host.Properties.Set(HostProperty.NetworkV1, hostNetworkV1)
	if err != nil {
		return nil, err
	}

	// Adds Host property SizingV1
	template.HostSize.DiskSize = diskSize // Makes sure the size of disk is correctly saved
	err = host.Properties.Set(HostProperty.SizingV1, &propsv1.HostSizing{
		// Note: from there, no idea what was the RequestedSize; caller will have to complement this information
		Template:      request.TemplateID,
		AllocatedSize: template.HostSize,
	})
	if err != nil {
		return nil, err
	}

	// --- query provider for host creation ---

	// Retry creation until success, for 10 minutes
	var (
		httpResp *http.Response
		r        servers.CreateResult
	)

	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			httpResp, r.Err = client.osclt.Compute.Post(client.osclt.Compute.ServiceURL("servers"), b, &r.Body, &gc.RequestOpts{
				OkCodes: []int{200, 202},
			})
			server, err := r.Extract()
			if err != nil {
				if server != nil {
					servers.Delete(client.osclt.Compute, server.ID)
				}
				return fmt.Errorf("query to create host '%s' failed: %s (HTTP return code: %d)", request.ResourceName, openstack.ProviderErrorToString(err), httpResp.StatusCode)
				// msg := fmt.Sprintf(msgFail, openstack.ProviderErrorToString(err))
				// // TODO Gotcha !!
				// log.Debugf(msg)
				// return fmt.Errorf(msg)
			}
			host.ID = server.ID

			defer func() {
				if err != nil {
					derr := servers.Delete(client.osclt.Compute, server.ID).ExtractErr()
					if derr != nil {
						log.Errorf("Failed to delete host '%s': %v", server.Name, derr)
					}
				}
			}()

			// Wait that host is ready, not just that the build is started
			host, err = client.WaitHostReady(host, time.Minute*5)
			if err != nil {
				switch err.(type) {
				case model.ErrResourceNotAvailable:
					return fmt.Errorf("host '%s' is in ERROR state", request.ResourceName)
				default:
					return fmt.Errorf("timeout waiting host '%s' ready: %s", request.ResourceName, openstack.ProviderErrorToString(err))
					// msg := fmt.Sprintf(msgFail, openstack.ProviderErrorToString(err))
					// // TODO Gotcha !!
					// log.Debugf(msg)
					// return fmt.Errorf(msg)
				}
			}
			return nil
		},
		10*time.Minute,
	)
	if retryErr != nil {
		return nil, err
	}
	if host == nil {
		return nil, errors.New("unexpected problem creating host")
	}

	// Starting from here, delete host if exiting with error
	defer func() {
		if err != nil {
			derr := client.DeleteHost(host.ID)
			if derr != nil {
				log.Warnf("Failed to delete host '%s': %v", host.Name, derr)
			}
		}
	}()

	if request.PublicIP {
		fip, err := client.attachFloatingIP(host)
		if err != nil {
			spew.Dump(err)
			return nil, fmt.Errorf("error attaching public IP for host '%s': %s", request.ResourceName, openstack.ProviderErrorToString(err))
		}

		// Starting from here, delete Floating IP if exiting with error
		defer func() {
			if err != nil {
				derr := client.DeleteFloatingIP(fip.ID)
				if derr != nil {
					log.Errorf("Error deleting Floating IP: %v", derr)
				}
			}
		}()

		err = host.Properties.Get(HostProperty.NetworkV1, hostNetworkV1)
		if err != nil {
			return nil, err
		}
		if IPVersion.IPv4.Is(fip.PublicIPAddress) {
			hostNetworkV1.PublicIPv4 = fip.PublicIPAddress
		} else if IPVersion.IPv6.Is(fip.PublicIPAddress) {
			hostNetworkV1.PublicIPv6 = fip.PublicIPAddress
		}

		// Updates Host property NetworkV1 in host instance
		err = host.Properties.Set(HostProperty.NetworkV1, hostNetworkV1)
		if err != nil {
			return nil, err
		}

		if defaultGateway == nil && defaultNetwork.Name != model.SingleHostNetworkName {
			err = client.enableHostRouterMode(host)
			if err != nil {
				return nil, fmt.Errorf("error enabling gateway mode of host '%s': %s", request.ResourceName, openstack.ProviderErrorToString(err))
			}
		}
	}

	log.Infoln(msgSuccess)
	return host, nil
}

// validatehostName validates the name of an host based on known FlexibleEngine requirements
func validatehostName(req model.HostRequest) (bool, error) {
	s := check.Struct{
		"ResourceName": check.Composite{
			check.NonEmpty{},
			check.Regex{Constraint: `^[a-zA-Z0-9_-]+$`},
			check.MaxChar{Constraint: 64},
		},
	}

	e := s.Validate(req)
	if e.HasErrors() {
		errors, _ := e.GetErrorsByKey("ResourceName")
		var errs []string
		for _, msg := range errors {
			errs = append(errs, msg.Error())
		}
		return false, fmt.Errorf(strings.Join(errs, " + "))
	}
	return true, nil
}

// GetHost updates the data inside host with the data from provider
func (client *Client) GetHost(hostParam interface{}) (*model.Host, error) {
	var (
		host     *model.Host
		server   *servers.Server
		err      error
		notFound bool
	)

	switch hostParam.(type) {
	case *model.Host:
		host = hostParam.(*model.Host)
	case string:
		host = model.NewHost()
		host.ID = hostParam.(string)
	default:
		panic("hostParam must be a string or a *model.Host!")
	}

	const timeout = time.Minute * 15
	retryErr := retry.WhileUnsuccessful(
		func() error {
			server, err = servers.Get(client.osclt.Compute, host.ID).Extract()
			if err != nil {
				switch err.(type) {
				case gc.ErrDefault404:
					// If error is "resource not found", we want to return GopherCloud error as-is to be able
					// to behave differently in this special case. To do so, stop the retry
					notFound = true
					return nil
				case gc.ErrDefault500:
					// When the response is "Internal Server Error", retries
					log.Println("received 'Internal Server Error', retrying...")
					return err
				}
				// Any other error stops the retry
				err = fmt.Errorf("Error getting host '%s': %s", host.ID, openstack.ProviderErrorToString(err))
				return nil
			}
			if server.Status != "ERROR" && server.Status != "CREATING" {
				host.LastState = toHostState(server.Status)
				return nil
			}
			return fmt.Errorf("server not ready yet")
		},
		timeout,
		1*time.Second,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			msg := "failed to get host"
			if host != nil {
				msg += fmt.Sprintf(" '%s'", host.Name)
			}
			msg += fmt.Sprintf(" information after %v", timeout)
			if err != nil {
				msg += fmt.Sprintf(": %v", err)
			}
			return nil, fmt.Errorf(msg)
		default:
		}
	}
	if err != nil {
		return nil, err
	}
	if notFound {
		return nil, model.ResourceNotFoundError("host", host.ID)
	}
	err = client.complementHost(host, server)
	return host, err
}

// complementHost complements Host data with content of server parameter
func (client *Client) complementHost(host *model.Host, server *servers.Server) error {
	networks, addresses, ipv4, ipv6, err := client.collectAddresses(host)
	if err != nil {
		return err
	}

	// Updates intrinsic data of host if needed
	if host.ID == "" {
		host.ID = server.ID
	}
	if host.Name == "" {
		host.Name = server.Name
	}

	host.LastState = toHostState(server.Status)

	// Updates Host Property propsv1.HostDescription
	hostDescriptionV1 := propsv1.NewHostDescription()
	err = host.Properties.Get(HostProperty.DescriptionV1, hostDescriptionV1)
	if err != nil {
		return err
	}
	hostDescriptionV1.Created = server.Created
	hostDescriptionV1.Updated = server.Updated
	err = host.Properties.Set(HostProperty.DescriptionV1, hostDescriptionV1)
	if err != nil {
		return err
	}

	// // Updates Host Property propsv1.HostSizing
	// hostSizingV1 := propsv1.NewHostSizing()
	// err = host.Properties.Get(HostProperty.SizingV1, hostSizingV1)
	// if err != nil {
	// 	return err
	// }
	// hostSizingV1.AllocatedSize = client.toHostSize(server.Flavor)
	// err = host.Properties.Set(HostProperty.SizingV1, hostSizingV1)
	// if err != nil {
	// 	return err
	// }

	// Updates Host Property HostNetwork
	hostNetworkV1 := propsv1.NewHostNetwork()
	err = host.Properties.Get(HostProperty.NetworkV1, hostNetworkV1)
	if err != nil {
		return nil
	}
	if hostNetworkV1.PublicIPv4 == "" {
		hostNetworkV1.PublicIPv4 = ipv4
	}
	if hostNetworkV1.PublicIPv6 == "" {
		hostNetworkV1.PublicIPv6 = ipv6
	}

	if len(hostNetworkV1.NetworksByID) > 0 {
		ipv4Addresses := map[string]string{}
		ipv6Addresses := map[string]string{}
		for netid, netname := range hostNetworkV1.NetworksByID {
			if ip, ok := addresses[IPVersion.IPv4][netid]; ok {
				ipv4Addresses[netid] = ip
			} else if ip, ok := addresses[IPVersion.IPv4][netname]; ok {
				ipv4Addresses[netid] = ip
			} else {
				ipv4Addresses[netid] = ""
			}

			if ip, ok := addresses[IPVersion.IPv6][netid]; ok {
				ipv6Addresses[netid] = ip
			} else if ip, ok := addresses[IPVersion.IPv6][netname]; ok {
				ipv6Addresses[netid] = ip
			} else {
				ipv6Addresses[netid] = ""
			}
		}
		hostNetworkV1.IPv4Addresses = ipv4Addresses
		hostNetworkV1.IPv6Addresses = ipv6Addresses
	} else {
		networksByID := map[string]string{}
		ipv4Addresses := map[string]string{}
		ipv6Addresses := map[string]string{}
		for _, netid := range networks {
			networksByID[netid] = ""

			if ip, ok := addresses[IPVersion.IPv4][netid]; ok {
				ipv4Addresses[netid] = ip
			} else {
				ipv4Addresses[netid] = ""
			}

			if ip, ok := addresses[IPVersion.IPv6][netid]; ok {
				ipv6Addresses[netid] = ip
			} else {
				ipv6Addresses[netid] = ""
			}
		}
		hostNetworkV1.NetworksByID = networksByID
		// IPvxAddresses are here indexed by names... At least we have them...
		hostNetworkV1.IPv4Addresses = ipv4Addresses
		hostNetworkV1.IPv6Addresses = ipv6Addresses
	}

	// Updates network name and relationships if needed
	for netid, netname := range hostNetworkV1.NetworksByID {
		if netname == "" {
			net, err := client.GetNetwork(netid)
			if err != nil {
				log.Errorf("failed to get network '%s'", netid)
				continue
			}
			hostNetworkV1.NetworksByID[netid] = net.Name
			hostNetworkV1.NetworksByName[net.Name] = netid
		}
	}

	return host.Properties.Set(HostProperty.NetworkV1, hostNetworkV1)
}

// collectAddresses converts adresses returned by the OpenStack driver
// Returns string slice containing the name of the networks, string map of IP addresses
// (indexed on network name), public ipv4 and ipv6 (if they exists)
func (client *Client) collectAddresses(host *model.Host) ([]string, map[IPVersion.Enum]map[string]string, string, string, error) {
	var (
		networks      = []string{}
		addrs         = map[IPVersion.Enum]map[string]string{}
		AcccessIPv4   string
		AcccessIPv6   string
		allInterfaces = []nics.Interface{}
	)

	pager := client.listInterfaces(host.ID)
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := nics.ExtractInterfaces(page)
		if err != nil {
			return false, err
		}
		allInterfaces = append(allInterfaces, list...)
		return true, nil
	})
	if err != nil {
		return networks, addrs, "", "", err
	}

	addrs[IPVersion.IPv4] = map[string]string{}
	addrs[IPVersion.IPv6] = map[string]string{}

	for _, item := range allInterfaces {
		networks = append(networks, item.NetID)
		for _, address := range item.FixedIPs {
			fixedIP := address.IPAddress
			ipv4 := net.ParseIP(fixedIP).To4() != nil
			if item.NetID == client.osclt.Cfg.ProviderNetwork {
				if ipv4 {
					AcccessIPv4 = fixedIP
				} else {
					AcccessIPv6 = fixedIP
				}
			} else {
				if ipv4 {
					addrs[IPVersion.IPv4][item.NetID] = fixedIP
				} else {
					addrs[IPVersion.IPv6][item.NetID] = fixedIP
				}
			}
		}
	}
	return networks, addrs, AcccessIPv4, AcccessIPv6, nil
}

// GetHostByName ...
func (client *Client) GetHostByName(name string) (*model.Host, error) {
	return client.osclt.GetHostByName(name)
}

// GetHostState ...
func (client *Client) GetHostState(hostParam interface{}) (HostState.Enum, error) {
	return client.osclt.GetHostState(hostParam)
}

// ListHosts lists available hosts
func (client *Client) ListHosts() ([]*model.Host, error) {
	pager := servers.List(client.osclt.Compute, servers.ListOpts{})
	var hosts []*model.Host
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := servers.ExtractServers(page)
		if err != nil {
			return false, err
		}

		for _, srv := range list {
			h := model.NewHost()
			h.ID = srv.ID
			err := client.complementHost(h, &srv)
			if err != nil {
				return false, err
			}
			hosts = append(hosts, h)
		}
		return true, nil
	})
	if len(hosts) == 0 && err != nil {
		return nil, fmt.Errorf("error listing hosts: %s", openstack.ProviderErrorToString(err))
	}
	return hosts, nil
}

// DeleteHost deletes the host identified by id
func (client *Client) DeleteHost(id string) error {
	_, err := client.GetHost(id)
	if err != nil {
		return err
	}

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
			var host *servers.Server
			innerRetryErr := retry.WhileUnsuccessfulDelay5Seconds(
				func() error {
					host, err = servers.Get(client.osclt.Compute, id).Extract()
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
					return fmt.Errorf("host '%s' not deleted after %v", id, 1*time.Minute)
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
		log.Printf("failed to remove host '%s': %s", id, outerRetryErr.Error())
		return err
	}
	return nil
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
func (client *Client) attachFloatingIP(host *model.Host) (*FloatingIP, error) {
	fip, err := client.CreateFloatingIP()
	if err != nil {
		return nil, fmt.Errorf("failed to attach Floating IP on host '%s': %s", host.Name, openstack.ProviderErrorToString(err))
	}

	err = client.AssociateFloatingIP(host, fip.ID)
	if err != nil {
		nerr := client.DeleteFloatingIP(fip.ID)
		if nerr != nil {
			log.Warnf("Error deleting floating ip: %v", nerr)
		}
		return nil, fmt.Errorf("failed to attach Floating IP to host '%s': %s", host.Name, openstack.ProviderErrorToString(err))
	}
	return fip, nil
}

// EnableHostRouterMode enables the host to act as a router/gateway.
func (client *Client) enableHostRouterMode(host *model.Host) error {
	portID, err := client.getOpenstackPortID(host)
	if err != nil {
		return fmt.Errorf("failed to enable Router Mode on host '%s': %s", host.Name, openstack.ProviderErrorToString(err))
	}
	if portID == nil {
		return fmt.Errorf("failed to enable Router Mode on host '%s': failed to find OpenStack port", host.Name)
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
func (client *Client) disableHostRouterMode(host *model.Host) error {
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
func (client *Client) getOpenstackPortID(host *model.Host) (*string, error) {
	ip := host.GetPrivateIP()
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
func (client *Client) toHostSize(flavor map[string]interface{}) *propsv1.HostSize {
	if i, ok := flavor["id"]; ok {
		fid := i.(string)
		tpl, _ := client.GetTemplate(fid)
		return tpl.HostSize
	}
	hostSize := propsv1.NewHostSize()
	if _, ok := flavor["vcpus"]; ok {
		hostSize.Cores = flavor["vcpus"].(int)
		hostSize.DiskSize = flavor["disk"].(int)
		hostSize.RAMSize = flavor["ram"].(float32) / 1000.0
	}
	return hostSize
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

// CreateKeyPair creates and import a key pair
func (client *Client) CreateKeyPair(name string) (*model.KeyPair, error) {
	return client.osclt.CreateKeyPair(name)
}

// GetKeyPair returns the key pair identified by id
func (client *Client) GetKeyPair(id string) (*model.KeyPair, error) {
	return client.osclt.GetKeyPair(id)
}

// ListKeyPairs lists available key pairs
func (client *Client) ListKeyPairs() ([]model.KeyPair, error) {
	return client.osclt.ListKeyPairs()
}

// DeleteKeyPair deletes the key pair identified by id
func (client *Client) DeleteKeyPair(id string) error {
	return client.osclt.DeleteKeyPair(id)
}

// ListAvailabilityZones lists the usable Availability Zones
func (client *Client) ListAvailabilityZones(all bool) (map[string]bool, error) {
	return client.osclt.ListAvailabilityZones(all)
}

// GetImage returns the Image referenced by id
func (client *Client) GetImage(id string) (*model.Image, error) {
	return client.osclt.GetImage(id)
}

func isWindowsImage(image model.Image) bool {
	return strings.Contains(strings.ToLower(image.Name), "windows")
}
func isBMSImage(image model.Image) bool {
	return strings.HasPrefix(strings.ToUpper(image.Name), "OBS-BMS") ||
		strings.HasPrefix(strings.ToUpper(image.Name), "OBS_BMS")
}

// ListImages lists available OS images
func (client *Client) ListImages(all bool) ([]model.Image, error) {
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

func addGPUCfg(tpl *model.HostTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

// GetTemplate returns the Template referenced by id
func (client *Client) GetTemplate(id string) (*model.HostTemplate, error) {
	tpl, err := client.osclt.GetTemplate(id)
	if tpl != nil {
		addGPUCfg(tpl)
	}
	return tpl, err
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (client *Client) ListTemplates(all bool) ([]model.HostTemplate, error) {
	allTemplates, err := client.osclt.ListTemplates(all)
	if err != nil {
		return nil, err
	}
	var tpls []model.HostTemplate
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

// RebootHost ...
func (client *Client) RebootHost(id string) error {
	return client.osclt.RebootHost(id)
}

// WaitHostReady waits an host achieve ready state
// hostParam can be an ID of host, or an instance of *model.Host; any other type will panic
func (client *Client) WaitHostReady(hostParam interface{}, timeout time.Duration) (*model.Host, error) {
	var (
		host        *model.Host
		hostInError bool
		err         error
	)

	retryErr := retry.WhileUnsuccessful(
		func() error {
			host, err = client.GetHost(hostParam)
			if err != nil {
				return err
			}
			if host.LastState == HostState.ERROR {
				hostInError = true
				return nil
			}
			if host.LastState != HostState.STARTED {
				return fmt.Errorf("not in ready state (current state: %s)", host.LastState.String())
			}
			return nil
		},
		2*time.Second,
		timeout,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			msg := "timeout waiting to get host"
			if host != nil {
				msg += fmt.Sprintf(" '%s'", host.Name)
			}
			msg += fmt.Sprintf("information after %v", timeout)
			if err != nil {
				msg += fmt.Sprintf(": %v", err)
			}
			return nil, fmt.Errorf(msg)
		default:
			return nil, retryErr
		}
	}
	// If hoste state is ERROR, returns the error
	if hostInError {
		return nil, model.ResourceNotAvailableError("host", "")
	}

	return host, err
}
