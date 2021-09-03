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

package huaweicloud

import (
	"encoding/base64"
	"fmt"
	"net"

	"github.com/asaskevich/govalidator"
	"github.com/davecgh/go-spew/spew"
	"github.com/pengux/check"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"

	"github.com/gophercloud/gophercloud"
	nics "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/attachinterfaces"
	exbfv "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/bootfromvolume"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

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
		return nil, normalizeError(err)
	}

	if len(opts.BlockDevice) == 0 {
		err := gophercloud.ErrMissingInput{}
		err.Argument = "bootfromvolume.CreateOptsExt.BlockDevice"
		return nil, fail.InvalidInstanceContentError("opts.BlockDevice", "cannot be empty slice")
	}

	serverMap, ok := base["server"].(map[string]interface{})
	if !ok {
		return nil, fail.InconsistentError("base['server']", "is not a map[string]")
	}

	blkDevices := make([]map[string]interface{}, len(opts.BlockDevice))

	for i, bd := range opts.BlockDevice {
		b, err := gophercloud.BuildRequestBody(bd, "")
		if err != nil {
			return nil, normalizeError(err)
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
		return nil, normalizeError(err)
	}

	if opts.UserData != nil {
		var userData string
		if _, err := base64.StdEncoding.DecodeString(string(opts.UserData)); err != nil {
			userData = base64.StdEncoding.EncodeToString(opts.UserData)
		} else {
			userData = string(opts.UserData)
		}
		// logrus.Debugf("Base64 encoded userdata size = %d bytes", len(userData))
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
		for i, network := range opts.Networks {
			networks[i] = make(map[string]interface{})
			if network.UUID != "" {
				networks[i]["uuid"] = network.UUID
			}
			if network.Port != "" {
				networks[i]["port"] = network.Port
			}
			if network.FixedIP != "" {
				networks[i]["fixed_ip"] = network.FixedIP
			}
		}
		b["networks"] = networks
	}

	// If FlavorRef isn't provided, use FlavorName to ascertain the flavor ID.
	if opts.FlavorRef == "" {
		if opts.FlavorName == "" {
			return nil, fail.InvalidInstanceContentError("opts.FlavorRef", "cannot be empty string if 'opts.FlavorName' is empty string")
		}
		if sc == nil {
			return nil, fail.InvalidInstanceContentError("opts.ServiceClient", "cannot be nil if 'opts.FlavorRef' is empty string")
		}
		var flavorID string
		xerr := stacks.RetryableRemoteCall(
			func() (innerErr error) {
				flavorID, innerErr = getFlavorIDFromName(sc, opts.FlavorName)
				return normalizeError(innerErr)
			},
			normalizeError,
		)
		if xerr != nil {
			return nil, xerr
		}
		b["flavorRef"] = flavorID
	}

	return map[string]interface{}{"server": b}, nil
}

// getFlavorIDFromName is a convienience function that returns a flavor's ID given its name.
func getFlavorIDFromName(client *gophercloud.ServiceClient, name string) (string, error) {
	count := 0
	id := ""
	allPages, err := flavors.ListDetail(client, nil).AllPages()
	if err != nil {
		return "", err
	}

	all, err := flavors.ExtractFlavors(allPages)
	if err != nil {
		return "", err
	}

	for _, f := range all {
		if f.Name == name {
			count++
			id = f.ID
		}
	}

	switch count {
	case 0:
		err := &gophercloud.ErrResourceNotFound{}
		err.ResourceType = "flavor"
		err.Name = name
		return "", err
	case 1:
		return id, nil
	default:
		err := &gophercloud.ErrMultipleResourcesFound{}
		err.ResourceType = "flavor"
		err.Name = name
		err.Count = count
		return "", err
	}
}

// CreateHost creates a new host
func (s stack) CreateHost(request abstract.HostRequest) (host *abstract.HostFull, userData *userdata.Content, xerr fail.Error) {
	nullAhf := abstract.NewHostFull()
	nullUdc := userdata.NewContent()
	if s.IsNull() {
		return nullAhf, nullUdc, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.compute"), "(%s)", request.ResourceName).WithStopwatch().Entering().Exiting()
	defer fail.OnPanic(&xerr)

	// msgFail := "failed to create Host resource: %s"
	msgSuccess := fmt.Sprintf("Host resource '%s' created successfully", request.ResourceName)

	if len(request.Subnets) == 0 && !request.PublicIP {
		return nullAhf, nullUdc, abstract.ResourceInvalidRequestError("host creation", "cannot create a host without public IP or without attached network")
	}

	// Validating name of the host
	if ok, xerr := validateHostname(request); !ok {
		if xerr != nil {
			return nullAhf, nullUdc, fail.InvalidRequestError("name '%s' is invalid for a FlexibleEngine Host: %s", request.ResourceName, xerr.Error())
		}
		return nullAhf, nullUdc, fail.InvalidRequestError("name '%s' is invalid for a FlexibleEngine Host", request.ResourceName)
	}

	// The default Network is the first of the provided list, by convention
	defaultSubnet := request.Subnets[0]
	defaultSubnetID := defaultSubnet.ID
	isGateway := request.IsGateway // || defaultSubnet.Name == abstract.SingleHostNetworkName
	// Make sure to allocate public IP if host is a gateway
	request.PublicIP = request.PublicIP || isGateway

	var nets []servers.Network
	// Add private networks
	for _, v := range request.Subnets {
		nets = append(nets, servers.Network{
			UUID: v.ID,
		})
	}

	if xerr = stacks.ProvideCredentialsIfNeeded(&request); xerr != nil {
		return nullAhf, nullUdc, fail.Wrap(xerr, "failed to provide credentials for the host")
	}

	// --- prepares data structures for Provider usage ---

	// Constructs userdata content
	userData = userdata.NewContent()
	xerr = userData.Prepare(s.cfgOpts, request, defaultSubnet.CIDR, "")
	if xerr != nil {
		xerr = fail.Wrap(xerr, "failed to prepare user data content")
		logrus.Debugf(strprocess.Capitalize(xerr.Error()))
		return nullAhf, nullUdc, xerr
	}

	template, xerr := s.InspectTemplate(request.TemplateID)
	if xerr != nil {
		return nullAhf, nullUdc, fail.Wrap(xerr, "failed to get template")
	}

	rim, xerr := s.InspectImage(request.ImageID)
	if xerr != nil {
		return nullAhf, nullUdc, xerr
	}

	if request.DiskSize > template.DiskSize {
		template.DiskSize = request.DiskSize
	}

	if int(rim.DiskSize) > template.DiskSize {
		template.DiskSize = int(rim.DiskSize)
	}

	if template.DiskSize == 0 {
		// Determines appropriate disk size
		if template.Cores < 16 { // nolint
			template.DiskSize = 100
		} else if template.Cores < 32 {
			template.DiskSize = 200
		} else {
			template.DiskSize = 400
		}
	}

	// Select usable availability zone
	az, xerr := s.SelectedAvailabilityZone()
	if xerr != nil {
		return nullAhf, nullUdc, fail.Wrap(xerr, "failed to select Availability Zone")
	}

	// Defines boot disk
	bootdiskOpts := blockDevice{
		SourceType:          exbfv.SourceImage,
		DestinationType:     exbfv.DestinationVolume,
		BootIndex:           "0",
		DeleteOnTermination: true,
		UUID:                request.ImageID,
		VolumeType:          "SSD",
		VolumeSize:          template.DiskSize,
	}
	// Defines server
	userDataPhase1, xerr := userData.Generate(userdata.PHASE1_INIT)
	if xerr != nil {
		return nil, userData, xerr
	}

	// defines creation options
	srvOpts := serverCreateOpts{
		Name:             request.ResourceName,
		SecurityGroups:   []string{},
		Networks:         nets,
		FlavorRef:        request.TemplateID,
		UserData:         userDataPhase1,
		AvailabilityZone: az,
	}

	// Defines host "Extension bootfromvolume" options
	bdOpts := bootdiskCreateOptsExt{
		CreateOptsBuilder: srvOpts,
		BlockDevice:       []blockDevice{bootdiskOpts},
	}
	b, err := bdOpts.ToServerCreateMap()
	if err != nil {
		return nil, userData, fail.Wrap(err, "failed to build query to create host '%s'", request.ResourceName)
	}

	// --- Initializes abstract.HostCore ---

	ahc := abstract.NewHostCore()
	ahc.PrivateKey = userData.FirstPrivateKey
	ahc.Password = request.Password

	// --- query provider for host creation ---

	// Retry creation until success, for 10 minutes
	var (
		r      servers.CreateResult
		server *servers.Server
	)
	retryErr := retry.WhileUnsuccessful(
		func() error {
			innerXErr := stacks.RetryableRemoteCall(
				func() (innerErr error) {
					_, r.Err = s.Stack.ComputeClient.Post(s.Stack.ComputeClient.ServiceURL("servers"), b, &r.Body, &gophercloud.RequestOpts{
						OkCodes: []int{200, 202},
					})
					server, innerErr = r.Extract()
					xerr := normalizeError(innerErr)
					if xerr != nil {
						if server != nil && server.ID != "" {
							derr := servers.Delete(s.Stack.ComputeClient, server.ID).ExtractErr()
							if derr != nil {
								_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete host"))
							}
						}
					}
					switch xerr.(type) {
					case *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it's going to fail anyway
						return retry.StopRetryError(xerr)
					default:
						return xerr
					}
				},
				normalizeError,
			)
			if innerXErr != nil {
				return innerXErr
			}

			creationZone, zoneErr := s.GetAvailabilityZoneOfServer(server.ID)
			if zoneErr != nil {
				logrus.Tracef("Host successfully created but cannot confirm Availability Zone: %s", zoneErr)
			} else {
				logrus.Tracef("Host successfully created in requested Availability Zone '%s'", creationZone)
				if creationZone != srvOpts.AvailabilityZone {
					if srvOpts.AvailabilityZone != "" {
						logrus.Warnf("Host created in the WRONG availability zone: requested '%s' and got instead '%s'", srvOpts.AvailabilityZone, creationZone)
					}
				}
			}

			defer func() {
				if innerXErr != nil {
					derr := servers.Delete(s.ComputeClient, server.ID).ExtractErr()
					if derr != nil {
						logrus.Errorf("cleaning up on failure, failed to delete host: %s", derr.Error())
					}
				}
			}()

			ahc.ID = server.ID
			ahc.Name = server.Name

			// Wait that host is ready, not just that the build is started
			server, innerXErr = s.WaitHostState(ahc, hoststate.Started, temporal.GetHostTimeout())
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotAvailable:
					return fail.Wrap(innerXErr, "host '%s' is in Error state", request.ResourceName)
				default:
					return fail.Wrap(innerXErr, "timeout waiting host '%s' ready", request.ResourceName)
				}
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		temporal.GetLongOperationTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry: // here it should never happen
			return nil, userData, fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return nil, userData, fail.Wrap(fail.Cause(retryErr), "timeout")
		default:
			return nil, userData, retryErr
		}
	}

	// Starting from here, delete host if exiting with error
	defer func() {
		if xerr != nil {
			derr := s.DeleteHost(ahc.ID)
			if derr != nil {
				switch derr.(type) {
				case *fail.ErrNotFound:
					logrus.Errorf("Cleaning up on failure, failed to delete host '%s', resource not found: '%v'", ahc.Name, derr)
				case *fail.ErrTimeout:
					logrus.Errorf("Cleaning up on failure, failed to delete host '%s', timeout: '%v'", ahc.Name, derr)
				default:
					logrus.Errorf("Cleaning up on failure, failed to delete host '%s': '%v'", ahc.Name, derr)
				}
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	host, xerr = s.complementHost(ahc, server)
	if xerr != nil {
		return nil, nil, xerr
	}

	host.Networking.DefaultSubnetID = defaultSubnetID
	// host.Networking.DefaultGatewayID = defaultGatewayID
	// host.Networking.DefaultGatewayPrivateIP = defaultGatewayPrivateIP
	host.Networking.IsGateway = isGateway
	// Note: from there, no idea what was the RequestedSize; caller will have to complement this information
	host.Sizing = converters.HostTemplateToHostEffectiveSizing(template)

	if request.PublicIP {
		var fip *FloatingIP
		if fip, xerr = s.attachFloatingIP(host); xerr != nil {
			return nil, userData, fail.Wrap(xerr, "error attaching public IP for host '%s'", request.ResourceName)
		}
		if fip == nil {
			return nil, userData, fail.NewError("error attaching public IP for host: unknown error")
		}

		// Starting from here, delete Floating IP if exiting with error
		defer func() {
			if xerr != nil {
				derr := s.DeleteFloatingIP(fip.ID)
				if derr != nil {
					logrus.Errorf("Error deleting Floating IP: %v", derr)
					_ = xerr.AddConsequence(derr)
				}
			}
		}()

		if govalidator.IsIPv4(fip.PublicIPAddress) {
			host.Networking.PublicIPv4 = fip.PublicIPAddress
		} else if govalidator.IsIPv6(fip.PublicIPAddress) {
			host.Networking.PublicIPv6 = fip.PublicIPAddress
		}
		userData.PublicIP = fip.PublicIPAddress

		if isGateway {
			xerr = s.enableHostRouterMode(host)
			if xerr != nil {
				return nil, userData, fail.Wrap(xerr, "error enabling gateway mode of host '%s'", request.ResourceName)
			}
		}
	}

	logrus.Infoln(msgSuccess)
	return host, userData, nil
}

// validateHostname validates the name of an host based on known FlexibleEngine requirements
func validateHostname(req abstract.HostRequest) (bool, fail.Error) {
	s := check.Struct{
		"ResourceName": check.Composite{
			check.NonEmpty{},
			check.Regex{Constraint: `^[a-zA-Z0-9_-]+$`},
			check.MaxChar{Constraint: 64},
		},
	}

	e := s.Validate(req)
	if e.HasErrors() {
		errorList, _ := e.GetErrorsByKey("ResourceName")
		var errs []error
		for _, msg := range errorList {
			errs = append(errs, msg)
		}
		return false, fail.NewErrorList(errs)
	}
	return true, nil
}

// InspectHost updates the data inside host with the data from provider
func (s stack) InspectHost(hostParam stacks.HostParameter) (host *abstract.HostFull, xerr fail.Error) {
	nullAHF := abstract.NewHostFull()
	if s.IsNull() {
		return nullAHF, fail.InvalidInstanceError()
	}

	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAHF, xerr
	}

	server, xerr := s.WaitHostState(ahf, hoststate.Started, temporal.GetOperationTimeout())
	if xerr != nil {
		return nullAHF, xerr
	}
	if server == nil {
		return nullAHF, abstract.ResourceNotFoundError("host", hostRef)
	}

	if host, xerr = s.complementHost(ahf.Core, server); xerr != nil {
		return nullAHF, xerr
	}
	if !host.OK() {
		logrus.Warnf("[TRACE] Unexpected host status: %s", spew.Sdump(host))
	}

	return host, nil
}

// complementHost complements IPAddress data with content of server parameter
func (s stack) complementHost(host *abstract.HostCore, server *servers.Server) (completedHost *abstract.HostFull, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	networks, addresses, ipv4, ipv6, xerr := s.collectAddresses(host)
	if xerr != nil {
		return nil, xerr
	}

	// Updates intrinsic data of host if needed
	if host.ID == "" {
		host.ID = server.ID
	}
	if host.Name == "" {
		host.Name = server.Name
	}
	host.LastState = toHostState(server.Status)
	if host.LastState != hoststate.Started {
		logrus.Warnf("[TRACE] Unexpected host's last state: %v", host.LastState)
	}

	completedHost = abstract.NewHostFull()
	completedHost.Core = host
	completedHost.Description.Created = server.Created
	completedHost.Description.Updated = server.Updated

	if completedHost.Networking.PublicIPv4 == "" {
		completedHost.Networking.PublicIPv4 = ipv4
	}
	if completedHost.Networking.PublicIPv6 == "" {
		completedHost.Networking.PublicIPv6 = ipv6
	}
	if len(completedHost.Networking.SubnetsByID) > 0 {
		ipv4Addresses := map[string]string{}
		ipv6Addresses := map[string]string{}
		for netid, netname := range completedHost.Networking.SubnetsByID {
			if ip, ok := addresses[ipversion.IPv4][netid]; ok {
				ipv4Addresses[netid] = ip
			} else if ip, ok := addresses[ipversion.IPv4][netname]; ok {
				ipv4Addresses[netid] = ip
			} else {
				ipv4Addresses[netid] = ""
			}

			if ip, ok := addresses[ipversion.IPv6][netid]; ok {
				ipv6Addresses[netid] = ip
			} else if ip, ok := addresses[ipversion.IPv6][netname]; ok {
				ipv6Addresses[netid] = ip
			} else {
				ipv6Addresses[netid] = ""
			}
		}
		completedHost.Networking.IPv4Addresses = ipv4Addresses
		completedHost.Networking.IPv6Addresses = ipv6Addresses
	} else {
		subnetsByID := map[string]string{}
		ipv4Addresses := map[string]string{}
		ipv6Addresses := map[string]string{}
		for _, netid := range networks {
			subnetsByID[netid] = ""

			if ip, ok := addresses[ipversion.IPv4][netid]; ok {
				ipv4Addresses[netid] = ip
			} else {
				ipv4Addresses[netid] = ""
			}

			if ip, ok := addresses[ipversion.IPv6][netid]; ok {
				ipv6Addresses[netid] = ip
			} else {
				ipv6Addresses[netid] = ""
			}
		}
		completedHost.Networking.SubnetsByID = subnetsByID
		// IPvxAddresses are here indexed by names... At least we have them...
		completedHost.Networking.IPv4Addresses = ipv4Addresses
		completedHost.Networking.IPv6Addresses = ipv6Addresses
	}

	// Updates network name and relationships if needed
	var errors []error
	for subnetID, subnetName := range completedHost.Networking.SubnetsByID {
		if subnetName == "" {
			subnet, xerr := s.InspectSubnet(subnetID)
			if xerr != nil {
				logrus.Errorf("failed to get network '%s'", subnetID)
				errors = append(errors, xerr)
				continue
			}
			completedHost.Networking.SubnetsByID[subnetID] = subnet.Name
			completedHost.Networking.SubnetsByName[subnet.Name] = subnetID
		}
	}
	if len(errors) > 0 {
		return nil, fail.NewErrorList(errors)
	}

	return completedHost, nil
}

// collectAddresses converts adresses returned by the OpenStack driver
// Returns string slice containing the name of the networks, string map of IP addresses
// (indexed on network name), public ipv4 and ipv6 (if they exists)
func (s stack) collectAddresses(host *abstract.HostCore) ([]string, map[ipversion.Enum]map[string]string, string, string, fail.Error) {
	var (
		networks      []string
		addrs         = map[ipversion.Enum]map[string]string{}
		AcccessIPv4   string
		AcccessIPv6   string
		allInterfaces []nics.Interface
	)

	xerr := stacks.RetryableRemoteCall(
		func() error {
			innerErr := s.listInterfaces(host.ID).EachPage(func(page pagination.Page) (bool, error) {
				list, err := nics.ExtractInterfaces(page)
				if err != nil {
					return false, err
				}
				allInterfaces = append(allInterfaces, list...)
				return true, nil
			})
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if xerr != nil {
		return networks, addrs, "", "", xerr
	}

	addrs[ipversion.IPv4] = map[string]string{}
	addrs[ipversion.IPv6] = map[string]string{}

	for _, item := range allInterfaces {
		networks = append(networks, item.NetID)
		for _, address := range item.FixedIPs {
			fixedIP := address.IPAddress
			ipv4 := net.ParseIP(fixedIP).To4() != nil
			if item.NetID == s.cfgOpts.ProviderNetwork {
				if ipv4 {
					AcccessIPv4 = fixedIP
				} else {
					AcccessIPv6 = fixedIP
				}
			} else {
				if ipv4 {
					addrs[ipversion.IPv4][item.NetID] = fixedIP
				} else {
					addrs[ipversion.IPv6][item.NetID] = fixedIP
				}
			}
		}
	}
	return networks, addrs, AcccessIPv4, AcccessIPv6, nil
}

// ListHosts lists available hosts
func (s stack) ListHosts(details bool) (abstract.HostList, fail.Error) {
	var emptyList abstract.HostList
	if s.IsNull() {
		return emptyList, fail.InvalidInstanceError()
	}

	var hostList abstract.HostList
	xerr := stacks.RetryableRemoteCall(
		func() error {
			innerErr := servers.List(s.Stack.ComputeClient, servers.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
				list, err := servers.ExtractServers(page)
				if err != nil {
					return false, err
				}

				for _, srv := range list {
					h := abstract.NewHostCore()
					h.ID = srv.ID
					var ah *abstract.HostFull
					if details {
						ah, err = s.complementHost(h, &srv)
						if err != nil {
							return false, err
						}
					} else {
						ah = abstract.NewHostFull()
						ah.Core = h
					}
					hostList = append(hostList, ah)
				}
				return true, nil
			})
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if xerr != nil {
		return emptyList, xerr
	}
	// VPL: empty host list is not an abnormal situation, do not log or raise error
	return hostList, nil
}

// DeleteHost deletes the host identified by id
func (s stack) DeleteHost(hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}

	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	_, xerr = s.InspectHost(ahf)
	if xerr != nil {
		return xerr
	}

	if s.cfgOpts.UseFloatingIP {
		fip, xerr := s.getFloatingIPOfHost(ahf.Core.ID)
		if xerr == nil {
			if fip != nil {
				// Floating IP found, first dissociate it from the host...
				retryErr := stacks.RetryableRemoteCall(
					func() error {
						err := floatingips.DisassociateInstance(s.Stack.ComputeClient, ahf.Core.ID, floatingips.DisassociateOpts{
							FloatingIP: fip.IP,
						}).ExtractErr()
						return normalizeError(err)
					},
					normalizeError,
				)
				if retryErr != nil {
					return retryErr
				}

				// then delete it.
				retryErr = stacks.RetryableRemoteCall(
					func() error {
						err := floatingips.Delete(s.Stack.ComputeClient, fip.ID).ExtractErr()
						return normalizeError(err)
					},
					normalizeError,
				)
				if retryErr != nil {
					return retryErr
				}
			}
		}
	}

	// Try to remove host for 3 minutes
	resourcePresent := true
	outerRetryErr := retry.WhileUnsuccessful(
		func() error {
			// 1st, send delete host order
			if resourcePresent {
				innerRetryErr := stacks.RetryableRemoteCall(
					func() error {
						innerErr := servers.Delete(s.Stack.ComputeClient, ahf.Core.ID).ExtractErr()
						return normalizeError(innerErr)
					},
					normalizeError,
				)
				if innerRetryErr != nil {
					switch innerRetryErr.(type) {
					case *fail.ErrNotFound:
						// Resource not found, consider deletion succeeded (if the entry doesn't exist at all,
						// metadata deletion will return an error)
						return nil
					default:
						return innerRetryErr
					}
				}
			}

			// 2nd, check host status every 5 seconds until check failed.
			// If check succeeds but state is Error, retry the deletion.
			// If check fails and error isn't 'resource not found', retry
			if resourcePresent {
				var host *servers.Server
				innerRetryErr := retry.WhileUnsuccessful(
					func() error {
						commRetryErr := stacks.RetryableRemoteCall(
							func() (innerErr error) {
								host, innerErr = servers.Get(s.Stack.ComputeClient, hostRef).Extract()
								return normalizeError(innerErr)
							},
							normalizeError,
						)
						if commRetryErr == nil {
							if toHostState(host.Status) == hoststate.Error {
								return nil
							}
							return fail.NewError("host '%s' state is '%s'", host.Name, host.Status)
						}
						// FIXME: capture more error types
						switch commRetryErr.(type) { // nolint
						case *fail.ErrNotFound:
							resourcePresent = false
							return nil
						}
						return commRetryErr
					},
					temporal.GetDefaultDelay(),
					temporal.GetHostCleanupTimeout(),
				)
				if innerRetryErr != nil {
					switch innerRetryErr.(type) {
					case *retry.ErrStopRetry:
						return fail.Wrap(fail.Cause(innerRetryErr), "stopping retries")
					case *retry.ErrTimeout:
						return fail.Wrap(fail.Cause(innerRetryErr), "timeout")
					default:
						return innerRetryErr
					}
				}
			}
			if !resourcePresent {
				return nil
			}
			return fail.NewError("host '%s' in state 'Error', retrying to delete", hostRef)
		},
		0,
		temporal.GetHostCleanupTimeout(),
	)
	if outerRetryErr != nil {
		switch outerRetryErr.(type) {
		case *retry.ErrStopRetry: // here it should never happen
			return fail.Wrap(fail.Cause(outerRetryErr), "stopping retries")
		case *retry.ErrTimeout:
			return fail.Wrap(fail.Cause(outerRetryErr), "timeout")
		default:
			return outerRetryErr
		}
	}
	if !resourcePresent {
		return abstract.ResourceNotFoundError("host", hostRef)
	}
	return nil
}

// getFloatingIP returns the floating IP associated with the host identified by hostID
// By convention only one floating IP is allocated to an host
func (s stack) getFloatingIPOfHost(hostID string) (*floatingips.FloatingIP, fail.Error) {
	var fips []floatingips.FloatingIP
	commRetryErr := stacks.RetryableRemoteCall(
		func() error {
			innerErr := floatingips.List(s.Stack.ComputeClient).EachPage(func(page pagination.Page) (bool, error) {
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
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return nil, commRetryErr
	}
	// VPL: fip not found is not an abnormal situation, do not log or raise error
	if len(fips) > 1 {
		return nil, fail.InconsistentError("configuration error, more than one Floating IP associated to host '%s'", hostID)
	}
	if len(fips) == 0 {
		return nil, nil
	}
	return &fips[0], nil
}

// attachFloatingIP creates a Floating IP and attaches it to an host
func (s stack) attachFloatingIP(host *abstract.HostFull) (*FloatingIP, fail.Error) {
	fip, xerr := s.CreateFloatingIP(host)
	if xerr != nil {
		return nil, xerr
	}

	xerr = s.AssociateFloatingIP(host.Core, fip.ID)
	if xerr != nil {
		derr := s.DeleteFloatingIP(fip.ID)
		if derr != nil {
			logrus.Warnf("Error deleting floating ip: %v", derr)
		}
		_ = xerr.AddConsequence(derr)
		return nil, xerr
	}

	return fip, nil
}

// EnableHostRouterMode enables the host to act as a router/gateway.
func (s stack) enableHostRouterMode(host *abstract.HostFull) fail.Error {
	var (
		portID *string
	)

	// Sometimes, getOpenstackPortID doesn't find network interface, so let's retry in case it's a bad timing issue
	retryErr := retry.WhileUnsuccessfulWithHardTimeout(
		func() error {
			var innerErr fail.Error
			portID, innerErr = s.getOpenstackPortID(host)
			if innerErr != nil {
				return innerErr
			}
			if portID == nil {
				return fail.NewError("failed to find OpenStack port")
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		temporal.GetOperationTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry: // here it should never happen
			return fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return fail.Wrap(fail.Cause(retryErr), "timeout")
		default:
			return retryErr
		}
	}

	commRetryErr := stacks.RetryableRemoteCall(
		func() error {
			pairs := []ports.AddressPair{
				{
					IPAddress: "1.1.1.1/0",
				},
			}
			opts := ports.UpdateOpts{AllowedAddressPairs: &pairs}
			_, innerErr := ports.Update(s.Stack.NetworkClient, *portID, opts).Extract()
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return commRetryErr
	}
	return nil
}

// DisableHostRouterMode disables the host to act as a router/gateway.
func (s stack) disableHostRouterMode(host *abstract.HostFull) fail.Error {
	portID, xerr := s.getOpenstackPortID(host)
	if xerr != nil {
		return fail.NewError("failed to disable Router Mode on host '%s'", host.Core.Name)
	}
	if portID == nil {
		return fail.NewError("failed to disable Router Mode on host '%s': failed to find OpenStack port", host.Core.Name)
	}

	commRetryErr := stacks.RetryableRemoteCall(
		func() error {
			opts := ports.UpdateOpts{AllowedAddressPairs: nil}
			_, innerErr := ports.Update(s.Stack.NetworkClient, *portID, opts).Extract()
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return commRetryErr
	}
	return nil
}

// listInterfaces returns a pager of the interfaces attached to host identified by 'serverID'
func (s stack) listInterfaces(hostID string) pagination.Pager {
	url := s.Stack.ComputeClient.ServiceURL("servers", hostID, "os-interface")
	return pagination.NewPager(s.Stack.ComputeClient, url, func(r pagination.PageResult) pagination.Page {
		return nics.InterfacePage{SinglePageBase: pagination.SinglePageBase(r)}
	})
}

// getOpenstackPortID returns the port ID corresponding to the first private IP address of the host
// returns nil,nil if not found
func (s stack) getOpenstackPortID(host *abstract.HostFull) (*string, fail.Error) {
	ip := host.Networking.IPv4Addresses[host.Networking.DefaultSubnetID]
	found := false
	nic := nics.Interface{}
	commRetryErr := stacks.RetryableRemoteCall(
		func() error {
			innerErr := s.listInterfaces(host.Core.ID).EachPage(func(page pagination.Page) (bool, error) {
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
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return nil, fail.Wrap(commRetryErr, "failed to list OpenStack Interfaces of host '%s'", host.Core.Name)
	}
	if !found {
		return nil, abstract.ResourceNotFoundError("Port ID corresponding to host", host.Core.Name)
	}
	return &nic.PortID, nil
}

// toHostState converts host status returned by FlexibleEngine driver into HostState enum
func toHostState(status string) hoststate.Enum {
	switch status {
	case "BUILD", "build", "BUILDING", "building":
		return hoststate.Starting
	case "ACTIVE", "active":
		return hoststate.Started
	case "RESCUED", "rescued":
		return hoststate.Stopping
	case "Stopped", "stopped", "SHUTOFF", "shutoff":
		return hoststate.Stopped
	default:
		return hoststate.Error
	}
}
