/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/davecgh/go-spew/spew"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud"
	nics "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/attachinterfaces"
	az "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/availabilityzones"
	exbfv "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/bootfromvolume"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type blockDevice struct {
	// SourceType must be one of: "volume", "snapshot", "image", or "blank".
	SourceType exbfv.SourceType `json:"source_type" required:"true"`

	// UUID is the unique identifier for the existing volume, snapshot, or
	// image (see above).
	UUID string `json:"uuid,omitempty"`

	// BootIndex is the boot index. It defaults to 0.
	BootIndex string `json:"boot_index,omitempty"`

	// DeleteOnTermination specifies whether to delete the attached volume
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
		// logrus.WithContext(ctx).Debugf("Base64 encoded userdata size = %d bytes", len(userData))
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
			return nil, fail.InvalidInstanceContentError(
				"opts.FlavorRef", "cannot be empty string if 'opts.FlavorName' is empty string",
			)
		}
		if sc == nil {
			return nil, fail.InvalidInstanceContentError(
				"opts.ServiceClient", "cannot be nil if 'opts.FlavorRef' is empty string",
			)
		}
		var flavorID string
		xerr := stacks.RetryableRemoteCall(context.Background(),
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

// getFlavorIDFromName is a convenience function that returns a flavor's ID given its name.
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

// ListAvailabilityZones lists the usable AvailabilityZones
func (s stack) ListAvailabilityZones(ctx context.Context) (list map[string]bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var emptyMap map[string]bool
	if valid.IsNil(s) {
		return emptyMap, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage(""))

	var allPages pagination.Page
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			allPages, innerErr = az.List(s.ComputeClient).AllPages()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return emptyMap, xerr
	}

	content, err := az.ExtractAvailabilityZones(allPages)
	if err != nil {
		return emptyMap, fail.ConvertError(err)
	}

	azList := map[string]bool{}
	for _, zone := range content {
		if zone.ZoneState.Available {
			azList[zone.ZoneName] = zone.ZoneState.Available
		}
	}

	// VPL: what's the point if there ios
	if len(azList) == 0 {
		logrus.WithContext(ctx).Warnf("no Availability Zones detected !")
	}

	return azList, nil
}

// SelectedAvailabilityZone returns the selected availability zone
func (s stack) SelectedAvailabilityZone(ctx context.Context) (string, fail.Error) {
	if valid.IsNil(s) {
		return "", fail.InvalidInstanceError()
	}

	if s.selectedAvailabilityZone == "" {
		cfg, err := s.GetRawAuthenticationOptions(ctx)
		if err != nil {
			return "", err
		}
		s.selectedAvailabilityZone = cfg.AvailabilityZone
		if s.selectedAvailabilityZone == "" {
			azList, xerr := s.ListAvailabilityZones(ctx)
			if xerr != nil {
				return "", xerr
			}
			var azone string
			for azone = range azList {
				break
			}
			s.selectedAvailabilityZone = azone
		}
		logrus.WithContext(ctx).Debugf("Selected Availability Zone: '%s'", s.selectedAvailabilityZone)
	}
	return s.selectedAvailabilityZone, nil
}

// GetAvailabilityZoneOfServer retrieves the availability zone of server 'serverID'
func (s stack) GetAvailabilityZoneOfServer(ctx context.Context, serverID string) (string, fail.Error) {
	if valid.IsNil(s) {
		return "", fail.InvalidInstanceError()
	}
	if serverID == "" {
		return "", fail.InvalidParameterError("serverID", "cannot be empty string")
	}

	type ServerWithAZ struct {
		servers.Server
		az.ServerAvailabilityZoneExt
	}

	var (
		allPages   pagination.Page
		allServers []ServerWithAZ
	)
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			allPages, innerErr = servers.List(s.ComputeClient, nil).AllPages()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return "", xerr
	}

	err := servers.ExtractServersInto(allPages, &allServers)
	if err != nil {
		return "", NormalizeError(err)
	}

	for _, server := range allServers {
		if server.ID == serverID {
			return server.AvailabilityZone, nil
		}
	}

	return "", fail.NotFoundError("unable to find availability zone information for server '%s'", serverID)
}

// CreateHost creates a new host
func (s stack) CreateHost(ctx context.Context, request abstract.HostRequest, extra interface{}) (host *abstract.HostFull, userData *userdata.Content, ferr fail.Error) {
	var xerr fail.Error
	if valid.IsNil(s) {
		return nil, nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.compute"), "(%s)", request.ResourceName).WithStopwatch().Entering().Exiting()
	defer fail.OnPanic(&ferr)

	// msgFail := "failed to create Host resource: %s"
	msgSuccess := fmt.Sprintf("Host resource '%s' created successfully", request.ResourceName)

	if len(request.Subnets) == 0 && !request.PublicIP {
		return nil, nil, abstract.ResourceInvalidRequestError(
			"host creation", "cannot create a host without public IP or without attached network",
		)
	}

	// Validating name of the host
	if ok, xerr := validateHostname(request); !ok {
		if xerr != nil {
			return nil, nil, fail.InvalidRequestError(
				"name '%s' is invalid for a FlexibleEngine Host: %s", request.ResourceName, xerr.Error(),
			)
		}
		return nil, nil, fail.InvalidRequestError(
			"name '%s' is invalid for a FlexibleEngine Host", request.ResourceName,
		)
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
		nets = append(nets, servers.Network{UUID: v.ID})

	}

	if xerr = stacks.ProvideCredentialsIfNeeded(&request); xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to provide credentials for the host")
	}

	// --- prepares data structures for Provider usage ---

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "bad timings")
	}

	// Constructs userdata content
	userData = userdata.NewContent()
	xerr = userData.Prepare(s.cfgOpts, request, defaultSubnet.CIDR, "", timings)
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to prepare user data content")
	}

	template, xerr := s.InspectTemplate(ctx, request.TemplateID)
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to get template")
	}

	rim, xerr := s.InspectImage(ctx, request.ImageID)
	if xerr != nil {
		return nil, nil, xerr
	}

	diskSize := request.DiskSize
	if diskSize > template.DiskSize {
		diskSize = request.DiskSize
	}

	if int(rim.DiskSize) > diskSize {
		diskSize = int(rim.DiskSize)
	}

	if diskSize == 0 {
		// Determines appropriate disk size
		// if still zero here, we take template.DiskSize
		if template.DiskSize != 0 {
			diskSize = template.DiskSize
		} else {
			if template.Cores < 16 { // nolint
				template.DiskSize = 100
			} else if template.Cores < 32 {
				template.DiskSize = 200
			} else {
				template.DiskSize = 400
			}
		}
	}

	if diskSize < 10 {
		diskSize = 10
	}

	// Select usable availability zone
	zone, xerr := s.SelectedAvailabilityZone(ctx)
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to select Availability Zone")
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
	userDataPhase1, xerr := userData.Generate(userdata.PHASE1_INIT)
	if xerr != nil {
		return nil, userData, xerr
	}

	metadata := make(map[string]string)
	metadata["ManagedBy"] = "safescale"
	metadata["DeclaredInBucket"] = s.cfgOpts.MetadataBucket
	metadata["Image"] = request.ImageRef
	metadata["Template"] = request.TemplateID
	metadata["CreationDate"] = time.Now().Format(time.RFC3339)

	// defines creation options
	srvOpts := serverCreateOpts{
		Name:             request.ResourceName,
		SecurityGroups:   []string{},
		Networks:         nets,
		FlavorRef:        request.TemplateID,
		UserData:         userDataPhase1,
		AvailabilityZone: zone,
		Metadata:         metadata,
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

	if extra != nil {
		into, ok := extra.(map[string]string)
		if !ok {
			return nil, nil, fail.InvalidParameterError("extra", "must be a map[string]string")
		}
		for k, v := range into {
			k, v := k, v
			ahc.Tags[k] = v
		}
	}

	// --- query provider for host creation ---

	// Starting from here, delete host if exiting with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if ahc.IsConsistent() {
				derr := s.DeleteHost(cleanupContextFrom(ctx), ahc.ID)
				if derr != nil {
					switch derr.(type) {
					case *fail.ErrNotFound:
						logrus.WithContext(ctx).Errorf(
							"Cleaning up on failure, failed to delete host '%s', resource not found: '%v'", ahc.Name, derr,
						)
					case *fail.ErrTimeout:
						logrus.WithContext(ctx).Errorf("Cleaning up on failure, failed to delete host '%s', timeout: '%v'", ahc.Name, derr)
					default:
						logrus.WithContext(ctx).Errorf("Cleaning up on failure, failed to delete host '%s': '%v'", ahc.Name, derr)
					}
					_ = ferr.AddConsequence(derr)
				}
			}
		}
	}()

	// Retry creation until success, for 10 minutes
	var (
		finalServer *servers.Server
	)
	retryErr := retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			innerXErr := stacks.RetryableRemoteCall(ctx,
				func() (extErr error) {
					select {
					case <-ctx.Done():
						return retry.StopRetryError(ctx.Err())
					default:
					}

					var r servers.CreateResult
					var hr *http.Response
					var server *servers.Server
					hr, r.Err = s.ComputeClient.Post( // nolint
						s.ComputeClient.ServiceURL("servers"), b, &r.Body, &gophercloud.RequestOpts{
							OkCodes: []int{200, 202},
						},
					)
					defer closer(hr)
					var innerErr error
					server, innerErr = r.Extract()
					xerr := normalizeError(innerErr)
					if xerr != nil {
						if server != nil && server.ID != "" {
							derr := servers.Delete(s.ComputeClient, server.ID).ExtractErr()
							if derr != nil {
								_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete host"))
							}
						}
						switch xerr.(type) {
						case *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it's going to fail anyway
							return retry.StopRetryError(xerr)
						default:
							return xerr
						}
					}

					finalServer = server
					return nil
				},
				normalizeError,
			)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *retry.ErrStopRetry, *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it's going to fail anyway
					return retry.StopRetryError(innerXErr, "stopping creation retries")
				default:
					return innerXErr
				}
			}

			ahc.ID = finalServer.ID
			ahc.Name = finalServer.Name

			if ahc.ID == "" {
				return fail.InconsistentError("machine created with empty id")
			}

			creationZone, zoneErr := s.GetAvailabilityZoneOfServer(ctx, finalServer.ID)
			if zoneErr != nil {
				logrus.WithContext(ctx).Tracef("Host successfully created but cannot confirm Availability Zone: %s", zoneErr)
			} else {
				logrus.WithContext(ctx).Tracef("Host successfully created in requested Availability Zone '%s'", creationZone)
				if creationZone != srvOpts.AvailabilityZone {
					if srvOpts.AvailabilityZone != "" {
						logrus.WithContext(ctx).Warnf(
							"Host created in the WRONG availability zone: requested '%s' and got instead '%s'",
							srvOpts.AvailabilityZone, creationZone,
						)
					}
				}
			}

			defer func() {
				if innerXErr != nil {
					if finalServer != nil && finalServer.ID != "" {
						derr := servers.Delete(s.ComputeClient, finalServer.ID).ExtractErr()
						if derr != nil {
							logrus.WithContext(ctx).Errorf("cleaning up on failure, failed to delete host: %s", derr.Error())
						}
					}
				}
			}()

			// Wait that host is ready, not just that the build is started
			finalServer, innerXErr = s.WaitHostState(ctx, ahc, hoststate.Started, 2*timings.HostOperationTimeout())
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotAvailable:
					_ = s.DeleteHost(cleanupContextFrom(ctx), finalServer.ID)
					return fail.Wrap(innerXErr, "host '%s' is in Error state", request.ResourceName)

				default:
					_ = s.DeleteHost(cleanupContextFrom(ctx), finalServer.ID)
					return innerXErr
				}
			}

			innerXErr = s.rpcSetMetadataOfInstance(ctx, finalServer.ID, ahc.Tags)
			if innerXErr != nil {
				return innerXErr
			}

			return nil
		},
		timings.NormalDelay(),
		timings.HostLongOperationTimeout(),
	)

	// Starting from here, delete host if exiting with error
	defer func() {
		if ferr != nil && ahc.ID != "" {
			derr := s.DeleteHost(ctx, ahc.ID)
			if derr != nil {
				switch derr.(type) {
				case *fail.ErrNotFound:
					logrus.Errorf("Cleaning up on failure, failed to delete host '%s', resource not found: '%v'", ahc.Name, derr)
				case *fail.ErrTimeout:
					logrus.Errorf("Cleaning up on failure, failed to delete host '%s', timeout: '%v'", ahc.Name, derr)
				default:
					logrus.Errorf("Cleaning up on failure, failed to delete host '%s': '%v'", ahc.Name, derr)
				}
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

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

	host, xerr = s.complementHost(ctx, ahc, finalServer)
	if xerr != nil {
		return nil, nil, xerr
	}

	host.Networking.DefaultSubnetID = defaultSubnetID
	// host.Networking.DefaultGatewayID = defaultGatewayID
	// host.Networking.DefaultGatewayPrivateIP = defaultGatewayPrivateIP
	host.Networking.IsGateway = isGateway
	// Note: from there, no idea what was the RequestedSize; caller will have to complement this information
	host.Sizing = converters.HostTemplateToHostEffectiveSizing(*template)

	if request.PublicIP {
		var fip *FloatingIP

		// Starting from here, delete Floating IP if exiting with error
		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil {
				if fip != nil {
					derr := s.DeleteFloatingIP(cleanupContextFrom(ctx), fip.ID)
					if derr != nil {
						logrus.WithContext(ctx).Errorf("Error deleting Floating IP: %v", derr)
						_ = ferr.AddConsequence(derr)
					}
				}
			}
		}()

		if fip, xerr = s.attachFloatingIP(ctx, host); xerr != nil {
			return nil, userData, fail.Wrap(xerr, "error attaching public IP for host '%s'", request.ResourceName)
		}
		if fip == nil {
			return nil, userData, fail.NewError("error attaching public IP for host: unknown error")
		}

		if valid.IsIPv4(fip.PublicIPAddress) {
			host.Networking.PublicIPv4 = fip.PublicIPAddress
		} else if valid.IsIPv6(fip.PublicIPAddress) {
			host.Networking.PublicIPv6 = fip.PublicIPAddress
		}
		userData.PublicIP = fip.PublicIPAddress

		if isGateway {
			xerr = s.enableHostRouterMode(ctx, host)
			if xerr != nil {
				return nil, userData, fail.Wrap(xerr, "error enabling gateway mode of host '%s'", request.ResourceName)
			}
		}
	}

	logrus.WithContext(ctx).Infoln(msgSuccess)
	return host, userData, nil
}

// validateHostname validates the name of a host based on known FlexibleEngine requirements
func validateHostname(req abstract.HostRequest) (bool, fail.Error) {
	err := validation.ValidateStruct(&req,
		validation.Field(&req.ResourceName, validation.Required, validation.Length(1, 64)),
		validation.Field(&req.ResourceName, validation.Required, validation.Match(regexp.MustCompile(`^[a-zA-Z0-9_-]+$`))),
	)
	if err != nil {
		return false, fail.Wrap(err, "validation issue")
	}

	return true, nil
}

func extractImage(in *images.Image) (_ abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	properties := in.Properties
	imagev, ok := properties["image"]
	if !ok {
		return abstract.Image{}, fail.NewError("key 'image' not found")
	}
	image, ok := imagev.(map[string]interface{})
	if !ok {
		return abstract.Image{}, fail.NewError("invalid cast")
	}

	dv, ok := image["minDisk"]
	if !ok {
		return abstract.Image{}, fail.NewError("key 'minDisk' not found")
	}
	d, ok := dv.(float64)
	if !ok {
		return abstract.Image{}, fail.NewError("invalid new format")
	}

	idv, ok := image["id"]
	if !ok {
		return abstract.Image{}, fail.NewError("key 'id' not found")
	}

	id, ok := idv.(string)
	if !ok {
		return abstract.Image{}, fail.NewError("invalid new format")
	}

	namev, ok := image["name"]
	if !ok {
		return abstract.Image{}, fail.NewError("key 'name' not found")
	}

	name, ok := namev.(string)
	if !ok {
		return abstract.Image{}, fail.NewError("invalid new format")
	}

	out := abstract.Image{
		ID:       id,
		Name:     name,
		DiskSize: int64(d),
	}

	return out, nil
}

// InspectImage returns the Image referenced by id
func (s stack) InspectImage(ctx context.Context, id string) (_ *abstract.Image, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	var img *images.Image
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			aimg, innerErr := images.Get(s.ComputeClient, id).Extract()
			if innerErr != nil {
				return innerErr
			}
			img = aimg
			return nil
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	if img == nil {
		return nil, fail.UnknownError("get image information didn't fail, but it was nil")
	}

	if img.ID == id {
		out := &abstract.Image{
			ID:       img.ID,
			Name:     img.Name,
			DiskSize: int64(img.MinDiskGigabytes),
		}
		return out, nil
	}

	// if we are here this means that image description is not truly compatible with openstack
	out, err := extractImage(img)
	if err != nil {
		// probably image internals has changed, dump image description
		logrus.WithContext(ctx).Warnf("this image description is invalid: %s", spew.Sdump(img))
		return nil, fail.Wrap(err, "huawei has changed the way it populates *images.Image")
	}

	return &out, nil
}

// InspectHost updates the data inside host with the data from provider
// Returns:
// - *abstract.HostFull, nil if no error occurs
func (s stack) InspectHost(ctx context.Context, hostParam stacks.HostParameter) (host *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	ahf, hostRef, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	server, xerr := s.WaitHostState(ctx, ahf, hoststate.Any, timings.OperationTimeout())
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			if server != nil {
				ahf.Core.ID = server.ID
				ahf.Core.Name = server.Name
				ahf.Core.LastState = hoststate.Error
				return ahf, fail.Wrap(xerr, "host '%s' is in Error state", hostRef)
			}
			return nil, fail.Wrap(xerr, "host '%s' is in Error state", hostRef)
		default:
			return nil, xerr
		}
	}

	if server == nil {
		return nil, abstract.ResourceNotFoundError("host", hostRef)
	}

	host, xerr = s.complementHost(ctx, ahf.Core, server)
	if xerr != nil {
		return nil, xerr
	}

	if !host.OK() {
		logrus.WithContext(ctx).Warnf("[TRACE] Unexpected host status: %s", spew.Sdump(host))
	}
	return host, xerr
}

// ListImages lists available OS images
func (s stack) ListImages(ctx context.Context, _ bool) (imgList []*abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage(""))

	opts := images.ListOpts{
		Status: images.ImageStatusActive,
		Sort:   "name=asc,updated_at:desc",
	}

	// Retrieve a pager (i.e. a paginated collection)
	pager := images.List(s.ComputeClient, opts)

	// Define an anonymous function to be executed on each page's iteration
	imgList = []*abstract.Image{}
	err := pager.EachPage(
		func(page pagination.Page) (bool, error) {
			imageList, err := images.ExtractImages(page)
			if err != nil {
				return false, err
			}

			for _, img := range imageList {
				imgList = append(imgList, &abstract.Image{ID: img.ID, Name: img.Name})
			}
			return true, nil
		},
	)
	if err != nil {
		return nil, NormalizeError(err)
	}
	return imgList, nil
}

// ListTemplates lists available Host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (s stack) ListTemplates(ctx context.Context, _ bool) ([]*abstract.HostTemplate, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering()
	defer tracer.Exiting()

	opts := flavors.ListOpts{}

	var flvList []*abstract.HostTemplate
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			return flavors.ListDetail(s.ComputeClient, opts).EachPage(
				func(page pagination.Page) (bool, error) {
					list, err := flavors.ExtractFlavors(page)
					if err != nil {
						return false, err
					}
					flvList = make([]*abstract.HostTemplate, 0, len(list))
					for _, v := range list {
						flvList = append(
							flvList, &abstract.HostTemplate{
								Cores:    v.VCPUs,
								RAMSize:  float32(v.RAM) / 1000.0,
								DiskSize: v.Disk,
								ID:       v.ID,
								Name:     v.Name,
							},
						)
					}
					return true, nil
				},
			)
		},
		NormalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry:
			return nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *fail.ErrTimeout:
			return nil, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return nil, xerr
		}
	}
	if len(flvList) == 0 {
		logrus.WithContext(ctx).Debugf("Template list empty")
	}
	return flvList, nil
}

// complementHost complements Host data with content of server parameter
func (s stack) complementHost(ctx context.Context, host *abstract.HostCore, server *servers.Server) (completedHost *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	networks, addresses, ipv4, ipv6, xerr := s.collectAddresses(ctx, host)
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

	completedHost = abstract.NewHostFull()
	completedHost.Core = host
	completedHost.Description.Created = server.Created
	completedHost.Description.Updated = server.Updated
	completedHost.CurrentState = host.LastState

	completedHost.Core.Tags["Template"], _ = server.Image["id"].(string) // nolint
	completedHost.Core.Tags["Image"], _ = server.Flavor["id"].(string)   // nolint

	// recover metadata
	for k, v := range server.Metadata {
		completedHost.Core.Tags[k] = v
	}

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
			subnet, xerr := s.InspectSubnet(ctx, subnetID)
			if xerr != nil {
				logrus.WithContext(ctx).Errorf("failed to get network '%s'", subnetID)
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
func (s stack) collectAddresses(ctx context.Context, host *abstract.HostCore) ([]string, map[ipversion.Enum]map[string]string, string, string, fail.Error) {
	var (
		networks      []string
		addrs         = map[ipversion.Enum]map[string]string{}
		AcccessIPv4   string
		AcccessIPv6   string
		allInterfaces []nics.Interface
	)

	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			innerErr := s.listInterfaces(host.ID).EachPage(
				func(page pagination.Page) (bool, error) {
					list, err := nics.ExtractInterfaces(page)
					if err != nil {
						return false, err
					}
					allInterfaces = append(allInterfaces, list...)
					return true, nil
				},
			)
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
func (s stack) ListHosts(ctx context.Context, details bool) (abstract.HostList, fail.Error) {
	var emptyList abstract.HostList
	if valid.IsNil(s) {
		return emptyList, fail.InvalidInstanceError()
	}

	var hostList abstract.HostList
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			innerErr := servers.List(s.ComputeClient, servers.ListOpts{}).EachPage(
				func(page pagination.Page) (bool, error) {
					list, err := servers.ExtractServers(page)
					if err != nil {
						return false, err
					}

					for _, srv := range list {
						h := abstract.NewHostCore()
						h.ID = srv.ID
						var ah *abstract.HostFull
						if details {
							ah, err = s.complementHost(ctx, h, &srv)
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
				},
			)
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if xerr != nil {
		return emptyList, xerr
	}

	return hostList, nil
}

// DeleteHost deletes the host identified by id
func (s stack) DeleteHost(ctx context.Context, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}

	ahf, hostRef, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	_, xerr = s.InspectHost(ctx, ahf)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable: // It's in ERROR state, but it's there
			debug.IgnoreError2(ctx, xerr)
		default:
			return xerr
		}
	}

	if s.cfgOpts.UseFloatingIP {
		fip, xerr := s.getFloatingIPOfHost(ctx, ahf.Core.ID)
		if xerr != nil {
			return xerr
		}

		if fip != nil {
			// Floating IP found, first dissociate it from the host...
			retryErr := stacks.RetryableRemoteCall(ctx,
				func() error {
					err := floatingips.DisassociateInstance(
						s.ComputeClient, ahf.Core.ID, floatingips.DisassociateOpts{
							FloatingIP: fip.IP,
						},
					).ExtractErr()
					return normalizeError(err)
				},
				normalizeError,
			)
			if retryErr != nil {
				return retryErr
			}

			// then delete it.
			retryErr = stacks.RetryableRemoteCall(ctx,
				func() error {
					err := floatingips.Delete(s.ComputeClient, fip.ID).ExtractErr()
					return normalizeError(err)
				},
				normalizeError,
			)
			if retryErr != nil {
				return retryErr
			}
		}

	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	// Try to remove host for 3 minutes
	resourcePresent := true
	outerRetryErr := retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			// 1st, send delete host order
			if resourcePresent { // nolint
				innerRetryErr := stacks.RetryableRemoteCall(ctx,
					func() error {
						innerErr := servers.Delete(s.ComputeClient, ahf.Core.ID).ExtractErr()
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

				var host *servers.Server
				innerRetryErr = retry.WhileUnsuccessful(
					func() error {
						select {
						case <-ctx.Done():
							return retry.StopRetryError(ctx.Err())
						default:
						}

						commRetryErr := stacks.RetryableRemoteCall(ctx,
							func() (innerErr error) {
								host, innerErr = servers.Get(s.ComputeClient, hostRef).Extract()
								return normalizeError(innerErr)
							},
							normalizeError,
						)
						if commRetryErr != nil {
							// FIXME: capture more error types
							switch commRetryErr.(type) {
							case *fail.ErrNotFound:
								resourcePresent = false
								return nil
							default:
							}
							return commRetryErr
						}
						if toHostState(host.Status) == hoststate.Error {
							return nil
						}
						return fail.NewError("host '%s' state is '%s'", host.Name, host.Status)
					},
					timings.NormalDelay(),
					timings.HostCleanupTimeout(),
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
		2*timings.HostCleanupTimeout(), // inner retry already has HostCleanupTimeout, so here we need more
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
// By convention only one floating IP is allocated to a host
func (s stack) getFloatingIPOfHost(ctx context.Context, hostID string) (*floatingips.FloatingIP, fail.Error) {
	var fips []floatingips.FloatingIP
	commRetryErr := stacks.RetryableRemoteCall(ctx,
		func() error {
			innerErr := floatingips.List(s.ComputeClient).EachPage(
				func(page pagination.Page) (bool, error) {
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
				},
			)
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

// attachFloatingIP creates a Floating IP and attaches it to a host
func (s stack) attachFloatingIP(ctx context.Context, host *abstract.HostFull) (*FloatingIP, fail.Error) {
	fip, xerr := s.CreateFloatingIP(ctx, host)
	if xerr != nil {
		return nil, xerr
	}

	xerr = s.AssociateFloatingIP(ctx, host.Core, fip.ID)
	if xerr != nil {
		rerr := s.DeleteFloatingIP(ctx, fip.ID)
		if rerr != nil {
			logrus.WithContext(ctx).Warnf("Error deleting floating ip: %v", rerr)
			_ = xerr.AddConsequence(rerr)
		}
		return nil, xerr
	}

	return fip, nil
}

// EnableHostRouterMode enables the host to act as a router/gateway.
func (s stack) enableHostRouterMode(ctx context.Context, host *abstract.HostFull) fail.Error {
	var (
		portID *string
	)

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	// Sometimes, getOpenstackPortID doesn't find network interface, so let's retry in case it's a bad timing issue
	retryErr := retry.WhileUnsuccessfulWithHardTimeout(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			var innerErr fail.Error
			portID, innerErr = s.getOpenstackPortID(ctx, host)
			if innerErr != nil {
				return innerErr
			}
			if portID == nil {
				return fail.NewError("failed to find OpenStack port")
			}
			return nil
		},
		timings.NormalDelay(),
		timings.OperationTimeout(),
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

	commRetryErr := stacks.RetryableRemoteCall(ctx,
		func() error {
			pairs := []ports.AddressPair{
				{
					IPAddress: "1.1.1.1/0",
				},
			}
			opts := ports.UpdateOpts{AllowedAddressPairs: &pairs}
			_, innerErr := ports.Update(s.NetworkClient, *portID, opts).Extract()
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
	url := s.ComputeClient.ServiceURL("servers", hostID, "os-interface")
	return pagination.NewPager(
		s.ComputeClient, url, func(r pagination.PageResult) pagination.Page {
			return nics.InterfacePage{SinglePageBase: pagination.SinglePageBase(r)}
		},
	)
}

// getOpenstackPortID returns the port ID corresponding to the first private IP address of the host
// returns nil,nil if not found
func (s stack) getOpenstackPortID(ctx context.Context, host *abstract.HostFull) (*string, fail.Error) {
	ip := host.Networking.IPv4Addresses[host.Networking.DefaultSubnetID]
	found := false
	nic := nics.Interface{}
	commRetryErr := stacks.RetryableRemoteCall(ctx,
		func() error {
			innerErr := s.listInterfaces(host.Core.ID).EachPage(
				func(page pagination.Page) (bool, error) {
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
				},
			)
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
	case "":
		return hoststate.Unknown
	default:
		return hoststate.Error
	}
}
