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

package huaweicloud

import (
    "encoding/base64"
    "fmt"
    "net"
    "net/http"

    "github.com/davecgh/go-spew/spew"
    "github.com/pengux/check"
    uuid "github.com/satori/go.uuid"
    "github.com/sirupsen/logrus"

    "github.com/gophercloud/gophercloud"
    nics "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/attachinterfaces"
    exbfv "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/bootfromvolume"
    "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
    "github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
    "github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
    "github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
    "github.com/gophercloud/gophercloud/pagination"

    "github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
    "github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
    "github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
    "github.com/CS-SI/SafeScale/lib/server/resources/abstract"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
    "github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
    "github.com/CS-SI/SafeScale/lib/utils"
    "github.com/CS-SI/SafeScale/lib/utils/debug"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
    netretry "github.com/CS-SI/SafeScale/lib/utils/net"
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
        return nil, openstack.NormalizeError(err)
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
            return nil, openstack.NormalizeError(err)
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
        return nil, openstack.NormalizeError(err)
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
        xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
            func() (innerErr error) {
                flavorID, innerErr = flavors.IDFromName(sc, opts.FlavorName)
                return openstack.NormalizeError(innerErr)
            },
            temporal.GetCommunicationTimeout(),
        )
        if xerr != nil {
            return nil, xerr
        }
        b["flavorRef"] = flavorID
    }

    return map[string]interface{}{"server": b}, nil
}

// CreateHost creates a new host
// On success returns an instance of abstract.Host, and a string containing the script to execute to finalize host installation
func (s *Stack) CreateHost(request abstract.HostRequest) (host *abstract.HostFull, userData *userdata.Content, xerr fail.Error) {
    if s == nil {
        return nil, nil, fail.InvalidInstanceError()
    }

    tracer := debug.NewTracer(nil, true, "(%s)", request.ResourceName).WithStopwatch().Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
    defer fail.OnPanic(&xerr)

    userData = userdata.NewContent()

    // msgFail := "failed to create Host resource: %s"
    msgSuccess := fmt.Sprintf("Host resource '%s' created successfully", request.ResourceName)

    if len(request.Networks) == 0 && !request.PublicIP {
        return nil, userData, abstract.ResourceInvalidRequestError("host creation", "cannot create a host without network and without public access (would be unreachable)")
    }

    // Validating name of the host
    if ok, xerr := validateHostname(request); !ok {
        return nil, userData, fail.InvalidRequestError("name '%s' is invalid for a FlexibleEngine Host: %s", request.ResourceName, xerr.Error())
    }

    // The Default Network is the first of the provided list, by convention
    defaultNetwork := request.Networks[0]
    defaultNetworkID := defaultNetwork.ID
    isGateway := request.IsGateway // || defaultNetwork.Name == abstract.SingleHostNetworkName
    // Make sure to allocate Public IP if host is a gateway
    request.PublicIP = request.PublicIP || isGateway

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
            return nil, userData, fail.Wrap(err, "error creating UID")
        }

        name := fmt.Sprintf("%s_%s", request.ResourceName, id)
        request.KeyPair, xerr = s.CreateKeyPair(name)
        if xerr != nil {
            msg := fmt.Sprintf("failed to create host key pair: %+v", xerr)
            logrus.Debugf(strprocess.Capitalize(msg))
        }
    }
    if request.Password == "" {
        password, xerr := utils.GeneratePassword(16)
        if xerr != nil {
            return nil, userData, fail.Wrap(xerr, "failed to generate password")
        }
        request.Password = password
    }

    // --- prepares data structures for Provider usage ---

    // Constructs userdata content
    xerr = userData.Prepare(s.cfgOpts, request, defaultNetwork.CIDR, "")
    if xerr != nil {
        xerr = fail.Wrap(xerr, "failed to prepare user data content")
        logrus.Debugf(strprocess.Capitalize(xerr.Error()))
        return nil, userData, xerr
    }

    template, xerr := s.GetTemplate(request.TemplateID)
    if xerr != nil {
        return nil, userData, fail.Wrap(xerr, "failed to get image")
    }

    // Determines appropriate disk size
    if request.DiskSize > template.DiskSize {
        template.DiskSize = request.DiskSize
    } else if template.DiskSize == 0 {
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
        return nil, userData, xerr
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
    srvOpts := serverCreateOpts{
        Name:             request.ResourceName,
        SecurityGroups:   []string{s.SecurityGroup.Name},
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
    ahc.PrivateKey = request.KeyPair.PrivateKey
    ahc.Password = request.Password

    // --- query provider for host creation ---

    // Retry creation until success, for 10 minutes
    var (
        httpResp *http.Response
        r        servers.CreateResult
        server   *servers.Server
    )
    retryErr := retry.WhileUnsuccessfulDelay5Seconds(
        func() error {
            innerXErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
                func() (innerErr error) {
                    httpResp, r.Err = s.Stack.ComputeClient.Post(s.Stack.ComputeClient.ServiceURL("servers"), b, &r.Body, &gophercloud.RequestOpts{
                        OkCodes: []int{200, 202},
                    })
                    server, innerErr = r.Extract()
                    if innerErr != nil {
                        if server != nil {
                            derr := servers.Delete(s.Stack.ComputeClient, server.ID).ExtractErr()
                            if derr != nil {
                                logrus.Errorf("cleanung up on failure, failed to delete host: %v", derr)
                            }
                        }
                        _ = httpResp    // VPL: to make go vet happy
                        // var codeStr string
                        // if httpResp != nil {
                        //     codeStr = fmt.Sprintf(" (HTTP return code: %d)", httpResp.StatusCode)
                        // }
                        // return fail.NewError("query to create host '%s' failed: %s%s", request.ResourceName, openstack.ProviderErrorToString(innerErr), codeStr)
                    }
                    return openstack.NormalizeError(innerErr)
                },
                temporal.GetCommunicationTimeout(),
            )
            if innerXErr != nil {
                return innerXErr
            }

            creationZone, zoneErr := s.GetAvailabilityZoneOfServer(server.ID)
            if zoneErr != nil {
                logrus.Tracef("Host successfully created but can't confirm AZ: %s", zoneErr)
            } else {
                logrus.Tracef("Host successfully created in requested AZ '%s'", creationZone)
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
                        logrus.Errorf("cleaning up on failure, failed to delete host: %v", derr)
                    }
                }
            }()

            ahc.ID = server.ID
            ahc.Name = server.Name

            // Wait that host is ready, not just that the build is started
            server, innerXErr = s.WaitHostState(ahc, hoststate.STARTED, temporal.GetHostTimeout())
            if innerXErr != nil {
                switch innerXErr.(type) {
                case *fail.ErrNotAvailable:
                    return fail.Prepend(innerXErr, "host '%s' is in ERROR state", request.ResourceName)
                default:
                    return fail.Prepend(innerXErr, "timeout waiting host '%s' ready", request.ResourceName)
                }
            }
            return nil
        },
        temporal.GetLongOperationTimeout(),
    )
    if retryErr != nil {
        return nil, userData, retryErr
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
    host.Network.DefaultNetworkID = defaultNetworkID
    // host.Network.DefaultGatewayID = defaultGatewayID
    // host.Network.DefaultGatewayPrivateIP = defaultGatewayPrivateIP
    host.Network.IsGateway = isGateway
    // Note: from there, no idea what was the RequestedSize; caller will have to complement this information
    host.Sizing = converters.HostTemplateToHostEffectiveSizing(*template)

    if request.PublicIP {
        var fip *FloatingIP
        if fip, xerr = s.attachFloatingIP(ahc); xerr != nil {
            return nil, userData, fail.Prepend(xerr, "error attaching public IP for host '%s'", request.ResourceName)
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

        if ipversion.IPv4.Is(fip.PublicIPAddress) {
            host.Network.PublicIPv4 = fip.PublicIPAddress
        } else if ipversion.IPv6.Is(fip.PublicIPAddress) {
            host.Network.PublicIPv6 = fip.PublicIPAddress
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
func (s *Stack) InspectHost(hostParam stacks.HostParameter) (host *abstract.HostFull, xerr fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }

    ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
    if xerr != nil {
        return nil, xerr
    }

    server, xerr := s.WaitHostState(ahf, hoststate.STARTED, 2*temporal.GetBigDelay())
    if xerr != nil {
        return nil, xerr
    }
    if server == nil {
        return nil, abstract.ResourceNotFoundError("host", hostRef)
    }

    if host, xerr = s.complementHost(ahf.Core, server); xerr != nil {
        return nil, xerr
    }
    if xerr != nil {
        return nil, xerr
    }
    if !host.OK() {
        logrus.Warnf("[TRACE] Unexpected host status: %s", spew.Sdump(host))
    }
    return host, nil
}

// complementHost complements Host data with content of server parameter
func (s *Stack) complementHost(host *abstract.HostCore, server *servers.Server) (completedHost *abstract.HostFull, xerr fail.Error) {
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
    if host.LastState != hoststate.STARTED {
        logrus.Warnf("[TRACE] Unexpected host's last state: %v", host.LastState)
    }

    completedHost = abstract.NewHostFull()
    completedHost.Core = host
    completedHost.Description.Created = server.Created
    completedHost.Description.Updated = server.Updated

    if completedHost.Network.PublicIPv4 == "" {
        completedHost.Network.PublicIPv4 = ipv4
    }
    if completedHost.Network.PublicIPv6 == "" {
        completedHost.Network.PublicIPv6 = ipv6
    }
    if len(completedHost.Network.NetworksByID) > 0 {
        ipv4Addresses := map[string]string{}
        ipv6Addresses := map[string]string{}
        for netid, netname := range completedHost.Network.NetworksByID {
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
        completedHost.Network.IPv4Addresses = ipv4Addresses
        completedHost.Network.IPv6Addresses = ipv6Addresses
    } else {
        networksByID := map[string]string{}
        ipv4Addresses := map[string]string{}
        ipv6Addresses := map[string]string{}
        for _, netid := range networks {
            networksByID[netid] = ""

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
        completedHost.Network.NetworksByID = networksByID
        // IPvxAddresses are here indexed by names... At least we have them...
        completedHost.Network.IPv4Addresses = ipv4Addresses
        completedHost.Network.IPv6Addresses = ipv6Addresses
    }

    // Updates network name and relationships if needed
    var errors []error
    for netid, netname := range completedHost.Network.NetworksByID {
        if netname == "" {
            network, xerr := s.GetNetwork(netid)
            if xerr != nil {
                logrus.Errorf("failed to get network '%s'", netid)
                errors = append(errors, xerr)
                continue
            }
            completedHost.Network.NetworksByID[netid] = network.Name
            completedHost.Network.NetworksByName[network.Name] = netid
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
func (s *Stack) collectAddresses(host *abstract.HostCore) ([]string, map[ipversion.Enum]map[string]string, string, string, fail.Error) {
    var (
        networks      []string
        addrs         = map[ipversion.Enum]map[string]string{}
        AcccessIPv4   string
        AcccessIPv6   string
        allInterfaces []nics.Interface
    )

    xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            innerErr := s.listInterfaces(host.ID).EachPage(func(page pagination.Page) (bool, error) {
                list, err := nics.ExtractInterfaces(page)
                if err != nil {
                    return false, err
                }
                allInterfaces = append(allInterfaces, list...)
                return true, nil
            })
            return openstack.NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
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
func (s *Stack) ListHosts(details bool) (abstract.HostList, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }

    var hostList abstract.HostList
    xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
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
            return openstack.NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
    if xerr != nil {
        return nil, xerr

    }
    // VPL: empty host list is not an abnormal situation, do not log or raise error
    return hostList, nil
}

// DeleteHost deletes the host identified by id
func (s *Stack) DeleteHost(hostParam stacks.HostParameter) fail.Error {
    if s == nil {
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
                retryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
                    func() error {
                        err := floatingips.DisassociateInstance(s.Stack.ComputeClient, ahf.Core.ID, floatingips.DisassociateOpts{
                            FloatingIP: fip.IP,
                        }).ExtractErr()
                        return openstack.NormalizeError(err)
                    },
                    temporal.GetCommunicationTimeout(),
                )
                if retryErr != nil {
                    return retryErr
                }

                // then delete it.
                retryErr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
                    func() error {
                        err := floatingips.Delete(s.Stack.ComputeClient, fip.ID).ExtractErr()
                        return openstack.NormalizeError(err)
                    },
                    temporal.GetCommunicationTimeout(),
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
                innerRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
                    func() error {
                        innerErr := servers.Delete(s.Stack.ComputeClient, ahf.Core.ID).ExtractErr()
                        return openstack.NormalizeError(innerErr)
                    },
                    temporal.GetCommunicationTimeout(),
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
                innerRetryErr := retry.WhileUnsuccessfulDelay5Seconds(
                    func() error {
                        commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
                            func() (innerErr error) {
                                host, innerErr = servers.Get(s.Stack.ComputeClient, hostRef).Extract()
                                return openstack.NormalizeError(innerErr)
                            },
                            temporal.GetCommunicationTimeout(),
                        )
                        if commRetryErr == nil {
                            if toHostState(host.Status) == hoststate.ERROR {
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
                    temporal.GetCommunicationTimeout(),
                )
                if innerRetryErr != nil {
                    if _, ok := innerRetryErr.(*retry.ErrTimeout); ok {
                        // retry deletion...
                        return fail.Prepend(abstract.ResourceTimeoutError("host", hostRef, temporal.GetContextTimeout()),
                            "host '%s' not deleted after %v", hostRef, temporal.GetContextTimeout())
                    }
                    return innerRetryErr
                }
            }
            if !resourcePresent {
                return nil
            }
            return fail.NewError("host '%s' in state 'ERROR', retrying to delete", hostRef)
        },
        0,
        temporal.GetHostCleanupTimeout(),
    )
    if outerRetryErr != nil {
        logrus.Errorf("failed to remove host '%s': %s", hostRef, outerRetryErr.Error())
        return outerRetryErr
    }
    if !resourcePresent {
        return abstract.ResourceNotFoundError("host", hostRef)
    }
    return nil
}

// getFloatingIP returns the floating IP associated with the host identified by hostID
// By convention only one floating IP is allocated to an host
func (s *Stack) getFloatingIPOfHost(hostID string) (*floatingips.FloatingIP, fail.Error) {
    var fips []floatingips.FloatingIP
    commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
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
            return openstack.NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
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
func (s *Stack) attachFloatingIP(host *abstract.HostCore) (*FloatingIP, fail.Error) {
    fip, xerr := s.CreateFloatingIP()
    if xerr != nil {
        return nil, xerr
    }

    xerr = s.AssociateFloatingIP(host, fip.ID)
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
func (s *Stack) enableHostRouterMode(host *abstract.HostFull) fail.Error {
    var (
        portID *string
    )

    // Sometimes, getOpenstackPortID doesn't find network interface, so let's retry in case it's a bad timing issue
    retryErr := retry.WhileUnsuccessfulDelay5SecondsTimeout(
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
        temporal.GetBigDelay(),
    )
    if retryErr != nil {
        return fail.Wrap(retryErr, "failed to enable Router Mode on host '%s'", host.Core.Name)
    }

    commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            pairs := []ports.AddressPair{
                {
                    IPAddress: "1.1.1.1/0",
                },
            }
            opts := ports.UpdateOpts{AllowedAddressPairs: &pairs}
            _, innerErr := ports.Update(s.Stack.NetworkClient, *portID, opts).Extract()
            return openstack.NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
    if commRetryErr != nil {
        return commRetryErr
    }
    return nil
}

// DisableHostRouterMode disables the host to act as a router/gateway.
func (s *Stack) disableHostRouterMode(host *abstract.HostFull) fail.Error {
    portID, xerr := s.getOpenstackPortID(host)
    if xerr != nil {
        return fail.NewError("failed to disable Router Mode on host '%s'", host.Core.Name)
    }
    if portID == nil {
        return fail.NewError("failed to disable Router Mode on host '%s': failed to find OpenStack port", host.Core.Name)
    }

    commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            opts := ports.UpdateOpts{AllowedAddressPairs: nil}
            _, innerErr := ports.Update(s.Stack.NetworkClient, *portID, opts).Extract()
            return openstack.NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
    if commRetryErr != nil {
        return commRetryErr
    }
    return nil
}

// listInterfaces returns a pager of the interfaces attached to host identified by 'serverID'
func (s *Stack) listInterfaces(hostID string) pagination.Pager {
    url := s.Stack.ComputeClient.ServiceURL("servers", hostID, "os-interface")
    return pagination.NewPager(s.Stack.ComputeClient, url, func(r pagination.PageResult) pagination.Page {
        return nics.InterfacePage{SinglePageBase: pagination.SinglePageBase(r)}
    })
}

// getOpenstackPortID returns the port ID corresponding to the first private IP address of the host
// returns nil,nil if not found
func (s *Stack) getOpenstackPortID(host *abstract.HostFull) (*string, fail.Error) {
    ip := host.Network.IPv4Addresses[host.Network.DefaultNetworkID]
    found := false
    nic := nics.Interface{}
    commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
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
            return openstack.NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
    if commRetryErr != nil {
        return nil, fail.Prepend(commRetryErr, "failed to list OpenStack Interfaces of host '%s'", host.Core.Name)
    }
    if !found {
        return nil, abstract.ResourceNotFoundError("Port ID corresponding to host", host.Core.Name)
    }
    return &nic.PortID, nil
}

// // toHostSizing converts flavor attributes returned by OpenStack driver into abstract.HostEffectiveSizing
// func (s *Stack) toHostSizing(flavor map[string]interface{}) *abstract.HostEffectiveSizing {
// 	if i, ok := flavor["id"]; ok {
// 		fid, ok := i.(string)
// 		if !ok {
// 			return nil
// 		}
// 		tpl, err := s.GetTemplate(fid)
// 		if err != nil {
// 			return nil
// 		}
// 		return converters.HostTemplateToHostEffectiveSizing(tpl)
// 	}
// 	hostSizing := &abstract.HostEffectiveSizing{}
// 	if _, ok := flavor["vcpus"]; ok {
// 		hostSizing.Cores, _ = flavor["vcpus"].(int)
// 		hostSizing.DiskSize, _ = flavor["disk"].(int)
// 		hostSizing.RAMSize, _ = flavor["ram"].(float32)
// 		hostSizing.RAMSize /= 1000.0
// 	}
// 	return hostSizing
// }

// toHostState converts host status returned by FlexibleEngine driver into HostState enum
func toHostState(status string) hoststate.Enum {
    switch status {
    case "BUILD", "build", "BUILDING", "building":
        return hoststate.STARTING
    case "ACTIVE", "active":
        return hoststate.STARTED
    case "RESCUED", "rescued":
        return hoststate.STOPPING
    case "STOPPED", "stopped", "SHUTOFF", "shutoff":
        return hoststate.STOPPED
    default:
        return hoststate.ERROR
    }
}
