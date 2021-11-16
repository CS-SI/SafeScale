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
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
	volumesv2 "github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/secgroups"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/startstop"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/regions"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/pagination"
	"github.com/sirupsen/logrus"

	// Gophercloud OpenStack API
	"github.com/gophercloud/gophercloud"
	gcos "github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// stack is the implementation for huaweicloud cloud stack
type stack struct {
	ComputeClient  *gophercloud.ServiceClient
	NetworkClient  *gophercloud.ServiceClient
	IdentityClient *gophercloud.ServiceClient
	VolumeClient   *gophercloud.ServiceClient
	Driver         *gophercloud.ProviderClient
	// Opts contains authentication options
	authOpts stacks.AuthenticationOptions
	cfgOpts  stacks.ConfigurationOptions
	// Instance of the default Network/VPC
	vpc *abstract.Network

	// DefaultSecurityGroupName is the name of the default security groups
	DefaultSecurityGroupName string
	// // DefaultSecurityGroupDescription contains a description for the default security groups
	// DefaultSecurityGroupDescription string
	// // SecurityGroup is an instance of the default security group
	SecurityGroup     *abstract.SecurityGroup
	ProviderNetworkID string

	// versions contains the last version supported for each service
	versions map[string]string

	// selectedAvailabilityZone contains the last selected availability zone chosen
	selectedAvailabilityZone string
}

// NullStack is not exposed through API, is needed essentially by testss
func NullStack() *stack { // nolint
	return &stack{}
}

// New authenticates and return interface stack
func New(auth stacks.AuthenticationOptions, cfg stacks.ConfigurationOptions) (api.Stack, fail.Error) {
	// gophercloud doesn't know how to determine Auth API version to use for FlexibleEngine.
	// So we help him to.
	if auth.IdentityEndpoint == "" {
		return nil, fail.InvalidParameterError("auth.IdentityEndpoint", "cannot be empty string")
	}

	if auth.DomainName == "" && auth.DomainID == "" {
		auth.DomainName = "Default"
	}

	authOptions := auth
	scope := gophercloud.AuthScope{
		ProjectName: auth.Region,
		DomainName:  auth.DomainName,
	}

	gcOpts := gophercloud.AuthOptions{
		IdentityEndpoint: auth.IdentityEndpoint,
		Username:         auth.Username,
		UserID:           auth.UserID,
		Password:         auth.Password,
		DomainID:         auth.DomainID,
		DomainName:       auth.DomainName,
		TenantID:         auth.TenantID,
		TenantName:       auth.TenantName,
		AllowReauth:      auth.AllowReauth,
		TokenID:          auth.TokenID,
		Scope:            &scope,
	}

	if cfg.DefaultSecurityGroupName == "" {
		cfg.DefaultSecurityGroupName = defaultSecurityGroupName
	}

	s := stack{
		DefaultSecurityGroupName: cfg.DefaultSecurityGroupName,

		authOpts: auth,
		cfgOpts:  cfg,
	}

	// FIXME: detect versions instead of statically declare them
	s.versions = map[string]string{
		"compute": "v2",
		"volume":  "v2",
		"network": "v2",
	}

	// Openstack client
	xerr := stacks.RetryableRemoteCall(
		func() error {
			var innerErr error
			s.Driver, innerErr = gcos.AuthenticatedClient(gcOpts)
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAuthenticated:
			return nil, fail.NotAuthenticatedError("authentication failed")
		default:
			return nil, xerr
		}
	}

	// Identity API
	endpointOpts := gophercloud.EndpointOpts{Region: auth.Region}
	xerr = stacks.RetryableRemoteCall(
		func() error {
			var innerErr error
			s.IdentityClient, innerErr = gcos.NewIdentityV2(s.Driver, endpointOpts)
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	// Compute API
	switch s.versions["compute"] {
	case "v2":
		xerr = stacks.RetryableRemoteCall(
			func() error {
				var innerErr error
				s.ComputeClient, innerErr = gcos.NewComputeV2(s.Driver, endpointOpts)
				return innerErr
			},
			NormalizeError,
		)
	default:
		return nil, fail.NotImplementedError("unmanaged Openstack service 'compute' version '%s'", s.versions["compute"])
	}
	if xerr != nil {
		return nil, xerr
	}

	// Network API
	switch s.versions["network"] {
	case "v2":
		xerr = stacks.RetryableRemoteCall(
			func() error {
				var innerErr error
				s.NetworkClient, innerErr = gcos.NewNetworkV2(s.Driver, endpointOpts)
				return innerErr
			},
			NormalizeError,
		)
	default:
		return nil, fail.NotImplementedError("unmanaged Openstack service 'network' version '%s'", s.versions["network"])
	}
	if xerr != nil {
		return nil, xerr
	}

	// Volume API
	switch s.versions["volume"] {
	case "v1":
		xerr = stacks.RetryableRemoteCall(
			func() error {
				var innerErr error
				s.VolumeClient, innerErr = gcos.NewBlockStorageV1(s.Driver, endpointOpts)
				return innerErr
			},
			NormalizeError,
		)
	case "v2":
		xerr = stacks.RetryableRemoteCall(
			func() error {
				var innerErr error
				s.VolumeClient, innerErr = gcos.NewBlockStorageV2(s.Driver, endpointOpts)
				return innerErr
			},
			NormalizeError,
		)
	default:
		return nil, fail.NotImplementedError("unmanaged service 'volumes' version '%s'", s.versions["volumes"])
	}
	if xerr != nil {
		return nil, xerr
	}

	// Get provider network ID from network service
	if cfg.ProviderNetwork != "" {
		xerr = stacks.RetryableRemoteCall(
			func() error {
				var innerErr error
				s.ProviderNetworkID, innerErr = getIDFromName(s.NetworkClient, cfg.ProviderNetwork)
				return innerErr
			},
			NormalizeError,
		)
		if xerr != nil {
			return nil, xerr
		}
	}

	// FIXME: should be moved on iaas.factory.go to apply on all providers (if the provider proposes AZ)
	validAvailabilityZones, xerr := s.ListAvailabilityZones()
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError(xerr)
		default:
			return nil, xerr
		}
	} else if len(validAvailabilityZones) != 0 {
		var validZones []string
		zoneIsValidInput := false
		for az, valid := range validAvailabilityZones {
			if valid {
				if az == auth.AvailabilityZone {
					zoneIsValidInput = true
				}
				validZones = append(validZones, `'`+az+`'`)
			}
		}
		if !zoneIsValidInput {
			return nil, fail.InvalidRequestError("invalid Availability zone '%s', valid zones are %s", auth.AvailabilityZone, strings.Join(validZones, ","))
		}

	}

	// Identity API
	var identity *gophercloud.ServiceClient
	commRetryErr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			identity, innerErr = gcos.NewIdentityV3(s.Driver, gophercloud.EndpointOpts{})
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return nil, commRetryErr
	}

	// Recover Project ID of region
	listOpts := projects.ListOpts{
		Enabled: gophercloud.Enabled,
		Name:    authOptions.Region,
	}
	var allProjects []projects.Project
	commRetryErr = stacks.RetryableRemoteCall(
		func() error {
			allPages, innerErr := projects.List(identity, listOpts).AllPages()
			if innerErr != nil {
				return normalizeError(innerErr)
			}
			allProjects, innerErr = projects.ExtractProjects(allPages)
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return nil, commRetryErr
	}
	if len(allProjects) > 0 {
		authOptions.ProjectID = allProjects[0].ID
	} else {
		return nil, fail.NewError("failed to found project ID corresponding to region '%s'", authOptions.Region)
	}

	s.authOpts = auth
	s.cfgOpts = cfg
	s.IdentityClient = identity
	s.cfgOpts.UseFloatingIP = true

	// Initializes the VPC
	xerr = s.initVPC()
	if xerr != nil {
		return nil, xerr
	}

	return &s, nil
}

// ListRegions ...
func (s stack) ListRegions() (list []string, xerr fail.Error) {
	var emptySlice []string
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering().Exiting()

	var allPages pagination.Page
	xerr = stacks.RetryableRemoteCall(
		func() (innerErr error) {
			listOpts := regions.ListOpts{
				// ParentRegionID: "RegionOne",
			}
			allPages, innerErr = regions.List(s.IdentityClient, listOpts).AllPages()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return emptySlice, xerr
	}

	allRegions, err := regions.ExtractRegions(allPages)
	if err != nil {
		return emptySlice, fail.ConvertError(err)
	}

	var results []string
	for _, v := range allRegions {
		results = append(results, v.ID)
	}
	return results, nil
}

// InspectTemplate returns the Template referenced by id
func (s stack) InspectTemplate(id string) (template abstract.HostTemplate, xerr fail.Error) {
	nullAHT := abstract.HostTemplate{}
	if s.IsNull() {
		return nullAHT, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAHT, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Try to get template
	var flv *flavors.Flavor
	xerr = stacks.RetryableRemoteCall(
		func() (innerErr error) {
			flv, innerErr = flavors.Get(s.ComputeClient, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nullAHT, xerr
	}
	template = abstract.HostTemplate{
		Cores:    flv.VCPUs,
		RAMSize:  float32(flv.RAM) / 1000.0,
		DiskSize: flv.Disk,
		ID:       flv.ID,
		Name:     flv.Name,
	}
	return template, nil
}

// CreateKeyPair TODO: replace with code to create KeyPair on provider side if it exists
// creates and import a key pair
func (s stack) CreateKeyPair(name string) (*abstract.KeyPair, fail.Error) {
	nullAKP := &abstract.KeyPair{}
	if s.IsNull() {
		return nullAKP, fail.InvalidInstanceError()
	}
	if name == "" {
		return nullAKP, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	return abstract.NewKeyPair(name)
}

// InspectKeyPair TODO: replace with openstack code to get keypair (if it exits)
// returns the key pair identified by id
func (s stack) InspectKeyPair(id string) (*abstract.KeyPair, fail.Error) {
	nullAKP := &abstract.KeyPair{}
	if s.IsNull() {
		return nullAKP, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAKP, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	kp, err := keypairs.Get(s.ComputeClient, id, nil).Extract()
	if err != nil {
		return nil, fail.Wrap(err, "error getting keypair")
	}
	return &abstract.KeyPair{
		ID:         kp.Name,
		Name:       kp.Name,
		PrivateKey: kp.PrivateKey,
		PublicKey:  kp.PublicKey,
	}, nil
}

// ListKeyPairs lists available key pairs
// Returned list can be empty
func (s stack) ListKeyPairs() ([]abstract.KeyPair, fail.Error) {
	var emptySlice []abstract.KeyPair
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering().Exiting()

	var kpList []abstract.KeyPair
	xerr := stacks.RetryableRemoteCall(
		func() error {
			return keypairs.List(s.ComputeClient, nil).EachPage(
				func(page pagination.Page) (bool, error) {
					list, err := keypairs.ExtractKeyPairs(page)
					if err != nil {
						return false, err
					}

					for _, v := range list {
						kpList = append(
							kpList, abstract.KeyPair{
								ID:         v.Name,
								Name:       v.Name,
								PublicKey:  v.PublicKey,
								PrivateKey: v.PrivateKey,
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
		return emptySlice, xerr
	}
	// Note: empty list is not an error, so do not raise one
	return kpList, nil
}

// DeleteKeyPair deletes the key pair identified by id
func (s stack) DeleteKeyPair(id string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering().Exiting()

	xerr := stacks.RetryableRemoteCall(
		func() error {
			return keypairs.Delete(s.ComputeClient, id, nil).ExtractErr()
		},
		NormalizeError,
	)
	if xerr != nil {
		return xerr
	}
	return nil
}

// BindSecurityGroupToSubnet binds a security group to a subnet
func (s stack) BindSecurityGroupToSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if subnetID != "" {
		return fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	return stacks.RetryableRemoteCall(
		func() error {
			var innerErr error
			// FIXME: bind security group to port associated to subnet
			return innerErr
		},
		NormalizeError,
	)
}

// UnbindSecurityGroupFromSubnet unbinds a security group from a subnet
func (s stack) UnbindSecurityGroupFromSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if subnetID == "" {
		return fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	return stacks.RetryableRemoteCall(
		func() error {
			var innerErr error
			// FIXME: unbind security group from port associated to subnet
			return innerErr
		},
		NormalizeError,
	)
}

// AddPublicIPToVIP adds a public IP to VIP
func (s stack) AddPublicIPToVIP(vip *abstract.VirtualIP) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}

	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (s stack) BindHostToVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}
	if hostID = strings.TrimSpace(hostID); hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	var vipPort *ports.Port
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			vipPort, innerErr = ports.Get(s.NetworkClient, vip.ID).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return xerr
	}
	hostPorts, xerr := s.rpcListPorts(ports.ListOpts{
		DeviceID:  hostID,
		NetworkID: vip.NetworkID,
	})
	if xerr != nil {
		return xerr
	}
	addressPair := ports.AddressPair{
		MACAddress: vipPort.MACAddress,
		IPAddress:  vip.PrivateIP,
	}
	for _, p := range hostPorts {
		p := p
		p.AllowedAddressPairs = append(p.AllowedAddressPairs, addressPair)
		xerr = stacks.RetryableRemoteCall(
			func() error {
				_, innerErr := ports.Update(s.NetworkClient, p.ID, ports.UpdateOpts{AllowedAddressPairs: &p.AllowedAddressPairs}).Extract()
				return innerErr
			},
			NormalizeError,
		)
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (s stack) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}
	if hostID = strings.TrimSpace(hostID); hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	var vipPort *ports.Port
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			vipPort, innerErr = ports.Get(s.NetworkClient, vip.ID).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return xerr
	}
	hostPorts, xerr := s.rpcListPorts(ports.ListOpts{
		DeviceID:  hostID,
		NetworkID: vip.NetworkID,
	})
	if xerr != nil {
		return xerr
	}
	for _, p := range hostPorts {
		var newAllowedAddressPairs []ports.AddressPair
		for _, a := range p.AllowedAddressPairs {
			if a.MACAddress != vipPort.MACAddress {
				newAllowedAddressPairs = append(newAllowedAddressPairs, a)
			}
		}
		xerr = stacks.RetryableRemoteCall(
			func() error {
				_, innerErr := ports.Update(s.NetworkClient, p.ID, ports.UpdateOpts{AllowedAddressPairs: &newAllowedAddressPairs}).Extract()
				return innerErr
			},
			NormalizeError,
		)
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// DeleteVIP deletes the port corresponding to the VIP
func (s stack) DeleteVIP(vip *abstract.VirtualIP) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}

	for _, v := range vip.Hosts {
		xerr := s.UnbindHostFromVIP(vip, v.ID)
		if xerr != nil {
			return xerr
		}
	}
	return stacks.RetryableRemoteCall(
		func() error {
			return ports.Delete(s.NetworkClient, vip.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// ClearHostStartupScript clears the userdata startup script for Host instance (metadata service)
// Does nothing for OpenStack, userdata cannot be updated
func (s stack) ClearHostStartupScript(hostParam stacks.HostParameter) fail.Error {
	return nil
}

// GetHostState returns the current state of host identified by id
// hostParam can be a string or an instance of *abstract.HostCore; any other type will return an fail.InvalidParameterError
func (s stack) GetHostState(hostParam stacks.HostParameter) (hoststate.Enum, fail.Error) {
	if s.IsNull() {
		return hoststate.Unknown, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering().Exiting()

	host, xerr := s.InspectHost(hostParam)
	if xerr != nil {
		return hoststate.Error, xerr
	}
	return host.CurrentState, nil
}

// StopHost stops the host identified by id
func (s stack) StopHost(hostParam stacks.HostParameter, gracefully bool) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()

	return stacks.RetryableRemoteCall(
		func() error {
			return startstop.Stop(s.ComputeClient, ahf.Core.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// StartHost starts the host identified by id
func (s stack) StartHost(hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()

	return stacks.RetryableRemoteCall(
		func() error {
			return startstop.Start(s.ComputeClient, ahf.Core.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// RebootHost reboots unconditionally the host identified by id
func (s stack) RebootHost(hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()

	// Try first a soft reboot, and if it fails (because host isn't in ACTIVE state), tries a hard reboot
	return stacks.RetryableRemoteCall(
		func() error {
			innerErr := servers.Reboot(
				s.ComputeClient, ahf.Core.ID, servers.RebootOpts{Type: servers.SoftReboot},
			).ExtractErr()
			if innerErr != nil {
				innerErr = servers.Reboot(
					s.ComputeClient, ahf.Core.ID, servers.RebootOpts{Type: servers.HardReboot},
				).ExtractErr()
			}
			return innerErr
		},
		NormalizeError,
	)
}

// ResizeHost ...
func (s stack) ResizeHost(hostParam stacks.HostParameter, request abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	nullAHF := abstract.NewHostFull()
	if s.IsNull() {
		return nullAHF, fail.InvalidInstanceError()
	}
	_ /*ahf*/, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAHF, xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()

	// TODO: RESIZE Resize IPAddress HERE
	logrus.Warn("Trying to resize a Host...")

	// TODO: RESIZE Call this
	// servers.Resize()

	return nil, fail.NotImplementedError("ResizeHost() not implemented yet") // FIXME: Technical debt
}

// WaitHostState waits a host achieve defined state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return an utils.ErrInvalidParameter
func (s stack) WaitHostState(hostParam stacks.HostParameter, state hoststate.Enum, timeout time.Duration) (server *servers.Server, xerr fail.Error) {
	nullServer := &servers.Server{}
	if s.IsNull() {
		return nullServer, fail.InvalidInstanceError()
	}

	ahf, hostLabel, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullServer, xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s, %s, %v)", hostLabel,
		state.String(), timeout).WithStopwatch().Entering().Exiting()

	retryErr := retry.WhileUnsuccessful(
		func() (innerErr error) {
			if ahf.Core.ID != "" {
				server, innerErr = s.rpcGetHostByID(ahf.Core.ID)
			} else {
				server, innerErr = s.rpcGetHostByName(ahf.Core.Name)
			}

			if innerErr != nil {
				switch innerErr.(type) {
				case *fail.ErrNotFound:
					// If error is "resource not found", we want to return error as-is to be able
					// to behave differently in this special case. To do so, stop the retry
					return retry.StopRetryError(abstract.ResourceNotFoundError("host", ahf.Core.Name), "")
				case *fail.ErrInvalidRequest:
					// If error is "invalid request", no need to retry, it will always be so
					return retry.StopRetryError(innerErr, "error getting Host %s", hostLabel)
				case *fail.ErrNotAvailable:
					return innerErr
				default:
					if errorMeansServiceUnavailable(innerErr) {
						return innerErr
					}

					// Any other error stops the retry
					return retry.StopRetryError(innerErr, "error getting Host %s", hostLabel)
				}
			}

			if server == nil {
				return fail.NotFoundError("provider did not send information for Host %s", hostLabel)
			}

			ahf.Core.ID = server.ID // makes sure that on next turn we get IPAddress by ID
			lastState := toHostState(server.Status)

			// If we had a response, and the target state is Any, this is a success no matter what
			if state == hoststate.Any {
				return nil
			}

			// If state matches, we consider this a success no matter what
			switch lastState {
			case state:
				return nil
			case hoststate.Error:
				return retry.StopRetryError(fail.NotAvailableError("state of Host '%s' is 'ERROR'", hostLabel))
			case hoststate.Starting, hoststate.Stopping:
				return fail.NewError("host '%s' not ready yet", hostLabel)
			default:
				return retry.StopRetryError(
					fail.NewError(
						"host status of '%s' is in state '%s'", hostLabel, lastState.String(),
					),
				)
			}
		},
		temporal.GetMinDelay(),
		timeout,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *fail.ErrTimeout:
			return nullServer, fail.Wrap(
				fail.Cause(retryErr), "timeout waiting to get host '%s' information after %v", hostLabel, timeout,
			)
		case *fail.ErrAborted:
			cause := retryErr.Cause()
			if cause != nil {
				retryErr = fail.ConvertError(cause)
			}
			return server, retryErr // Not available error keeps the server info, good
		default:
			return nullServer, retryErr
		}
	}
	if server == nil {
		return nullServer, fail.NotFoundError("failed to query Host '%s'", hostLabel)
	}
	return server, nil
}

// WaitHostReady waits a host achieve ready state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return an utils.ErrInvalidParameter
func (s stack) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	nullAHC := abstract.NewHostCore()
	if s.IsNull() {
		return nullAHC, fail.InvalidInstanceError()
	}

	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAHC, xerr
	}

	server, xerr := s.WaitHostState(hostParam, hoststate.Started, timeout)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			// FIXME: Wrong, we need name, status and ID at least here
			if server != nil {
				ahf.Core.ID = server.ID
				ahf.Core.Name = server.Name
				ahf.Core.LastState = hoststate.Error
				return ahf.Core, fail.Wrap(xerr, "host '%s' is in Error state", hostRef)
			}
			return nullAHC, fail.Wrap(xerr, "host '%s' is in Error state", hostRef)
		default:
			return nullAHC, xerr
		}
	}

	ahf, xerr = s.complementHost(ahf.Core, server)
	if xerr != nil {
		return nullAHC, xerr
	}

	return ahf.Core, nil
}

// BindSecurityGroupToHost binds a security group to a host
// If Security Group is already bound to IPAddress, returns *fail.ErrDuplicate
func (s stack) BindSecurityGroupToHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	asg, xerr = s.InspectSecurityGroup(asg)
	if xerr != nil {
		return xerr
	}

	return stacks.RetryableRemoteCall(
		func() error {
			return secgroups.AddServer(s.ComputeClient, ahf.Core.ID, asg.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// UnbindSecurityGroupFromHost unbinds a security group from a host
func (s stack) UnbindSecurityGroupFromHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	return stacks.RetryableRemoteCall(
		func() error {
			return secgroups.RemoveServer(s.ComputeClient, ahf.Core.ID, asg.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// DeleteVolume deletes the volume identified by id
func (s stack) DeleteVolume(id string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if id = strings.TrimSpace(id); id == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.volume"), "("+id+")").WithStopwatch().Entering().Exiting()

	var timeout = temporal.GetOperationTimeout()
	xerr = retry.WhileUnsuccessful(
		func() error {
			innerXErr := stacks.RetryableRemoteCall(
				func() error {
					return volumesv2.Delete(s.VolumeClient, id, nil).ExtractErr()
				},
				NormalizeError,
			)
			switch innerXErr.(type) { // nolint
			case *fail.ErrInvalidRequest:
				return fail.NotAvailableError("volume not in state 'available'")
			case *fail.ErrNotFound:
				return retry.StopRetryError(innerXErr)
			}
			return innerXErr
		},
		temporal.GetDefaultDelay(),
		timeout,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return fail.Wrap(fail.Cause(xerr), "timeout")
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		default:
			return xerr
		}
	}
	return nil
}

// CreateVolumeAttachment attaches a volume to an host
// - 'name' of the volume attachment
// - 'volume' to attach
// - 'host' on which the volume is attached
func (s stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	if s.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if request.Name = strings.TrimSpace(request.Name); request.Name == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("request.Name")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.volume"), "("+request.Name+")").WithStopwatch().Entering().Exiting()

	// Creates the attachment
	var va *volumeattach.VolumeAttachment
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			va, innerErr = volumeattach.Create(s.ComputeClient, request.HostID, volumeattach.CreateOpts{
				VolumeID: request.VolumeID,
			}).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return "", xerr
	}
	return va.ID, nil
}

// InspectVolumeAttachment returns the volume attachment identified by id
func (s stack) InspectVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	nullAVA := abstract.NewVolumeAttachment()
	if s.IsNull() {
		return nullAVA, fail.InvalidInstanceError()
	}
	if serverID = strings.TrimSpace(serverID); serverID == "" {
		return nullAVA, fail.InvalidParameterCannotBeEmptyStringError("serverID")
	}
	if id = strings.TrimSpace(id); id == "" {
		return nullAVA, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.volume"), "('"+serverID+"', '"+id+"')").WithStopwatch().Entering().Exiting()

	var va *volumeattach.VolumeAttachment
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			va, innerErr = volumeattach.Get(s.ComputeClient, serverID, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nullAVA, xerr
	}
	return &abstract.VolumeAttachment{
		ID:       va.ID,
		ServerID: va.ServerID,
		VolumeID: va.VolumeID,
		Device:   va.Device,
	}, nil
}

// ListVolumeAttachments lists available volume attachment
func (s stack) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, fail.Error) {
	var emptySlice []abstract.VolumeAttachment
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}
	if serverID = strings.TrimSpace(serverID); serverID == "" {
		return emptySlice, fail.InvalidParameterCannotBeEmptyStringError("serverID")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.volume"), "('"+serverID+"')").WithStopwatch().Entering().Exiting()

	var vs []abstract.VolumeAttachment
	xerr := stacks.RetryableRemoteCall(
		func() error {
			vs = []abstract.VolumeAttachment{} // If call fails, need to reset volume list to prevent duplicates
			return volumeattach.List(s.ComputeClient, serverID).EachPage(func(page pagination.Page) (bool, error) {
				list, err := volumeattach.ExtractVolumeAttachments(page)
				if err != nil {
					return false, err
				}
				for _, va := range list {
					ava := abstract.VolumeAttachment{
						ID:       va.ID,
						ServerID: va.ServerID,
						VolumeID: va.VolumeID,
						Device:   va.Device,
					}
					vs = append(vs, ava)
				}
				return true, nil
			})
		},
		NormalizeError,
	)
	if xerr != nil {
		return emptySlice, xerr
	}
	return vs, nil
}

// DeleteVolumeAttachment deletes the volume attachment identified by id
func (s stack) DeleteVolumeAttachment(serverID, vaID string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if serverID = strings.TrimSpace(serverID); serverID == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("serverID")
	}
	if vaID = strings.TrimSpace(vaID); vaID == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("vaID")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.volume"), "('"+serverID+"', '"+vaID+"')").WithStopwatch().Entering().Exiting()

	return stacks.RetryableRemoteCall(
		func() error {
			return volumeattach.Delete(s.ComputeClient, serverID, vaID).ExtractErr()
		},
		NormalizeError,
	)
}

func (s stack) Migrate(operation string, params map[string]interface{}) fail.Error {
	return nil
}

// IsNull ...
func (s *stack) IsNull() bool {
	return s == nil || s.Driver == nil
}

// GetStackName returns the name of the stack
func (s stack) GetStackName() string {
	return "huaweicloud"
}

// initVPC initializes the instance of the Networking/VPC if one is defined in tenant
func (s *stack) initVPC() fail.Error {
	if s.cfgOpts.DefaultNetworkName != "" {
		an, xerr := s.InspectNetworkByName(s.cfgOpts.DefaultNetworkName)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// FIXME: error or automatic DefaultNetwork creation ?
				debug.IgnoreError(xerr)
			default:
				return xerr
			}
		} else {
			s.vpc = an
		}
	}
	return nil
}
