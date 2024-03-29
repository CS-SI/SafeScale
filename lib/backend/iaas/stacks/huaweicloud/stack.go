/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/api"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
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

	// Gophercloud OpenStack API
	"github.com/gophercloud/gophercloud"
	gcos "github.com/gophercloud/gophercloud/openstack"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
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

	*temporal.MutableTimings
}

// NullStack is not exposed through API, is needed essentially by tests // FIXME: No
func NullStack() api.Stack { // nolint
	return nil
}

// New authenticates and return interface stack
//
//goland:noinspection GoExportedFuncWithUnexportedType
func New(auth stacks.AuthenticationOptions, cfg stacks.ConfigurationOptions, serviceVerions map[string]string) (*stack, fail.Error) { // nolint
	ctx := context.Background()
	// gophercloud doesn't know how to determine Auth API version to use for FlexibleEngine.
	// So we help him to.
	if auth.IdentityEndpoint == "" {
		return nil, fail.InvalidParameterError("auth.IdentityEndpoint", "cannot be empty string")
	}

	if auth.DomainName == "" && auth.DomainID == "" {
		auth.DomainName = "Default"
	}

	scope := gophercloud.AuthScope{
		ProjectID: auth.ProjectID,
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

	s := &stack{
		DefaultSecurityGroupName: cfg.DefaultSecurityGroupName,

		authOpts: auth,
		cfgOpts:  cfg,
	}

	// TODO: detect versions instead of statically declare them
	s.versions = map[string]string{
		"compute":       "v2",
		"volume":        "v2",
		"network":       "v2",
		"networkclient": "v1",
	}
	for k, v := range serviceVerions {
		s.versions[k] = v
	}

	// Openstack client
	xerr := stacks.RetryableRemoteCall(ctx,
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
	xerr = stacks.RetryableRemoteCall(ctx,
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
		xerr = stacks.RetryableRemoteCall(ctx,
			func() error {
				var innerErr error
				s.ComputeClient, innerErr = gcos.NewComputeV2(s.Driver, endpointOpts)
				return innerErr
			},
			NormalizeError,
		)
	default:
		// TODO : this should be a NotImplemented error but we use a generic one instead because NotImplemented is too verbose
		return nil, fail.NewError("unmanaged Openstack service 'compute' version '%s'", s.versions["compute"])
	}
	if xerr != nil {
		return nil, xerr
	}

	// Network API
	switch s.versions["network"] {
	case "v2":
		xerr = stacks.RetryableRemoteCall(ctx,
			func() error {
				var innerErr error
				s.NetworkClient, innerErr = gcos.NewNetworkV2(s.Driver, endpointOpts)
				return innerErr
			},
			NormalizeError,
		)
	default:
		// TODO : this should be a NotImplemented error but we use a generic one instead because NotImplemented is too verbose
		return nil, fail.NewError("unmanaged Openstack service 'network' version '%s'", s.versions["network"])
	}
	if xerr != nil {
		return nil, xerr
	}

	// Volume API
	switch s.versions["volume"] {
	case "v1":
		xerr = stacks.RetryableRemoteCall(ctx,
			func() error {
				var innerErr error
				s.VolumeClient, innerErr = gcos.NewBlockStorageV1(s.Driver, endpointOpts)
				return innerErr
			},
			NormalizeError,
		)
	case "v2":
		xerr = stacks.RetryableRemoteCall(ctx,
			func() error {
				var innerErr error
				s.VolumeClient, innerErr = gcos.NewBlockStorageV2(s.Driver, endpointOpts)
				return innerErr
			},
			NormalizeError,
		)
	default:
		// TODO : this should be a NotImplemented error but we use a generic one instead because NotImplemented is too verbose
		return nil, fail.NewError("unmanaged service 'volumes' version '%s'", s.versions["volume"])
	}
	if xerr != nil {
		return nil, xerr
	}

	// Get provider network ID from network service
	if cfg.ProviderNetwork != "" {
		xerr = stacks.RetryableRemoteCall(ctx,
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

	// TODO: should be moved on iaas.factory.go to apply on all providers (if the provider proposes AZ)
	validAvailabilityZones, xerr := s.ListAvailabilityZones(ctx)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError2(ctx, xerr)
		default:
			return nil, xerr
		}
	} else if len(validAvailabilityZones) != 0 {
		var validZones []string
		zoneIsValidInput := false
		for az, isvalid := range validAvailabilityZones {
			if isvalid {
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
	commRetryErr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			identity, innerErr = gcos.NewIdentityV3(s.Driver, gophercloud.EndpointOpts{})
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return nil, commRetryErr
	}

	s.authOpts = auth
	s.cfgOpts = cfg
	s.IdentityClient = identity
	s.cfgOpts.UseFloatingIP = true

	if cfg.Timings != nil {
		s.MutableTimings = cfg.Timings
		_ = s.MutableTimings.Update(temporal.NewTimings())
	} else {
		s.MutableTimings = temporal.NewTimings()
	}

	// Initializes the VPC
	xerr = s.initVPC(context.Background())
	if xerr != nil {
		return nil, xerr
	}

	return s, nil
}

// ListRegions ...
func (s stack) ListRegions(ctx context.Context) (list []string, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	var allPages pagination.Page
	xerr := stacks.RetryableRemoteCall(ctx,
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
		return nil, xerr
	}

	allRegions, err := regions.ExtractRegions(allPages)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	var results []string
	for _, v := range allRegions {
		results = append(results, v.ID)
	}
	return results, nil
}

// InspectTemplate returns the Template referenced by id
func (s stack) InspectTemplate(ctx context.Context, id string) (template *abstract.HostTemplate, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	// Try to get template
	var flv *flavors.Flavor
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			flv, innerErr = flavors.Get(s.ComputeClient, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	template = &abstract.HostTemplate{
		Cores:    flv.VCPUs,
		RAMSize:  float32(flv.RAM) / 1000.0,
		DiskSize: flv.Disk,
		ID:       flv.ID,
		Name:     flv.Name,
	}
	return template, nil
}

// CreateKeyPair creates and import a key pair
func (s stack) CreateKeyPair(ctx context.Context, name string) (*abstract.KeyPair, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	return abstract.NewKeyPair(name)
}

// InspectKeyPair returns the key pair identified by id
func (s stack) InspectKeyPair(ctx context.Context, id string) (*abstract.KeyPair, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

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
func (s stack) ListKeyPairs(ctx context.Context) ([]*abstract.KeyPair, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	var kpList []*abstract.KeyPair
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			return keypairs.List(s.ComputeClient, nil).EachPage(
				func(page pagination.Page) (bool, error) {
					list, err := keypairs.ExtractKeyPairs(page)
					if err != nil {
						return false, err
					}

					for _, v := range list {
						kpList = append(
							kpList, &abstract.KeyPair{
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
		return nil, xerr
	}

	return kpList, nil
}

// DeleteKeyPair deletes the key pair identified by id
func (s stack) DeleteKeyPair(ctx context.Context, id string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	xerr := stacks.RetryableRemoteCall(ctx,
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

// AddPublicIPToVIP adds a public IP to VIP
func (s stack) AddPublicIPToVIP(ctx context.Context, vip *abstract.VirtualIP) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}

	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (s stack) BindHostToVIP(ctx context.Context, vip *abstract.VirtualIP, hostID string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}
	if hostID = strings.TrimSpace(hostID); hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	var vipPort *ports.Port
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			vipPort, innerErr = ports.Get(s.NetworkClient, vip.ID).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return xerr
	}
	hostPorts, xerr := s.rpcListPorts(ctx, ports.ListOpts{
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
		xerr = stacks.RetryableRemoteCall(ctx,
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
func (s stack) UnbindHostFromVIP(ctx context.Context, vip *abstract.VirtualIP, hostID string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}
	if hostID = strings.TrimSpace(hostID); hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	var vipPort *ports.Port
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			vipPort, innerErr = ports.Get(s.NetworkClient, vip.ID).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return xerr
	}
	hostPorts, xerr := s.rpcListPorts(ctx, ports.ListOpts{
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
		xerr = stacks.RetryableRemoteCall(ctx,
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
func (s stack) DeleteVIP(ctx context.Context, vip *abstract.VirtualIP) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}

	for _, v := range vip.Hosts {
		xerr := s.UnbindHostFromVIP(ctx, vip, v.ID)
		if xerr != nil {
			return xerr
		}
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return ports.Delete(s.NetworkClient, vip.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// ClearHostStartupScript clears the userdata startup script for Host instance (metadata service)
// Does nothing for OpenStack, userdata cannot be updated
func (s stack) ClearHostStartupScript(ctx context.Context, hostParam stacks.HostParameter) fail.Error {
	return nil
}

func (s stack) ChangeSecurityGroupSecurity(ctx context.Context, b bool, b2 bool, net string, s2 string) fail.Error {
	return nil
}

func (s stack) GetHostState(ctx context.Context, hostParam stacks.HostParameter) (hoststate.Enum, fail.Error) {
	if valid.IsNil(s) {
		return hoststate.Unknown, fail.InvalidInstanceError()
	}

	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	if ahf.Core.ID != "" {
		server, innerErr := s.rpcGetHostByID(ctx, ahf.Core.ID)
		if innerErr != nil {
			return hoststate.Unknown, innerErr
		}

		return toHostState(server.Status), nil
	} else {
		server, innerErr := s.rpcGetHostByName(ctx, ahf.Core.Name)
		if innerErr != nil {
			return hoststate.Unknown, innerErr
		}

		return toHostState(server.Status), nil
	}
}

// StopHost stops the host identified by id
func (s stack) StopHost(ctx context.Context, hostParam stacks.HostParameter, gracefully bool) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return startstop.Stop(s.ComputeClient, ahf.Core.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// StartHost starts the host identified by id
func (s stack) StartHost(ctx context.Context, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return startstop.Start(s.ComputeClient, ahf.Core.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// RebootHost reboots unconditionally the host identified by id
func (s stack) RebootHost(ctx context.Context, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	// Only hard reboot fixes problems
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			innerErr := servers.Reboot(
				s.ComputeClient, ahf.Core.ID, servers.RebootOpts{Type: servers.HardReboot},
			).ExtractErr()
			return innerErr
		},
		NormalizeError,
	)
}

// WaitHostState waits a host achieve defined state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return an utils.ErrInvalidParameter
func (s stack) WaitHostState(ctx context.Context, hostParam stacks.HostParameter, state hoststate.Enum, timeout time.Duration) (server *servers.Server, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	ahf, hostLabel, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	retryErr := retry.WhileUnsuccessful(
		func() (innerErr error) {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			if ahf.Core.ID != "" {
				server, innerErr = s.rpcGetHostByID(ctx, ahf.Core.ID)
			} else {
				server, innerErr = s.rpcGetHostByName(ctx, ahf.Core.Name)
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

			ahf.Core.ID = server.ID // makes sure that on next turn we get Host by ID
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
		timings.SmallDelay(),
		timeout,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *fail.ErrTimeout:
			return nil, fail.Wrap(
				fail.Cause(retryErr), "timeout waiting to get host '%s' information after %v", hostLabel, timeout,
			)
		case *fail.ErrAborted:
			cause := retryErr.Cause()
			if cause != nil {
				retryErr = fail.ConvertError(cause)
			}
			return server, retryErr // Not available error keeps the server info, good
		default:
			return nil, retryErr
		}
	}
	if server == nil {
		return nil, fail.NotFoundError("failed to query Host '%s'", hostLabel)
	}
	return server, nil
}

// WaitHostReady waits a host achieve ready state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return an utils.ErrInvalidParameter
func (s stack) WaitHostReady(ctx context.Context, hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	ahf, hostRef, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}

	server, xerr := s.WaitHostState(ctx, hostParam, hoststate.Started, timeout)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			if server != nil {
				ahf.Core.ID = server.ID
				ahf.Core.Name = server.Name
				ahf.Core.LastState = hoststate.Error
				return ahf.Core, fail.Wrap(xerr, "host '%s' is in Error state", hostRef)
			}
			return nil, fail.Wrap(xerr, "host '%s' is in Error state", hostRef)
		default:
			return nil, xerr
		}
	}

	ahf, xerr = s.complementHost(ctx, ahf.Core, server)
	if xerr != nil {
		return nil, xerr
	}

	return ahf.Core, nil
}

// BindSecurityGroupToHost binds a security group to a host
// If Security Group is already bound to Host, returns *fail.ErrDuplicate
func (s stack) BindSecurityGroupToHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	asg, xerr = s.InspectSecurityGroup(ctx, asg)
	if xerr != nil {
		return xerr
	}

	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return secgroups.AddServer(s.ComputeClient, ahf.Core.ID, asg.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// UnbindSecurityGroupFromHost unbinds a security group from a host
func (s stack) UnbindSecurityGroupFromHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return secgroups.RemoveServer(s.ComputeClient, ahf.Core.ID, asg.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// DeleteVolume deletes the volume identified by id
func (s stack) DeleteVolume(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if id = strings.TrimSpace(id); id == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	timeout := timings.OperationTimeout()
	xerr = retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			innerXErr := stacks.RetryableRemoteCall(ctx,
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
		timings.NormalDelay(),
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

// CreateVolumeAttachment attaches a volume to a host
// - 'name' of the volume attachment
// - 'volume' to attach
// - 'host' on which the volume is attached
func (s stack) CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	if valid.IsNil(s) {
		return "", fail.InvalidInstanceError()
	}
	if request.Name = strings.TrimSpace(request.Name); request.Name == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("request.Name")
	}

	// Creates the attachment
	var va *volumeattach.VolumeAttachment
	xerr := stacks.RetryableRemoteCall(ctx,
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
func (s stack) InspectVolumeAttachment(ctx context.Context, serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if serverID = strings.TrimSpace(serverID); serverID == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("serverID")
	}
	if id = strings.TrimSpace(id); id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	var va *volumeattach.VolumeAttachment
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			va, innerErr = volumeattach.Get(s.ComputeClient, serverID, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	return &abstract.VolumeAttachment{
		ID:       va.ID,
		ServerID: va.ServerID,
		VolumeID: va.VolumeID,
		Device:   va.Device,
	}, nil
}

// ListVolumeAttachments lists available volume attachment
func (s stack) ListVolumeAttachments(ctx context.Context, serverID string) ([]*abstract.VolumeAttachment, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if serverID = strings.TrimSpace(serverID); serverID == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("serverID")
	}

	var vs []*abstract.VolumeAttachment
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			vs = []*abstract.VolumeAttachment{} // If call fails, need to reset volume list to prevent duplicates
			return volumeattach.List(s.ComputeClient, serverID).EachPage(func(page pagination.Page) (bool, error) {
				list, err := volumeattach.ExtractVolumeAttachments(page)
				if err != nil {
					return false, err
				}
				for _, va := range list {
					ava := &abstract.VolumeAttachment{
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
		return nil, xerr
	}
	return vs, nil
}

// DeleteVolumeAttachment deletes the volume attachment identified by id
func (s stack) DeleteVolumeAttachment(ctx context.Context, serverID, vaID string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if serverID = strings.TrimSpace(serverID); serverID == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("serverID")
	}
	if vaID = strings.TrimSpace(vaID); vaID == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("vaID")
	}

	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return volumeattach.Delete(s.ComputeClient, serverID, vaID).ExtractErr()
		},
		NormalizeError,
	)
}

// IsNull ...
func (s *stack) IsNull() bool {
	return s == nil || s.Driver == nil
}

// GetStackName returns the name of the stack
func (s stack) GetStackName() (string, fail.Error) {
	return "huaweicloud", nil
}

func (s stack) GetType() (_ string, ferr fail.Error) {
	return "classic", nil
}

// initVPC initializes the instance of the Networking/VPC if one is defined in tenant
func (s *stack) initVPC(ctx context.Context) fail.Error {
	if s.cfgOpts.DefaultNetworkName != "" {
		an, xerr := s.InspectNetworkByName(ctx, s.cfgOpts.DefaultNetworkName)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// FIXME: error or automatic DefaultNetwork creation ?
				debug.IgnoreError2(ctx, xerr)
			default:
				return xerr
			}
		} else {
			s.vpc = an
		}
	}
	return nil
}

// Timings returns the instance containing current timeout settings
func (s *stack) Timings() (temporal.Timings, fail.Error) {
	if valid.IsNil(s) {
		return temporal.NewTimings(), fail.InvalidInstanceError()
	}
	if s.MutableTimings == nil {
		s.MutableTimings = temporal.NewTimings()
	}
	return s.MutableTimings, nil
}

func (s *stack) UpdateTags(ctx context.Context, kind abstract.Enum, id string, lmap map[string]string) fail.Error {
	if kind != abstract.HostResource {
		return fail.NotImplementedError("Tagging resources other than hosts not implemented yet")
	}

	xerr := s.rpcSetMetadataOfInstance(ctx, id, lmap)
	return xerr
}

func (s *stack) DeleteTags(ctx context.Context, kind abstract.Enum, id string, keys []string) fail.Error {
	if kind != abstract.HostResource {
		return fail.NotImplementedError("Tagging resources other than hosts not implemented yet")
	}

	report := make(map[string]string)
	for _, k := range keys {
		report[k] = ""
	}

	xerr := s.rpcDeleteMetadataOfInstance(ctx, id, report)
	return xerr
}
