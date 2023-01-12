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
	"strings"

	// Gophercloud OpenStack API
	"github.com/gophercloud/gophercloud"
	gcos "github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/regions"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// stack is the implementation for huaweicloud cloud stack
type stack struct {
	ComputeClient  *gophercloud.ServiceClient
	NetworkClient  *gophercloud.ServiceClient
	IdentityClient *gophercloud.ServiceClient
	VolumeClient   *gophercloud.ServiceClient
	Driver         *gophercloud.ProviderClient
	// Opts contains authentication options
	authOpts iaasoptions.Authentication
	cfgOpts  iaasoptions.Configuration
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

// NullStack is not exposed through API, is needed essentially by tests
func NullStack() *stack { // nolint
	return &stack{}
}

// New authenticates and return interface stack
//
//goland:noinspection GoExportedFuncWithUnexportedType
func New(auth iaasoptions.Authentication, cfg iaasoptions.Configuration) (*stack, fail.Error) { // nolint
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
		"compute": "v2",
		"volume":  "v2",
		"network": "v2",
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
		return nil, fail.NotImplementedError("unmanaged Openstack service 'compute' version '%s'", s.versions["compute"])
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
		return nil, fail.NotImplementedError("unmanaged Openstack service 'network' version '%s'", s.versions["network"])
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
		return nil, fail.NotImplementedError("unmanaged service 'volumes' version '%s'", s.versions["volumes"])
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
			debug.IgnoreErrorWithContext(ctx, xerr)
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

	// Note: If timeouts and/or delays have to be adjusted, do it here in stack.timeouts and/or stack.delays
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
func (instance *stack) ListRegions(ctx context.Context) (list []string, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.huaweicloud") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering().Exiting()

	var allPages pagination.Page
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			listOpts := regions.ListOpts{
				// ParentRegionID: "RegionOne",
			}
			allPages, innerErr = regions.List(instance.IdentityClient, listOpts).AllPages()
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
func (instance *stack) InspectTemplate(ctx context.Context, id string) (template *abstract.HostTemplate, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if instance.ComputeClient == nil {
		return nil, fail.InvalidInstanceContentError("instance.ComputeClient", "cannot be nil")
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.huaweicloud") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Try to get template
	var flv *flavors.Flavor
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			flv, innerErr = flavors.Get(instance.ComputeClient, id).Extract()
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
func (instance *stack) CreateKeyPair(ctx context.Context, name string) (*abstract.KeyPair, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.huaweicloud") || tracing.ShouldTrace("stacks.compute"), "(%s)", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	return abstract.NewKeyPair(name)
}

// InspectKeyPair returns the key pair identified by id
func (instance *stack) InspectKeyPair(ctx context.Context, id string) (*abstract.KeyPair, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if instance.ComputeClient == nil {
		return nil, fail.InvalidInstanceContentError("instance.ComputeClient", "cannot be nil")
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.huaweicloud") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	kp, err := keypairs.Get(instance.ComputeClient, id, nil).Extract()
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
func (instance *stack) ListKeyPairs(ctx context.Context) ([]*abstract.KeyPair, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if instance.ComputeClient == nil {
		return nil, fail.InvalidInstanceContentError("instance.ComputeClient", "cannot be nil")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.huaweicloud") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering().Exiting()

	var kpList []*abstract.KeyPair
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			return keypairs.List(instance.ComputeClient, nil).EachPage(
				func(page pagination.Page) (bool, error) {
					list, err := keypairs.ExtractKeyPairs(page)
					if err != nil {
						return false, err
					}

					for _, v := range list {
						item := &abstract.KeyPair{
							ID:         v.Name,
							Name:       v.Name,
							PublicKey:  v.PublicKey,
							PrivateKey: v.PrivateKey,
						}
						kpList = append(kpList, item)
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
	// Note: empty list is not an error, so do not raise one
	return kpList, nil
}

// DeleteKeyPair deletes the key pair identified by id
func (instance *stack) DeleteKeyPair(ctx context.Context, id string) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if instance.ComputeClient == nil {
		return fail.InvalidInstanceContentError("instance.ComputeClient", "cannot be nil")
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.huaweicloud") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering().Exiting()

	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			return keypairs.Delete(instance.ComputeClient, id, nil).ExtractErr()
		},
		NormalizeError,
	)
	if xerr != nil {
		return xerr
	}
	return nil
}

// AddPublicIPToVIP adds a public IP to VIP
func (instance *stack) AddPublicIPToVIP(ctx context.Context, vip *abstract.VirtualIP) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (instance *stack) BindHostToVIP(ctx context.Context, vip *abstract.VirtualIP, hostID string) fail.Error {
	if valid.IsNil(instance) {
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
			vipPort, innerErr = ports.Get(instance.NetworkClient, vip.ID).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return xerr
	}
	hostPorts, xerr := instance.rpcListPorts(ctx, ports.ListOpts{
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
				_, innerErr := ports.Update(instance.NetworkClient, p.ID, ports.UpdateOpts{AllowedAddressPairs: &p.AllowedAddressPairs}).Extract()
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
func (instance *stack) UnbindHostFromVIP(ctx context.Context, vip *abstract.VirtualIP, hostID string) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if instance.ComputeClient == nil {
		return fail.InvalidInstanceContentError("instance.ComputeClient", "cannot be nil")
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
			vipPort, innerErr = ports.Get(instance.NetworkClient, vip.ID).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return xerr
	}
	hostPorts, xerr := instance.rpcListPorts(ctx, ports.ListOpts{
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
				_, innerErr := ports.Update(instance.NetworkClient, p.ID, ports.UpdateOpts{AllowedAddressPairs: &newAllowedAddressPairs}).Extract()
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
func (instance *stack) DeleteVIP(ctx context.Context, vip *abstract.VirtualIP) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if instance.NetworkClient == nil {
		return fail.InvalidInstanceContentError("instance.NetworkClient", "cannot be nil")
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}

	for _, v := range vip.Hosts {
		xerr := instance.UnbindHostFromVIP(ctx, vip, v.ID)
		if xerr != nil {
			return xerr
		}
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return ports.Delete(instance.NetworkClient, vip.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// ClearHostStartupScript clears the userdata startup script for Host instance (metadata service)
// Does nothing for OpenStack, userdata cannot be updated
func (instance *stack) ClearHostStartupScript(ctx context.Context, hostParam iaasapi.HostIdentifier) fail.Error {
	return nil
}

func (instance *stack) ChangeSecurityGroupSecurity(ctx context.Context, b bool, b2 bool, net string, s2 string) fail.Error {
	return nil
}

func (instance *stack) Migrate(ctx context.Context, operation string, params map[string]interface{}) fail.Error {
	if operation == "networklayers" {
		abstractSubnet, ok := params["layer"].(*abstract.Subnet)
		if !ok {
			return fail.InvalidParameterError("params[layer]", "should be *abstract.Subnet")
		}
		// huaweicloud added a layer called "IPv4 SubnetID", which is returned as SubnetID but is not; Network is the real "OpenStack" Subnet ID
		// FIXME: maybe huaweicloud has to be reviewed/rewritten not to use a mix of pure OpenStack API and customized Huaweicloud API?
		abstractSubnet.ID = abstractSubnet.Network
	}

	return nil
}

// IsNull ...
func (instance *stack) IsNull() bool {
	return instance == nil || instance.Driver == nil
}

// GetStackName returns the name of the stack
func (instance *stack) GetStackName() (string, fail.Error) {
	return "huaweicloud", nil
}

// initVPC initializes the instance of the Networking/VPC if one is defined in tenant
func (instance *stack) initVPC(ctx context.Context) fail.Error {
	if instance.cfgOpts.DefaultNetworkName != "" {
		an, xerr := instance.InspectNetworkByName(ctx, instance.cfgOpts.DefaultNetworkName)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// FIXME: error or automatic DefaultNetwork creation ?
				debug.IgnoreErrorWithContext(ctx, xerr)
			default:
				return xerr
			}
		} else {
			instance.vpc = an
		}
	}
	return nil
}

// Timings returns the instance containing current timeout settings
func (instance *stack) Timings() (temporal.Timings, fail.Error) {
	if valid.IsNil(instance) {
		return temporal.NewTimings(), fail.InvalidInstanceError()
	}
	if instance.MutableTimings == nil {
		instance.MutableTimings = temporal.NewTimings()
	}
	return instance.MutableTimings, nil
}

func (instance *stack) UpdateTags(ctx context.Context, kind abstract.Enum, id string, lmap map[string]string) fail.Error {
	if kind != abstract.HostResource {
		return fail.NotImplementedError("Tagging resources other than hosts not implemented yet")
	}

	xerr := instance.rpcSetMetadataOfInstance(ctx, id, lmap)
	return xerr
}

func (instance *stack) DeleteTags(ctx context.Context, kind abstract.Enum, id string, keys []string) fail.Error {
	if kind != abstract.HostResource {
		return fail.NotImplementedError("Tagging resources other than hosts not implemented yet")
	}

	report := make(map[string]string)
	for _, k := range keys {
		report[k] = ""
	}

	xerr := instance.rpcDeleteMetadataOfInstance(ctx, id, report)
	return xerr
}
