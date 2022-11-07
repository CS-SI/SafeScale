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

package openstack // Package openstack contains the implemenation of a stack for OpenStack providers

import (
	context2 "context"
	"strings"

	iaasoptions "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/options"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"golang.org/x/net/context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// stack contains the needs to operate on stack OpenStack
type stack struct {
	ComputeClient  *gophercloud.ServiceClient
	NetworkClient  *gophercloud.ServiceClient
	VolumeClient   *gophercloud.ServiceClient
	IdentityClient *gophercloud.ServiceClient
	Driver         *gophercloud.ProviderClient

	authOpts iaasoptions.Authentication
	cfgOpts  iaasoptions.Configuration

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

// NullStack returns a null value of the stack
func NullStack() *stack { // nolint
	return &stack{}
}

// New authenticates and returns a stack pointer
func New(auth iaasoptions.Authentication, authScope *gophercloud.AuthScope, cfg iaasoptions.Configuration, serviceVersions map[string]string) (*stack, fail.Error) { // nolint
	ctx := context.Background()

	if auth.DomainName == "" && auth.DomainID == "" {
		auth.DomainName = "Default"
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
		Scope:            authScope,
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
	for k, v := range serviceVersions {
		s.versions[k] = v
	}

	// Openstack client
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			var innerErr error
			s.Driver, innerErr = openstack.AuthenticatedClient(gcOpts)
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
			s.IdentityClient, innerErr = openstack.NewIdentityV2(s.Driver, endpointOpts)
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
				s.ComputeClient, innerErr = openstack.NewComputeV2(s.Driver, endpointOpts)
				return innerErr
			},
			NormalizeError,
		)
	default:
		return nil, fail.NotImplementedError("unmanaged Openstack service 'compute' version '%s'", serviceVersions["compute"])
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
				s.NetworkClient, innerErr = openstack.NewNetworkV2(s.Driver, endpointOpts)
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
				s.VolumeClient, innerErr = openstack.NewBlockStorageV1(s.Driver, endpointOpts)
				return innerErr
			},
			NormalizeError,
		)
	case "v2":
		xerr = stacks.RetryableRemoteCall(ctx,
			func() error {
				var innerErr error
				s.VolumeClient, innerErr = openstack.NewBlockStorageV2(s.Driver, endpointOpts)
				return innerErr
			},
			NormalizeError,
		)
	default:
		return nil, fail.NotImplementedError("unmanaged service 'volumes' version '%s'", serviceVersions["volumes"])
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

	// Note: If timeouts and/or delays have to be adjusted, do it here in stack.timeouts and/or stack.delays
	if cfg.Timings != nil {
		s.MutableTimings = cfg.Timings
		_ = s.MutableTimings.Update(temporal.NewTimings())
	} else {
		s.MutableTimings = temporal.NewTimings()
	}

	return s, nil
}

// IsNull ...
func (instance *stack) IsNull() bool {
	return instance == nil || instance.Driver == nil
}

// GetStackName returns the name of the stack
func (instance stack) GetStackName() (string, fail.Error) {
	return "openstack", nil
}

// Timings returns the instance containing current timeout settings
func (instance *stack) Timings() (temporal.Timings, fail.Error) {
	if instance == nil {
		return temporal.NewTimings(), fail.InvalidInstanceError()
	}
	if instance.MutableTimings == nil {
		instance.MutableTimings = temporal.NewTimings()
	}
	return instance.MutableTimings, nil
}

func (instance *stack) UpdateTags(ctx context2.Context, kind abstract.Enum, id string, lmap map[string]string) fail.Error {
	if kind != abstract.HostResource {
		return fail.NotImplementedError("Tagging resources other than hosts not implemented yet")
	}

	xerr := instance.rpcSetMetadataOfInstance(ctx, id, lmap)
	return xerr
}

func (instance *stack) DeleteTags(ctx context2.Context, kind abstract.Enum, id string, keys []string) fail.Error {
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
