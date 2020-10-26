/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package openstack

import (
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// Stack contains the needs to operate on Stack OpenStack
type Stack struct {
	ComputeClient  *gophercloud.ServiceClient
	NetworkClient  *gophercloud.ServiceClient
	VolumeClient   *gophercloud.ServiceClient
	IdentityClient *gophercloud.ServiceClient
	Driver         *gophercloud.ProviderClient

	authOpts stacks.AuthenticationOptions
	cfgOpts  stacks.ConfigurationOptions

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

// NullStacks returns a null value of the stack
func NullStack() *Stack {
	return &Stack{}
}

// New authenticates and returns a Stack pointer
func New(auth stacks.AuthenticationOptions, authScope *gophercloud.AuthScope, cfg stacks.ConfigurationOptions, serviceVersions map[string]string) (*Stack, fail.Error) {
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

	s := Stack{
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
	for k, v := range serviceVersions {
		s.versions[k] = v
	}

	// Openstack client
	xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			var innerErr error
			s.Driver, innerErr = openstack.AuthenticatedClient(gcOpts)
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}

	// Identity API
	endpointOpts := gophercloud.EndpointOpts{Region: auth.Region}
	xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			var innerErr error
			s.IdentityClient, innerErr = openstack.NewIdentityV2(s.Driver, endpointOpts)
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}

	// Compute API
	//endpointOpts := gophercloud.EndpointOpts{Region: auth.Region}
	switch s.versions["compute"] {
	case "v2":
		xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
			func() error {
				var innerErr error
				s.ComputeClient, innerErr = openstack.NewComputeV2(s.Driver, endpointOpts)
				return NormalizeError(innerErr)
			},
			temporal.GetCommunicationTimeout(),
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
		xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
			func() error {
				var innerErr error
				s.NetworkClient, innerErr = openstack.NewNetworkV2(s.Driver, endpointOpts)
				return NormalizeError(innerErr)
			},
			temporal.GetCommunicationTimeout(),
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
		xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
			func() error {
				var innerErr error
				s.VolumeClient, innerErr = openstack.NewBlockStorageV1(s.Driver, endpointOpts)
				return NormalizeError(innerErr)
			},
			temporal.GetCommunicationTimeout(),
		)
	case "v2":
		xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
			func() error {
				var innerErr error
				s.VolumeClient, innerErr = openstack.NewBlockStorageV2(s.Driver, endpointOpts)
				return NormalizeError(innerErr)
			},
			temporal.GetCommunicationTimeout(),
		)
	default:
		return nil, fail.NotImplementedError("unmanaged service 'volumes' version '%s'", serviceVersions["volumes"])
	}
	if xerr != nil {
		return nil, xerr
	}

	// Get provider network ID from network service
	if cfg.ProviderNetwork != "" {
		xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
			func() error {
				var innerErr error
				s.ProviderNetworkID, innerErr = networks.IDFromName(s.NetworkClient, cfg.ProviderNetwork)
				return NormalizeError(innerErr)
			},
			temporal.GetCommunicationTimeout(),
		)
		if xerr != nil {
			return nil, xerr
		}
	}

	return &s, nil
}

// IsNull ...
func (s *Stack) IsNull() bool {
	return s == nil || s.Driver == nil
}
