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

package huaweicloud

import (
	// Gophercloud OpenStack API
	"github.com/gophercloud/gophercloud"
	gcos "github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// stack is the implementation for huaweicloud cloud stack
type stack struct {
	// use openstack Stack when fully openstack compliant
	*openstack.Stack
	// Identity contains service client of openstack Identity service
	identityClient *gophercloud.ServiceClient
	// Opts contains authentication options
	authOpts stacks.AuthenticationOptions
	// CfgOpts ...
	cfgOpts stacks.ConfigurationOptions
	// Instance of the default Network/VPC
	vpc *abstract.Network
}

// NullStack is not exposed through API, is needed essentially by testss
func NullStack() *stack {
	return &stack{}
}

// New authenticates and return interface Stack
func New(auth stacks.AuthenticationOptions, cfg stacks.ConfigurationOptions) (api.Stack, fail.Error) {
	// gophercloud doesn't know how to determine Auth API version to use for FlexibleEngine.
	// So we help him to.
	if auth.IdentityEndpoint == "" {
		return nil, fail.InvalidParameterError("auth.IdentityEndpoint", "cannot be empty string")
	}

	authOptions := auth
	scope := gophercloud.AuthScope{
		ProjectName: auth.Region,
		DomainName:  auth.DomainName,
	}

	parentStack, xerr := openstack.New(auth, &scope, cfg, nil)
	if xerr != nil {
		return nil, xerr
	}

	// Identity API
	var identity *gophercloud.ServiceClient
	commRetryErr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			identity, innerErr = gcos.NewIdentityV3(parentStack.Driver, gophercloud.EndpointOpts{})
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

	s := stack{
		authOpts:       auth,
		cfgOpts:        cfg,
		identityClient: identity,
		Stack:          parentStack,
	}
	s.cfgOpts.UseFloatingIP = true

	// Initializes the VPC
	xerr = s.initVPC()
	if xerr != nil {
		return nil, xerr
	}

	return &s, nil
}

// initVPC initializes the instance of the Networking/VPC if one is defined in tenant
func (s *stack) initVPC() fail.Error {
	if s.cfgOpts.DefaultNetworkName != "" {
		an, xerr := s.InspectNetworkByName(s.cfgOpts.DefaultNetworkName)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// FIXME: error or automatic DefaultNetwork creation ?
				//// VPC not found, create it
				//req := abstract.NetworkRequest{
				//	Name: s.authOpts.DefaultNetworkName,
				//	CIDR: s.authOpts.DefaultNetworkCIDR,
				//}
				//an, xerr = s.CreateNetwork(req)
				//if xerr != nil {
				//	return fail.NewError("failed to initialize VPC '%s'", s.authOpts.DefaultNetworkName)
				//}
				//s.vpc = an
			default:
				return xerr
			}
		} else {
			s.vpc = an
		}
	}
	return nil
}
