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
	"fmt"

	// Gophercloud OpenStack API
	gc "github.com/gophercloud/gophercloud"
	gcos "github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// Stack is the implementation for huaweicloud cloud stack
type Stack struct {
	// use openstack stack when fully openstack compliant
	*openstack.Stack
	// Identity contains service client of openstack Identity service
	identityClient *gc.ServiceClient
	// Opts contains authentication options
	authOpts stacks.AuthenticationOptions
	// CfgOpts ...
	cfgOpts stacks.ConfigurationOptions
	// Instance of the VPC
	vpc *VPC
}

// New authenticates and return interface Stack
func New(auth stacks.AuthenticationOptions, cfg stacks.ConfigurationOptions) (*Stack, error) {
	// gophercloud doesn't know how to determine Auth API version to use for FlexibleEngine.
	// So we help him to.
	if auth.IdentityEndpoint == "" {
		return nil, scerr.InvalidParameterError("auth.IdentityEndpoint", "cannot be empty string")
	}

	authOptions := auth
	scope := gc.AuthScope{
		ProjectName: auth.Region,
		DomainName:  auth.DomainName,
	}

	stack, err := openstack.New(auth, &scope, cfg, nil)
	if err != nil {
		return nil, err
	}

	// Identity API
	identity, err := gcos.NewIdentityV3(stack.Driver, gc.EndpointOpts{})
	if err != nil {
		return nil, fmt.Errorf("%s", openstack.ProviderErrorToString(err))
	}

	// Recover Project ID of region
	listOpts := projects.ListOpts{
		Enabled: gc.Enabled,
		Name:    authOptions.Region,
	}
	allPages, err := projects.List(identity, listOpts).AllPages()
	if err != nil {
		return nil, fmt.Errorf("failed to query project ID corresponding to region '%s': %s", authOptions.Region, openstack.ProviderErrorToString(err))
	}
	allProjects, err := projects.ExtractProjects(allPages)
	if err != nil {
		return nil, fmt.Errorf("failed to load project ID corresponding to region '%s': %s", authOptions.Region, openstack.ProviderErrorToString(err))
	}
	if len(allProjects) > 0 {
		authOptions.ProjectID = allProjects[0].ID
	} else {
		return nil, fmt.Errorf("failed to found project ID corresponding to region '%s': %s", authOptions.Region, openstack.ProviderErrorToString(err))
	}

	s := Stack{
		authOpts:       auth,
		cfgOpts:        cfg,
		identityClient: identity,
		Stack:          stack,
	}
	s.cfgOpts.UseFloatingIP = true

	// Initializes the VPC
	err = s.initVPC()
	if err != nil {
		return nil, err
	}

	return &s, nil
}

// initVPC initializes the VPC if it doesn't exist
func (s *Stack) initVPC() error {
	// Tries to get VPC information
	vpcID, err := s.findVPCID()
	if err != nil {
		return err
	}
	if vpcID != nil {
		s.vpc, err = s.GetVPC(*vpcID)
		return err
	}

	vpc, err := s.CreateVPC(VPCRequest{
		Name: s.authOpts.VPCName,
		CIDR: s.authOpts.VPCCIDR,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize VPC '%s': %s", s.authOpts.VPCName, openstack.ProviderErrorToString(err))
	}
	s.vpc = vpc
	return nil
}

// findVPC returns the ID about the VPC
func (s *Stack) findVPCID() (*string, error) {
	var router *openstack.Router
	found := false
	routers, err := s.Stack.ListRouters()
	if err != nil {
		return nil, fmt.Errorf("error listing routers: %s", openstack.ProviderErrorToString(err))
	}
	for _, r := range routers {
		if r.Name == s.authOpts.VPCName {
			found = true
			router = &r
			break
		}
	}
	if found && router != nil {
		return &router.ID, nil
	}
	return nil, nil
}
