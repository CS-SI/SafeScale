/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	secgroups "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"

	"github.com/CS-SI/SafeScale/iaas/stack"
	"github.com/CS-SI/SafeScale/iaas/stack/openstack"
)

// Stack is the implementation for huaweicloud cloud stack
type Stack struct {
	// Opts contains authentication options
	AuthOpts *stack.AuthenticationOptions
	// CfgOpts ...
	CfgOpts *stack.ConfigurationOptions
	// Identity contains service client of openstack Identity service
	Identity *gc.ServiceClient
	// osclt is the openstack.Stack instance to use when fully openstack compliant
	osclt *openstack.Stack
	// Instance of the VPC
	vpc *VPC
	// defaultSecurityGroup contains the name of the default security group for the VPC
	defaultSecurityGroup string
	// SecurityGroup is an instance of the default security group
	SecurityGroup *secgroups.SecGroup
}

// New authenticates and return interface Stack
func New(auth stack.AuthenticationOptions, cfg stack.ConfigurationOptions) (*Stack, error) {
	// gophercloud doesn't know how to determine Auth API version to use for FlexibleEngine.
	// So we help him to.
	if auth.IdentityEndpoint == "" {
		panic("auth.IdentityEndpoint is empty!")
	}

	authOptions := auth
	authOptions.Scope = tokens.Scope{
		ProjectName: auth.Region,
		DomainName:  auth.DomainName,
	}

	stack, err := openstack.New(auth, cfg)
	if err != nil {
		return nil, err
	}

	// Identity API
	identity, err := gcos.NewIdentityV3(stack.Driver, gc.EndpointOpts{})
	if err != nil {
		return nil, fmt.Errorf("%s", openstack.ErrorToString(err))
	}

	// Recover Project ID of region
	listOpts := projects.ListOpts{
		Enabled: gc.Enabled,
		Name:    opts.Region,
	}
	allPages, err := projects.List(identity, listOpts).AllPages()
	if err != nil {
		return nil, fmt.Errorf("failed to query project ID corresponding to region '%s': %s", opts.Region, openstack.ProviderErrorToString(err))
	}
	allProjects, err := projects.ExtractProjects(allPages)
	if err != nil {
		return nil, fmt.Errorf("failed to load project ID corresponding to region '%s': %s", opts.Region, openstack.ProviderErrorToString(err))
	}
	if len(allProjects) > 0 {
		opts.ProjectID = allProjects[0].ID
	} else {
		return nil, fmt.Errorf("failed to found project ID corresponding to region '%s': %s", opts.Region, openstack.ProviderErrorToString(err))
	}

	s := Stack{
		AuthOpts: &auth,
		CfgOpts:  &cfg,
		Identity: identity,
		osclt:    stack,
	}
	s.CfgOpts.UseFloatingIP = true

	// Initializes the VPC
	err = s.initVPC()
	if err != nil {
		return nil, err
	}

	// Initializes the default security group
	err = s.initDefaultSecurityGroup()
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
		Name: client.Opts.VPCName,
		CIDR: client.Opts.VPCCIDR,
	})
	if err != nil {
		return fmt.Errorf("Failed to initialize VPC '%s': %s", s.AuthOpts.VPCName, stack_openstack.ProviderErrorToString(err))
	}
	s.vpc = vpc
	return nil
}

// findVPC returns the ID about the VPC
func (s *Stack) findVPCID() (*string, error) {
	var router *openstack.Router
	found := false
	routers, err := s.osclt.ListRouters()
	if err != nil {
		return nil, fmt.Errorf("Error listing routers: %s", openstack.ErrorToString(err))
	}
	for _, r := range routers {
		if r.Name == s.AuthOpts.VPCName {
			found = true
			router = &r
			break
		}
	}
	if found {
		return &router.ID, nil
	}
	return nil, nil
}
