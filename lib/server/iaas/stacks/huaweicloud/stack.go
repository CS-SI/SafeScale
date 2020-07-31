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

    // Gophercloud OpenStack API
    "github.com/gophercloud/gophercloud"
    gcos "github.com/gophercloud/gophercloud/openstack"
    "github.com/gophercloud/gophercloud/openstack/identity/v3/projects"

    "github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
    "github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Stack is the implementation for huaweicloud cloud stack
type Stack struct {
    // use openstack stack when fully openstack compliant
    *openstack.Stack
    // Identity contains service client of openstack Identity service
    identityClient *gophercloud.ServiceClient
    // Opts contains authentication options
    authOpts stacks.AuthenticationOptions
    // CfgOpts ...
    cfgOpts stacks.ConfigurationOptions
    // Instance of the VPC
    vpc *VPC
}

// New authenticates and return interface Stack
func New(auth stacks.AuthenticationOptions, cfg stacks.ConfigurationOptions) (*Stack, fail.Error) {
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

    stack, xerr := openstack.New(auth, &scope, cfg, nil)
    if xerr != nil {
        return nil, xerr
    }

    // Identity API
    identity, err := gcos.NewIdentityV3(stack.Driver, gophercloud.EndpointOpts{})
    if err != nil {
        return nil, fail.NewError(openstack.ProviderErrorToString(err))
    }

    // Recover Project ID of region
    listOpts := projects.ListOpts{
        Enabled: gophercloud.Enabled,
        Name:    authOptions.Region,
    }
    allPages, err := projects.List(identity, listOpts).AllPages()
    if err != nil {
        return nil, fail.NewError("failed to query project ID corresponding to region '%s': %s", authOptions.Region, openstack.ProviderErrorToString(err))
    }
    allProjects, err := projects.ExtractProjects(allPages)
    if err != nil {
        return nil, fail.NewError("failed to load project ID corresponding to region '%s': %s", authOptions.Region, openstack.ProviderErrorToString(err))
    }
    if len(allProjects) > 0 {
        authOptions.ProjectID = allProjects[0].ID
    } else {
        return nil, fail.NewError("failed to found project ID corresponding to region '%s': %s", authOptions.Region, openstack.ProviderErrorToString(err))
    }

    s := Stack{
        authOpts:       auth,
        cfgOpts:        cfg,
        identityClient: identity,
        Stack:          stack,
    }
    s.cfgOpts.UseFloatingIP = true

    // Initializes the VPC
    xerr = s.initVPC()
    if xerr != nil {
        return nil, xerr
    }

    return &s, nil
}

// initVPC initializes the VPC if it doesn't exist
func (s *Stack) initVPC() fail.Error {
    // Tries to get VPC information
    vpcID, xerr := s.findVPCID()
    if xerr != nil {
        return xerr
    }
    if vpcID != nil {
        s.vpc, xerr = s.GetVPC(*vpcID)
        return xerr
    }

    vpc, xerr := s.CreateVPC(VPCRequest{
        Name: s.authOpts.VPCName,
        CIDR: s.authOpts.VPCCIDR,
    })
    if xerr != nil {
        return fail.NewError("failed to initialize VPC '%s'", s.authOpts.VPCName)
    }
    s.vpc = vpc
    return nil
}

// findVPC returns the ID about the VPC
func (s *Stack) findVPCID() (*string, fail.Error) {
    var router *openstack.Router
    found := false
    routers, err := s.Stack.ListRouters()
    if err != nil {
        return nil, fail.NewError("error listing routers: %s", openstack.ProviderErrorToString(err))
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
