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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or provideried.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package openstack

import (
	"fmt"

	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/secgroups"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/iaas/providers"
	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/iaas/resources/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/iaas/stacks"
	"github.com/CS-SI/SafeScale/iaas/stacks/openstack"
)

const (
	defaultSecurityGroup = "default"
)

// provider is the providerementation of the openstack provider respecting api.Provider
type provider struct {
	*openstack.Stack

	SecurityGroup     *secgroups.SecurityGroup
	ExternalNetworkID string
}

// New creates a new instance of pure openstack provider
func New() providers.Provider {
	return &provider{}
}

// Build build a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (providers.Provider, error) {
	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	network, _ := params["network"].(map[string]interface{})

	identityEndpoint, _ := identity["IdentityEndpoint"].(string)
	username, _ := identity["Username"].(string)
	password, _ := identity["Password"].(string)
	tenantName, _ := compute["TenantName"].(string)
	region, _ := compute["Region"].(string)
	floatingIPPool, _ := network["FloatingIPPool"].(string)
	providerNetwork, _ := network["ExternalNetwork"].(string)
	if providerNetwork == "" {
		providerNetwork = "public"
	}
	defaultImage, _ := compute["DefaultImage"].(string)
	dnsServers, _ := network["DNSServers"].([]string)
	if len(dnsServers) <= 0 {
		dnsServers = []string{"8.8.8.8", "1.1.1.1"}
	}

	authOptions := stacks.AuthenticationOptions{
		IdentityEndpoint: identityEndpoint,
		Username:         username,
		Password:         password,
		TenantName:       tenantName,
		Region:           region,
		FloatingIPPool:   floatingIPPool,
	}

	metadataBucketName, err := objectstorage.BuildMetadataBucketName("openstack", region, tenantName, "0")
	if err != nil {
		return nil, err
	}

	cfgOptions := stacks.ConfigurationOptions{
		ProviderNetwork:           providerNetwork,
		UseFloatingIP:             true,
		UseLayer3Networking:       true,
		AutoHostNetworkInterfaces: true,
		VolumeSpeeds: map[string]VolumeSpeed.Enum{
			"standard":   VolumeSpeed.COLD,
			"performant": VolumeSpeed.HDD,
		},
		DNSList:        dnsServers,
		DefaultImage:   defaultImage,
		MetadataBucket: metadataBucketName,
	}

	stack, err := openstack.New(authOptions, nil, cfgOptions)
	if err != nil {
		return nil, err
	}
	newP := &provider{Stack: stack}
	err = newP.initDefaultSecurityGroup()
	if err != nil {
		return nil, err
	}
	return newP, nil
}

// getDefaultSecurityGroup returns the default security group
func (p *provider) getDefaultSecurityGroup() (*secgroups.SecurityGroup, error) {
	var sgList []secgroups.SecurityGroup

	err := secgroups.List(p.Stack.ComputeClient).EachPage(func(page pagination.Page) (bool, error) {
		list, err := secgroups.ExtractSecurityGroups(page)
		if err != nil {
			return false, err
		}
		for _, e := range list {
			if e.Name == defaultSecurityGroup {
				sgList = append(sgList, e)
			}
		}
		return true, nil
	})
	if len(sgList) == 0 {
		return nil, err
	}
	if len(sgList) > 1 {
		return nil, fmt.Errorf("Configuration error: More than one default security groups exists")
	}

	return &sgList[0], nil
}

// createTCPRules creates TCP rules to configure the default security group
func (p *provider) createTCPRules(groupID string) error {
	// Open TCP Ports
	ruleOpts := secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      1,
		ToPort:        65535,
		IPProtocol:    "TCP",
		CIDR:          "0.0.0.0/0",
	}

	_, err := secgroups.CreateRule(p.Stack.ComputeClient, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      1,
		ToPort:        65535,
		IPProtocol:    "TCP",
		CIDR:          "::/0",
	}
	_, err = secgroups.CreateRule(p.Stack.ComputeClient, ruleOpts).Extract()
	return err
}

// createTCPRules creates UDP rules to configure the default security group
func (p *provider) createUDPRules(groupID string) error {
	// Open UDP Ports
	ruleOpts := secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      1,
		ToPort:        65535,
		IPProtocol:    "UDP",
		CIDR:          "0.0.0.0/0",
	}

	_, err := secgroups.CreateRule(p.Stack.ComputeClient, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      1,
		ToPort:        65535,
		IPProtocol:    "UDP",
		CIDR:          "::/0",
	}
	_, err = secgroups.CreateRule(p.Stack.ComputeClient, ruleOpts).Extract()
	return err
}

// createICMPRules creates UDP rules to configure the default security group
func (p *provider) createICMPRules(groupID string) error {
	// Open TCP Ports
	ruleOpts := secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      -1,
		ToPort:        -1,
		IPProtocol:    "ICMP",
		CIDR:          "0.0.0.0/0",
	}

	_, err := secgroups.CreateRule(p.Stack.ComputeClient, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      -1,
		ToPort:        -1,
		IPProtocol:    "ICMP",
		CIDR:          "::/0",
	}
	_, err = secgroups.CreateRule(p.Stack.ComputeClient, ruleOpts).Extract()
	return err
}

// initDefaultSecurityGroup create an open Security Group
// The default security group opens all TCP, UDP, ICMP ports
// Security is managed individually on each host using a linux firewall
func (p *provider) initDefaultSecurityGroup() error {
	sg, err := p.getDefaultSecurityGroup()
	if err != nil {
		return err
	}
	if sg != nil {
		p.SecurityGroup = sg
		return nil
	}
	opts := secgroups.CreateOpts{
		Name:        defaultSecurityGroup,
		Description: "Default security group",
	}

	group, err := secgroups.Create(p.Stack.ComputeClient, opts).Extract()
	if err != nil {
		return err
	}
	err = p.createTCPRules(group.ID)
	if err != nil {
		secgroups.Delete(p.Stack.ComputeClient, group.ID)
		return err
	}

	err = p.createUDPRules(group.ID)
	if err != nil {
		secgroups.Delete(p.Stack.ComputeClient, group.ID)
		return err
	}
	err = p.createICMPRules(group.ID)
	if err != nil {
		secgroups.Delete(p.Stack.ComputeClient, group.ID)
		return err
	}
	p.SecurityGroup = group
	return nil
}

// GetAuthOpts returns the auth options
func (p *provider) GetAuthOpts() (providers.Config, error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.GetAuthenticationOptions()
	cfg.Set("TenantName", opts.TenantName)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthUrl", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)
	return cfg, nil
}

// GetCfgOpts return configuration parameters
func (p *provider) GetCfgOpts() (providers.Config, error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.GetConfigurationOptions()
	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("DefaultImage", opts.DefaultImage)
	return cfg, nil
}

// ListTemplates ...
// Value of all has no impact on the result
func (p *provider) ListTemplates(all bool) ([]resources.HostTemplate, error) {
	allTemplates, err := p.Stack.ListTemplates()
	if err != nil {
		return nil, err
	}
	return allTemplates, nil
}

// ListImages ...
// Value of all has no impact on the result
func (p *provider) ListImages(all bool) ([]resources.Image, error) {
	allImages, err := p.Stack.ListImages()
	if err != nil {
		return nil, err
	}
	return allImages, nil
}

// init registers the openstack provider
func init() {
	iaas.Register("openstack", &provider{})
}
