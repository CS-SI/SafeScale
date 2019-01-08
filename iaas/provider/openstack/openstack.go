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

package openstack

import (
	"fmt"

	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/secgroups"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/model"
	"github.com/CS-SI/SafeScale/iaas/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/iaas/provider"
	"github.com/CS-SI/SafeScale/iaas/provider/api"
	"github.com/CS-SI/SafeScale/iaas/stack"
	"github.com/CS-SI/SafeScale/iaas/stack/openstack"
)

// impl is the implementation of the openstack provider respecting api.Provider
type impl struct {
	*openstack.Stack

	SecurityGroup     *secgroups.SecurityGroup
	ExternalNetworkID string
}

// Build build a new Client from configuration parameter
func (p *impl) Build(params map[string]interface{}) (api.Provider, error) {
	identityEndpoint, _ := params["IdentityEndpoint"].(string)
	username, _ := params["Username"].(string)
	password, _ := params["Password"].(string)
	tenantName, _ := params["TenantName"].(string)
	region, _ := params["Region"].(string)
	floatingIPPool, _ := params["FloatingIPPool"].(string)
	providerNetwork, _ := params["ExternalNetwork"].(string)
	if providerNetwork == "" {
		providerNetwork = "public"
	}
	defaultImage, _ := params["DefaultImage"].(string)
	dnsServers, _ := params["DNSServers"].([]string)
	if len(dnsServers) <= 0 {
		dnsServers = []string{"8.8.8.8", "1.1.1.1"}
	}

	authOptions := &stack.AuthenticationOptions{
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

	cfgOptions := &stack.ConfigurationOptions{
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

	var err error
	stack, err := openstack.New(authOptions, cfgOptions)
	if err != nil {
		return nil, err
	}
	newP := &impl{Stack: stack}
	err = newP.initDefaultSecurityGroup()
	if err != nil {
		return nil, err
	}
	return newP, nil
}

// getDefaultSecurityGroup returns the default security group
func (p *impl) getDefaultSecurityGroup() (*secgroups.SecurityGroup, error) {
	var sgList []secgroups.SecurityGroup

	err := secgroups.List(p.Stack.Compute).EachPage(func(page pagination.Page) (bool, error) {
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
func (p *impl) createTCPRules(groupID string) error {
	// Open TCP Ports
	ruleOpts := secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      1,
		ToPort:        65535,
		IPProtocol:    "TCP",
		CIDR:          "0.0.0.0/0",
	}

	_, err := secgroups.CreateRule(p.Stack.Compute, ruleOpts).Extract()
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
	_, err = secgroups.CreateRule(p.Stack.Compute, ruleOpts).Extract()
	return err
}

// createTCPRules creates UDP rules to configure the default security group
func (p *impl) createUDPRules(groupID string) error {
	// Open UDP Ports
	ruleOpts := secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      1,
		ToPort:        65535,
		IPProtocol:    "UDP",
		CIDR:          "0.0.0.0/0",
	}

	_, err := secgroups.CreateRule(p.Stack.Compute, ruleOpts).Extract()
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
	_, err = secgroups.CreateRule(p.Stack.Compute, ruleOpts).Extract()
	return err
}

// createICMPRules creates UDP rules to configure the default security group
func (p *impl) createICMPRules(groupID string) error {
	// Open TCP Ports
	ruleOpts := secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      -1,
		ToPort:        -1,
		IPProtocol:    "ICMP",
		CIDR:          "0.0.0.0/0",
	}

	_, err := secgroups.CreateRule(p.Stack.Compute, ruleOpts).Extract()
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
	_, err = secgroups.CreateRule(p.Stack.Compute, ruleOpts).Extract()
	return err
}

// initDefaultSecurityGroup create an open Security Group
// The default security group opens all TCP, UDP, ICMP ports
// Security is managed individually on each host using a linux firewall
func (p *impl) initDefaultSecurityGroup() error {
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

	group, err := secgroups.Create(p.Stack.Compute, opts).Extract()
	if err != nil {
		return err
	}
	err = p.createTCPRules(group.ID)
	if err != nil {
		secgroups.Delete(p.Stack.Compute, group.ID)
		return err
	}

	err = p.createUDPRules(group.ID)
	if err != nil {
		secgroups.Delete(p.Stack.Compute, group.ID)
		return err
	}
	err = p.createICMPRules(group.ID)
	if err != nil {
		secgroups.Delete(p.Stack.Compute, group.ID)
		return err
	}
	p.SecurityGroup = group
	return nil
}

// GetAuthOpts returns the auth options
func (p *impl) GetAuthOpts() (provider.Config, error) {
	cfg := provider.ConfigMap{}

	cfg.Set("TenantName", p.Stack.AuthOpts.TenantName)
	cfg.Set("Login", p.Stack.AuthOpts.Username)
	cfg.Set("Password", p.Stack.AuthOpts.Password)
	cfg.Set("AuthUrl", p.Stack.AuthOpts.IdentityEndpoint)
	cfg.Set("Region", p.Stack.AuthOpts.Region)
	return cfg, nil
}

// GetCfgOpts return configuration parameters
func (p *impl) GetCfgOpts() (provider.Config, error) {
	cfg := provider.ConfigMap{}

	cfg.Set("DNSList", p.Stack.CfgOpts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", p.Stack.CfgOpts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", p.Stack.CfgOpts.UseLayer3Networking)
	cfg.Set("DefaultImage", p.Stack.CfgOpts.DefaultImage)
	return cfg, nil
}

// ListTemplates ...
// Value of all has no impact on the result
func (p *impl) ListTemplates(all bool) ([]model.HostTemplate, error) {
	allTemplates, err := p.Stack.ListTemplates()
	if err != nil {
		return nil, err
	}
	return allTemplates, nil
}

// ListImages ...
// Value of all has no impact on the result
func (p *impl) ListImages(all bool) ([]model.Image, error) {
	allImages, err := p.Stack.ListImages()
	if err != nil {
		return nil, err
	}
	return allImages, nil
}

// init registers the openstack provider
func init() {
	iaas.Register("openstack", &impl{})
}
