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

	"github.com/CS-SI/SafeScale/iaas/provider"
	"github.com/CS-SI/SafeScale/iaas/provider/api"
	"github.com/CS-SI/SafeScale/iaas/resource/enums/VolumeSpeed"

	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/secgroups"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/iaas/stack/openstack"
)

// Openstack is the implementation of the openstack provider respecting api.Provider
type Openstack struct {
	Opts  *AuthOptions
	Cfg   *CfgOptions
	stack *openstack.Stack

	SecurityGroup     *secgroups.SecurityGroup
	ProviderNetworkID string
}

// Build build a new Client from configuration parameter
func (p *Openstack) Build(params map[string]interface{}) (api.Provider, error) {
	IdentityEndpoint, _ := params["IdentityEndpoint"].(string)
	Username, _ := params["Username"].(string)
	Password, _ := params["Password"].(string)
	TenantName, _ := params["TenantName"].(string)
	Region, _ := params["Region"].(string)
	FloatingIPPool, _ := params["FloatingIPPool"].(string)
	newP := OpenStack{
		AuthOpts: AuthOptions{
			IdentityEndpoint: IdentityEndpoint,
			Username:         Username,
			Password:         Password,
			TenantName:       TenantName,
			Region:           Region,
			FloatingIPPool:   FloatingIPPool,
		},
		CfgOpts: CfgOptions{
			ProviderNetwork:           "public",
			UseFloatingIP:             true,
			UseLayer3Networking:       true,
			AutoHostNetworkInterfaces: true,
			VolumeSpeeds: map[string]VolumeSpeed.Enum{
				"standard":   VolumeSpeed.COLD,
				"performant": VolumeSpeed.HDD,
			},
			DNSList:    []string{"185.23.94.244", "185.23.94.244"},
			S3Protocol: "swiftks",
		},
	}
	newP.stack, err = openstack.New(newP.AuthOpts, newP.CfgOpts)
	if err != nil {
		return nil, err
	}
	err = newP.initDefaultSecurityGroup()
	if err != nil {
		return nil, err
	}
	return &newP, err
}

// getDefaultSecurityGroup returns the default security group
func (p *Openstack) getDefaultSecurityGroup() (*secgroups.SecurityGroup, error) {
	var sgList []secgroups.SecurityGroup

	err := secgroups.List(p.stack.Compute).EachPage(func(page pagination.Page) (bool, error) {
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
func (p *Openstack) createTCPRules(groupID string) error {
	// Open TCP Ports
	ruleOpts := secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      1,
		ToPort:        65535,
		IPProtocol:    "TCP",
		CIDR:          "0.0.0.0/0",
	}

	_, err := secgroups.CreateRule(p.stack.Compute, ruleOpts).Extract()
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
	_, err = secgroups.CreateRule(p.stack.Compute, ruleOpts).Extract()
	return err
}

// createTCPRules creates UDP rules to configure the default security group
func (p *Openstack) createUDPRules(groupID string) error {
	// Open UDP Ports
	ruleOpts := secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      1,
		ToPort:        65535,
		IPProtocol:    "UDP",
		CIDR:          "0.0.0.0/0",
	}

	_, err := secgroups.CreateRule(p.stack.Compute, ruleOpts).Extract()
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
	_, err = secgroups.CreateRule(p.stack.Compute, ruleOpts).Extract()
	return err
}

// createICMPRules creates UDP rules to configure the default security group
func (p *Openstack) createICMPRules(groupID string) error {
	// Open TCP Ports
	ruleOpts := secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      -1,
		ToPort:        -1,
		IPProtocol:    "ICMP",
		CIDR:          "0.0.0.0/0",
	}

	_, err := secgroups.CreateRule(p.stack.Compute, ruleOpts).Extract()
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
	_, err = secgroups.CreateRule(p.stack.Compute, ruleOpts).Extract()
	return err
}

// initDefaultSecurityGroup create an open Security Group
// The default security group opens all TCP, UDP, ICMP ports
// Security is managed individually on each host using a linux firewall
func (p *Openstack) initDefaultSecurityGroup() error {
	sg, err := client.getDefaultSecurityGroup()
	if err != nil {
		return err
	}
	if sg != nil {
		client.SecurityGroup = sg
		return nil
	}
	opts := secgroups.CreateOpts{
		Name:        defaultSecurityGroup,
		Description: "Default security group",
	}

	group, err := secgroups.Create(client.Compute, opts).Extract()
	if err != nil {
		return err
	}
	err = client.createTCPRules(group.ID)
	if err != nil {
		secgroups.Delete(client.Compute, group.ID)
		return err
	}

	err = client.createUDPRules(group.ID)
	if err != nil {
		secgroups.Delete(client.Compute, group.ID)
		return err
	}
	err = client.createICMPRules(group.ID)
	if err != nil {
		secgroups.Delete(client.Compute, group.ID)
		return err
	}
	client.SecurityGroup = group
	return nil
}

// GetAuthOpts returns the auth options
func (p *Openstack) GetAuthOpts() (provider.Config, error) {
	cfg := provider.ConfigMap{}

	cfg.Set("TenantName", p.AuthOpts.TenantName)
	cfg.Set("Login", p.AuthOpts.Username)
	cfg.Set("Password", p.AuthOpts.Password)
	cfg.Set("AuthUrl", p.AuthOpts.IdentityEndpoint)
	cfg.Set("Region", p.AuthOpts.Region)
	return cfg, nil
}

// GetCfgOpts return configuration parameters
func (p *Openstack) GetCfgOpts() (provider.Config, error) {
	cfg := provider.ConfigMap{}

	cfg.Set("DNSList", p.CfgOpts.DNSList)
	cfg.Set("S3Protocol", p.CfgOpts.S3Protocol)
	cfg.Set("AutoHostNetworkInterfaces", p.CfgOpts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", p.CfgOpts.UseLayer3Networking)
	cfg.Set("MetadataBucket", p.CfgOpts.MetadataBucketName)

	return cfg, nil
}
