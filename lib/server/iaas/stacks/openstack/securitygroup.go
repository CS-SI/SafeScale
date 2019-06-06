/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/CS-SI/SafeScale/iaas/stacks"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/secgroups"
	"github.com/gophercloud/gophercloud/pagination"
)

// GetSecurityGroup returns the default security group
func (s *Stack) GetSecurityGroup(name string) (*secgroups.SecurityGroup, error) {
	var sgList []secgroups.SecurityGroup

	err := secgroups.List(s.ComputeClient).EachPage(func(page pagination.Page) (bool, error) {
		list, err := secgroups.ExtractSecurityGroups(page)
		if err != nil {
			return false, err
		}
		for _, e := range list {
			if e.Name == name {
				sgList = append(sgList, e)
			}
		}
		return true, nil
	})
	if len(sgList) == 0 {
		return nil, err
	}
	if len(sgList) > 1 {
		return nil, fmt.Errorf("several security groups named '%s' found", name)
	}

	return &sgList[0], nil
}

// createTCPRules creates TCP rules to configure the default security group
func (s *Stack) createTCPRules(groupID string) error {
	// Open TCP Ports
	ruleOpts := secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      1,
		ToPort:        65535,
		IPProtocol:    "TCP",
		CIDR:          "0.0.0.0/0",
	}

	_, err := secgroups.CreateRule(s.ComputeClient, ruleOpts).Extract()
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
	_, err = secgroups.CreateRule(s.ComputeClient, ruleOpts).Extract()
	return err
}

// createTCPRules creates UDP rules to configure the default security group
func (s *Stack) createUDPRules(groupID string) error {
	// Open UDP Ports
	ruleOpts := secgroups.CreateRuleOpts{
		ParentGroupID: groupID,
		FromPort:      1,
		ToPort:        65535,
		IPProtocol:    "UDP",
		CIDR:          "0.0.0.0/0",
	}

	_, err := secgroups.CreateRule(s.ComputeClient, ruleOpts).Extract()
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
	_, err = secgroups.CreateRule(s.ComputeClient, ruleOpts).Extract()
	return err
}

// InitDefaultSecurityGroup create an open Security Group
// The default security group opens all TCP, UDP, ICMP ports
// Security is managed individually on each host using a linux firewall
func (s *Stack) InitDefaultSecurityGroup() error {
	sg, err := s.GetSecurityGroup(stacks.DefaultSecurityGroupName)
	if err != nil {
		return err
	}
	if sg != nil {
		s.SecurityGroup = sg
		return nil
	}
	opts := secgroups.CreateOpts{
		Name:        stacks.DefaultSecurityGroupName,
		Description: "Default security group",
	}

	group, err := secgroups.Create(s.ComputeClient, opts).Extract()
	if err != nil {
		return err
	}

	err = s.createTCPRules(group.ID)
	if err != nil {
		secgroups.Delete(s.ComputeClient, group.ID)
		return err
	}

	err = s.createUDPRules(group.ID)
	if err != nil {
		secgroups.Delete(s.ComputeClient, group.ID)
		return err
	}

	s.SecurityGroup = group
	return nil
}
