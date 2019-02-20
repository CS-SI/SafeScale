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

	"github.com/CS-SI/SafeScale/iaas/stacks"
	"github.com/CS-SI/SafeScale/iaas/stacks/openstack"
	secgroups "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	secrules "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/pagination"
)

// createTCPRules creates TCP rules to configure the default security group
func (s *Stack) createTCPRules(groupID string) error {
	// Inbound == ingress == coming from Outside
	ruleOpts := secrules.CreateOpts{
		Direction:      secrules.DirIngress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType4,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolTCP,
		RemoteIPPrefix: "0.0.0.0/0",
	}
	_, err := secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secrules.CreateOpts{
		Direction:      secrules.DirIngress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType6,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolTCP,
		RemoteIPPrefix: "::/0",
	}
	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
	if err != nil {
		return err
	}

	// Outbound = egress == going to Outside
	ruleOpts = secrules.CreateOpts{
		Direction:      secrules.DirEgress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType4,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolTCP,
		RemoteIPPrefix: "0.0.0.0/0",
	}
	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secrules.CreateOpts{
		Direction:      secrules.DirEgress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType6,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolTCP,
		RemoteIPPrefix: "::/0",
	}
	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
	return err
}

// createTCPRules creates UDP rules to configure the default security group
func (s *Stack) createUDPRules(groupID string) error {
	// Inbound == ingress == coming from Outside
	ruleOpts := secrules.CreateOpts{
		Direction:      secrules.DirIngress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType4,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolUDP,
		RemoteIPPrefix: "0.0.0.0/0",
	}
	_, err := secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secrules.CreateOpts{
		Direction:      secrules.DirIngress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType6,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolUDP,
		RemoteIPPrefix: "::/0",
	}
	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
	if err != nil {
		return err
	}

	// Outbound = egress == going to Outside
	ruleOpts = secrules.CreateOpts{
		Direction:      secrules.DirEgress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType4,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolUDP,
		RemoteIPPrefix: "0.0.0.0/0",
	}
	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secrules.CreateOpts{
		Direction:      secrules.DirEgress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType6,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolUDP,
		RemoteIPPrefix: "::/0",
	}
	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
	return err
}

// createICMPRules creates UDP rules to configure the default security group
func (s *Stack) createICMPRules(groupID string) error {
	// Inbound == ingress == coming from Outside
	ruleOpts := secrules.CreateOpts{
		Direction:      secrules.DirIngress,
		EtherType:      secrules.EtherType4,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolICMP,
		RemoteIPPrefix: "0.0.0.0/0",
	}
	_, err := secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secrules.CreateOpts{
		Direction: secrules.DirIngress,
		//		PortRangeMin:   0,
		//		PortRangeMax:   18,
		EtherType:      secrules.EtherType6,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolICMP,
		RemoteIPPrefix: "::/0",
	}
	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
	if err != nil {
		return err
	}

	// Outbound = egress == going to Outside
	ruleOpts = secrules.CreateOpts{
		Direction: secrules.DirEgress,
		//		PortRangeMin:   0,
		//		PortRangeMax:   18,
		EtherType:      secrules.EtherType4,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolICMP,
		RemoteIPPrefix: "0.0.0.0/0",
	}
	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secrules.CreateOpts{
		Direction: secrules.DirEgress,
		//		PortRangeMin:   0,
		//		PortRangeMax:   18,
		EtherType:      secrules.EtherType6,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolICMP,
		RemoteIPPrefix: "::/0",
	}
	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
	return err
}

// getDefaultSecurityGroup returns the default security group for the client, in the form
// sg-<VPCName>, if it exists.
func (s *Stack) getDefaultSecurityGroup() (*secgroups.SecGroup, error) {
	var sgList []secgroups.SecGroup
	opts := secgroups.ListOpts{
		Name: s.defaultSecurityGroupName,
	}
	err := secgroups.List(s.Stack.NetworkClient, opts).EachPage(func(page pagination.Page) (bool, error) {
		list, err := secgroups.ExtractGroups(page)
		if err != nil {
			return false, err
		}
		for _, g := range list {
			if g.Name == s.defaultSecurityGroupName {
				sgList = append(sgList, g)
			}
		}
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error listing routers: %s", openstack.ProviderErrorToString(err))
	}
	if len(sgList) == 0 {
		return nil, nil
	}
	if len(sgList) > 1 {
		return nil, fmt.Errorf("configuration error: multiple Security Groups named '%s' exist", s.defaultSecurityGroupName)
	}

	return &sgList[0], nil
}

// InitDefaultSecurityGroup create an open Security Group
// The default security group opens all TCP, UDP, ICMP ports
// Security is managed individually on each host using a linux firewall
func (s *Stack) InitDefaultSecurityGroup() error {
	s.defaultSecurityGroupName = stacks.DefaultSecurityGroupName + "." + s.authOpts.VPCName

	sg, err := s.getDefaultSecurityGroup()
	if err != nil {
		return err
	}
	if sg != nil {
		s.SecurityGroup = sg
		return nil
	}
	opts := secgroups.CreateOpts{
		Name:        s.defaultSecurityGroupName,
		Description: "Default security group for VPC " + s.authOpts.VPCName,
	}
	group, err := secgroups.Create(s.Stack.NetworkClient, opts).Extract()
	if err != nil {
		return fmt.Errorf("Failed to create Security Group '%s': %s", s.defaultSecurityGroupName, openstack.ProviderErrorToString(err))
	}
	err = s.createTCPRules(group.ID)
	if err == nil {
		err = s.createUDPRules(group.ID)
		if err == nil {
			err = s.createICMPRules(group.ID)
			if err == nil {
				s.SecurityGroup = group
				return nil
			}
		}
	}
	// Error occured...
	secgroups.Delete(s.Stack.NetworkClient, group.ID)
	return err
}
