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

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	secgroups "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	secrules "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/pagination"
)

// GetSecurityGroup returns the default security group
func (s *Stack) GetSecurityGroup(name string) (*secgroups.SecGroup, error) {
	var sgList []secgroups.SecGroup
	opts := secgroups.ListOpts{
		Name: s.DefaultSecurityGroupName,
	}
	err := secgroups.List(s.NetworkClient, opts).EachPage(func(page pagination.Page) (bool, error) {
		list, err := secgroups.ExtractGroups(page)
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

func (s *Stack) getDefaultSecurityGroup() (*secgroups.SecGroup, error) {
	sg, err := s.GetSecurityGroup(s.DefaultSecurityGroupName)
	if err != nil {
		return nil, fmt.Errorf("error listing routers: %s", ProviderErrorToString(err))
	}

	return sg, nil
}

// createTCPRules creates TCP rules to configure the default security group
func (s *Stack) createTCPRules(groupID string) error {
	// Open TCP Ports
	ruleOpts := secrules.CreateOpts{
		Direction:      secrules.DirIngress,
		PortRangeMin:   1,
		PortRangeMax:   65535,
		EtherType:      secrules.EtherType4,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolTCP,
		RemoteIPPrefix: "0.0.0.0/0",
	}

	_, err := secrules.Create(s.NetworkClient, ruleOpts).Extract()
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
	_, err = secrules.Create(s.NetworkClient, ruleOpts).Extract()
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
	_, err = secrules.Create(s.NetworkClient, ruleOpts).Extract()
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
	_, err = secrules.Create(s.NetworkClient, ruleOpts).Extract()
	return err
}

// createUDPRules creates UDP rules to configure the default security group
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
	_, err := secrules.Create(s.NetworkClient, ruleOpts).Extract()
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
	_, err = secrules.Create(s.NetworkClient, ruleOpts).Extract()
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
	_, err = secrules.Create(s.NetworkClient, ruleOpts).Extract()
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
	_, err = secrules.Create(s.NetworkClient, ruleOpts).Extract()
	return err
}

// createICMPRules creates ICMP rules inside the default security group
func (s *Stack) createICMPRules(groupID string) error {
	// Inbound == ingress == coming from Outside
	ruleOpts := secrules.CreateOpts{
		Direction:      secrules.DirIngress,
		EtherType:      secrules.EtherType4,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolICMP,
		RemoteIPPrefix: "0.0.0.0/0",
	}
	_, err := secrules.Create(s.NetworkClient, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secrules.CreateOpts{
		Direction:      secrules.DirIngress,
		EtherType:      secrules.EtherType6,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolICMP,
		RemoteIPPrefix: "::/0",
	}
	_, err = secrules.Create(s.NetworkClient, ruleOpts).Extract()
	if err != nil {
		return err
	}

	// Outbound = egress == going to Outside
	ruleOpts = secrules.CreateOpts{
		Direction:      secrules.DirEgress,
		EtherType:      secrules.EtherType4,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolICMP,
		RemoteIPPrefix: "0.0.0.0/0",
	}
	_, err = secrules.Create(s.NetworkClient, ruleOpts).Extract()
	if err != nil {
		return err
	}
	ruleOpts = secrules.CreateOpts{
		Direction:      secrules.DirEgress,
		EtherType:      secrules.EtherType6,
		SecGroupID:     groupID,
		Protocol:       secrules.ProtocolICMP,
		RemoteIPPrefix: "::/0",
	}
	_, err = secrules.Create(s.NetworkClient, ruleOpts).Extract()
	return err
}

// InitDefaultSecurityGroup create an open Security Group
// The default security group opens all TCP, UDP, ICMP ports
// Security is managed individually on each host using a linux firewall
func (s *Stack) InitDefaultSecurityGroup() error {
	if s.DefaultSecurityGroupName == "" {
		s.DefaultSecurityGroupName = stacks.DefaultSecurityGroupName
	}
	sg, err := s.getDefaultSecurityGroup()
	if err != nil {
		return err
	}
	if sg != nil {
		s.SecurityGroup = sg
		return nil
	}
	if s.DefaultSecurityGroupDescription == "" {
		s.DefaultSecurityGroupDescription = "Default security group"
	}
	opts := secgroups.CreateOpts{
		Name:        s.DefaultSecurityGroupName,
		Description: s.DefaultSecurityGroupDescription,
	}

	group, err := secgroups.Create(s.NetworkClient, opts).Extract()
	if err != nil {
		return err
	}

	err = s.createTCPRules(group.ID)
	if err != nil {
		secgroups.Delete(s.NetworkClient, group.ID)
		return err
	}

	err = s.createUDPRules(group.ID)
	if err != nil {
		secgroups.Delete(s.NetworkClient, group.ID)
		return err
	}

	err = s.createICMPRules(group.ID)
	if err != nil {
		secgroups.Delete(s.NetworkClient, group.ID)
		return err
	}

	s.SecurityGroup = group
	return nil
}
