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

package huaweicloud

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
)

// // createTCPRules creates TCP rules to configure the default security group
// func (s *Stack) createTCPRules(groupID string) error {
// 	// Inbound == ingress == coming from Outside
// 	ruleOpts := secrules.CreateOpts{
// 		Direction:      secrules.DirIngress,
// 		PortRangeMin:   1,
// 		PortRangeMax:   65535,
// 		EtherType:      secrules.EtherType4,
// 		SecGroupID:     groupID,
// 		Protocol:       secrules.ProtocolTCP,
// 		RemoteIPPrefix: "0.0.0.0/0",
// 	}
// 	_, err := secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
// 	if err != nil {
// 		return err
// 	}
// 	ruleOpts = secrules.CreateOpts{
// 		Direction:      secrules.DirIngress,
// 		PortRangeMin:   1,
// 		PortRangeMax:   65535,
// 		EtherType:      secrules.EtherType6,
// 		SecGroupID:     groupID,
// 		Protocol:       secrules.ProtocolTCP,
// 		RemoteIPPrefix: "::/0",
// 	}
// 	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
// 	if err != nil {
// 		return err
// 	}

// 	// Outbound = egress == going to Outside
// 	ruleOpts = secrules.CreateOpts{
// 		Direction:      secrules.DirEgress,
// 		PortRangeMin:   1,
// 		PortRangeMax:   65535,
// 		EtherType:      secrules.EtherType4,
// 		SecGroupID:     groupID,
// 		Protocol:       secrules.ProtocolTCP,
// 		RemoteIPPrefix: "0.0.0.0/0",
// 	}
// 	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
// 	if err != nil {
// 		return err
// 	}
// 	ruleOpts = secrules.CreateOpts{
// 		Direction:      secrules.DirEgress,
// 		PortRangeMin:   1,
// 		PortRangeMax:   65535,
// 		EtherType:      secrules.EtherType6,
// 		SecGroupID:     groupID,
// 		Protocol:       secrules.ProtocolTCP,
// 		RemoteIPPrefix: "::/0",
// 	}
// 	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
// 	return err
// }

// // createTCPRules creates UDP rules to configure the default security group
// func (s *Stack) createUDPRules(groupID string) error {
// 	// Inbound == ingress == coming from Outside
// 	ruleOpts := secrules.CreateOpts{
// 		Direction:      secrules.DirIngress,
// 		PortRangeMin:   1,
// 		PortRangeMax:   65535,
// 		EtherType:      secrules.EtherType4,
// 		SecGroupID:     groupID,
// 		Protocol:       secrules.ProtocolUDP,
// 		RemoteIPPrefix: "0.0.0.0/0",
// 	}
// 	_, err := secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
// 	if err != nil {
// 		return err
// 	}
// 	ruleOpts = secrules.CreateOpts{
// 		Direction:      secrules.DirIngress,
// 		PortRangeMin:   1,
// 		PortRangeMax:   65535,
// 		EtherType:      secrules.EtherType6,
// 		SecGroupID:     groupID,
// 		Protocol:       secrules.ProtocolUDP,
// 		RemoteIPPrefix: "::/0",
// 	}
// 	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
// 	if err != nil {
// 		return err
// 	}

// 	// Outbound = egress == going to Outside
// 	ruleOpts = secrules.CreateOpts{
// 		Direction:      secrules.DirEgress,
// 		PortRangeMin:   1,
// 		PortRangeMax:   65535,
// 		EtherType:      secrules.EtherType4,
// 		SecGroupID:     groupID,
// 		Protocol:       secrules.ProtocolUDP,
// 		RemoteIPPrefix: "0.0.0.0/0",
// 	}
// 	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
// 	if err != nil {
// 		return err
// 	}
// 	ruleOpts = secrules.CreateOpts{
// 		Direction:      secrules.DirEgress,
// 		PortRangeMin:   1,
// 		PortRangeMax:   65535,
// 		EtherType:      secrules.EtherType6,
// 		SecGroupID:     groupID,
// 		Protocol:       secrules.ProtocolUDP,
// 		RemoteIPPrefix: "::/0",
// 	}
// 	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
// 	return err
// }

// // createICMPRules creates UDP rules to configure the default security group
// func (s *Stack) createICMPRules(groupID string) error {
// 	// Inbound == ingress == coming from Outside
// 	ruleOpts := secrules.CreateOpts{
// 		Direction:      secrules.DirIngress,
// 		EtherType:      secrules.EtherType4,
// 		SecGroupID:     groupID,
// 		Protocol:       secrules.ProtocolICMP,
// 		RemoteIPPrefix: "0.0.0.0/0",
// 	}
// 	_, err := secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
// 	if err != nil {
// 		return err
// 	}
// 	ruleOpts = secrules.CreateOpts{
// 		Direction: secrules.DirIngress,
// 		//		PortRangeMin:   0,
// 		//		PortRangeMax:   18,
// 		EtherType:      secrules.EtherType6,
// 		SecGroupID:     groupID,
// 		Protocol:       secrules.ProtocolICMP,
// 		RemoteIPPrefix: "::/0",
// 	}
// 	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
// 	if err != nil {
// 		return err
// 	}

// 	// Outbound = egress == going to Outside
// 	ruleOpts = secrules.CreateOpts{
// 		Direction: secrules.DirEgress,
// 		//		PortRangeMin:   0,
// 		//		PortRangeMax:   18,
// 		EtherType:      secrules.EtherType4,
// 		SecGroupID:     groupID,
// 		Protocol:       secrules.ProtocolICMP,
// 		RemoteIPPrefix: "0.0.0.0/0",
// 	}
// 	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
// 	if err != nil {
// 		return err
// 	}
// 	ruleOpts = secrules.CreateOpts{
// 		Direction: secrules.DirEgress,
// 		//		PortRangeMin:   0,
// 		//		PortRangeMax:   18,
// 		EtherType:      secrules.EtherType6,
// 		SecGroupID:     groupID,
// 		Protocol:       secrules.ProtocolICMP,
// 		RemoteIPPrefix: "::/0",
// 	}
// 	_, err = secrules.Create(s.Stack.NetworkClient, ruleOpts).Extract()
// 	return err
// }

// // getDefaultSecurityGroup returns the default security group for the client, in the form
// // sg-<VPCName>, if it exists.
// func (s *Stack) getDefaultSecurityGroup() (*secgroups.SecGroup, error) {
// 	sg, err := s.Stack.GetSecurityGroup(s.defaultSecurityGroupName)
// 	if err != nil {
// 		return nil, fmt.Errorf("error listing routers: %s", openstack.ProviderErrorToString(err))
// 	}

// 	return sg, nil
// }

// InitDefaultSecurityGroup create an open Security Group
// The default security group opens all TCP, UDP, ICMP ports
// Security is managed individually on each host using a linux firewall
func (s *Stack) InitDefaultSecurityGroup() error {
	s.Stack.DefaultSecurityGroupName = stacks.DefaultSecurityGroupName + "." + s.authOpts.VPCName
	s.Stack.DefaultSecurityGroupDescription = "Default security group for VPC " + s.authOpts.VPCName
	return s.Stack.InitDefaultSecurityGroup()
}
