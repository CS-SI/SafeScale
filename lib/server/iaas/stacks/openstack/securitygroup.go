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

package openstack

import (
    secgroups "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
    secrules "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
    "github.com/gophercloud/gophercloud/pagination"

    "github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
    netretry "github.com/CS-SI/SafeScale/lib/utils/net"
    "github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// GetSecurityGroup returns the default security group
func (s *Stack) GetSecurityGroup(name string) (*secgroups.SecGroup, fail.Error) {
    var sgList []secgroups.SecGroup
    opts := secgroups.ListOpts{
        Name: s.DefaultSecurityGroupName,
    }
    xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            innerErr := secgroups.List(s.NetworkClient, opts).EachPage(func(page pagination.Page) (bool, error) {
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
            return NormalizeError(innerErr)
        },
        2*temporal.GetDefaultDelay(),
    )
    if xerr != nil {
        return nil, xerr
    }
    if len(sgList) > 1 {
        return nil, fail.OverflowError(nil, 1, "several security groups named '%s' found", name)
    }
    // VPL: no security group is not an abnormal situation, do not error
    if len(sgList) == 0 {
        return nil, nil
    }
    return &sgList[0], nil
}

func (s *Stack) getDefaultSecurityGroup() (*secgroups.SecGroup, fail.Error) {
    sg, xerr := s.GetSecurityGroup(s.DefaultSecurityGroupName)
    if xerr != nil {
        return nil, xerr
    }
    if sg == nil {
        return nil, fail.NotFoundError("no default security group (named '%s') found", s.DefaultSecurityGroupName)
    }
    return sg, nil
}

// TODO: write a public equivalent to addRuleToSecurityGroup with rule absgtraction from SafeScale (to be defined)
// addRuleToSecurityGroup adds a rule to a security group
func (s *Stack) addRuleToSecurityGroup(groupID string, rule secrules.CreateOpts) fail.Error {
    rule.SecGroupID = groupID
    return netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            _, err := secrules.Create(s.NetworkClient, rule).Extract()
            return NormalizeError(err)
        },
        2*temporal.GetDefaultDelay(),
    )
}

// createTCPRules creates TCP rules to configure the default security group
func (s *Stack) createTCPRules(groupID string) fail.Error {
    // Open TCP Ports
    rule := secrules.CreateOpts{
        Direction:      secrules.DirIngress,
        PortRangeMin:   1,
        PortRangeMax:   65535,
        EtherType:      secrules.EtherType4,
        Protocol:       secrules.ProtocolTCP,
        RemoteIPPrefix: "0.0.0.0/0",
    }
    if xerr := s.addRuleToSecurityGroup(groupID, rule); xerr != nil {
        return xerr
    }

    rule.EtherType = secrules.EtherType6
    rule.RemoteIPPrefix = "::/0"
    if xerr := s.addRuleToSecurityGroup(groupID, rule); xerr != nil {
        return xerr
    }

    // Outbound = egress == going to Outside
    rule = secrules.CreateOpts{
        Direction:      secrules.DirEgress,
        PortRangeMin:   1,
        PortRangeMax:   65535,
        EtherType:      secrules.EtherType4,
        Protocol:       secrules.ProtocolTCP,
        RemoteIPPrefix: "0.0.0.0/0",
    }
    if xerr := s.addRuleToSecurityGroup(groupID, rule); xerr != nil {
        return xerr
    }

    rule.EtherType = secrules.EtherType6
    rule.RemoteIPPrefix = "::/0"
    return s.addRuleToSecurityGroup(groupID, rule)
}

// createUDPRules creates UDP rules to configure the default security group
func (s *Stack) createUDPRules(groupID string) fail.Error {
    // Inbound == ingress == coming from Outside
    rule := secrules.CreateOpts{
        Direction:      secrules.DirIngress,
        PortRangeMin:   1,
        PortRangeMax:   65535,
        EtherType:      secrules.EtherType4,
        SecGroupID:     groupID,
        Protocol:       secrules.ProtocolUDP,
        RemoteIPPrefix: "0.0.0.0/0",
    }
    if xerr := s.addRuleToSecurityGroup(groupID, rule); xerr != nil {
        return xerr
    }

    rule.EtherType = secrules.EtherType6
    rule.RemoteIPPrefix = "::/0"
    if xerr := s.addRuleToSecurityGroup(groupID, rule); xerr != nil {
        return xerr
    }

    // Outbound = egress == going to Outside
    rule = secrules.CreateOpts{
        Direction:      secrules.DirEgress,
        PortRangeMin:   1,
        PortRangeMax:   65535,
        EtherType:      secrules.EtherType4,
        SecGroupID:     groupID,
        Protocol:       secrules.ProtocolUDP,
        RemoteIPPrefix: "0.0.0.0/0",
    }
    if xerr := s.addRuleToSecurityGroup(groupID, rule); xerr != nil {
        return xerr
    }

    rule.EtherType = secrules.EtherType6
    rule.RemoteIPPrefix =  "::/0"
    return s.addRuleToSecurityGroup(groupID, rule)
}

// createICMPRules creates ICMP rules inside the default security group
func (s *Stack) createICMPRules(groupID string) error {
    // Inbound == ingress == coming from Outside
    rule := secrules.CreateOpts{
        Direction:      secrules.DirIngress,
        EtherType:      secrules.EtherType4,
        SecGroupID:     groupID,
        Protocol:       secrules.ProtocolICMP,
        RemoteIPPrefix: "0.0.0.0/0",
    }
    if xerr := s.addRuleToSecurityGroup(groupID, rule); xerr != nil {
        return xerr
    }

    rule.EtherType = secrules.EtherType6
    rule.RemoteIPPrefix= "::/0"
    if xerr := s.addRuleToSecurityGroup(groupID, rule); xerr != nil {
        return xerr
    }

    // Outbound = egress == going to Outside
    rule = secrules.CreateOpts{
        Direction:      secrules.DirEgress,
        EtherType:      secrules.EtherType4,
        SecGroupID:     groupID,
        Protocol:       secrules.ProtocolICMP,
        RemoteIPPrefix: "0.0.0.0/0",
    }
    if xerr := s.addRuleToSecurityGroup(groupID, rule); xerr != nil {
        return xerr
    }

    rule.EtherType = secrules.EtherType6
    rule.RemoteIPPrefix = "::/0"
    return s.addRuleToSecurityGroup(groupID, rule)
}

// InitDefaultSecurityGroup create an open Security Group
// The default security group opens all TCP, UDP, ICMP ports
// Security is managed individually on each host using a linux firewall
func (s *Stack) InitDefaultSecurityGroup() fail.Error {
    if s.DefaultSecurityGroupName == "" {
        s.DefaultSecurityGroupName = stacks.DefaultSecurityGroupName
    }
    sg, xerr := s.getDefaultSecurityGroup()
    if xerr != nil {
        return xerr
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
        return fail.ToError(err)
    }

    err = s.createTCPRules(group.ID)
    if err != nil {
        secgroups.Delete(s.NetworkClient, group.ID)
        return fail.ToError(err)
    }

    err = s.createUDPRules(group.ID)
    if err != nil {
        secgroups.Delete(s.NetworkClient, group.ID)
        return fail.ToError(err)
    }

    err = s.createICMPRules(group.ID)
    if err != nil {
        secgroups.Delete(s.NetworkClient, group.ID)
        return fail.ToError(err)
    }

    s.SecurityGroup = group
    return nil
}
