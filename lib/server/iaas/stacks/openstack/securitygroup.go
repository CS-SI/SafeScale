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
    "github.com/CS-SI/SafeScale/lib/server/resources/abstract"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
    netretry "github.com/CS-SI/SafeScale/lib/utils/net"
    "github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// ListSecurityGroup lists existing security groups
func (s Stack) ListSecurityGroup() ([]*abstract.SecurityGroup, fail.Error) {
    var list []*abstract.SecurityGroup

    opts := secgroups.ListOpts{}
    xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            innerErr := secgroups.List(s.NetworkClient, opts).EachPage(func(page pagination.Page) (bool, error) {
                l, err := secgroups.ExtractGroups(page)
                if err != nil {
                    return false, err
                }
                for _, e := range l {
                    n := abstract.NewSecurityGroup(e.Name)
                    n.ID = e.ID
                    n.Description = e.Description
                    list = append(list, n)
                }
                return true, nil
            })
            return NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
    return list, xerr
}

// CreateSecurityGroup creates a security group
func (s Stack) CreateSecurityGroup(name string, description string, rules []abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
    // if s == nil {
    //     return nil, fail.InvalidInstanceError()
    // }

    asg, xerr := s.InspectSecurityGroup(name)
    if xerr != nil {
        switch xerr.(type) {
        case *fail.ErrNotFound:
            asg = abstract.NewSecurityGroup(name)
        default:
            return nil, xerr
        }
    } else {
        return nil, fail.DuplicateError("a security group named '%s' already exist", name)
    }

    // create security group on provider side
    createOpts := secgroups.CreateOpts{
        Name: name,
        Description: description,
    }
    xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            r, innerErr := secgroups.Create(s.NetworkClient, createOpts).Extract()
            if innerErr != nil {
                return NormalizeError(innerErr)
            }
            asg.ID = r.ID
            return nil
        },
        temporal.GetCommunicationTimeout(),
    )
    if xerr != nil {
        return nil, xerr
    }

    // Starting from here, delete security group on error
    defer func() {
        if xerr != nil {
            derr := s.DeleteSecurityGroup(asg)
            if derr != nil {
                _ = xerr.AddConsequence(fail.Prepend(derr, "cleaning up on failure, failed to delete security group"))
            }
        }
    }()


    // now adds security rules
    asg.Rules = make([]abstract.SecurityGroupRule, 0, len(rules))
    for _, v := range rules {
        if _, xerr := s.AddRuleToSecurityGroup(asg, v); xerr != nil {
            return nil, xerr
        }
        asg.Rules = append(asg.Rules, v)
    }
    return asg, nil
}

// DeleteSecurityGroup deletes a security group and its rules
func (s Stack) DeleteSecurityGroup(sgParam stacks.SecurityGroupParameter) fail.Error {
    // if s == nil {
    //     return fail.InvalidInstanceError()
    // }

    sg, xerr := s.InspectSecurityGroup(sgParam)
    if xerr != nil {
        return xerr
    }

    // delete security group rules
    for _, v := range sg.Rules {
        xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
            func() error {
                innerErr := secrules.Delete(s.NetworkClient, v.ID).ExtractErr()
                return NormalizeError(innerErr)
            },
            temporal.GetCommunicationTimeout(),
        )
        if xerr != nil {
            return xerr
        }
    }

    // delete security group
    return netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            innerErr := secgroups.Delete(s.NetworkClient, sg.ID).ExtractErr()
            return NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
}

// InspectSecurityGroup returns information about a security group
func (s Stack) InspectSecurityGroup(sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
    // if s == nil {
    //     return nil, fail.InvalidInstanceError()
    // }
    asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
    if xerr != nil {
        return nil, xerr
    }

    var (
        sg *abstract.SecurityGroup
        r *secgroups.SecGroup
    )

    xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            var innerErr error
            r, innerErr = secgroups.Get(s.NetworkClient, asg.ID).Extract()
            if innerErr != nil {
                innerErr = NormalizeError(innerErr)
                switch innerErr.(type) {
                case *fail.ErrNotFound: // If not found by id, try to get id of security group by name
                    id, innerErr := secgroups.IDFromName(s.NetworkClient, asg.ID)
                    if innerErr != nil {
                        return NormalizeError(innerErr)
                    }
                    r, innerErr = secgroups.Get(s.NetworkClient, id).Extract()
                }
            }
            return NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
    if xerr != nil {
        return nil, xerr
    }

    asg = abstract.NewSecurityGroup(r.Name)
    asg.ID = r.ID
    asg.Description = r.Description
    asg.Rules, xerr = convertRulesToAbstract(r.Rules)
    if xerr != nil {
        return nil, xerr
    }
    return sg, nil
}

// ClearSecurityGroup removes all rules but keep group
func (s Stack) ClearSecurityGroup(sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
    // if s == nil {
    //     return fail.InvalidInstanceError()
    // }
    asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
    if xerr != nil {
        return asg, xerr
    }

    asg, xerr = s.InspectSecurityGroup(asg.ID)
    if xerr != nil {
        return asg, xerr
    }

    // delete security group rules
    for _, v := range asg.Rules {
        xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
            func() error {
                innerErr := secrules.Delete(s.NetworkClient, v.ID).ExtractErr()
                return NormalizeError(innerErr)
            },
            temporal.GetCommunicationTimeout(),
        )
        if xerr != nil {
            switch xerr.(type){
            case *fail.ErrNotFound:
                continue
            default:
                return asg, xerr
            }
        }
    }
    asg.Rules = []abstract.SecurityGroupRule{}
    return asg, nil
}

// convertRulesToAbstract
func convertRulesToAbstract(in []secrules.SecGroupRule) ([]abstract.SecurityGroupRule, fail.Error) {
    out := make([]abstract.SecurityGroupRule, 0, len(in))
    for k, v := range in {
        direction := convertDirectionToAbstract(v.Direction)
        if direction == securitygroupruledirection.UNKNOWN {
            return nil, fail.InvalidRequestError("invalid value '%s' to 'Direction' field in rule #%d", v.Direction, k+1)
        }
        etherType := convertEtherTypeToAbstract(secrules.RuleEtherType(v.EtherType))
        if etherType == ipversion.Unknown {
            return nil, fail.InvalidRequestError("invalid value '%s' to 'EtherType' field in rule #%d", v.EtherType, k+1)
        }

        n := abstract.SecurityGroupRule{
            ID:          v.ID,
            EtherType:   etherType,
            Description: v.Description,
            Direction:   direction,
            Protocol:    v.Protocol,
            PortFrom:    uint16(v.PortRangeMin),
            PortTo:      uint16(v.PortRangeMax),
            CIDR:        v.RemoteIPPrefix,
        }
        out = append(out, n)
    }
    return out, nil
}

// convertDirectionToWay
func convertDirectionToAbstract(in string) securitygroupruledirection.Enum {
    switch secrules.RuleDirection(in) {
    case secrules.DirIngress:
        return securitygroupruledirection.INGRESS
    case secrules.DirEgress:
        return securitygroupruledirection.EGRESS
    default:
        return securitygroupruledirection.UNKNOWN
    }
}

func convertDirectionFromAbstract(in securitygroupruledirection.Enum) secrules.RuleDirection {
    switch in {
    case securitygroupruledirection.EGRESS:
        return secrules.DirEgress
    case securitygroupruledirection.INGRESS:
        return secrules.DirIngress
    default:
        return ""
    }
}

func convertEtherTypeToAbstract(in secrules.RuleEtherType) ipversion.Enum {
    switch in {
    case secrules.EtherType4:
        return ipversion.IPv4
    case secrules.EtherType6:
        return ipversion.IPv6
    default:
        return ipversion.Unknown
    }
}

func convertEtherTypeFromAbstract(in ipversion.Enum) secrules.RuleEtherType {
    switch in {
    case ipversion.IPv4:
        return secrules.EtherType4
    case ipversion.IPv6:
        return secrules.EtherType6
    default:
        return ""
    }
}

// VPL: obsolete
// // GetDefaultSecurityGroup returns the default security group
// func (s Stack) GetDefaultSecurityGroup(name string) (*secgroups.SecGroup, fail.Error) {
//     var sgList []secgroups.SecGroup
//     opts := secgroups.ListOpts{
//         Name: s.DefaultSecurityGroupName,
//     }
//     xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
//         func() error {
//             innerErr := secgroups.List(s.NetworkClient, opts).EachPage(func(page pagination.Page) (bool, error) {
//                 list, err := secgroups.ExtractGroups(page)
//                 if err != nil {
//                     return false, err
//                 }
//                 for _, e := range list {
//                     if e.Name == name {
//                         sgList = append(sgList, e)
//                     }
//                 }
//                 return true, nil
//             })
//             return NormalizeError(innerErr)
//         },
//         temporal.GetCommunicationTimeout(),
//     )
//     if xerr != nil {
//         return nil, xerr
//     }
//     if len(sgList) > 1 {
//         return nil, fail.OverflowError(nil, 1, "several security groups named '%s' found", name)
//     }
//     // VPL: no security group is not an abnormal situation, do not error
//     if len(sgList) == 0 {
//         return nil, nil
//     }
//     return &sgList[0], nil
// }

// VPL: obsolete
// func (s *Stack) getDefaultSecurityGroup() (*secgroups.SecGroup, fail.Error) {
//     sg, xerr := s.GetDefaultSecurityGroup(s.DefaultSecurityGroupName)
//     if xerr != nil {
//         return nil, xerr
//     }
//     if sg == nil {
//         return nil, fail.NotFoundError("no default security group (named '%s') found", s.DefaultSecurityGroupName)
//     }
//     return sg, nil
// }

// TODO: write a public equivalent to addRuleToSecurityGroup with rule abstraction from SafeScale (to be defined)
// // addRuleToSecurityGroup adds a rule to a security group
// func (s *Stack) addRuleToSecurityGroup(groupID string, rule secrules.CreateOpts) fail.Error {
//     rule.SecGroupID = groupID
//     return netretry.WhileCommunicationUnsuccessfulDelay1Second(
//         func() error {
//             _, err := secrules.Create(s.NetworkClient, rule).Extract()
//             return NormalizeError(err)
//         },
//         temporal.GetCommunicationTimeout(),
//     )
// }

// AddRuleToSecurityGroup adds a rule to a security group
// On success, return Security Group with added rule
func (s Stack) AddRuleToSecurityGroup(sgParam stacks.SecurityGroupParameter, rule abstract.SecurityGroupRule) (asg *abstract.SecurityGroup, xerr fail.Error) {
    // if s == nil {
    //     return fail.InvalidInstanceError()
    // }
    asg, xerr = stacks.ValidateSecurityGroupParameter(sgParam)
    if xerr != nil {
        return asg, xerr
    }

    asg, xerr = s.InspectSecurityGroup(asg)
    if xerr != nil {
        return asg, xerr
    }

    found, xerr := stacks.LookupRuleInSecurityGroup(asg, rule)
    if xerr != nil {
        return asg, xerr
    }
    if found {
        return asg, fail.DuplicateError("rule already in Security Group")
    }

    etherType := convertEtherTypeFromAbstract(rule.EtherType)
    if etherType == "" {    // If no valid EtherType is provided, force to IPv4
        etherType = secrules.EtherType4
    }
    direction := convertDirectionFromAbstract(rule.Direction)
    if direction == "" {    // Invalid direction is not permitted
        return asg, fail.InvalidRequestError("invalid value '%s' in 'Direction' field of rule", rule.Direction)
    }

    createOpts := secrules.CreateOpts{
        SecGroupID:     asg.ID,
        EtherType:      etherType,
        Direction:      direction,
        Description:    rule.Description,
        PortRangeMin:   int(rule.PortFrom),
        PortRangeMax:   int(rule.PortTo),
        Protocol:       secrules.RuleProtocol(rule.Protocol),
        RemoteIPPrefix: rule.CIDR,
    }
    return asg, netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            r, innerErr := secrules.Create(s.NetworkClient, createOpts).Extract()
            if innerErr != nil {
                return NormalizeError(innerErr)
            }
            rule.ID = r.ID
            asg.Rules = append(asg.Rules, rule)
            return nil
        },
        temporal.GetCommunicationTimeout(),
    )
}


// InitDefaultSecurityGroup create a SafeScale default Security Group, that will apply to every resources
func (s *Stack) InitDefaultSecurityGroup() fail.Error {
    rules := stacks.TCPRules()
    rules = append(rules, stacks.UDPRules()...)
    rules = append(rules, stacks.ICMPRules()...)

    asg, xerr := s.InspectSecurityGroup(s.DefaultSecurityGroupName)
    if xerr != nil {
        switch xerr.(type) {
        case *fail.ErrNotFound:
            if s.DefaultSecurityGroupDescription == "" {
                s.DefaultSecurityGroupDescription = "Default security group"
            }
            asg, xerr = s.CreateSecurityGroup(s.DefaultSecurityGroupName, s.DefaultSecurityGroupDescription, rules)
            if xerr != nil {
                return xerr
            }

            defer func() {
                if xerr != nil {
                    derr := s.DeleteSecurityGroup(asg)
                    if derr != nil {
                        _ = xerr.AddConsequence(fail.Prepend(derr, "cleaning up on failure, failed to delete Security Group '%s'", asg.Name))
                    }
                }
            }()
        }
    } else {
        for _, newRule := range rules {
            if _, xerr = s.AddRuleToSecurityGroup(asg, newRule); xerr != nil {
                switch xerr.(type) {
                case *fail.ErrDuplicate:    // If duplicate, consider a success and continue
                    continue
                default:
                    return xerr
                }
            }
        }
    }

    // s.SecurityGroup = asg
    return nil
}
