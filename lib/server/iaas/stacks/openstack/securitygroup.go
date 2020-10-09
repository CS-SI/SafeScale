/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

const defaultSecurityGroupName = "default"

// ListSecurityGroups lists existing security groups
// Parameter 'networkRef' is not used in Openstack (they are tenant-wide)
func (s Stack) ListSecurityGroups(networkRef string) ([]*abstract.SecurityGroup, fail.Error) {
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
// Parameter 'networkRef' is not used in Openstack, Security Groups are tenant-wide.
// Returns nil, *fail.ErrDuplicate if already 1 security group exists with that name
// Returns nil, *fail.ErrDuplicate(with a cause *fail.ErrDuplicate) if more than 1 security group exist with that name
func (s Stack) CreateSecurityGroup(networkRef, name, description string, rules []abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	// if s == nil {
	//     return nil, fail.InvalidInstanceError()
	// }
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	asg, xerr := s.InspectSecurityGroup(name)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			asg = abstract.NewSecurityGroup(name)
			// continue
		case *fail.ErrDuplicate:
			// Special case : a duplicate error may come from OpenStack after normalization, because there are already more than 1
			// security groups with the same name. In this situation, returns a DuplicateError with the xerr as cause
			newErr := fail.DuplicateError("more than one Security Group named '%s' found", name)
			return nil, newErr.ForceSetCause(xerr)
		default:
			return nil, xerr
		}
	} else {
		return nil, fail.DuplicateError("a security group named '%s' already exist", name)
	}

	// create security group on provider side
	createOpts := secgroups.CreateOpts{
		Name:        name,
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
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete security group"))
			}
		}
	}()

	// In OpenStack, freshly created security group may contain default rules; we do not want them
	asg, xerr = s.ClearSecurityGroup(asg)
	if xerr != nil {
		return nil, xerr
	}

	// now adds security rules
	asg.Rules = make([]abstract.SecurityGroupRule, 0, len(rules))
	for _, v := range rules {
		if asg, xerr = s.AddRuleToSecurityGroup(asg, v); xerr != nil {
			return nil, xerr
		}
	}
	return asg, nil
}

// DeleteSecurityGroup deletes a security group and its rules
func (s Stack) DeleteSecurityGroup(sgParam stacks.SecurityGroupParameter) fail.Error {
	// if s == nil {
	//     return fail.InvalidInstanceError()
	// }

	asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg.ID)
		if xerr != nil {
			return xerr
		}
	}

	// delete security group rules
	for _, v := range asg.Rules {
		xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
			func() error {
				for _, id := range v.IDs {
					if innerErr := secrules.Delete(s.NetworkClient, id).ExtractErr(); innerErr != nil {
						return NormalizeError(innerErr)
					}
				}
				return nil
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
			innerErr := secgroups.Delete(s.NetworkClient, asg.ID).ExtractErr()
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

	var r *secgroups.SecGroup
	xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			var innerErr error
			r, innerErr = secgroups.Get(s.NetworkClient, asg.ID).Extract()
			if innerErr != nil {
				innerErr = NormalizeError(innerErr)
				switch innerErr.(type) {
				case *fail.ErrNotFound: // If not found by id, try to get id of security group by name
					var id string
					id, innerErr = secgroups.IDFromName(s.NetworkClient, asg.ID)
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
	return asg, nil
}

// ClearSecurityGroup removes all rules but keep group
func (s Stack) ClearSecurityGroup(sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	// if s == nil {
	//     return fail.InvalidInstanceError()
	// }
	asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg.ID)
		if xerr != nil {
			return asg, xerr
		}
	}

	// delete security group rules
	for _, v := range asg.Rules {
		xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
			func() error {
				for _, id := range v.IDs {
					if innerErr := secrules.Delete(s.NetworkClient, id).ExtractErr(); innerErr != nil {
						return NormalizeError(innerErr)
					}
				}
				return nil
			},
			temporal.GetCommunicationTimeout(),
		)
		if xerr != nil {
			switch xerr.(type) {
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
		if etherType == ipversion.UNKNOWN {
			return nil, fail.InvalidRequestError("invalid value '%s' to 'EtherType' field in rule #%d", v.EtherType, k+1)
		}

		n := abstract.SecurityGroupRule{
			IDs:         []string{v.ID},
			EtherType:   etherType,
			Description: v.Description,
			Direction:   direction,
			Protocol:    v.Protocol,
			PortFrom:    uint16(v.PortRangeMin),
			PortTo:      uint16(v.PortRangeMax),
			IPRanges:    []string{v.RemoteIPPrefix},
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
		return ipversion.UNKNOWN
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
		return nil, xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg.ID)
		if xerr != nil {
			return asg, xerr
		}
	}

	_, xerr = asg.Rules.IndexOfEquivalentRule(rule)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
		// continue
		default:
			return asg, xerr
		}
	}

	etherType := convertEtherTypeFromAbstract(rule.EtherType)
	if etherType == "" { // If no valid EtherType is provided, force to IPv4
		etherType = secrules.EtherType4
	}
	direction := convertDirectionFromAbstract(rule.Direction)
	if direction == "" { // Invalid direction is not permitted
		return asg, fail.InvalidRequestError("invalid value '%s' in 'Direction' field of rule", rule.Direction)
	}

	portFrom := rule.PortFrom
	portTo := rule.PortTo
	if portFrom == 0 && portTo != 0 {
		portFrom = portTo
	}
	if portFrom != 0 && portTo == 0 {
		portTo = portFrom
	}
	if portTo < portFrom {
		portFrom, portTo = portTo, portFrom
	}

	createOpts := secrules.CreateOpts{
		SecGroupID:   asg.ID,
		EtherType:    etherType,
		Direction:    direction,
		Description:  rule.Description,
		PortRangeMin: int(portFrom),
		PortRangeMax: int(portTo),
		Protocol:     secrules.RuleProtocol(rule.Protocol),
	}
	for _, v := range rule.IPRanges {
		createOpts.RemoteIPPrefix = v
		createOpts.Description = rule.Description + " (" + v + ")"

		xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
			func() error {
				r, innerErr := secrules.Create(s.NetworkClient, createOpts).Extract()
				if innerErr != nil {
					return NormalizeError(innerErr)
				}
				rule.IDs = append(rule.IDs, r.ID)
				return nil
			},
			temporal.GetCommunicationTimeout(),
		)
		if xerr != nil {
			return asg, xerr
		}
	}
	asg.Rules = append(asg.Rules, rule)

	return asg, nil
}

// DeleteRuleFromSecurityGroup deletes a rule identified by ID from a security group
// Checks first if the rule ID is present in the rules of the security group. If not found, returns (*abstract.SecurityGroup, *fail.ErrNotFound)
func (s Stack) DeleteRuleFromSecurityGroup(sgParam stacks.SecurityGroupParameter, rule abstract.SecurityGroupRule) (asg *abstract.SecurityGroup, xerr fail.Error) {
	// if s == nil {
	//     return fail.InvalidInstanceError()
	// }
	asg, xerr = stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg.ID)
		if xerr != nil {
			return asg, xerr
		}
	}

	index, xerr := asg.Rules.IndexOfEquivalentRule(rule)
	if xerr != nil {
		return asg, xerr
	}
	ruleIDs := asg.Rules[index].IDs

	return asg, netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			for k, v := range ruleIDs {
				innerErr := secrules.Delete(s.NetworkClient, v).ExtractErr()
				if innerErr != nil {
					return fail.Wrap(NormalizeError(innerErr), "failed to delete provider rule ID #%d", k)
				}
			}
			var innerXErr fail.Error
			asg.Rules, innerXErr = asg.Rules.RemoveRuleByIndex(index)
			if innerXErr != nil {
				return innerXErr
			}
			return nil
		},
		temporal.GetCommunicationTimeout(),
	)
}

// VPL: a default security group by network will be applied to every host, no need to create or update a default security group
//// InitDefaultSecurityGroups create a SafeScale default Security Group, that will apply to every resource
//func (s *Stack) InitDefaultSecurityGroups() fail.Error {
//	rules := stacks.DefaultTCPRules()
//	rules = append(rules, stacks.DefaultUDPRules()...)
//	rules = append(rules, stacks.DefaultICMPRules()...)
//
//	_, xerr := s.InspectSecurityGroup(s.DefaultSecurityGroupName)
//	if xerr != nil {
//		switch xerr.(type) {
//		case *fail.ErrNotFound:
//			// continue to create the default security group
//		default:
//			return xerr
//		}
//	}
//
//	_, xerr = s.CreateSecurityGroup(s.DefaultSecurityGroupName, "Default security group", rules)
//	if xerr != nil {
//		switch xerr.(type) {
//		case *fail.ErrDuplicate:
//			// If duplicate error contains a cause, returns the error, otherwise consider the Group already exists (and succeed)
//			if xerr.Cause() != nil {
//				return xerr
//			}
//		default:
//			return xerr
//		}
//	}
//
//	return nil
//}
