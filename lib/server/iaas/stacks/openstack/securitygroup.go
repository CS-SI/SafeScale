/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	secgroups "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	secrules "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

const defaultSecurityGroupName = "default"

// ListSecurityGroups lists existing security groups
// Parameter 'networkRef' is not used in Openstack (they are tenant-wide)
func (s Stack) ListSecurityGroups(networkRef string) ([]*abstract.SecurityGroup, fail.Error) {
	var emptySlice []*abstract.SecurityGroup
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	var list []*abstract.SecurityGroup
	opts := secgroups.ListOpts{}
	xerr := stacks.RetryableRemoteCall(
		func() error {
			list = []*abstract.SecurityGroup{}
			return secgroups.List(s.NetworkClient, opts).EachPage(func(page pagination.Page) (bool, error) {
				l, err := secgroups.ExtractGroups(page)
				if err != nil {
					return false, err
				}
				for _, e := range l {
					n := abstract.NewSecurityGroup()
					n.Name = e.Name
					n.ID = e.ID
					n.Description = e.Description
					list = append(list, n)
				}
				return true, nil
			})
		},
		NormalizeError,
	)
	return list, xerr
}

// CreateSecurityGroup creates a security group
// Parameter 'networkRef' is not used in Openstack, Security Groups are tenant-wide.
// Returns nil, *fail.ErrDuplicate if already 1 security group exists with that name
// Returns nil, *fail.ErrDuplicate(with a cause *fail.ErrDuplicate) if more than 1 security group exist with that name
func (s Stack) CreateSecurityGroup(networkRef, name, description string, rules abstract.SecurityGroupRules) (*abstract.SecurityGroup, fail.Error) {
	nullASG := abstract.NewSecurityGroup()
	if s.IsNull() {
		return nullASG, fail.InvalidInstanceError()
	}
	if name == "" {
		return nullASG, fail.InvalidParameterError("name", "cannot be empty string")
	}

	asg, xerr := s.InspectSecurityGroup(name)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			asg = abstract.NewSecurityGroup()
			asg.Name = name
			// continue
			debug.IgnoreError(xerr)
		case *fail.ErrDuplicate:
			// Special case : a duplicate error may come from OpenStack after normalization, because there are already more than 1
			// security groups with the same name. In this situation, returns a DuplicateError with the xerr as cause
			return nullASG, fail.DuplicateErrorWithCause(xerr, "more than one Security Group named '%s' found", name)
		default:
			return nullASG, xerr
		}
	} else {
		return nullASG, fail.DuplicateError("a security group named '%s' already exist", name)
	}

	// create security group on provider side
	createOpts := secgroups.CreateOpts{
		Name:        name,
		Description: description,
	}
	xerr = stacks.RetryableRemoteCall(
		func() error {
			r, innerErr := secgroups.Create(s.NetworkClient, createOpts).Extract()
			if innerErr != nil {
				return innerErr
			}
			asg.ID = r.ID
			return nil
		},
		NormalizeError,
	)
	if xerr != nil {
		return nullASG, xerr
	}

	// Starting from here, delete security group on error
	defer func() {
		if xerr != nil {
			if derr := s.DeleteSecurityGroup(asg); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete security group"))
			}
		}
	}()

	// In OpenStack, freshly created security group may contain default rules; we do not want them
	asg, xerr = s.ClearSecurityGroup(asg)
	if xerr != nil {
		return nullASG, xerr
	}

	// now adds security rules
	asg.Rules = make(abstract.SecurityGroupRules, 0, len(rules))
	for _, v := range rules {
		if asg, xerr = s.AddRuleToSecurityGroup(asg, v); xerr != nil {
			return nullASG, xerr
		}
	}
	return asg, nil
}

// DeleteSecurityGroup deletes a security group and its rules
func (s Stack) DeleteSecurityGroup(asg *abstract.SecurityGroup) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if asg.IsNull() {
		return fail.InvalidParameterError("asg", "cannot be null value of '*abstract.SecurityGroup'")
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg.ID)
		if xerr != nil {
			return xerr
		}
	}

	// delete security group rules
	for _, v := range asg.Rules {
		xerr = stacks.RetryableRemoteCall(
			func() error {
				for _, id := range v.IDs {
					if innerErr := secrules.Delete(s.NetworkClient, id).ExtractErr(); innerErr != nil {
						return innerErr
					}
				}
				return nil
			},
			NormalizeError,
		)
		if xerr != nil {
			return xerr
		}
	}

	// delete security group
	return stacks.RetryableRemoteCall(
		func() error {
			return secgroups.Delete(s.NetworkClient, asg.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// InspectSecurityGroup returns information about a security group
func (s Stack) InspectSecurityGroup(sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	nullASG := abstract.NewSecurityGroup()
	if s.IsNull() {
		return nullASG, fail.InvalidInstanceError()
	}
	asg, asgLabel, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nullASG, xerr
	}

	var r *secgroups.SecGroup
	xerr = stacks.RetryableRemoteCall(
		func() (innerErr error) {
			var id string
			switch {
			case asg.ID != "":
				id = asg.ID
			case asg.Name != "":
				// FIXME: returning *groups.secgroup may be more convenient; currently, we read twice the same record
				id, innerErr = getSGIDFromName(s.NetworkClient, asg.Name)
				if innerErr != nil {
					return innerErr
				}
			}
			if id == "" {
				return fail.NotFoundError("failed to query Security Group %s", asgLabel)
			}
			r, innerErr = secgroups.Get(s.NetworkClient, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nullASG, fail.NotFoundError("failed to query Security Group %s", asgLabel)
		default:
			return nullASG, xerr
		}
	}
	if r == nil {
		return nullASG, fail.NotFoundError("failed to find Security Group %s", asgLabel)
	}

	asg.ID = r.ID
	asg.Name = r.Name
	asg.Description = r.Description
	if asg.Rules, xerr = toAbstractSecurityGroupRules(r.Rules); xerr != nil {
		return nullASG, xerr
	}
	return asg, nil
}

// ClearSecurityGroup removes all rules but keep group
func (s Stack) ClearSecurityGroup(sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	nullASG := abstract.NewSecurityGroup()
	if s.IsNull() {
		return nullASG, fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nullASG, xerr
	}
	asg, xerr = s.InspectSecurityGroup(asg.ID)
	if xerr != nil {
		return asg, xerr
	}

	// delete security group rules
	for _, v := range asg.Rules {
		xerr = stacks.RetryableRemoteCall(
			func() error {
				for _, id := range v.IDs {
					if innerErr := secrules.Delete(s.NetworkClient, id).ExtractErr(); innerErr != nil {
						return innerErr
					}
				}
				return nil
			},
			NormalizeError,
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
	asg.Rules = abstract.SecurityGroupRules{}
	return asg, nil
}

// toAbstractSecurityGroupRules
func toAbstractSecurityGroupRules(in []secrules.SecGroupRule) (abstract.SecurityGroupRules, fail.Error) {
	out := make(abstract.SecurityGroupRules, 0, len(in))
	for k, v := range in {
		direction := convertDirectionToAbstract(v.Direction)
		if direction == securitygroupruledirection.Unknown {
			return nil, fail.InvalidRequestError("invalid value '%s' to 'Direction' field in rule #%d", v.Direction, k+1)
		}
		etherType := convertEtherTypeToAbstract(secrules.RuleEtherType(v.EtherType))
		if etherType == ipversion.Unknown {
			return nil, fail.InvalidRequestError("invalid value '%s' to 'EtherType' field in rule #%d", v.EtherType, k+1)
		}

		r := &abstract.SecurityGroupRule{
			IDs:         []string{v.ID},
			EtherType:   etherType,
			Description: v.Description,
			Direction:   direction,
			Protocol:    v.Protocol,
			PortFrom:    int32(v.PortRangeMin),
			PortTo:      int32(v.PortRangeMax),
		}
		switch direction {
		case securitygroupruledirection.Ingress:
			if v.RemoteGroupID != "" {
				r.Sources = []string{v.RemoteGroupID}
			} else {
				r.Sources = []string{v.RemoteIPPrefix}
			}
		case securitygroupruledirection.Egress:
			if v.RemoteGroupID != "" {
				r.Targets = []string{v.RemoteGroupID}
			} else {
				r.Targets = []string{v.RemoteIPPrefix}
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// convertDirectionToAbstract ...
func convertDirectionToAbstract(in string) securitygroupruledirection.Enum {
	switch secrules.RuleDirection(in) {
	case secrules.DirIngress:
		return securitygroupruledirection.Ingress
	case secrules.DirEgress:
		return securitygroupruledirection.Egress
	default:
		return securitygroupruledirection.Unknown
	}
}

// convertDirectionFromAbstract ...
func convertDirectionFromAbstract(in securitygroupruledirection.Enum) secrules.RuleDirection {
	switch in {
	case securitygroupruledirection.Egress:
		return secrules.DirEgress
	case securitygroupruledirection.Ingress:
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

// AddRuleToSecurityGroup adds a rule to a security group
// On success, return Security Group with added rule
func (s Stack) AddRuleToSecurityGroup(sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (asg *abstract.SecurityGroup, xerr fail.Error) {
	nullASG := abstract.NewSecurityGroup()
	if s.IsNull() {
		return nullASG, fail.InvalidInstanceError()
	}

	asg, _, xerr = stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nullASG, xerr
	}

	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg.ID)
		if xerr != nil {
			return asg, xerr
		}
	}

	if _, xerr = asg.Rules.IndexOfEquivalentRule(rule); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError(xerr)
		default:
			return asg, xerr
		}
	}

	direction := convertDirectionFromAbstract(rule.Direction)
	if direction == "" { // Invalid direction is not permitted
		return asg, fail.InvalidRequestError("invalid value '%s' in 'Direction' field of rule", rule.Direction)
	}

	var (
		involved   []string
		usesGroups bool
	)
	switch rule.Direction {
	case securitygroupruledirection.Ingress:
		involved = rule.Sources
		usesGroups, xerr = rule.SourcesConcernGroups()
		if xerr != nil {
			return nil, xerr
		}
	case securitygroupruledirection.Egress:
		involved = rule.Targets
		usesGroups, xerr = rule.TargetsConcernGroups()
		if xerr != nil {
			return nil, xerr
		}
	default:
		return nil, fail.InvalidParameterError("in.Direction", "contains an unsupported value")
	}

	etherType := convertEtherTypeFromAbstract(rule.EtherType)
	if etherType == "" { // If no valid EtherType is provided, force to IPv4
		etherType = secrules.EtherType4
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

	rule.IDs = make([]string, 0, len(involved))
	if usesGroups {
		for _, v := range involved {
			createOpts.RemoteGroupID = v
			createOpts.Description = rule.Description + " (" + v + ")"
			xerr = stacks.RetryableRemoteCall(
				func() error {
					r, innerErr := secrules.Create(s.NetworkClient, createOpts).Extract()
					if innerErr != nil {
						return innerErr
					}
					rule.IDs = append(rule.IDs, r.ID)
					return nil
				},
				NormalizeError,
			)
			if xerr != nil {
				return asg, xerr
			}
		}
	} else {
		for _, v := range involved {
			createOpts.RemoteIPPrefix = v
			createOpts.Description = rule.Description + " (" + v + ")"
			xerr = stacks.RetryableRemoteCall(
				func() error {
					r, innerErr := secrules.Create(s.NetworkClient, createOpts).Extract()
					if innerErr != nil {
						return innerErr
					}
					rule.IDs = append(rule.IDs, r.ID)
					return nil
				},
				NormalizeError,
			)
			if xerr != nil {
				return asg, xerr
			}
		}
	}
	asg.Rules = append(asg.Rules, rule)

	return asg, nil
}

// DeleteRuleFromSecurityGroup deletes a rule identified by ID from a security group
// Checks first if the rule ID is present in the rules of the security group. If not found, returns (*abstract.SecurityGroup, *fail.ErrNotFound)
func (s Stack) DeleteRuleFromSecurityGroup(sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (asg *abstract.SecurityGroup, xerr fail.Error) {
	nullASG := abstract.NewSecurityGroup()
	if s.IsNull() {
		return nullASG, fail.InvalidInstanceError()
	}
	asg, _, xerr = stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nullASG, xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg.ID)
		if xerr != nil {
			return asg, xerr
		}
	}
	if rule == nil {
		return nullASG, fail.InvalidParameterCannotBeNilError("rule")
	}

	index, xerr := asg.Rules.IndexOfEquivalentRule(rule)
	if xerr != nil {
		return asg, xerr
	}
	ruleIDs := asg.Rules[index].IDs

	return asg, stacks.RetryableRemoteCall(
		func() error {
			for k, v := range ruleIDs {
				innerErr := secrules.Delete(s.NetworkClient, v).ExtractErr()
				if innerErr != nil {
					return fail.Wrap(innerErr, "failed to delete provider rule #%d", k)
				}
			}
			var innerXErr fail.Error
			asg.Rules, innerXErr = asg.Rules.RemoveRuleByIndex(index)
			if innerXErr != nil {
				return innerXErr
			}

			return nil
		},
		NormalizeError,
	)
}

// GetDefaultSecurityGroupName returns the name of the Security Group automatically bound to hosts
func (s Stack) GetDefaultSecurityGroupName() string {
	if s.IsNull() {
		return ""
	}
	return s.GetConfigurationOptions().DefaultSecurityGroupName
}

// EnableSecurityGroup enables a Security Group
// Does actually nothing for openstack
func (s Stack) EnableSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return fail.NotAvailableError("openstack cannot enable a Security Group")
}

// DisableSecurityGroup disables a Security Group
// Does actually nothing for openstack
func (s Stack) DisableSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return fail.NotAvailableError("openstack cannot disable a Security Group")
}
