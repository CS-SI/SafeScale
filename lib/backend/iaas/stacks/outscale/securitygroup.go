/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package outscale

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/outscale/osc-sdk-go/osc"
)

// ListSecurityGroups lists existing security groups
func (s stack) ListSecurityGroups(ctx context.Context, networkRef string) (list []*abstract.SecurityGroup, ferr fail.Error) {
	list = []*abstract.SecurityGroup{}
	if valid.IsNil(s) {
		return list, fail.InvalidInstanceError()
	}

	groups, xerr := s.rpcReadSecurityGroups(ctx, networkRef, nil)
	if xerr != nil {
		return list, xerr
	}

	list = make([]*abstract.SecurityGroup, 0, len(groups))
	for _, v := range groups {
		if networkRef == "" || v.NetId == networkRef {
			asg := toAbstractSecurityGroup(v)
			list = append(list, asg)
		}
	}
	return list, nil
}

func toAbstractSecurityGroup(in osc.SecurityGroup) *abstract.SecurityGroup {
	out := abstract.NewSecurityGroup()
	out.Name = in.SecurityGroupName
	out.ID = in.SecurityGroupId
	out.Description = in.Description
	out.Rules = make(abstract.SecurityGroupRules, 0, len(in.InboundRules)+len(in.OutboundRules))
	for _, v := range in.InboundRules {
		out.Rules = append(out.Rules, toAbstractSecurityGroupRule(v, securitygroupruledirection.Ingress))
	}
	for _, v := range in.OutboundRules {
		out.Rules = append(out.Rules, toAbstractSecurityGroupRule(v, securitygroupruledirection.Egress))
	}
	return out
}

func toAbstractSecurityGroupRule(in osc.SecurityGroupRule, direction securitygroupruledirection.Enum) *abstract.SecurityGroupRule {
	out := &abstract.SecurityGroupRule{
		Direction: direction,
		Protocol:  in.IpProtocol,
		PortFrom:  in.FromPortRange,
		PortTo:    in.ToPortRange,
		Targets:   in.IpRanges,
	}
	return out
}

// CreateSecurityGroup creates a security group
func (s stack) CreateSecurityGroup(ctx context.Context, networkRef, name, description string, rules abstract.SecurityGroupRules) (asg *abstract.SecurityGroup, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	resp, xerr := s.rpcCreateSecurityGroup(ctx, networkRef, name, description)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := s.rpcDeleteSecurityGroup(context.Background(), resp.SecurityGroupId); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Security Group '%s'", name))
			}
		}
	}()

	// clears the default rules
	if len(resp.OutboundRules) > 0 {
		if xerr = s.rpcDeleteSecurityGroupRules(ctx, resp.SecurityGroupId, "Outbound", resp.OutboundRules); xerr != nil {
			return asg, xerr
		}
	}
	if len(resp.InboundRules) > 0 {
		if xerr = s.rpcDeleteSecurityGroupRules(ctx, resp.SecurityGroupId, "Inbound", resp.InboundRules); xerr != nil {
			return asg, xerr
		}
	}

	asg = toAbstractSecurityGroup(resp)
	for k, v := range rules {
		asg, xerr = s.AddRuleToSecurityGroup(ctx, asg, v)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to add rule #%d", k)
		}
	}

	return asg, nil
}

// DeleteSecurityGroup deletes a security group and its rules
func (s stack) DeleteSecurityGroup(ctx context.Context, asg *abstract.SecurityGroup) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if valid.IsNil(asg) {
		return fail.InvalidParameterError("asg", "cannot be null value of '*abstract.SecurityGroup'")
	}
	if !asg.IsConsistent() {
		var xerr fail.Error
		asg, xerr = s.InspectSecurityGroup(ctx, asg.ID)
		if xerr != nil {
			return xerr
		}
	}

	return s.rpcDeleteSecurityGroup(ctx, asg.ID)
}

// InspectSecurityGroup returns information about a security group
func (s stack) InspectSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}

	var group osc.SecurityGroup
	if asg.ID != "" {
		group, xerr = s.rpcReadSecurityGroupByID(ctx, asg.ID)
	} else {
		group, xerr = s.rpcReadSecurityGroupByName(ctx, asg.Network, asg.Name)
	}
	if xerr != nil {
		return nil, xerr
	}

	out := abstract.NewSecurityGroup()
	out.Name = group.SecurityGroupName
	out.ID = asg.ID
	out.Description = group.Description
	return out, nil
}

// ClearSecurityGroup removes all rules but keep group
func (s stack) ClearSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(ctx, asg.ID)
		if xerr != nil {
			return asg, xerr
		}
	}

	group, xerr := s.rpcReadSecurityGroupByID(ctx, asg.ID)
	if xerr != nil {
		return asg, xerr
	}

	if len(group.InboundRules) > 0 {
		if xerr = s.rpcDeleteSecurityGroupRules(ctx, asg.ID, "Inbound", group.InboundRules); xerr != nil {
			return asg, xerr
		}
	}
	if len(group.OutboundRules) > 0 {
		if xerr = s.rpcDeleteSecurityGroupRules(ctx, asg.ID, "Outbound", group.OutboundRules); xerr != nil {
			return asg, xerr
		}
	}

	asg.Rules = abstract.SecurityGroupRules{}
	return asg, nil
}

// AddRuleToSecurityGroup adds a rule to a security group
func (s stack) AddRuleToSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(ctx, asg.ID)
		if xerr != nil {
			return asg, xerr
		}
	}

	if rule.EtherType == ipversion.IPv6 {
		// No IPv6 at Outscale (?)
		return asg, nil
	}

	flow, oscRule, xerr := fromAbstractSecurityGroupRule(rule)
	if xerr != nil {
		return asg, xerr
	}

	if xerr := s.rpcCreateSecurityGroupRules(ctx, asg.ID, flow, []osc.SecurityGroupRule{oscRule}); xerr != nil {
		return asg, xerr
	}
	asg.Rules = append(asg.Rules, rule)
	return s.InspectSecurityGroup(ctx, asg.ID)
}

func fromAbstractSecurityGroupRule(in *abstract.SecurityGroupRule) (_ string, _ osc.SecurityGroupRule, ferr fail.Error) {
	rule := osc.SecurityGroupRule{}
	if in == nil {
		return "", rule, fail.InvalidParameterCannotBeNilError("in")
	}

	if in.EtherType == ipversion.IPv6 {
		// No IPv6 at Outscale (?)
		return "", rule, fail.InvalidRequestError("IPv6 is not supported")
	}

	var (
		involved   []string
		flow       string
		usesGroups bool
	)
	var xerr fail.Error

	switch in.Direction {
	case securitygroupruledirection.Ingress:
		flow = "Inbound"
		involved = in.Sources
		usesGroups, xerr = in.SourcesConcernGroups()
		if xerr != nil {
			return "", rule, xerr
		}
	case securitygroupruledirection.Egress:
		flow = "Outbound"
		involved = in.Targets
		usesGroups, xerr = in.TargetsConcernGroups()
		if xerr != nil {
			return "", rule, xerr
		}
	default:
		return "", rule, fail.InvalidParameterError("in.Direction", "contains an unsupported value")
	}

	if in.Protocol == "" {
		in.Protocol = "-1"
	}
	rule.IpProtocol = in.Protocol
	rule.FromPortRange = in.PortFrom
	rule.ToPortRange = in.PortTo
	if rule.FromPortRange == 0 && rule.ToPortRange == 0 {
		switch in.Protocol {
		case "icmp", "-1":
			rule.FromPortRange, rule.ToPortRange = 0, 0
		default:
			rule.FromPortRange, rule.ToPortRange = 1, 65535
		}
	} else {
		if rule.ToPortRange == 0 && rule.FromPortRange > 0 {
			rule.ToPortRange = rule.FromPortRange
		}
		if rule.FromPortRange > rule.ToPortRange {
			rule.FromPortRange, rule.ToPortRange = rule.ToPortRange, rule.FromPortRange
		}
	}

	if usesGroups {
		rule.SecurityGroupsMembers = make([]osc.SecurityGroupsMember, 0, len(involved))
		for _, v := range involved {
			rule.SecurityGroupsMembers = append(rule.SecurityGroupsMembers, osc.SecurityGroupsMember{SecurityGroupId: v})
		}
	} else {
		rule.IpRanges = involved
	}

	return flow, rule, nil
}

// DeleteRuleFromSecurityGroup deletes a rule identified by ID from a security group
// Checks first if the rule ID is present in the rules of the security group. If not found, returns (*abstract.SecurityGroup, *fail.ErrNotFound)
func (s stack) DeleteRuleFromSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(ctx, asg.ID)
		if xerr != nil {
			return asg, xerr
		}
	}

	// IPv6 not supported at Outscale (?)
	if rule.EtherType == ipversion.IPv6 {
		return asg, nil
	}

	index, xerr := asg.Rules.IndexOfEquivalentRule(rule)
	if xerr != nil {
		return nil, xerr
	}

	flow, oscRule, xerr := fromAbstractSecurityGroupRule(rule)
	if xerr != nil {
		return nil, xerr
	}

	xerr = s.rpcDeleteSecurityGroupRules(ctx, asg.ID, flow, []osc.SecurityGroupRule{oscRule})
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// consider a missing rule as a successful deletion and continue
			debug.IgnoreError2(ctx, xerr)
		default:
			return nil, xerr
		}
	}

	innerXErr := asg.RemoveRuleByIndex(index)
	if innerXErr != nil {
		return nil, innerXErr
	}

	return s.InspectSecurityGroup(ctx, asg.ID)
}

// GetDefaultSecurityGroupName returns the name of the Security Group automatically bound to hosts
func (s stack) GetDefaultSecurityGroupName(context.Context) (string, fail.Error) {
	// TODO, check this
	return "", nil
}
