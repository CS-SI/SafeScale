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

package outscale

import (
	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ListSecurityGroups lists existing security groups
func (s stack) ListSecurityGroups(networkID string) (list []*abstract.SecurityGroup, xerr fail.Error) {
	list = []*abstract.SecurityGroup{}
	if s.IsNull() {
		return list, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()

	groups, xerr := s.rpcReadSecurityGroups(networkID, nil)
	if xerr != nil {
		return list, xerr
	}

	list = make([]*abstract.SecurityGroup, 0, len(groups))
	for _, v := range groups {
		if networkID == "" || v.NetId == networkID {
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
	out.Rules = make([]abstract.SecurityGroupRule, 0, len(in.InboundRules)+len(in.OutboundRules))
	for _, v := range in.InboundRules {
		out.Rules = append(out.Rules, toAbstractSecurityGroupRule(v, securitygroupruledirection.INGRESS))
	}
	for _, v := range in.OutboundRules {
		out.Rules = append(out.Rules, toAbstractSecurityGroupRule(v, securitygroupruledirection.EGRESS))
	}
	return out
}

func toAbstractSecurityGroupRule(in osc.SecurityGroupRule, direction securitygroupruledirection.Enum) abstract.SecurityGroupRule {
	out := abstract.SecurityGroupRule{
		Direction: direction,
		Protocol:  in.IpProtocol,
		PortFrom:  int32(in.FromPortRange),
		PortTo:    int32(in.ToPortRange),
		Involved:  in.IpRanges,
	}
	return out
}

// CreateSecurityGroup creates a security group
func (s stack) CreateSecurityGroup(networkID, name, description string, rules []abstract.SecurityGroupRule) (asg *abstract.SecurityGroup, xerr fail.Error) {
	nullASG := abstract.NewSecurityGroup()
	if s.IsNull() {
		return nullASG, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcCreateSecurityGroup(networkID, name, description)
	if xerr != nil {
		return nullASG, xerr
	}

	defer func() {
		if xerr != nil {
			if derr := s.rpcDeleteSecurityGroup(resp.SecurityGroupId); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Security Group '%s'", name))
			}
		}
	}()

	// clears the default rules
	if len(resp.OutboundRules) > 0 {
		if xerr = s.rpcDeleteSecurityGroupRules(resp.SecurityGroupId, "Outbound", resp.OutboundRules); xerr != nil {
			return asg, xerr
		}
	}
	if len(resp.InboundRules) > 0 {
		if xerr = s.rpcDeleteSecurityGroupRules(asg.ID, "Inbound", resp.InboundRules); xerr != nil {
			return asg, xerr
		}
	}

	asg = toAbstractSecurityGroup(resp)
	for k, v := range rules {
		asg, xerr = s.AddRuleToSecurityGroup(asg, v)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to add rule #%d", k)
		}
	}

	return asg, nil
}

// DeleteSecurityGroup deletes a security group and its rules
func (s stack) DeleteSecurityGroup(sgParam stacks.SecurityGroupParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg.ID)
		if xerr != nil {
			return xerr
		}
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	return s.rpcDeleteSecurityGroup(asg.ID)
}

// InspectSecurityGroup returns information about a security group
func (s stack) InspectSecurityGroup(sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	nullASG := abstract.NewSecurityGroup()
	if s.IsNull() {
		return nullASG, fail.InvalidInstanceError()
	}
	asg, sgLabel, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nullASG, xerr
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale"), "(%s)", sgLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	var group osc.SecurityGroup
	if asg.ID != "" {
		group, xerr = s.rpcReadSecurityGroupByID(asg.ID)
	} else {
		group, xerr = s.rpcReadSecurityGroupByName(asg.NetworkID, asg.Name)
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
func (s stack) ClearSecurityGroup(sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	nullASG := abstract.NewSecurityGroup()
	if s.IsNull() {
		return nullASG, fail.InvalidInstanceError()
	}
	asg, sgLabel, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg.ID)
		if xerr != nil {
			return asg, xerr
		}
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale"), "(%s)", sgLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	group, xerr := s.rpcReadSecurityGroupByID(asg.ID)
	if xerr != nil {
		return asg, xerr
	}

	if len(group.InboundRules) > 0 {
		if xerr = s.rpcDeleteSecurityGroupRules(asg.ID, "Inbound", group.InboundRules); xerr != nil {
			return asg, xerr
		}
	}
	if len(group.OutboundRules) > 0 {
		if xerr = s.rpcDeleteSecurityGroupRules(asg.ID, "Outbound", group.OutboundRules); xerr != nil {
			return asg, xerr
		}
	}

	asg.Rules = abstract.SecurityGroupRules{}
	return asg, nil
}

// AddRuleToSecurityGroup adds a rule to a security group
func (s stack) AddRuleToSecurityGroup(sgParam stacks.SecurityGroupParameter, rule abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	nullASG := abstract.NewSecurityGroup()
	if s.IsNull() {
		return nullASG, fail.InvalidInstanceError()
	}
	asg, sgLabel, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nullASG, xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg.ID)
		if xerr != nil {
			return asg, xerr
		}
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale"), "(%s)", sgLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	if rule.EtherType == ipversion.IPv6 {
		// No IPv6 at Outscale (?)
		return asg, nil
	}

	flow, oscRule, xerr := fromAbstractSecurityGroupRule(rule)
	if xerr != nil {
		return asg, xerr
	}

	if xerr := s.rpcCreateSecurityGroupRules(asg.ID, flow, []osc.SecurityGroupRule{oscRule}); xerr != nil {
		return asg, xerr
	}
	return s.InspectSecurityGroup(asg.ID)
}

func fromAbstractSecurityGroupRule(in abstract.SecurityGroupRule) (string, osc.SecurityGroupRule, fail.Error) {
	rule := osc.SecurityGroupRule{}
	if in.EtherType == ipversion.IPv6 {
		// No IPv6 at Outscale (?)
		return "", rule, fail.InvalidRequestError("IPv6 is not supported")
	}

	flow := ""
	switch in.Direction {
	case securitygroupruledirection.INGRESS:
		flow = "Inbound"
	case securitygroupruledirection.EGRESS:
		flow = "Outbound"
	default:
		return "", rule, fail.InvalidRequestError("direction of the rule is invalid")
	}

	usesGroups, xerr := in.ConcernsGroups()
	if xerr != nil {
		return "", rule, xerr
	}

	if in.Protocol == "" {
		in.Protocol = "-1"
	}
	rule.IpProtocol = in.Protocol
	rule.FromPortRange = int32(in.PortFrom)
	rule.ToPortRange = int32(in.PortTo)
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
		rule.SecurityGroupsMembers = make([]osc.SecurityGroupsMember, 0, len(in.Involved))
		for _, v := range in.Involved {
			rule.SecurityGroupsMembers = append(rule.SecurityGroupsMembers, osc.SecurityGroupsMember{SecurityGroupId: v})
		}
	} else {
		rule.IpRanges = in.Involved
	}

	return flow, rule, nil
}

// DeleteRuleFromSecurityGroup deletes a rule identified by ID from a security group
// Checks first if the rule ID is present in the rules of the security group. If not found, returns (*abstract.SecurityGroup, *fail.ErrNotFound)
func (s stack) DeleteRuleFromSecurityGroup(sgParam stacks.SecurityGroupParameter, rule abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	nullASG := abstract.NewSecurityGroup()
	if s.IsNull() {
		return nullASG, fail.InvalidInstanceError()
	}
	asg, sgLabel, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg.ID)
		if xerr != nil {
			return asg, xerr
		}
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale"), "(%s, %s)", sgLabel, rule.Description).WithStopwatch().Entering()
	defer tracer.Exiting()

	// IPv6 not supported at Outscale (?)
	if rule.EtherType == ipversion.IPv6 {
		return asg, nil
	}

	flow, oscRule, xerr := fromAbstractSecurityGroupRule(rule)
	if xerr != nil {
		return nil, xerr
	}

	if xerr := s.rpcDeleteSecurityGroupRules(asg.ID, flow, []osc.SecurityGroupRule{oscRule}); xerr != nil {
		return nil, xerr
	}

	return s.InspectSecurityGroup(asg.ID)
}

// GetDefaultSecurityGroupName returns the name of the Security Group automatically bound to hosts
func (s stack) GetDefaultSecurityGroupName() string {
	return ""
}
