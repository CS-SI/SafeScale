/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// ListSecurityGroups lists existing security groups
func (instance *stack) ListSecurityGroups(ctx context.Context, networkRef string) (list []*abstract.SecurityGroup, ferr fail.Error) {
	list = []*abstract.SecurityGroup{}
	if valid.IsNil(instance) {
		return list, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()

	groups, xerr := instance.rpcReadSecurityGroups(ctx, networkRef, nil)
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
	out, _ := abstract.NewSecurityGroup()
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
func (instance *stack) CreateSecurityGroup(ctx context.Context, networkRef, name, description string, rules abstract.SecurityGroupRules) (asg *abstract.SecurityGroup, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.outscale"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := instance.rpcCreateSecurityGroup(ctx, networkRef, name, description)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := instance.rpcDeleteSecurityGroup(context.Background(), resp.SecurityGroupId); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Security Group '%s'", name))
			}
		}
	}()

	// clears the default rules
	if len(resp.OutboundRules) > 0 {
		if xerr = instance.rpcDeleteSecurityGroupRules(ctx, resp.SecurityGroupId, "Outbound", resp.OutboundRules); xerr != nil {
			return asg, xerr
		}
	}
	if len(resp.InboundRules) > 0 {
		if xerr = instance.rpcDeleteSecurityGroupRules(ctx, resp.SecurityGroupId, "Inbound", resp.InboundRules); xerr != nil {
			return asg, xerr
		}
	}

	asg = toAbstractSecurityGroup(resp)
	xerr = instance.AddRulesToSecurityGroup(ctx, asg, rules...)
	if xerr != nil {
		return nil, xerr
	}

	return asg, nil
}

// DeleteSecurityGroup deletes a security group and its rules
func (instance *stack) DeleteSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupIdentifier) (ferr fail.Error) {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}
	asg, sgLabel, xerr := iaasapi.ValidateSecurityGroupIdentifier(sgParam)
	if xerr != nil {
		return xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = instance.InspectSecurityGroup(ctx, asg.ID)
		if xerr != nil {
			return xerr
		}
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.outscale"), "(%s)", sgLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	return instance.rpcDeleteSecurityGroup(ctx, asg.ID)
}

// InspectSecurityGroup returns information about a security group
func (instance *stack) InspectSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupIdentifier) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	asg, sgLabel, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.outscale"), "(%s)", sgLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	var group osc.SecurityGroup
	if asg.ID != "" {
		group, xerr = instance.rpcReadSecurityGroupByID(ctx, asg.ID)
	} else {
		group, xerr = instance.rpcReadSecurityGroupByName(ctx, asg.Network, asg.Name)
	}
	if xerr != nil {
		return nil, xerr
	}

	out, _ := abstract.NewSecurityGroup()
	out.Name = group.SecurityGroupName
	out.ID = asg.ID
	out.Description = group.Description
	return out, nil
}

// ClearSecurityGroup removes all rules but keep group
func (instance *stack) ClearSecurityGroup(ctx context.Context, asg *abstract.SecurityGroup) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	_, sgLabel, xerr := iaasapi.ValidateSecurityGroupIdentifier(asg)
	if xerr != nil {
		return xerr
	}
	if !asg.IsComplete() {
		return fail.InconsistentError("asg is not complete")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.outscale"), "(%s)", sgLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	group, xerr := instance.rpcReadSecurityGroupByID(ctx, asg.ID)
	if xerr != nil {
		return xerr
	}

	if len(group.InboundRules) > 0 {
		xerr = instance.rpcDeleteSecurityGroupRules(ctx, asg.ID, "Inbound", group.InboundRules)
		if xerr != nil {
			return xerr
		}
	}
	if len(group.OutboundRules) > 0 {
		xerr = instance.rpcDeleteSecurityGroupRules(ctx, asg.ID, "Outbound", group.OutboundRules)
		if xerr != nil {
			return xerr
		}
	}

	asg.Rules = abstract.SecurityGroupRules{}
	return nil
}

// AddRulesToSecurityGroup adds rules to a security group
func (instance *stack) AddRulesToSecurityGroup(ctx context.Context, asg *abstract.SecurityGroup, rules ...*abstract.SecurityGroupRule) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	_, sgLabel, xerr := stacks.ValidateSecurityGroupParameter(asg)
	if xerr != nil {
		return xerr
	}
	if !asg.IsComplete() {
		return fail.InconsistentError("asg is not complete")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.outscale"), "(%s)", sgLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	// FIXME: validator for security group rules? not existent yet...
	// rulesAsUnity := make(abstract.SecurityGroupRules, 0, len(rules))
	// for i := 0; i < len(rules); i++  {
	// 	rulesAsUnity[i] = rules[i]
	// }
	// xerr = rulesAsUnity.Validate()
	// if xerr != nil {
	// 	return nil, xerr
	// }

	for i := 0; i < len(rules); i++ {
		if rules[i].EtherType == ipversion.IPv6 {
			// No IPv6 at Outscale (?)
			return nil
		}

		flow, oscRule, xerr := fromAbstractSecurityGroupRule(rules[i])
		if xerr != nil {
			return xerr
		}

		xerr = instance.rpcCreateSecurityGroupRules(ctx, asg.ID, flow, []osc.SecurityGroupRule{oscRule})
		if xerr != nil {
			return fail.Wrap(xerr, "failed to create rule #%d", i)
		}

		asg.Rules = append(asg.Rules, rules[i])
	}

	asg, xerr = instance.InspectSecurityGroup(ctx, asg)
	return xerr
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
		involved = in.Targets
		usesGroups, xerr = in.TargetsConcernGroups()
		if xerr != nil {
			return "", rule, xerr
		}
	case securitygroupruledirection.Egress:
		flow = "Outbound"
		involved = in.Sources
		usesGroups, xerr = in.SourcesConcernGroups()
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

// DeleteRulesFromSecurityGroup deletes rules from a security group
// Checks first if the rule ID is present in the rules of the security group. If not found, returns (*abstract.SecurityGroup, *fail.ErrNotFound)
func (instance *stack) DeleteRulesFromSecurityGroup(ctx context.Context, asg *abstract.SecurityGroup, rules ...*abstract.SecurityGroupRule) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	_, sgLabel, xerr := stacks.ValidateSecurityGroupParameter(asg)
	if xerr != nil {
		return xerr
	}
	if !asg.IsComplete() {
		return fail.InconsistentError("asg is not complete")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.outscale"), "(%s, <rules>)", sgLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	for _, currentRule := range rules {
		// IPv6 not supported at Outscale (?)
		if currentRule.EtherType == ipversion.IPv6 {
			return nil
		}

		flow, oscRule, xerr := fromAbstractSecurityGroupRule(currentRule)
		if xerr != nil {
			return xerr
		}

		index, xerr := asg.Rules.IndexOfEquivalentRule(currentRule)
		if xerr != nil {
			return xerr
		}

		xerr = instance.rpcDeleteSecurityGroupRules(ctx, asg.ID, flow, []osc.SecurityGroupRule{oscRule})
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// consider a missing rule as a successful deletion and continue
				debug.IgnoreError(xerr)
			default:
				return xerr
			}
		}

		xerr = asg.RemoveRuleByIndex(index)
		if xerr != nil {
			return xerr
		}
	}

	return nil
}

// GetDefaultSecurityGroupName returns the name of the Security Group automatically bound to hosts
func (instance *stack) GetDefaultSecurityGroupName(context.Context) (string, fail.Error) {
	return "", nil
}

// EnableSecurityGroup enables a Security Group
// Does actually nothing for openstack
func (instance *stack) EnableSecurityGroup(context.Context, *abstract.SecurityGroup) fail.Error {
	return fail.NotAvailableError("openstack cannot enable a Security Group")
}

// DisableSecurityGroup disables a Security Group
// Does actually nothing for openstack
func (instance *stack) DisableSecurityGroup(context.Context, *abstract.SecurityGroup) fail.Error {
	return fail.NotAvailableError("openstack cannot disable a Security Group")
}
