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
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/antihax/optional"
	"github.com/outscale/osc-sdk-go/osc"
)

// ListSecurityGroups lists existing security groups
func (s Stack) ListSecurityGroups(networkID string) (list []*abstract.SecurityGroup, xerr fail.Error) {
	// if s == nil {
	//     return nil, fail.InvalidInstanceError()
	// }
	list = []*abstract.SecurityGroup{}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()

	readSecurityGroupsRequest := osc.ReadSecurityGroupsRequest{}
	resp, _, err := s.client.SecurityGroupApi.ReadSecurityGroups(s.auth, &osc.ReadSecurityGroupsOpts{
		ReadSecurityGroupsRequest: optional.NewInterface(readSecurityGroupsRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}

	list = make([]*abstract.SecurityGroup, 0, len(resp.SecurityGroups))
	for _, v := range resp.SecurityGroups {
		if networkID == "" || v.NetId == networkID {
			asg := toAbstractSecurityGroup(v)
			list = append(list, asg)
		}
	}
	return list, nil
}

func toAbstractSecurityGroup(in osc.SecurityGroup) *abstract.SecurityGroup {
	out := abstract.NewSecurityGroup(in.SecurityGroupName)
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
		PortFrom:  uint16(in.FromPortRange),
		PortTo:    uint16(in.ToPortRange),
		IPRanges:  in.IpRanges,
	}
	return out
}

//// listSecurityGroupIDs lists the ids of the security group bound to Network
//func (s Stack) listSecurityGroupIDs(networkID string) (list []string, xerr fail.Error) {
//    list = []string{}
//
//    tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.outscale")).WithStopwatch().Entering()
//    defer tracer.Exiting()
//
//    readSecurityGroupsRequest := osc.ReadSecurityGroupsRequest{}
//    resp, _, err := s.client.SecurityGroupApi.ReadSecurityGroups(s.auth, &osc.ReadSecurityGroupsOpts{
//        ReadSecurityGroupsRequest: optional.NewInterface(readSecurityGroupsRequest),
//    })
//    if err != nil {
//        return nil, normalizeError(err)
//    }
//
//    list = make([]string, 0, len(resp.SecurityGroups))
//    for _, v := range resp.SecurityGroups {
//        if networkID == "" || v.NetId == networkID {
//            list = append(list, v.SecurityGroupId)
//        }
//    }
//    return list, nil
//}

// CreateSecurityGroup creates a security group
// Note: parameter 'networkRef' is not used in Outscale, Security Groups scope is tenant-wide.
func (s Stack) CreateSecurityGroup(networkRef, name, description string, rules []abstract.SecurityGroupRule) (asg *abstract.SecurityGroup, xerr fail.Error) {
	// if s == nil {
	//     return nil, fail.InvalidInstanceError()
	// }
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	createSecurityGroupRequest := osc.CreateSecurityGroupRequest{
		Description:       description,
		SecurityGroupName: name,
	}
	resp, _, err := s.client.SecurityGroupApi.CreateSecurityGroup(s.auth, &osc.CreateSecurityGroupOpts{
		CreateSecurityGroupRequest: optional.NewInterface(createSecurityGroupRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}

	asg = toAbstractSecurityGroup(resp.SecurityGroup)

	defer func() {
		if xerr != nil {
			derr := s.DeleteSecurityGroup(asg.ID)
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Security Group '%s'", asg.Name))
			}
		}
	}()

	for k, v := range rules {
		asg, xerr = s.AddRuleToSecurityGroup(asg, v)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to add rule #%d", k)
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

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	deleteSecurityGroupRequest := osc.DeleteSecurityGroupRequest{
		SecurityGroupId: asg.ID,
	}
	_, _, err := s.client.SecurityGroupApi.DeleteSecurityGroup(s.auth, &osc.DeleteSecurityGroupOpts{
		DeleteSecurityGroupRequest: optional.NewInterface(deleteSecurityGroupRequest),
	})
	return normalizeError(err)
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
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg.ID)
		if xerr != nil {
			return asg, xerr
		}
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	readSecurityGroupsRequest := osc.ReadSecurityGroupsRequest{
		Filters: osc.FiltersSecurityGroup{
			SecurityGroupIds: []string{asg.ID},
		},
	}
	res, _, err := s.client.SecurityGroupApi.ReadSecurityGroups(s.auth, &osc.ReadSecurityGroupsOpts{
		ReadSecurityGroupsRequest: optional.NewInterface(readSecurityGroupsRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	sgs := res.SecurityGroups
	if len(sgs) == 0 {
		return nil, fail.NotFoundError("failed to find a Security Group with ID '%s'", asg.ID)
	}
	if len(sgs) > 1 {
		return nil, fail.InconsistentError("found more than one Security Group with ID '%s'", asg.ID)
	}

	sg := res.SecurityGroups[0]
	out := abstract.NewSecurityGroup(sg.SecurityGroupName)
	out.ID = asg.ID
	out.Description = sg.Description
	return out, nil
}

// ClearSecurityGroup removes all rules but keep group
func (s Stack) ClearSecurityGroup(sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	// if s == nil {
	//     return nullAsg, fail.InvalidInstanceError()
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

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	deleteSecurityGroupRuleRequest := osc.DeleteSecurityGroupRuleRequest{
		SecurityGroupId: asg.ID,
		//Rules:           sg.InboundRules,
		Flow: "Inbound",
	}
	_, _, err := s.client.SecurityGroupRuleApi.DeleteSecurityGroupRule(s.auth, &osc.DeleteSecurityGroupRuleOpts{
		DeleteSecurityGroupRuleRequest: optional.NewInterface(deleteSecurityGroupRuleRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}

	deleteSecurityGroupRuleRequest.Flow = "Outbound"
	_, _, err = s.client.SecurityGroupRuleApi.DeleteSecurityGroupRule(s.auth, &osc.DeleteSecurityGroupRuleOpts{
		DeleteSecurityGroupRuleRequest: optional.NewInterface(deleteSecurityGroupRuleRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	asg.Rules = abstract.SecurityGroupRules{}
	return asg, nil
}

// AddRuleToSecurityGroup adds a rule to a security group
func (s Stack) AddRuleToSecurityGroup(sgParam stacks.SecurityGroupParameter, rule abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	// if s == nil {
	//     return nullAsg, fail.InvalidInstanceError()
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

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	flow, oscRule, xerr := fromAbstractSecurityGroupRule(rule)
	if xerr != nil {
		return nil, xerr
	}
	createSecurityGroupRuleRequest := osc.CreateSecurityGroupRuleRequest{
		SecurityGroupId: asg.ID,
		Rules:           []osc.SecurityGroupRule{oscRule},
		Flow:            flow,
	}
	_, _, err := s.client.SecurityGroupRuleApi.CreateSecurityGroupRule(s.auth, &osc.CreateSecurityGroupRuleOpts{
		CreateSecurityGroupRuleRequest: optional.NewInterface(createSecurityGroupRuleRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	return s.InspectSecurityGroup(asg.ID)
}

func fromAbstractSecurityGroupRule(in abstract.SecurityGroupRule) (string, osc.SecurityGroupRule, fail.Error) {
	rule := osc.SecurityGroupRule{}

	flow := ""
	switch in.Direction {
	case securitygroupruledirection.INGRESS:
		flow = "Inbound"
	case securitygroupruledirection.EGRESS:
		flow = "Outbound"
	default:
		return "", rule, fail.InvalidRequestError("direction of the rule is invalid")
	}

	rule.IpProtocol = in.Protocol
	if in.PortFrom <= 0 && in.PortTo <= 0 {
		rule.FromPortRange, rule.ToPortRange = -1, -1
	} else {
		if in.PortFrom > in.PortTo {
			in.PortFrom, in.PortTo = in.PortTo, in.PortFrom
		}
	}
	rule.IpRanges = in.IPRanges

	return flow, rule, nil
}

// DeleteRuleFromSecurityGroup deletes a rule identified by ID from a security group
// Checks first if the rule ID is present in the rules of the security group. If not found, returns (*abstract.SecurityGroup, *fail.ErrNotFound)
func (s Stack) DeleteRuleFromSecurityGroup(sgParam stacks.SecurityGroupParameter, rule abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	// if s == nil {
	//     return false, fail.InvalidInstanceError()
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

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale"), "(%s, %s)", asg.ID, rule.Description).WithStopwatch().Entering()
	defer tracer.Exiting()

	flow, oscRule, xerr := fromAbstractSecurityGroupRule(rule)
	if xerr != nil {
		return nil, xerr
	}

	deleteSecurityGroupRuleRequest := osc.DeleteSecurityGroupRuleRequest{
		SecurityGroupId: asg.ID,
		Rules:           []osc.SecurityGroupRule{oscRule},
		Flow:            flow,
	}
	_, _, err := s.client.SecurityGroupRuleApi.DeleteSecurityGroupRule(s.auth, &osc.DeleteSecurityGroupRuleOpts{
		DeleteSecurityGroupRuleRequest: optional.NewInterface(deleteSecurityGroupRuleRequest),
	})
	if err != nil {
		return asg, normalizeError(err)
	}

	return s.InspectSecurityGroup(asg.ID)
}
