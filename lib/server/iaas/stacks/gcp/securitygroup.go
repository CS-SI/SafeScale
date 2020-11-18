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

package gcp

import (
	"fmt"
	"strings"

	uuid "github.com/satori/go.uuid"
	"google.golang.org/api/compute/v1"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ListSecurityGroups lists existing security groups
// There is no Security Group resource in GCP, so ListSecurityGroups always returns empty slice
func (s stack) ListSecurityGroups(networkRef string) ([]*abstract.SecurityGroup, fail.Error) {
	var emptySlice []*abstract.SecurityGroup
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.gcp")).WithStopwatch().Entering()
	defer tracer.Exiting()

	return emptySlice, nil
}

// CreateSecurityGroup creates a security group
// Actually creates GCP Firewall Rules corresponding to the Security Group rules
func (s stack) CreateSecurityGroup(networkRef, name, description string, rules []abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, xerr fail.Error) {
	nullASG := abstract.NewSecurityGroup()
	if s.IsNull() {
		return nullASG, fail.InvalidInstanceError()
	}
	if name == "" {
		return nullASG, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	uuid, err := uuid.NewV4()
	if err != nil {
		return nullASG, fail.Wrap(err, "failed to generate unique id for Security Group")
	}

	asg := abstract.NewSecurityGroup()
	asg.ID = fmt.Sprintf("sfsg-%s", uuid)
	asg.Name = name
	asg.Description = description + " (" + asg.ID + ")"
	asg.NetworkID = networkRef
	asg.Rules = rules

	defer func() {
		if xerr != nil {
			for _, v := range asg.Rules {
				for _, r := range v.IDs {
					if derr := s.rpcDeleteFirewallRuleByID(r); derr != nil {
						_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete firewall rule %s", r))
					}
				}
			}
		}
	}()

	for k, v := range asg.Rules {
		asg, xerr = s.AddRuleToSecurityGroup(asg, v)
		if xerr != nil {
			return nullASG, fail.Wrap(xerr, "failed adding rule #%d", k)
		}
	}

	return asg, nil
}

func fromAbstractSecurityGroupRule(in abstract.SecurityGroupRule) (string, bool, []string, bool, []string, []*compute.FirewallAllowed, fail.Error) {
	if in.EtherType == ipversion.IPv6 {
		return "", false, nil, false, nil, nil, fail.InvalidRequestError("unsupported IPv6 rule")
	}

	var (
		direction        string
		sources, targets []string
		ports            string
	)

	sourcesUseGroups, xerr := in.SourcesConcernGroups()
	if xerr != nil {
		return "", false, nil, false, nil, nil, xerr
	}
	targetsUseGroups, xerr := in.TargetsConcernGroups()
	if xerr != nil {
		return "", false, nil, false, nil, nil, xerr
	}
	switch in.Direction {
	case securitygroupruledirection.INGRESS:
		direction = "INGRESS"
		sources = in.Sources
		targets = in.Targets
	case securitygroupruledirection.EGRESS:
		direction = "EGRESS"
		targets = in.Targets
	default:
		return "", false, nil, false, nil, nil, fail.InvalidParameterError("in.Direction", "must contain either 'securitygroupruledirection.INGRESS' or 'securitygroupruledirection.EGRESS'")
	}

	var allowed []*compute.FirewallAllowed
	if in.Protocol == "" {
		// empty protocol means all protocols : tcp, udp, icmp (leaving out sctp for now; do not know what to do with this)
		allowed = make([]*compute.FirewallAllowed, 0, 3)
		allowed = append(allowed, &compute.FirewallAllowed{IPProtocol: "tcp", Ports: []string{"0-65535"}})
		allowed = append(allowed, &compute.FirewallAllowed{IPProtocol: "udp", Ports: []string{"0-65535"}})
		allowed = append(allowed, &compute.FirewallAllowed{IPProtocol: "icmp"})
	} else {
		item := compute.FirewallAllowed{
			IPProtocol: in.Protocol,
		}
		switch strings.ToLower(in.Protocol) {
		case "tcp", "udp", "sctp":
			if in.PortTo <= 0 {
				in.PortTo = in.PortFrom
			} else if in.PortFrom > in.PortTo {
				in.PortFrom, in.PortTo = in.PortTo, in.PortFrom
			}
			if in.PortFrom <= 0 && in.PortTo <= 0 {
				in.PortFrom, in.PortTo = 0, 63353
			}
			if in.PortFrom != in.PortTo {
				ports = fmt.Sprintf("%d-%d", in.PortFrom, in.PortTo)
			} else {
				ports = fmt.Sprintf("%d", in.PortFrom)
			}
			item.Ports = []string{ports}
		}
		allowed = append(allowed, &item)
	}
	return direction, sourcesUseGroups, sources, targetsUseGroups, targets, allowed, nil
}

// DeleteSecurityGroup deletes a security group and its rules
func (s stack) DeleteSecurityGroup(asg *abstract.SecurityGroup) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if asg.IsNull() {
		return fail.InvalidParameterError("asg", "cannot be null value of '*abstract.SecurityGroup'")
	}
	if !asg.IsComplete() {
		return fail.InvalidParameterError("sgParam", "must be complete")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	if len(asg.Rules) > 0 {
		for k, v := range asg.Rules {
			for _, r := range v.IDs {
				if xerr = s.rpcDeleteFirewallRuleByID(r); xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// rule not found, consider it as a removal success
					default:
						return fail.Wrap(xerr, "failed to delete rule %d", k)
					}
				}
			}
		}
	}
	return nil
}

// InspectSecurityGroup returns information about a security group
// Actually there is no Security Group resource in GCP, so this function always returns a *fail.ErrNotAvailable error
func (s stack) InspectSecurityGroup(sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	if s.IsNull() {
		return &abstract.SecurityGroup{}, fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return asg, fail.InvalidParameterError("sgParam", "must be consistent")
	}

	// tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	// defer tracer.Exiting()

	return asg, fail.NotAvailableError("no real Security Group resource proposed by gcp")
}

// ClearSecurityGroup removes all rules but keep group
func (s stack) ClearSecurityGroup(sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	nullASG := abstract.NewSecurityGroup()
	if s.IsNull() {
		return nullASG, fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nullASG, xerr
	}
	if !asg.IsComplete() {
		return nullASG, fail.InvalidParameterError("sgParam", "must be complete")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	if len(asg.Rules) > 0 {
		for k, v := range asg.Rules {
			for _, r := range v.IDs {
				if xerr = s.rpcDeleteFirewallRuleByID(r); xerr != nil {
					return asg, fail.Wrap(xerr, "failed to delete rule %d", k)
				}
			}
			v.IDs = []string{}
		}
	}
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
	if !asg.IsComplete() {
		return nullASG, fail.InvalidParameterError("sgParam", "must be complete")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", sgLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	if rule.EtherType == ipversion.IPv6 {
		// No IPv6 at Outscale (?)
		return asg, nil
	}

	direction, sourcesUseGroups, sources, targetsUseGroups, destinations, allowed, xerr := fromAbstractSecurityGroupRule(rule)
	if xerr != nil {
		return asg, xerr
	}
	ruleName := fmt.Sprintf("%s-%d", asg.ID, len(asg.Rules))
	// description := fmt.Sprintf("SafeScale SG '%s', rule #%d", asg.Name, len(asg.Rules))
	resp, xerr := s.rpcCreateFirewallRule(ruleName, asg.NetworkID, rule.Description, direction, sourcesUseGroups, sources, targetsUseGroups, destinations, allowed, nil)
	if xerr != nil {
		return asg, xerr
	}
	rule.IDs = append(rule.IDs, fmt.Sprintf("%d", resp.Id))
	asg.Rules = append(asg.Rules, rule)
	return asg, nil
}

// DeleteRuleFromSecurityGroup deletes a rule from a security group
// For now, this function does nothing in GCP context (have to figure out how to identify Firewall rule corresponding to abstract Security Group rule
func (s stack) DeleteRuleFromSecurityGroup(sgParam stacks.SecurityGroupParameter, rule abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	nullASG := abstract.NewSecurityGroup()
	if s.IsNull() {
		return nullASG, fail.InvalidInstanceError()
	}
	asg, sgLabel, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nullASG, xerr
	}
	if !asg.IsComplete() {
		return nullASG, fail.InvalidParameterError("sgParam", "must contain Security Group ID")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s, %v)", sgLabel, rule).WithStopwatch().Entering()
	defer tracer.Exiting()

	return nil, fail.NotImplementedError()
}

// DisableSecurityGroup disables the rules of a Security Group
func (s stack) DisableSecurityGroup(asg *abstract.SecurityGroup) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if asg.IsNull() {
		return fail.InvalidParameterError("asg", "cannot be null value of '*abstract.SecurityGroup")
	}
	if !asg.IsComplete() {
		return fail.InvalidParameterError("asg", "must be complete")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", asg.GetName()).WithStopwatch().Entering()
	defer tracer.Exiting()

	for _, v := range asg.Rules {
		for _, r := range v.IDs {
			resp, xerr := s.rpcGetFirewallRuleByID(r)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					continue
				default:
					return xerr
				}
			}

			if xerr = s.rpcDisableFirewallRuleByName(resp.Name); xerr != nil {
				return xerr
			}
		}
	}
	return nil
}

// EnableSecurityGroup enables the rules of a Security Group
func (s stack) EnableSecurityGroup(asg *abstract.SecurityGroup) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if asg.IsNull() {
		return fail.InvalidParameterError("asg", "cannot be null value of '*abstract.SecurityGroup")
	}
	if !asg.IsComplete() {
		return fail.InvalidParameterError("asg", "must be complete")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", asg.GetName()).WithStopwatch().Entering()
	defer tracer.Exiting()

	for _, v := range asg.Rules {
		for _, r := range v.IDs {
			resp, xerr := s.rpcGetFirewallRuleByID(r)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					continue
				default:
					return xerr
				}
			}

			if xerr = s.rpcDisableFirewallRuleByName(resp.Name); xerr != nil {
				return xerr
			}
		}
	}

	return nil
}

// GetDefaultSecurityGroupName returns the name of the Security Group automatically bound to hosts
func (s stack) GetDefaultSecurityGroupName() string {
	if s.IsNull() {
		return ""
	}
	return s.GetConfigurationOptions().DefaultSecurityGroupName
}
