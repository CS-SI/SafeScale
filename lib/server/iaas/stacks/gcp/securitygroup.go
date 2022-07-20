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

package gcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	uuid "github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"

	"google.golang.org/api/compute/v1"

	"github.com/CS-SI/SafeScale/v22/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ListSecurityGroups lists existing security groups
// There is no Security Group resource in GCP, so ListSecurityGroups always returns empty slice
func (s stack) ListSecurityGroups(ctx context.Context, networkRef string) ([]*abstract.SecurityGroup, fail.Error) {
	var emptySlice []*abstract.SecurityGroup
	if valid.IsNil(s) {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.gcp")).WithStopwatch().Entering()
	defer tracer.Exiting()

	return emptySlice, nil
}

// CreateSecurityGroup creates a security group
// Actually creates GCP Firewall Rules corresponding to the Security Group rules
func (s stack) CreateSecurityGroup(ctx context.Context, networkRef, name, description string, rules abstract.SecurityGroupRules) (_ *abstract.SecurityGroup, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	auuid, err := uuid.NewV4()
	if err != nil {
		return nil, fail.Wrap(err, "failed to generate unique id for Security Group")
	}

	asg := abstract.NewSecurityGroup()
	asg.ID = fmt.Sprintf("sfsg-%s", auuid)
	asg.Name = name
	asg.Description = description + " (" + asg.ID + ")"
	asg.Network = networkRef
	asg.Rules = rules

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			for _, v := range asg.Rules {
				for _, r := range v.IDs {
					if derr := s.rpcDeleteFirewallRuleByID(context.Background(), r); derr != nil {
						switch ferr.(type) {
						case *fail.ErrNotFound:
							// rule not found, considered as a removal success
							debug.IgnoreError(ferr)
							continue
						default:
							_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete firewall rule %s", r))
						}
					}
					logrus.WithContext(ctx).Debugf("Deleted rule: %s", r)
				}
			}
		}
	}()

	for k, v := range asg.Rules {
		var xerr fail.Error
		asg, xerr = s.AddRuleToSecurityGroup(ctx, asg, v)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed adding rule #%d", k)
		}
	}

	return asg, nil
}

func fromAbstractSecurityGroupRule(in *abstract.SecurityGroupRule) (string, bool, []string, bool, []string, []*compute.FirewallAllowed, fail.Error) {
	if in == nil {
		return "", false, nil, false, nil, nil, fail.InvalidParameterCannotBeNilError("in")
	}

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
	case securitygroupruledirection.Ingress:
		direction = "Ingress"
		sources = in.Sources
		targets = in.Targets
	case securitygroupruledirection.Egress:
		direction = "Egress"
		targets = in.Targets
	default:
		return "", false, nil, false, nil, nil, fail.InvalidParameterError("in.Direction", "must contain either 'securitygroupruledirection.Ingress' or 'securitygroupruledirection.Egress'")
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
func (s stack) DeleteSecurityGroup(ctx context.Context, asg *abstract.SecurityGroup) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if valid.IsNil(asg) {
		return fail.InvalidParameterError("asg", "cannot be null value of '*abstract.SecurityGroup'")
	}
	if !asg.IsComplete() {
		return fail.InvalidParameterError("sgParam", "must be complete")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	if len(asg.Rules) > 0 {
		for k, v := range asg.Rules {
			for _, r := range v.IDs {
				var xerr fail.Error
				if xerr = s.rpcDeleteFirewallRuleByID(ctx, r); xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// rule not found, considered as a removal success
						debug.IgnoreError(xerr)
						continue
					default:
						return fail.Wrap(xerr, "failed to delete rule %d", k)
					}
				}
				logrus.WithContext(ctx).Debugf("Deleted rule: %s", r)
			}
		}
	}
	return nil
}

// InspectSecurityGroup returns information about a security group
// Actually there is no Security Group resource in GCP, so this function always returns a *fail.NotImplementedError error
func (s stack) InspectSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(s) {
		return &abstract.SecurityGroup{}, fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return asg, fail.InvalidParameterError("sgParam", "must be consistent")
	}

	// FIXME: This is a mistake
	return asg, fail.NotImplementedError("no real Security Group resource proposed by gcp") // FIXME: Technical debt
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
	if !asg.IsComplete() {
		return nil, fail.InvalidParameterError("sgParam", "must be complete")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	if len(asg.Rules) > 0 {
		for k, v := range asg.Rules {
			for _, r := range v.IDs {
				if xerr = s.rpcDeleteFirewallRuleByID(ctx, r); xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// rule not found, considered as a removal success
						debug.IgnoreError(xerr)
						continue
					default:
						return asg, fail.Wrap(xerr, "failed to delete rule %d", k)
					}
				}
				logrus.WithContext(ctx).Debugf("Deleted rule: %s", r)
			}
			v.IDs = []string{}
		}
	}
	return asg, nil
}

// AddRuleToSecurityGroup adds a rule to a security group
func (s stack) AddRuleToSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	asg, sgLabel, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}
	if !asg.IsComplete() {
		return nil, fail.InvalidParameterError("sgParam", "must be complete")
	}
	if rule == nil {
		return nil, fail.InvalidParameterCannotBeNilError("rule")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", sgLabel).WithStopwatch().Entering()
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
	resp, xerr := s.rpcCreateFirewallRule(ctx, ruleName, asg.Network, rule.Description, direction, sourcesUseGroups, sources, targetsUseGroups, destinations, allowed, nil)
	if xerr != nil {
		return asg, xerr
	}

	logrus.WithContext(ctx).Debugf("Created rule: %d with name %s", resp.Id, resp.Name)
	rule.IDs = append(rule.IDs, fmt.Sprintf("%d", resp.Id))
	asg.Rules = append(asg.Rules, rule)
	return asg, nil
}

// DeleteRuleFromSecurityGroup deletes a rule from a security group
// For now, this function does nothing in GCP context (have to figure out how to identify Firewall rule corresponding to abstract Security Group rule
func (s stack) DeleteRuleFromSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	asg, sgLabel, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}
	if !asg.IsComplete() {
		return nil, fail.InvalidParameterError("sgParam", "must contain Security Group ID")
	}
	if rule == nil {
		return nil, fail.InvalidParameterCannotBeNilError("rule")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s, %v)", sgLabel, rule).WithStopwatch().Entering()
	defer tracer.Exiting()

	return nil, fail.NotImplementedError() // FIXME: Technical debt
}

// DisableSecurityGroup disables the rules of a Security Group
func (s stack) DisableSecurityGroup(ctx context.Context, asg *abstract.SecurityGroup) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if valid.IsNil(asg) {
		return fail.InvalidParameterError("asg", "cannot be null value of '*abstract.SecurityGroup")
	}
	if !asg.IsComplete() {
		return fail.InvalidParameterError("asg", "must be complete")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", asg.GetName()).WithStopwatch().Entering()
	defer tracer.Exiting()

	for _, v := range asg.Rules {
		for _, r := range v.IDs {
			resp, xerr := s.rpcGetFirewallRuleByID(ctx, r)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					continue
				default:
					return xerr
				}
			}

			if xerr = s.rpcDisableFirewallRuleByName(ctx, resp.Name); xerr != nil {
				return xerr
			}
		}
	}
	return nil
}

// EnableSecurityGroup enables the rules of a Security Group
func (s stack) EnableSecurityGroup(ctx context.Context, asg *abstract.SecurityGroup) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if valid.IsNil(asg) {
		return fail.InvalidParameterError("asg", "cannot be null value of '*abstract.SecurityGroup")
	}
	if !asg.IsComplete() {
		return fail.InvalidParameterError("asg", "must be complete")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", asg.GetName()).WithStopwatch().Entering()
	defer tracer.Exiting()

	for _, v := range asg.Rules {
		for _, r := range v.IDs {
			resp, xerr := s.rpcGetFirewallRuleByID(ctx, r)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					continue
				default:
					return xerr
				}
			}

			if xerr = s.rpcDisableFirewallRuleByName(ctx, resp.Name); xerr != nil {
				return xerr
			}
		}
	}

	return nil
}

// GetDefaultSecurityGroupName returns the name of the Security Group automatically bound to hosts
func (s stack) GetDefaultSecurityGroupName(ctx context.Context) (string, fail.Error) {
	if valid.IsNil(s) {
		return "", fail.InvalidInstanceError()
	}

	cfg, err := s.GetRawConfigurationOptions(ctx)
	if err != nil {
		return "", err
	}

	return cfg.DefaultSecurityGroupName, nil
}
