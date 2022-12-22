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

package aws

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ListSecurityGroups lists existing security groups
func (s stack) ListSecurityGroups(ctx context.Context, networkRef string) ([]*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.gcp")).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcDescribeSecurityGroups(ctx, aws.String(networkRef), nil)
	if xerr != nil {
		return nil, xerr
	}

	out := make([]*abstract.SecurityGroup, 0, len(resp))
	for k, v := range resp {
		item, xerr := toAbstractSecurityGroup(v)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to convert rule #%d", k)
		}
		out = append(out, item)
	}
	return out, nil
}

// CreateSecurityGroup creates a security group
// Note: parameter 'networkRef' is used in AWS, Security Groups scope is Network/VPC-wide.
func (s stack) CreateSecurityGroup(ctx context.Context, networkRef, name, description string, rules abstract.SecurityGroupRules) (_ *abstract.SecurityGroup, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	network, xerr := s.InspectNetwork(ctx, networkRef)
	if xerr != nil {
		return nil, xerr
	}

	// Create the security group with the VPC, name and description.
	resp, xerr := s.rpcCreateSecurityGroup(ctx, aws.String(network.ID), aws.String(name), aws.String(description))
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create security group named '%s'", name)
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := s.rpcDeleteSecurityGroup(context.Background(), resp); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Security Group '%s'", name))
			}
		}
	}()

	asg := abstract.NewSecurityGroup()
	asg.Name = name
	asg.ID = aws.StringValue(resp)
	asg.Network = network.ID
	asg.Description = description

	// clears default rules set at creation
	if _, xerr = s.ClearSecurityGroup(ctx, asg); xerr != nil {
		return nil, xerr
	}

	// Converts abstract rules to AWS IpPermissions
	ingressPermissions, egressPermissions, xerr := s.fromAbstractSecurityGroupRules(*asg, rules)
	if xerr != nil {
		return nil, xerr
	}

	// Add permissions to the Security Group
	if xerr = s.addRules(ctx, asg, ingressPermissions, egressPermissions); xerr != nil {
		return nil, xerr
	}

	asg.Rules = rules

	return asg, nil
}

// fromAbstractSecurityGroupRules converts a slice of abstract.SecurityGroupRule to a couple of slices of AWS ec2.IpPermission,
// corresponding respectively to ingress and egress IpPermission
func (s stack) fromAbstractSecurityGroupRules(asg abstract.SecurityGroup, in abstract.SecurityGroupRules) ([]*ec2.IpPermission, []*ec2.IpPermission, fail.Error) {
	ingress := make([]*ec2.IpPermission, 0, len(in))
	egress := make([]*ec2.IpPermission, 0, len(in))
	for _, v := range in {
		// IPv6 rules not supported (there is something to do on VPC or subnet side, currently adding IPv6 rules leads to AWS error "CIDR block ::/0 is malformed"
		if v.EtherType == ipversion.IPv6 {
			continue
		}
		item, xerr := s.fromAbstractSecurityGroupRule(asg, *v)
		if xerr != nil {
			return nil, nil, xerr
		}
		switch v.Direction {
		case securitygroupruledirection.Ingress:
			ingress = append(ingress, item)
		case securitygroupruledirection.Egress:
			egress = append(egress, item)
		default:
			return nil, nil, fail.InvalidRequestError("rule #%d contains an invalid direction '%d'", v.Direction)
		}
	}
	return ingress, egress, nil
}

// fromAbstractSecurityGroupRule converts an abstract.SecurityGroupRule to AWS ec2.IpPermission
func (s stack) fromAbstractSecurityGroupRule(asg abstract.SecurityGroup, in abstract.SecurityGroupRule) (_ *ec2.IpPermission, ferr fail.Error) {
	var (
		involved   []string
		usesGroups bool
	)
	var xerr fail.Error
	switch in.Direction {
	case securitygroupruledirection.Ingress:
		involved = in.Sources
		usesGroups, xerr = in.SourcesConcernGroups()
		if xerr != nil {
			return nil, xerr
		}
	case securitygroupruledirection.Egress:
		involved = in.Targets
		usesGroups, xerr = in.TargetsConcernGroups()
		if xerr != nil {
			return nil, xerr
		}
	default:
		return nil, fail.InvalidParameterError("in.Direction", "contains an unsupported value")
	}

	if in.Protocol == "" {
		in.Protocol = "-1"
	}
	if in.Protocol == "icmp" {
		if in.PortFrom == 0 {
			in.PortFrom = -1
		}
		if in.PortTo == 0 {
			in.PortTo = -1
		}
	} else if in.PortTo == 0 {
		in.PortTo = in.PortFrom

	}

	var groupPairs []*ec2.UserIdGroupPair
	var ipranges []*ec2.IpRange

	out := &ec2.IpPermission{}
	if usesGroups {
		groupPairs = make([]*ec2.UserIdGroupPair, 0, len(in.Targets))
		for _, v := range involved {
			item := ec2.UserIdGroupPair{
				VpcId:   aws.String(asg.Network),
				GroupId: aws.String(v),
			}
			groupPairs = append(groupPairs, &item)
		}
		out.SetUserIdGroupPairs(groupPairs)
	} else {
		ipranges = make([]*ec2.IpRange, 0, len(involved))
		for _, v := range involved {
			ipranges = append(ipranges, &ec2.IpRange{CidrIp: aws.String(v)})
		}
		out.SetIpRanges(ipranges)
	}

	out.SetIpProtocol(in.Protocol).
		SetFromPort(int64(in.PortFrom)).
		SetToPort(int64(in.PortTo))
	return out, nil
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

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	return s.rpcDeleteSecurityGroup(ctx, aws.String(asg.ID))
}

// InspectSecurityGroup returns information about a security group
func (s stack) InspectSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	asg, sgLabel, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	if asg.ID != "" {
		resp, xerr := s.rpcDescribeSecurityGroupByID(ctx, aws.String(asg.ID))
		if xerr != nil {
			return nil, xerr
		}
		return toAbstractSecurityGroup(resp)
	}

	if asg.Name != "" {
		if asg.Network == "" {
			return nil, fail.InvalidParameterError("sgParam", "field 'Network' cannot be empty string when using Security Group name")
		}
		resp, xerr := s.rpcDescribeSecurityGroupByName(ctx, aws.String(asg.Network), aws.String(asg.Name))
		if xerr != nil {
			return nil, xerr
		}
		return toAbstractSecurityGroup(resp)
	}

	return nil, fail.NotFoundError("failed to find Security Group %s", sgLabel)
}

// toAbstractSecurityGroup converts a security group coming from AWS to an abstracted Security Group
func toAbstractSecurityGroup(in *ec2.SecurityGroup) (_ *abstract.SecurityGroup, ferr fail.Error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	out := &abstract.SecurityGroup{
		ID:          aws.StringValue(in.GroupId),
		Network:     aws.StringValue(in.VpcId),
		Name:        aws.StringValue(in.GroupName),
		Description: aws.StringValue(in.Description),
	}
	var xerr fail.Error
	out.Rules, xerr = toAbstractSecurityGroupRules(in)
	if xerr != nil {
		return nil, xerr
	}
	return out, nil
}

// toAbstractSecurityGroupRules converts rules of a security group coming from AWS to a slice of abstracted security group rules
func toAbstractSecurityGroupRules(in *ec2.SecurityGroup) (abstract.SecurityGroupRules, fail.Error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	var out abstract.SecurityGroupRules
	for _, v := range in.IpPermissions {
		item, xerr := toAbstractSecurityGroupRule(v, securitygroupruledirection.Ingress, ipversion.IPv4)
		if xerr != nil {
			return nil, xerr
		}

		out = append(out, item)
	}

	for _, v := range in.IpPermissionsEgress {
		item, xerr := toAbstractSecurityGroupRule(v, securitygroupruledirection.Egress, ipversion.IPv4)
		if xerr != nil {
			return nil, xerr
		}

		out = append(out, item)
	}

	return out, nil
}

// toAbstractSecurityGroupRule converts a security group coming from AWS to a slice of abstracted security group rules
func toAbstractSecurityGroupRule(in *ec2.IpPermission, direction securitygroupruledirection.Enum, etherType ipversion.Enum) (*abstract.SecurityGroupRule, fail.Error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	out := abstract.NewSecurityGroupRule()
	out.Direction = direction
	out.EtherType = etherType
	out.Protocol = aws.StringValue(in.IpProtocol)
	out.PortFrom = int32(aws.Int64Value(in.FromPort))
	out.PortTo = int32(aws.Int64Value(in.ToPort))

	out.Targets = make([]string, 0, len(in.IpRanges))
	for _, ip := range in.IpRanges {
		out.Targets = append(out.Targets, aws.StringValue(ip.CidrIp))
	}
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

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.aws"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcDescribeSecurityGroupByID(ctx, aws.String(asg.ID))
	if xerr != nil {
		return asg, xerr
	}

	if len(resp.IpPermissions) > 0 {
		if xerr = s.rpcRevokeSecurityGroupIngress(ctx, aws.String(asg.ID), resp.IpPermissions); xerr != nil {
			return asg, xerr
		}
	}
	if len(resp.IpPermissionsEgress) > 0 {
		if xerr = s.rpcRevokeSecurityGroupEgress(ctx, aws.String(asg.ID), resp.IpPermissionsEgress); xerr != nil {
			return asg, xerr
		}
	}
	return s.InspectSecurityGroup(ctx, asg)
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
	if rule == nil {
		return nil, fail.InvalidParameterCannotBeNilError("rule")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	ingressPermissions, egressPermissions, xerr := s.fromAbstractSecurityGroupRules(*asg, abstract.SecurityGroupRules{rule})
	if xerr != nil {
		return asg, xerr
	}

	// Add permissions to the security group
	if xerr = s.addRules(ctx, asg, ingressPermissions, egressPermissions); xerr != nil {
		return asg, xerr
	}

	asg.Rules = append(asg.Rules, rule)
	return s.InspectSecurityGroup(ctx, asg)
}

// addRules applies the rules to the security group
func (s stack) addRules(ctx context.Context, asg *abstract.SecurityGroup, ingress, egress []*ec2.IpPermission) fail.Error {
	if len(ingress) > 0 {
		if xerr := s.rpcAuthorizeSecurityGroupIngress(ctx, aws.String(asg.ID), ingress); xerr != nil {
			return fail.Wrap(xerr, "unable to add ingress rules to Security Group '%s'", asg.Name)
		}
	}
	if len(egress) > 0 {
		if xerr := s.rpcAuthorizeSecurityGroupEgress(ctx, aws.String(asg.ID), egress); xerr != nil {
			return fail.Wrap(xerr, "unable to add egress rules to Security Group '%s'", asg.Name)
		}
	}
	return nil
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
	if rule == nil {
		return nil, fail.InvalidParameterCannotBeNilError("rule")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s, '%s')", asg.ID, rule.Description).WithStopwatch().Entering()
	defer tracer.Exiting()

	ingressPermissions, egressPermissions, xerr := s.fromAbstractSecurityGroupRules(*asg, abstract.SecurityGroupRules{rule})
	if xerr != nil {
		return asg, xerr
	}

	if xerr = s.deleteRules(ctx, asg, ingressPermissions, egressPermissions); xerr != nil {
		return asg, xerr
	}

	return s.InspectSecurityGroup(ctx, asg)
}

// deleteRules deletes the rules from the security group
func (s stack) deleteRules(ctx context.Context, asg *abstract.SecurityGroup, ingress, egress []*ec2.IpPermission) fail.Error {
	// Add permissions to the security group
	if len(ingress) > 0 {
		if xerr := s.rpcRevokeSecurityGroupIngress(ctx, aws.String(asg.ID), ingress); xerr != nil {
			return fail.Wrap(xerr, "failed to delete ingress rules from Security Group '%s'", asg.Name)
		}
	}

	if len(egress) > 0 {
		xerr := s.rpcRevokeSecurityGroupEgress(ctx, aws.String(asg.ID), egress)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// consider a missing rule(s) as a successful deletion
				debug.IgnoreError2(ctx, xerr)
			default:
				return fail.Wrap(xerr, "failed to delete egress rules from Security Group '%s'", asg.Name)
			}
		}
	}

	return nil
}

// GetDefaultSecurityGroupName returns the name of the Security Group automatically bound to Hosts by provider
func (s stack) GetDefaultSecurityGroupName(ctx context.Context) (string, fail.Error) {
	cfg, err := s.GetRawConfigurationOptions(ctx)
	if err != nil {
		return "", err
	}

	return cfg.DefaultSecurityGroupName, nil
}

// EnableSecurityGroup enables a Security Group
// Does actually nothing for openstack
func (s stack) EnableSecurityGroup(context.Context, *abstract.SecurityGroup) fail.Error {
	return fail.NotAvailableError("aws cannot enable a Security Group")
}

// DisableSecurityGroup disables a Security Group
// Does actually nothing for openstack
func (s stack) DisableSecurityGroup(context.Context, *abstract.SecurityGroup) fail.Error {
	return fail.NotAvailableError("aws cannot disable a Security Group")
}
