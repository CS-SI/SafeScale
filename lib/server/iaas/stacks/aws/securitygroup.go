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

package aws

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// ListSecurityGroups lists existing security groups
func (s Stack) ListSecurityGroups(networkRef string) ([]*abstract.SecurityGroup, fail.Error) {
	// if s == nil {
	//     return nil, fail.InvalidInstanceError()
	// }

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.gcp")).WithStopwatch().Entering()
	defer tracer.Exiting()

	return nil, fail.NotImplementedError()
}

// CreateSecurityGroup creates a security group
// Note: parameter 'networkRef' is used in AWS, Security Groups scope is Network/VPC-wide.
func (s Stack) CreateSecurityGroup(networkRef, name, description string, rules []abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	// if s == nil {
	//     return nil, fail.InvalidInstanceError()
	// }
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	network, xerr := s.InspectNetwork(networkRef)
	if xerr != nil {
		return nil, xerr
	}

	// Create the security group with the VPC, name and description.
	csgo, err := s.EC2Service.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
		Description: aws.String(description),
		GroupName:   aws.String(name),
		VpcId:       aws.String(network.ID),
	})
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), "failed to create security group named '%s'", name)
	}

	asg := abstract.NewSecurityGroup(name)
	asg.ID = aws.StringValue(csgo.GroupId)
	asg.Description = description
	asg.Rules = rules

	defer func() {
		if xerr != nil {
			_, derr := s.EC2Service.DeleteSecurityGroup(&ec2.DeleteSecurityGroupInput{
				GroupId: aws.String(asg.ID),
			})
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(normalizeError(derr), "claning up on failure, failed to delete Security Group '%s'", asg.Name))
			}
		}
	}()

	//var ports []portDef

	//// Add common ports
	//ports = append(ports, portDef{"tcp", 22, 22})
	//ports = append(ports, portDef{"tcp", 80, 80})
	//ports = append(ports, portDef{"tcp", 443, 443})
	//
	//// Guacamole ports
	//ports = append(ports, portDef{"tcp", 8080, 8080})
	//ports = append(ports, portDef{"tcp", 8009, 8009})
	//ports = append(ports, portDef{"tcp", 9009, 9009})
	//ports = append(ports, portDef{"tcp", 3389, 3389})
	//ports = append(ports, portDef{"tcp", 5900, 5900})
	//ports = append(ports, portDef{"tcp", 63011, 63011})
	//
	//// Add time server
	//ports = append(ports, portDef{"udp", 123, 123})
	//
	//// Add kubernetes see https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#check-required-ports
	//ports = append(ports, portDef{"tcp", 6443, 6443})
	//ports = append(ports, portDef{"tcp", 2379, 2380})
	//ports = append(ports, portDef{"tcp", 10250, 10250})
	//ports = append(ports, portDef{"tcp", 10251, 10251})
	//ports = append(ports, portDef{"tcp", 10252, 10252})
	//ports = append(ports, portDef{"tcp", 10255, 10255})
	//ports = append(ports, portDef{"tcp", 30000, 32767})
	//
	//// Add docker swarm ports
	//ports = append(ports, portDef{"tcp", 2376, 2376})
	//ports = append(ports, portDef{"tcp", 2377, 2377})
	//ports = append(ports, portDef{"tcp", 7946, 7946})
	//ports = append(ports, portDef{"udp", 7946, 7946})
	//ports = append(ports, portDef{"udp", 4789, 4789})
	//
	//// ping
	//ports = append(ports, portDef{"icmp", -1, -1})

	//var permissions []*ec2.IpPermission
	//for _, item := range ports {
	//	permissions = append(permissions, (&ec2.IpPermission{}).
	//		SetIpProtocol(item.protocol).
	//		SetFromPort(item.fromPort).
	//		SetToPort(item.toPort).
	//		SetIpRanges([]*ec2.IpRange{
	//			{CidrIp: aws.String("0.0.0.0/0")},
	//		}))
	//}

	// Converts abstract rules to AWS IpPermissions
	ingressPermissions, egressPermissions, xerr := fromAbstractSecurityGroupRules(rules)
	if xerr != nil {
		return nil, xerr
	}

	// Add permissions to the security group
	if xerr = s.addRules(asg, ingressPermissions, egressPermissions); xerr != nil {
		return nil, xerr
	}

	return asg, nil
}

// fromAbstractSecurityGroupRules converts a slice of abstract.SecurityGrouRule to a couple of slices of AWS IpPermission,
// corresponding rspectively to ingress and egress IpPermission
func fromAbstractSecurityGroupRules(in abstract.SecurityGroupRules) ([]*ec2.IpPermission, []*ec2.IpPermission, fail.Error) {
	if in == nil {
		return nil, nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	ingress := make([]*ec2.IpPermission, 0, len(in))
	egress := make([]*ec2.IpPermission, 0, len(in))
	for _, v := range in {
		switch v.Direction {
		case securitygroupruledirection.INGRESS:
			ingress = append(ingress, fromAbstractSecurityGroupRule(v))
		case securitygroupruledirection.EGRESS:
			egress = append(egress, fromAbstractSecurityGroupRule(v))
		default:
			return nil, nil, fail.InvalidRequestError("rule #%d contains an invalid direction '%d'", v.Direction)
		}
	}
	return ingress, egress, nil
}

// fromAbstractSecurityGroupRule converts an abstract.SecurityGroupRule to AWS IpPermission
func fromAbstractSecurityGroupRule(in abstract.SecurityGroupRule) *ec2.IpPermission {

	ipranges := make([]*ec2.IpRange, 0, len(in.IPRanges))
	for _, v := range in.IPRanges {
		ipranges = append(ipranges, &ec2.IpRange{CidrIp: aws.String(v)})
	}

	out := &ec2.IpPermission{}
	out.SetIpProtocol(in.Protocol).
		SetFromPort(int64(in.PortFrom)).
		SetToPort(int64(in.PortTo)).
		SetIpRanges(ipranges)
	return out
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

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	_, err := s.EC2Service.DeleteSecurityGroup(&ec2.DeleteSecurityGroupInput{
		GroupId: aws.String(asg.ID),
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

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	dgo, err := s.EC2Service.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{{
			Name:   aws.String("group-id"),
			Values: []*string{aws.String(asg.ID)},
		}},
	})
	if err != nil {
		return nil, normalizeError(err)
	}

	for _, sg := range dgo.SecurityGroups {
		//if aws.StringValue(sg.VpcId) == vpcID {
		return toAbstractSecurityGroup(sg)
		//}
	}

	return nil, fail.NotFoundError(fmt.Sprintf("Security group %s not found", asg.Name))
}

// toAbstractSecurityGroup converts a security group coming from AWS to an abstracted Security Group
func toAbstractSecurityGroup(in *ec2.SecurityGroup) (_ *abstract.SecurityGroup, xerr fail.Error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	out := &abstract.SecurityGroup{
		ID:          aws.StringValue(in.GroupId),
		Name:        aws.StringValue(in.GroupName),
		Description: aws.StringValue(in.Description),
	}
	out.Rules, xerr = toAbstractSecurityGroupRules(in)
	if xerr != nil {
		return nil, xerr
	}
	return out, nil
}

// toAbstractSecurityGroupRules converts rules of a security group coming from AWS to a slice of abstracted security group rules
func toAbstractSecurityGroupRules(in *ec2.SecurityGroup) ([]abstract.SecurityGroupRule, fail.Error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	var out []abstract.SecurityGroupRule
	for _, v := range in.IpPermissions {
		items, xerr := toAbstractSecurityGroupRule(v, securitygroupruledirection.INGRESS)
		if xerr != nil {
			return nil, xerr
		}
		out = append(out, items...)
	}

	for _, v := range in.IpPermissionsEgress {
		items, xerr := toAbstractSecurityGroupRule(v, securitygroupruledirection.EGRESS)
		if xerr != nil {
			return nil, xerr
		}
		out = append(out, items...)
	}

	return out, nil
}

// toAbstractSecurityGroupRule converts a security group coming from AWS to a slice of abstracted security group rules
func toAbstractSecurityGroupRule(in *ec2.IpPermission, direction securitygroupruledirection.Enum) ([]abstract.SecurityGroupRule, fail.Error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	out := make([]abstract.SecurityGroupRule, 0, len(in.IpRanges))
	item := abstract.NewSecurityGroupRule()
	item.Direction = direction
	item.Protocol = aws.StringValue(in.IpProtocol)
	item.PortFrom = uint16(aws.Int64Value(in.FromPort))
	item.PortTo = uint16(aws.Int64Value(in.ToPort))

	item.IPRanges = make([]string, 0, len(in.IpRanges))
	for _, ip := range in.IpRanges {
		item.IPRanges = append(item.IPRanges, aws.StringValue(ip.CidrIp))
		out = append(out, item)
	}
	return out, nil
}

// InspectSecurityGroupByName inspects a security group identified by name
func (s Stack) InspectSecurityGroupByName(networkRef, name string) (_ *abstract.SecurityGroup, xerr fail.Error) {
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	var an *abstract.Network
	if networkRef != "" {
		an, xerr = s.InspectNetwork(networkRef)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				an, xerr = s.InspectNetworkByName(networkRef)
			}
		}
		if xerr != nil {
			return nil, xerr
		}
	}

	query := &ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{{
			Name:   aws.String("group-name"),
			Values: []*string{aws.String(name)},
		}},
	}
	if an != nil {
		query.Filters = append(query.Filters, &ec2.Filter{
			Name:   aws.String("vpc-id"),
			Values: []*string{aws.String(an.ID)},
		})
	}

	dgo, err := s.EC2Service.DescribeSecurityGroups(query)
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(dgo.SecurityGroups) == 0 {
		if networkRef == "" {
			return nil, fail.NotFoundError("failed to find a security group named '%s'", name)
		}
		return nil, fail.NotFoundError("failed to find a security group named '%s' in Network/VPC '%s'", an.Name)
	}
	if len(dgo.SecurityGroups) > 1 {
		if networkRef == "" {
			return nil, fail.InconsistentError("provider returned more than one Security Group named '%s'", name)
		}
		return nil, fail.NotFoundError("provider returned more than one Security Group named '%s' in Network/VPC '%s'", an.Name)
	}
	return toAbstractSecurityGroup(dgo.SecurityGroups[0])
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

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	dgo, err := s.EC2Service.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{{
			Name:   aws.String("group-id"),
			Values: []*string{aws.String(asg.ID)},
		}},
	})
	if err != nil {
		return nil, normalizeError(err)
	}

	for _, sg := range dgo.SecurityGroups {
		query := &ec2.RevokeSecurityGroupIngressInput{
			GroupId:       sg.GroupId,
			IpPermissions: sg.IpPermissions,
		}
		if _, err = s.EC2Service.RevokeSecurityGroupIngress(query); err != nil {
			return nil, normalizeError(err)
		}
	}

	return s.InspectSecurityGroup(asg)
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

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	ingressPermissions, egressPermissions, xerr := fromAbstractSecurityGroupRules(abstract.SecurityGroupRules{rule})
	if xerr != nil {
		return asg, xerr
	}

	// Add permissions to the security group
	if xerr = s.addRules(asg, ingressPermissions, egressPermissions); xerr != nil {
		return asg, xerr
	}

	return s.InspectSecurityGroup(asg)
}

// addRules applies the rules to the security group
func (s Stack) addRules(asg *abstract.SecurityGroup, ingress, egress []*ec2.IpPermission) fail.Error {
	// Add permissions to the security group
	_, err := s.EC2Service.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		GroupId:       aws.String(asg.ID),
		IpPermissions: ingress,
	})
	if err != nil {
		return fail.Wrap(normalizeError(err), "unable to set ingress rules of security group '%s'", asg.Name)
	}

	_, err = s.EC2Service.AuthorizeSecurityGroupEgress(&ec2.AuthorizeSecurityGroupEgressInput{
		GroupId:       aws.String(asg.ID),
		IpPermissions: egress,
	})
	if err != nil {
		return fail.Wrap(normalizeError(err), "unable to set egress rules of security group '%s'", asg.Name)
	}

	return nil
}

// DeleteRuleFromSecurityGroup deletes a rule identified by ID from a security group
// Checks first if the rule ID is present in the rules of the security group. If not found, returns (*abstract.SecurityGroup, *fail.ErrNotFound)
func (s Stack) DeleteRuleFromSecurityGroup(sgParam stacks.SecurityGroupParameter, rule abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
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

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s, '%s')", asg.ID, rule.Description).WithStopwatch().Entering()
	defer tracer.Exiting()

	ingressPermissions, egressPermissions, xerr := fromAbstractSecurityGroupRules(abstract.SecurityGroupRules{rule})
	if xerr != nil {
		return asg, xerr
	}

	if xerr = s.deleteRules(asg, ingressPermissions, egressPermissions); xerr != nil {
		return asg, xerr
	}

	return s.InspectSecurityGroup(asg)
}

// deleteRules deletes the rules from the security group
func (s Stack) deleteRules(asg *abstract.SecurityGroup, ingress, egress []*ec2.IpPermission) fail.Error {
	// Add permissions to the security group
	if len(ingress) > 0 {
		_, err := s.EC2Service.RevokeSecurityGroupIngress(&ec2.RevokeSecurityGroupIngressInput{
			GroupId:       aws.String(asg.ID),
			IpPermissions: ingress,
		})
		if err != nil {
			return fail.Wrap(normalizeError(err), "unable to delete ingress rules of security group '%s'", asg.Name)
		}
	}

	if len(egress) > 0 {
		_, err := s.EC2Service.RevokeSecurityGroupEgress(&ec2.RevokeSecurityGroupEgressInput{
			GroupId:       aws.String(asg.ID),
			IpPermissions: egress,
		})
		if err != nil {
			return fail.Wrap(normalizeError(err), "unable to delete egress rules from security group '%s'", asg.Name)
		}
	}

	return nil
}

// GetDefaultSecurityGroupName returns the name of the Security Group automatically bound to hosts
func (s Stack) GetDefaultSecurityGroupName() string {
	return s.GetConfigurationOptions().DefaultSecurityGroupName
}
