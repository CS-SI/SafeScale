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
	"net"
	"reflect"

	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	// "github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"

	// "github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
	// propsv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
)

const tagNameLabel = "Name"

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (s *Stack) HasDefaultNetwork() bool {
	return false
}

// GetDefaultNetwork returns the *abstract.Network corresponding to the default network
func (s *Stack) GetDefaultNetwork() (*abstract.Network, fail.Error) {
	return nil, fail.NotFoundError("no default network in Stack")
}

// CreateNetwork creates a Network, ie a VPC in AWS terminology
func (s *Stack) CreateNetwork(req abstract.NetworkRequest) (res *abstract.Network, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%v)", req).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	var theVpc *ec2.Vpc

	// Check if network already there
	_, err := s.EC2Service.DescribeVpcs(&ec2.DescribeVpcsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:" + tagNameLabel),
				Values: []*string{aws.String(req.Name)},
			},
		},
	})
	if err != nil {
		xerr := normalizeError(err)
		switch xerr.(type) {
		case *fail.ErrNotFound:
		// continue
		default:
			return nil, xerr
		}
	} else {
		return nil, fail.DuplicateError("a VPC named '%s' already exists")
	}

	//for _, vpc := range out.Vpcs {
	//	nets := &abstract.Network{}
	//	nets.IPRanges = aws.StringValue(vpc.CidrBlock)
	//	nets.ID = aws.StringValue(vpc.VpcId)
	//	for _, tag := range vpc.Tags {
	//		if aws.StringValue(tag.Key) == tagNameLabel && aws.StringValue(tag.Value) == s.AwsConfig.NetworkName {
	//			theVpc = vpc
	//			break
	//		}
	//	}
	//	if theVpc != nil {
	//		return nil, fail.DuplicateError("a VPC named '%s' already exists")
	//	}
	//}

	// if not, create the network/VPC
	vpcOut, err := s.EC2Service.CreateVpc(&ec2.CreateVpcInput{
		CidrBlock: aws.String(req.CIDR),
	})
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), "failed to create VPC")
	}

	theVpc = vpcOut.Vpc

	// wait until available status
	if IsOperation(theVpc, "State", reflect.TypeOf("")) {
		retryErr := retry.WhileUnsuccessful(
			func() error {
				vpcTmp, err := s.EC2Service.DescribeVpcs(&ec2.DescribeVpcsInput{
					VpcIds: []*string{theVpc.VpcId},
				})
				if err != nil {
					return normalizeError(err)
				}
				if aws.StringValue(vpcTmp.Vpcs[0].State) != "available" {
					return fail.NewError("not ready")
				}
				return nil
			},
			temporal.GetMinDelay(),
			temporal.GetDefaultDelay(),
		)
		if retryErr != nil {
			return nil, retryErr
		}
	}

	// resource tagging
	_, err = s.EC2Service.CreateTags(&ec2.CreateTagsInput{
		Resources: []*string{theVpc.VpcId},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String(tagNameLabel),
				Value: aws.String(s.AwsConfig.NetworkName),
			},
		},
	})
	if err != nil {
		logrus.Warnf("error creating tags: %v", err)
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			if theVpc != nil {
				derr := s.DeleteNetwork(aws.StringValue(theVpc.VpcId))
				if derr != nil {
					_ = xerr.AddConsequence(derr)
				}
			}
		}
	}()

	gw, err := s.EC2Service.CreateInternetGateway(&ec2.CreateInternetGatewayInput{})
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), "failed to create internet gateway")
	}

	_, err = s.EC2Service.AttachInternetGateway(&ec2.AttachInternetGatewayInput{
		VpcId:             theVpc.VpcId,
		InternetGatewayId: gw.InternetGateway.InternetGatewayId,
	})
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), "failed to attach internet gateway to Network")
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			_, derr := s.EC2Service.DetachInternetGateway(&ec2.DetachInternetGatewayInput{
				InternetGatewayId: gw.InternetGateway.InternetGatewayId,
				VpcId:             theVpc.VpcId,
			})
			if derr != nil {
				_ = xerr.AddConsequence(normalizeError(derr))
			}
		}
	}()

	tables, err := s.EC2Service.DescribeRouteTables(&ec2.DescribeRouteTablesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("vpc-id"),
				Values: []*string{
					theVpc.VpcId,
				},
			},
		},
	})
	if err != nil || len(tables.RouteTables) < 1 {
		return nil, fail.Wrap(normalizeError(err), "No RouteTables")
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			_, derr := s.EC2Service.DeleteRoute(&ec2.DeleteRouteInput{
				DestinationCidrBlock: aws.String("0.0.0.0/0"),
				RouteTableId:         tables.RouteTables[0].RouteTableId,
			})
			if derr != nil {
				_ = xerr.AddConsequence(normalizeError(derr))
			}
		}
	}()

	_, err = s.EC2Service.CreateRoute(&ec2.CreateRouteInput{
		DestinationCidrBlock: aws.String("0.0.0.0/0"),
		GatewayId:            gw.InternetGateway.InternetGatewayId,
		RouteTableId:         tables.RouteTables[0].RouteTableId,
	})
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), "failed to create route")
	}

	net := abstract.NewNetwork()
	net.ID = aws.StringValue(theVpc.VpcId)
	net.Name = req.Name
	net.CIDR = req.CIDR
	net.DNSServers = req.DNSServers

	// Make sure we log warnings
	_ = net.OK()

	return net, nil
}

// InspectNetwork returns information about Network/VPC from AWS
func (s *Stack) InspectNetwork(id string) (_ *abstract.Network, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	req := &ec2.DescribeVpcsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{aws.String(id)},
			},
		},
	}
	out, err := s.EC2Service.DescribeVpcs(req)
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(out.Vpcs) == 0 {
		return nil, fail.NotFoundError("")
	}

	net, xerr := toAbstractNetwork(out.Vpcs[0])
	if xerr != nil {
		return nil, xerr
	}
	//net.Subnets, xerr = s.listSubnetIDs(net.ID)
	//if xerr != nil {
	//	return nil, xerr
	//}
	return net, nil
}

// toAbstractNetwork converts an ec2.Vpc to abstract.Network
func toAbstractNetwork(in *ec2.Vpc) (*abstract.Network, fail.Error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	out := abstract.NewNetwork()
	out.ID = aws.StringValue(in.VpcId)
	out.CIDR = aws.StringValue(in.CidrBlock)
	for _, v := range in.Tags {
		if aws.StringValue(v.Key) == tagNameLabel {
			out.Name = aws.StringValue(v.Value)
			break
		}
	}

	return out, nil
}

// InspectNetworkByName does the same as InspectNetwork but on its name
func (s *Stack) InspectNetworkByName(name string) (_ *abstract.Network, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "('%s')", name).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	req := &ec2.DescribeVpcsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:" + tagNameLabel),
				Values: []*string{aws.String(name)},
			},
		},
	}
	out, err := s.EC2Service.DescribeVpcs(req)
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(out.Vpcs) == 0 {
		return nil, fail.NotFoundError("failed to find a Network/VPC named '%s'", name)
	}
	if len(out.Vpcs) > 1 {
		return nil, fail.InconsistentError("provider returned more than 1 Network/VPC with name '%s'", name)
	}

	net, xerr := toAbstractNetwork(out.Vpcs[0])
	if xerr != nil {
		return nil, xerr
	}

	//net.Subnets, xerr = s.listSubnetIDs(net.ID)
	//if xerr != nil {
	//	return nil, xerr
	//}
	return net, nil
}

// ListNetworks ...
func (s *Stack) ListNetworks() (_ []*abstract.Network, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	out, err := s.EC2Service.DescribeVpcs(&ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, normalizeError(err)
	}
	var nets []*abstract.Network
	for _, vpc := range out.Vpcs {
		item := abstract.Network{}
		item.ID = aws.StringValue(vpc.VpcId)
		item.CIDR = aws.StringValue(vpc.CidrBlock)
		for _, tag := range vpc.Tags {
			if aws.StringValue(tag.Key) == tagNameLabel {
				if aws.StringValue(tag.Value) != "" {
					item.Name = aws.StringValue(tag.Value)
				}
			}
		}
		nets = append(nets, &item)
	}

	//subns, err := s.EC2Service.DescribeSubnets(&ec2.DescribeSubnetsInput{})
	//if err != nil {
	//	return nil, normalizeError(err)
	//}
	//
	//for _, subn := range subns.Subnets {
	//	vpcnet := abstract.Network{}
	//	vpcnet.ID = aws.StringValue(subn.SubnetId)
	//	vpcnet.IPRanges = aws.StringValue(subn.CidrBlock)
	//	vpcnet.Subnet = true
	//	vpcnet.Parent = aws.StringValue(subn.VpcId)
	//	for _, tag := range subn.Tags {
	//		if aws.StringValue(tag.Key) == tagNameLabel {
	//			if aws.StringValue(tag.Value) != "" {
	//				vpcnet.Name = aws.StringValue(tag.Value)
	//			}
	//		}
	//	}
	//	nets = append(nets, &vpcnet)
	//}

	return nets, nil
}

// DeleteNetwork ...
func (s *Stack) DeleteNetwork(id string) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	if _, xerr = s.InspectNetwork(id); xerr != nil {
		return xerr
	}

	gwTmp, err := s.EC2Service.DescribeInternetGateways(&ec2.DescribeInternetGatewaysInput{})
	if err != nil {
		return normalizeError(err)
	}

	for _, agwTmp := range gwTmp.InternetGateways {
		for _, att := range agwTmp.Attachments {
			if aws.StringValue(att.VpcId) == id {
				_, err = s.EC2Service.DetachInternetGateway(&ec2.DetachInternetGatewayInput{
					InternetGatewayId: agwTmp.InternetGatewayId,
					VpcId:             att.VpcId,
				})
				if err != nil {
					return normalizeError(err)
				}

				_, err = s.EC2Service.DeleteInternetGateway(&ec2.DeleteInternetGatewayInput{
					InternetGatewayId: agwTmp.InternetGatewayId,
				})
				if err != nil {
					return normalizeError(err)
				}
			}
		}
	}

	query := &ec2.DescribeRouteTablesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{aws.String(id)},
			},
		},
	}
	rtTmp, err := s.EC2Service.DescribeRouteTables(query)
	if err != nil {
		return normalizeError(err)
	}

	for _, artTmp := range rtTmp.RouteTables {
		hasMain := false
		// Dissociate
		for _, rta := range artTmp.Associations {
			if !aws.BoolValue(rta.Main) {
				_, err = s.EC2Service.DisassociateRouteTable(&ec2.DisassociateRouteTableInput{
					AssociationId: rta.RouteTableAssociationId,
				})
				if err != nil {
					return normalizeError(err)
				}
			} else {
				hasMain = true
			}
		}

		if hasMain {
			continue
		}

		_, err = s.EC2Service.DeleteRouteTable(&ec2.DeleteRouteTableInput{
			RouteTableId: artTmp.RouteTableId,
		})
		if err != nil {
			return normalizeError(err)
		}
	}

	_, err = s.EC2Service.DeleteVpc(&ec2.DeleteVpcInput{
		VpcId: aws.String(id),
	})
	if err != nil {
		return normalizeError(err)
	}

	return nil
}

func toHostState(state *ec2.InstanceState) (hoststate.Enum, fail.Error) {
	// The low byte represents the state. The high byte is an opaque internal value
	// and should be ignored.
	//
	//    * 0 : pending
	//
	//    * 16 : running
	//
	//    * 32 : shutting-down
	//
	//    * 48 : terminated
	//
	//    * 64 : stopping
	//
	//    * 80 : stopped
	if state == nil {
		return hoststate.ERROR, fail.NewError("unexpected host state")
	}
	if *state.Code == 0 {
		return hoststate.STARTING, nil
	}
	if *state.Code == 16 {
		return hoststate.STARTED, nil
	}
	if *state.Code == 32 {
		return hoststate.STOPPING, nil
	}
	if *state.Code == 48 {
		return hoststate.TERMINATED, nil
	}
	if *state.Code == 64 {
		return hoststate.STOPPING, nil
	}
	if *state.Code == 80 {
		return hoststate.STOPPED, nil
	}
	return hoststate.ERROR, fail.NewError("unexpected host state")
}

// CreateSubnet ...
func (s Stack) CreateSubnet(req abstract.SubnetRequest) (res *abstract.Subnet, xerr fail.Error) {
	//if s == nil {
	//	return nil, fail.InvalidInstanceError()
	//}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%v)", req).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	_, _, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return nil, fail.Wrap(err, "error parsing requested IPRanges")
	}
	sn, err := s.EC2Service.CreateSubnet(&ec2.CreateSubnetInput{
		CidrBlock:        aws.String(req.CIDR),
		VpcId:            aws.String(req.Network),
		AvailabilityZone: aws.String(s.AwsConfig.Zone),
	})
	if err != nil {
		return nil, normalizeError(err)
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			derr := s.DeleteSubnet(aws.StringValue(sn.Subnet.SubnetId))
			if derr != nil {
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	_, err = s.EC2Service.CreateTags(&ec2.CreateTagsInput{
		Resources: []*string{sn.Subnet.SubnetId},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String(tagNameLabel),
				Value: aws.String(req.Name),
			},
		},
	})
	if err != nil {
		logrus.Warn("Error creating tags")
	}

	if IsOperation(sn.Subnet, "State", reflect.TypeOf("")) {
		retryErr := retry.WhileUnsuccessful(
			func() error {
				snTmp, err := s.EC2Service.DescribeSubnets(&ec2.DescribeSubnetsInput{
					SubnetIds: []*string{sn.Subnet.SubnetId},
				})
				if err != nil {
					return normalizeError(err)
				}

				if aws.StringValue(snTmp.Subnets[0].State) != "available" {
					return fail.NewError("not ready")
				}

				return nil
			},
			temporal.GetMinDelay(),
			temporal.GetDefaultDelay(),
		)

		if retryErr != nil {
			switch retryErr.(type) {
			case *fail.ErrTimeout:
				return nil, fail.Wrap(retryErr.Cause(), "timeout")
			default:
				return nil, retryErr
			}
		}
	}

	tables, err := s.EC2Service.DescribeRouteTables(&ec2.DescribeRouteTablesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{aws.String(req.Network)},
			},
		},
	})
	if err != nil || len(tables.RouteTables) < 1 {
		return nil, fail.Wrap(normalizeError(err), "No RouteTables")
	}

	// First result should be the public interface
	_, err = s.EC2Service.AssociateRouteTable(&ec2.AssociateRouteTableInput{
		RouteTableId: tables.RouteTables[0].RouteTableId,
		SubnetId:     sn.Subnet.SubnetId,
	})
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), "failed to associate route tables to subnet")
	}

	subnet := abstract.NewSubnet()
	subnet.ID = aws.StringValue(sn.Subnet.SubnetId)
	subnet.Name = req.Name
	subnet.Network = req.Network
	subnet.CIDR = req.CIDR
	subnet.Domain = req.Domain
	subnet.IPVersion = ipversion.IPv4

	// Make sure we log warnings
	_ = subnet.OK()

	return subnet, nil
}

// InspectSubnet returns information about the Subnet from AWS
func (s *Stack) InspectSubnet(id string) (_ *abstract.Subnet, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	req := &ec2.DescribeSubnetsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("subnet-id"),
				Values: []*string{aws.String(id)},
			},
		},
	}
	resp, err := s.EC2Service.DescribeSubnets(req)
	if err != nil {
		return nil, normalizeError(err)
	}
	subnetCount := len(resp.Subnets)
	if subnetCount == 0 {
		return nil, fail.NotFoundError("failed to find subnet '%s'", id)
	}
	if subnetCount > 1 {
		return nil, fail.InconsistentError("provider returned more than one subnet with id %s", id)

	}
	return toAbstractSubnet(resp.Subnets[0])
}

func toAbstractSubnet(in *ec2.Subnet) (*abstract.Subnet, fail.Error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	out := abstract.NewSubnet()
	out.Network = aws.StringValue(in.VpcId)
	out.ID = aws.StringValue(in.SubnetId)
	out.CIDR = aws.StringValue(in.CidrBlock)
	out.IPVersion = ipversion.IPv4
	for _, v := range in.Tags {
		if aws.StringValue(v.Key) == tagNameLabel {
			out.Name = aws.StringValue(v.Value)
		}
	}
	return out, nil
}

// InspectSubnetByName ...
func (s *Stack) InspectSubnetByName(networkRef, subnetName string) (_ *abstract.Subnet, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if subnetName == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "('%s', '%s')", networkRef, subnetName).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	// not found by subnet id, try the combination of networkRef and subnetRef as subnet name
	req, xerr := s.initEC2DescribeSubnetsInput(networkRef)
	if xerr != nil {
		return nil, xerr
	}
	req.Filters = append(req.Filters, &ec2.Filter{
		Name:   aws.String("tag:" + tagNameLabel),
		Values: []*string{aws.String(subnetName)},
	})

	resp, err := s.EC2Service.DescribeSubnets(req)
	if err != nil {
		return nil, normalizeError(err)
	}
	subnetCount := len(resp.Subnets)
	if subnetCount == 0 {
		if networkRef != "" {
			return nil, fail.NotFoundError("failed to find a subnet with name '%s' in Network/VPC '%s'", subnetName, networkRef)
		}
		return nil, fail.NotFoundError("failed to find a subnet with name '%s'", subnetName)
	}
	if subnetCount > 1 {
		if networkRef != "" {
			return nil, fail.InconsistentError("provider returned more than one subnet with name '%s' in Network/VPC '%s'", subnetName, networkRef)
		}
		return nil, fail.InconsistentError("provider returned more than one subnet with name '%s'", subnetName)
	}

	return toAbstractSubnet(resp.Subnets[0])
}

// ListSubnets ...
func (s Stack) ListSubnets(networkRef string) (list []*abstract.Subnet, xerr fail.Error) {
	//if s == nil {
	//	return nil, fail.InvalidInstanceError()
	//}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	//out, err := s.EC2Service.DescribeVpcs(&ec2.DescribeVpcsInput{})
	//if err != nil {
	//	return nil, normalizeError(err)
	//}
	//
	//var nets []*abstract.Network
	//for _, vpc := range out.Vpcs {
	//	vpcnet := abstract.Network{}
	//	vpcnet.ID = aws.StringValue(vpc.VpcId)
	//	vpcnet.IPRanges = aws.StringValue(vpc.CidrBlock)
	//	for _, tag := range vpc.Tags {
	//		if aws.StringValue(tag.Key) == tagNameLabel {
	//			if aws.StringValue(tag.Value) != "" {
	//				vpcnet.Name = aws.StringValue(tag.Value)
	//			}
	//		}
	//	}
	//	nets = append(nets, &vpcnet)
	//}

	query, xerr := s.initEC2DescribeSubnetsInput(networkRef)
	if xerr != nil {
		return nil, xerr
	}
	subnets, err := s.EC2Service.DescribeSubnets(query)
	if err != nil {
		return nil, normalizeError(err)
	}

	list = make([]*abstract.Subnet, 0, len(subnets.Subnets))
	for _, v := range subnets.Subnets {
		item, xerr := toAbstractSubnet(v)
		if xerr != nil {
			return nil, xerr
		}
		list = append(list, item)
	}

	return list, nil
}

func (s Stack) initEC2DescribeSubnetsInput(networkRef string) (*ec2.DescribeSubnetsInput, fail.Error) {
	query := &ec2.DescribeSubnetsInput{}

	if networkRef != "" {
		n, xerr := s.InspectNetwork(networkRef)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// if not found, try networkRef as a name
				n, xerr = s.InspectNetworkByName(networkRef)
			default:
				return nil, xerr
			}
		}
		if xerr != nil {
			return nil, xerr
		}

		query.Filters = []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{aws.String(n.ID)},
			},
		}
	}
	return query, nil
}

// listSubnetIDs ...
func (s Stack) listSubnetIDs(networkRef string) (list []string, xerr fail.Error) {
	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	req, xerr := s.initEC2DescribeSubnetsInput(networkRef)
	if xerr != nil {
		return nil, xerr
	}
	subnets, err := s.EC2Service.DescribeSubnets(req)
	if err != nil {
		return nil, normalizeError(err)
	}

	list = make([]string, 0, len(subnets.Subnets))
	for _, v := range subnets.Subnets {
		list = append(list, aws.StringValue(v.SubnetId))
	}

	return list, nil
}

// DeleteSubnet ...
func (s Stack) DeleteSubnet(id string) (xerr fail.Error) {
	//if s == nil {
	//	return fail.InvalidInstanceError()
	//}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	// Disassociate route tables from subnet
	tables, err := s.EC2Service.DescribeRouteTables(&ec2.DescribeRouteTablesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("subnet-id"),
				Values: []*string{aws.String(id)},
			},
		},
	})
	if err != nil {
		return fail.Wrap(normalizeError(err), "failed to find route tables of subnet")
	}
	_ = ec2.RouteTableAssociation{}
	if tables != nil && len(tables.RouteTables) > 0 {
		for _, v := range tables.RouteTables {
			for _, w := range v.Associations {
				if aws.StringValue(w.SubnetId) == id {
					_, err = s.EC2Service.DisassociateRouteTable(&ec2.DisassociateRouteTableInput{
						AssociationId: w.RouteTableAssociationId,
					})
					if err != nil {
						return fail.Wrap(normalizeError(err), "failed to dissociate route tables from subnet")
					}
				}
			}
		}
	}

	query := &ec2.DeleteSubnetInput{
		SubnetId: &id,
	}
	_, err = s.EC2Service.DeleteSubnet(query)
	return normalizeError(err)
}

// BindSecurityGroupToSubnet binds a security group to a network
func (s *Stack) BindSecurityGroupToSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if subnetID == "" {
		return fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg)
		if xerr != nil {
			return xerr
		}
	}

	return fail.NotImplementedError()
}

// UnbindSecurityGroupFromSubnet unbinds a security group from a host
func (s *Stack) UnbindSecurityGroupFromSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if subnetID == "" {
		return fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	asg, xerr = s.InspectSecurityGroup(asg)
	if xerr != nil {
		return xerr
	}

	return fail.NotImplementedError()
}

// CreateVIP ...
func (s *Stack) CreateVIP(networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	return nil, fail.NotImplementedError("CreateVIP() not implemented yet") // FIXME: Technical debt
}

func (s *Stack) AddPublicIPToVIP(*abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

func (s *Stack) BindHostToVIP(*abstract.VirtualIP, string) fail.Error {
	return fail.NotImplementedError("BindHostToVIP() not implemented yet") // FIXME: Technical debt
}

func (s *Stack) UnbindHostFromVIP(*abstract.VirtualIP, string) fail.Error {
	return fail.NotImplementedError("UnbindHostToVIP() not implemented yet") // FIXME: Technical debt
}

func (s *Stack) DeleteVIP(*abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("DeleteVIP() not implemented yet") // FIXME: Technical debt
}
