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
	"net"
	"reflect"

	netutils "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	// "github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"

	// "github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	// propsv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
)

const (
	tagNameLabel = "Name"
)

var (
	awsTagNameLabel = aws.String(tagNameLabel)
)

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (s stack) HasDefaultNetwork(context.Context) (bool, fail.Error) {
	return false, nil
}

// GetDefaultNetwork returns the *abstract.Network corresponding to the default network
func (s stack) GetDefaultNetwork(context.Context) (*abstract.Network, fail.Error) {
	return nil, fail.NotFoundError("no default network in stack")
}

// CreateNetwork creates a Network, ie a VPC in AWS terminology
func (s stack) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (res *abstract.Network, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%v)", req).WithStopwatch().Entering().Exiting()

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	// Check if network already there
	if _, xerr = s.rpcDescribeVpcByName(ctx, aws.String(req.Name)); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreError(xerr)
			// continue
		default:
			return nil, xerr
		}
	} else {
		return nil, fail.DuplicateError("a Network/VPC named '%s' already exists")
	}

	// if not, create the network/VPC
	theVpc, xerr := s.rpcCreateVpc(ctx, aws.String(req.Name), aws.String(req.CIDR))
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create VPC")
	}

	// wait until available status
	if IsOperation(theVpc, "State", reflect.TypeOf("")) {
		retryErr := retry.WhileUnsuccessful(
			func() error {
				vpcTmp, innerXErr := s.rpcDescribeVpcByID(ctx, theVpc.VpcId)
				if innerXErr != nil {
					return innerXErr
				}
				if aws.StringValue(vpcTmp.State) != "available" {
					return fail.NewError("not ready")
				}
				return nil
			},
			timings.SmallDelay(),
			timings.OperationTimeout(),
		)
		if retryErr != nil {
			switch retryErr.(type) {
			case *retry.ErrStopRetry:
				return nil, fail.Wrap(fail.Cause(retryErr), "stopping retries")
			case *fail.ErrTimeout:
				return nil, fail.Wrap(fail.Cause(retryErr), "timeout")
			default:
				return nil, retryErr
			}
		}
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && !req.KeepOnFailure {
			if theVpc != nil {
				derr := s.DeleteNetwork(context.Background(), aws.StringValue(theVpc.VpcId))
				if derr != nil {
					_ = ferr.AddConsequence(derr)
				}
			}
		}
	}()

	gw, xerr := s.rpcCreateInternetGateway(ctx)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create internet gateway")
	}

	if xerr = s.rpcAttachInternetGateway(ctx, theVpc.VpcId, gw.InternetGatewayId); xerr != nil {
		return nil, fail.Wrap(xerr, "failed to attach internet gateway to Network")
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && !req.KeepOnFailure {
			if derr := s.rpcDetachInternetGateway(context.Background(), theVpc.VpcId, gw.InternetGatewayId); derr != nil {
				_ = ferr.AddConsequence(normalizeError(derr))
			}
		}
	}()

	tables, xerr := s.rpcDescribeRouteTables(ctx, aws.String("vpc-id"), []*string{theVpc.VpcId})
	if xerr != nil {
		return nil, xerr
	}
	if len(tables) < 1 {
		return nil, fail.InconsistentError("no Route Tables")
	}

	if xerr = s.rpcCreateRoute(ctx, gw.InternetGatewayId, tables[0].RouteTableId, aws.String("0.0.0.0/0")); xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create route")
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && !req.KeepOnFailure {
			if derr := s.rpcDeleteRoute(context.Background(), tables[0].RouteTableId, aws.String("0.0.0.0/0")); derr != nil {
				_ = ferr.AddConsequence(normalizeError(derr))
			}
		}
	}()

	anet := abstract.NewNetwork()
	anet.ID = aws.StringValue(theVpc.VpcId)
	anet.Name = req.Name
	anet.CIDR = req.CIDR
	anet.DNSServers = req.DNSServers

	// Make sure we log warnings
	_ = anet.OK()

	return anet, nil
}

// InspectNetwork returns information about Network/VPC from AWS
func (s stack) InspectNetwork(ctx context.Context, id string) (_ *abstract.Network, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	resp, xerr := s.rpcDescribeVpcByID(ctx, aws.String(id))
	if xerr != nil {
		return nil, xerr
	}

	anet, xerr := toAbstractNetwork(resp)
	if xerr != nil {
		return nil, xerr
	}

	return anet, nil
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
		if *v.Key == *awsTagNameLabel {
			out.Name = aws.StringValue(v.Value)
			break
		}
	}

	return out, nil
}

// InspectNetworkByName does the same as InspectNetwork but on its name
func (s stack) InspectNetworkByName(ctx context.Context, name string) (_ *abstract.Network, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "('%s')", name).WithStopwatch().Entering().Exiting()

	resp, xerr := s.rpcDescribeVpcByName(ctx, aws.String(name))
	if xerr != nil {
		return nil, xerr
	}

	anet, xerr := toAbstractNetwork(resp)
	if xerr != nil {
		return nil, xerr
	}

	return anet, nil
}

// ListNetworks ...
func (s stack) ListNetworks(ctx context.Context) (_ []*abstract.Network, ferr fail.Error) {
	var emptySlice []*abstract.Network
	if valid.IsNil(s) {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network")).WithStopwatch().Entering().Exiting()

	resp, xerr := s.rpcDescribeVpcs(ctx, nil)
	if xerr != nil {
		return emptySlice, xerr
	}

	nets := make([]*abstract.Network, 0, len(resp))
	for _, vpc := range resp {
		n := abstract.NewNetwork()
		n.ID = aws.StringValue(vpc.VpcId)
		n.CIDR = aws.StringValue(vpc.CidrBlock)
		for _, tag := range vpc.Tags {
			if *tag.Key == *awsTagNameLabel && aws.StringValue(tag.Value) != "" {
				n.Name = aws.StringValue(tag.Value)
			}
		}
		nets = append(nets, n)
	}

	return nets, nil
}

// DeleteNetwork ...
func (s stack) DeleteNetwork(ctx context.Context, id string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	var xerr fail.Error
	if _, xerr = s.InspectNetwork(ctx, id); xerr != nil {
		return xerr
	}

	gwTmp, xerr := s.rpcDescribeInternetGateways(ctx, aws.String(id), nil)
	if xerr != nil {
		return xerr
	}

	for _, agwTmp := range gwTmp {
		for _, att := range agwTmp.Attachments {
			if aws.StringValue(att.VpcId) == id {
				if xerr = s.rpcDetachInternetGateway(ctx, att.VpcId, agwTmp.InternetGatewayId); xerr != nil {
					return xerr
				}

				if xerr = s.rpcDeleteInternetGateway(ctx, agwTmp.InternetGatewayId); xerr != nil {
					return xerr
				}
			}
		}
	}

	rtTmp, xerr := s.rpcDescribeRouteTables(ctx, aws.String("vpc-id"), []*string{aws.String(id)})
	if xerr != nil {
		return xerr
	}

	if len(rtTmp) > 0 {
		for _, artTmp := range rtTmp {
			hasMain := false

			// Dissociate
			for _, rta := range artTmp.Associations {
				if !aws.BoolValue(rta.Main) {
					if xerr = s.rpcDisassociateRouteTable(ctx, rta.RouteTableAssociationId); xerr != nil {
						return xerr
					}
				} else {
					hasMain = true
				}
			}

			if hasMain {
				continue
			}

			if xerr = s.rpcDeleteRouteTable(ctx, artTmp.RouteTableId); xerr != nil {
				return xerr
			}
		}

		if xerr = s.rpcDeleteRoute(ctx, rtTmp[0].RouteTableId, aws.String("0.0.0.0/0")); xerr != nil {
			return xerr
		}
	}

	return s.rpcDeleteVpc(ctx, aws.String(id))
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
		return hoststate.Error, fail.NewError("unexpected host state")
	}

	switch aws.Int64Value(state.Code) & 0xff {
	case 0:
		return hoststate.Starting, nil
	case 16:
		return hoststate.Started, nil
	case 32:
		return hoststate.Stopping, nil
	case 48:
		return hoststate.Terminated, nil
	case 64:
		return hoststate.Stopping, nil
	case 80:
		return hoststate.Stopped, nil
	}
	return hoststate.Error, fail.NewError("unexpected host state")
}

// CreateSubnet ...
func (s stack) CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (res *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%v)", req).WithStopwatch().Entering().Exiting()

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
		return nil, fail.Wrap(err, "error parsing requested CIDR")
	}

	resp, xerr := s.rpcCreateSubnet(ctx, aws.String(req.Name), aws.String(req.NetworkID), aws.String(s.AwsConfig.Zone), aws.String(req.CIDR))
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && !req.KeepOnFailure {
			if derr := s.DeleteSubnet(context.Background(), aws.StringValue(resp.SubnetId)); derr != nil {
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

	if IsOperation(resp, "State", reflect.TypeOf("")) {
		retryErr := retry.WhileUnsuccessful(
			func() error {
				descr, innerXErr := s.rpcDescribeSubnetByID(ctx, resp.SubnetId)
				if innerXErr != nil {
					return innerXErr
				}
				if aws.StringValue(descr.State) != "available" {
					return fail.NewError("not ready (state = '%s')", descr.State)
				}
				return nil
			},
			timings.SmallDelay(),
			timings.OperationTimeout(),
		)
		if retryErr != nil {
			switch retryErr.(type) {
			case *retry.ErrStopRetry:
				return nil, fail.Wrap(fail.Cause(retryErr), "stopping retries")
			case *fail.ErrTimeout:
				return nil, fail.Wrap(fail.Cause(retryErr), "timeout")
			default:
				return nil, retryErr
			}
		}
	}
	tables, xerr := s.rpcDescribeRouteTables(ctx, aws.String("vpc-id"), []*string{aws.String(req.NetworkID)})
	if xerr != nil {
		return nil, xerr
	}
	if len(tables) < 1 {
		return nil, fail.InconsistentError("No Route Tables")
	}

	// First result should be the public interface
	if xerr = s.rpcAssociateRouteTable(ctx, resp.SubnetId, tables[0].RouteTableId); xerr != nil {
		return nil, fail.Wrap(xerr, "failed to associate route tables to Subnet")
	}

	subnet := abstract.NewSubnet()
	subnet.ID = aws.StringValue(resp.SubnetId)
	subnet.Name = req.Name
	subnet.Network = req.NetworkID
	subnet.CIDR = req.CIDR
	subnet.Domain = req.Domain
	subnet.IPVersion = ipversion.IPv4

	// Make sure we log warnings
	_ = subnet.OK()

	return subnet, nil
}

// InspectSubnet returns information about the Subnet from AWS
func (s stack) InspectSubnet(ctx context.Context, id string) (_ *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	resp, xerr := s.rpcDescribeSubnetByID(ctx, aws.String(id))
	if xerr != nil {
		return nil, xerr
	}

	return toAbstractSubnet(resp)
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
func (s stack) InspectSubnetByName(ctx context.Context, networkRef, subnetName string) (_ *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if subnetName == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "('%s', '%s')", networkRef, subnetName).WithStopwatch().Entering().Exiting()

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	req, xerr := s.initEC2DescribeSubnetsInput(ctx, networkRef)
	if xerr != nil {
		return nil, xerr
	}
	req.Filters = append(req.Filters, &ec2.Filter{
		Name:   aws.String("tag:" + tagNameLabel),
		Values: []*string{aws.String(subnetName)},
	})
	var resp *ec2.DescribeSubnetsOutput
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			resp, innerErr = s.EC2Service.DescribeSubnets(req)
			return normalizeError(innerErr)
		},
		timings.CommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
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
func (s stack) ListSubnets(ctx context.Context, networkRef string) (list []*abstract.Subnet, ferr fail.Error) {
	var emptySlice []*abstract.Subnet
	if valid.IsNil(s) {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network")).WithStopwatch().Entering().Exiting()

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	query, xerr := s.initEC2DescribeSubnetsInput(ctx, networkRef)
	if xerr != nil {
		return nil, xerr
	}

	var subnets *ec2.DescribeSubnetsOutput
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			subnets, innerErr = s.EC2Service.DescribeSubnets(query)
			return normalizeError(innerErr)
		},
		timings.CommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
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

func (s stack) initEC2DescribeSubnetsInput(ctx context.Context, networkRef string) (*ec2.DescribeSubnetsInput, fail.Error) {
	query := &ec2.DescribeSubnetsInput{}

	if networkRef != "" {
		n, xerr := s.InspectNetwork(ctx, networkRef)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// if not found, try networkRef as a name
				n, xerr = s.InspectNetworkByName(ctx, networkRef)
				if xerr != nil {
					return nil, xerr
				}
			default:
				return nil, xerr
			}
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
func (s stack) listSubnetIDs(ctx context.Context, networkRef string) (list []string, ferr fail.Error) { // nolint
	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network")).WithStopwatch().Entering().Exiting()

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	req, xerr := s.initEC2DescribeSubnetsInput(ctx, networkRef)
	if xerr != nil {
		return nil, xerr
	}

	var subnets *ec2.DescribeSubnetsOutput
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			subnets, innerErr = s.EC2Service.DescribeSubnets(req)
			return normalizeError(innerErr)
		},
		timings.CommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}

	list = make([]string, 0, len(subnets.Subnets))
	for _, v := range subnets.Subnets {
		list = append(list, aws.StringValue(v.SubnetId))
	}

	return list, nil
}

// DeleteSubnet ...
func (s stack) DeleteSubnet(ctx context.Context, id string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	// Disassociate route tables from subnet
	tables, xerr := s.rpcDescribeRouteTables(ctx, aws.String("association.subnet-id"), []*string{aws.String(id)})
	if xerr != nil {
		return fail.Wrap(xerr, "failed to find route tables of Subnet")
	}

	if len(tables) > 0 {
		for _, v := range tables {
			for _, a := range v.Associations {
				if aws.StringValue(a.SubnetId) == id {
					xerr = s.rpcDisassociateRouteTable(ctx, a.RouteTableAssociationId)
					if xerr != nil {
						return fail.Wrap(xerr, "failed to dissociate route tables from Subnet")
					}
				}
			}
		}
	}

	return s.rpcDeleteSubnet(ctx, aws.String(id))
}

// CreateVIP ...
func (s *stack) CreateVIP(ctx context.Context, networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	return nil, fail.NotImplementedError("CreateVIP() not implemented yet") // FIXME: Technical debt
}

func (s *stack) AddPublicIPToVIP(context.Context, *abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

func (s *stack) BindHostToVIP(context.Context, *abstract.VirtualIP, string) fail.Error {
	return fail.NotImplementedError("BindHostToVIP() not implemented yet") // FIXME: Technical debt
}

func (s *stack) UnbindHostFromVIP(context.Context, *abstract.VirtualIP, string) fail.Error {
	return fail.NotImplementedError("UnbindHostToVIP() not implemented yet") // FIXME: Technical debt
}

func (s *stack) DeleteVIP(context.Context, *abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("DeleteVIP() not implemented yet") // FIXME: Technical debt
}
