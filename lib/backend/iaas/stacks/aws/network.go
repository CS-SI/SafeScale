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

package aws

import (
	"context"
	"net"
	"reflect"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
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
func (instance *stack) HasDefaultNetwork() (bool, fail.Error) {
	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}

	options, xerr := instance.ConfigurationOptions()
	if xerr != nil {
		return false, xerr
	}

	return options.DefaultNetworkName != "", nil
}

// DefaultNetwork returns the *abstract.Network corresponding to the default network
func (instance *stack) DefaultNetwork(ctx context.Context) (*abstract.Network, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	options, xerr := instance.ConfigurationOptions()
	if xerr != nil {
		return nil, xerr
	}

	if options.DefaultNetworkName != "" {
		networkAbstract, xerr := instance.InspectNetwork(ctx, options.DefaultNetworkCIDR)
		if xerr != nil {
			return nil, xerr
		}

		return networkAbstract, nil
	}

	return nil, fail.NotFoundError("this provider has no default network")
}

// CreateNetwork creates a Network, ie a VPC in AWS terminology
func (instance *stack) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (res *abstract.Network, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%v)", req).WithStopwatch().Entering().Exiting()

	timings, xerr := instance.Timings()
	if xerr != nil {
		return nil, xerr
	}

	// Check if network already there
	if _, xerr = instance.rpcDescribeVpcByName(ctx, aws.String(req.Name)); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreErrorWithContext(ctx, xerr)
			// continue
		default:
			return nil, xerr
		}
	} else {
		return nil, fail.DuplicateError("a Network/VPC named '%s' already exists")
	}

	// if not, create the network/VPC
	theVpc, xerr := instance.rpcCreateVpc(ctx, aws.String(req.Name), aws.String(req.CIDR))
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create VPC")
	}

	// wait until available status
	if IsOperation(theVpc, "State", reflect.TypeOf("")) {
		retryErr := retry.WhileUnsuccessful(
			func() error {
				select {
				case <-ctx.Done():
					return retry.StopRetryError(ctx.Err())
				default:
				}

				vpcTmp, innerXErr := instance.rpcDescribeVpcByID(ctx, theVpc.VpcId)
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
		if ferr != nil && req.CleanOnFailure() {
			if theVpc != nil {
				derr := instance.DeleteNetwork(context.Background(), aws.StringValue(theVpc.VpcId))
				if derr != nil {
					_ = ferr.AddConsequence(derr)
				}
			}
		}
	}()

	gw, xerr := instance.rpcCreateInternetGateway(ctx)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create internet gateway")
	}

	if xerr = instance.rpcAttachInternetGateway(ctx, theVpc.VpcId, gw.InternetGatewayId); xerr != nil {
		return nil, fail.Wrap(xerr, "failed to attach internet gateway to Network")
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && req.CleanOnFailure() {
			derr := instance.rpcDetachInternetGateway(context.Background(), theVpc.VpcId, gw.InternetGatewayId)
			if derr != nil {
				_ = ferr.AddConsequence(normalizeError(derr))
			}
		}
	}()

	tables, xerr := instance.rpcDescribeRouteTables(ctx, aws.String("vpc-id"), []*string{theVpc.VpcId})
	if xerr != nil {
		return nil, xerr
	}
	if len(tables) < 1 {
		return nil, fail.InconsistentError("no Route Tables")
	}

	if xerr = instance.rpcCreateRoute(ctx, gw.InternetGatewayId, tables[0].RouteTableId, aws.String("0.0.0.0/0")); xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create route")
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && req.CleanOnFailure() {
			derr := instance.rpcDeleteRoute(context.Background(), tables[0].RouteTableId, aws.String("0.0.0.0/0"))
			if derr != nil {
				_ = ferr.AddConsequence(normalizeError(derr))
			}
		}
	}()

	anet, xerr := abstract.NewNetwork(abstract.WithName(req.Name))
	if xerr != nil {
		return nil, xerr
	}

	anet.ID = aws.StringValue(theVpc.VpcId)
	anet.CIDR = req.CIDR
	anet.DNSServers = req.DNSServers

	// Make sure we log warnings
	_ = anet.OK()

	return anet, nil
}

// InspectNetwork returns information about Network/VPC from AWS
func (instance *stack) InspectNetwork(ctx context.Context, id string) (_ *abstract.Network, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	resp, xerr := instance.rpcDescribeVpcByID(ctx, aws.String(id))
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

	out, _ := abstract.NewNetwork()
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
func (instance *stack) InspectNetworkByName(ctx context.Context, name string) (_ *abstract.Network, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "('%s')", name).WithStopwatch().Entering().Exiting()

	resp, xerr := instance.rpcDescribeVpcByName(ctx, aws.String(name))
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
func (instance *stack) ListNetworks(ctx context.Context) (_ []*abstract.Network, ferr fail.Error) {
	var emptySlice []*abstract.Network
	if valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network")).WithStopwatch().Entering().Exiting()

	resp, xerr := instance.rpcDescribeVpcs(ctx, nil)
	if xerr != nil {
		return emptySlice, xerr
	}

	nets := make([]*abstract.Network, 0, len(resp))
	for _, vpc := range resp {
		n, _ := abstract.NewNetwork()
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
func (instance *stack) DeleteNetwork(ctx context.Context, networkParam iaasapi.NetworkIdentifier) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	an, networkLabel, xerr := iaasapi.ValidateNetworkIdentifier(networkParam)
	if xerr != nil {
		return xerr
	}
	if an.ID == "" {
		return fail.InvalidParameterError("an", "invalid empty string in field 'ID'")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", networkLabel).WithStopwatch().Entering().Exiting()

	if _, xerr = instance.InspectNetwork(ctx, an.ID); xerr != nil {
		return xerr
	}

	gwTmp, xerr := instance.rpcDescribeInternetGateways(ctx, aws.String(an.ID), nil)
	if xerr != nil {
		return xerr
	}

	for _, agwTmp := range gwTmp {
		for _, att := range agwTmp.Attachments {
			if aws.StringValue(att.VpcId) == an.ID {
				if xerr = instance.rpcDetachInternetGateway(ctx, att.VpcId, agwTmp.InternetGatewayId); xerr != nil {
					return xerr
				}

				if xerr = instance.rpcDeleteInternetGateway(ctx, agwTmp.InternetGatewayId); xerr != nil {
					return xerr
				}
			}
		}
	}

	rtTmp, xerr := instance.rpcDescribeRouteTables(ctx, aws.String("vpc-id"), []*string{aws.String(an.ID)})
	if xerr != nil {
		return xerr
	}

	if len(rtTmp) > 0 {
		for _, artTmp := range rtTmp {
			hasMain := false

			// Dissociate
			for _, rta := range artTmp.Associations {
				if !aws.BoolValue(rta.Main) {
					if xerr = instance.rpcDisassociateRouteTable(ctx, rta.RouteTableAssociationId); xerr != nil {
						return xerr
					}
				} else {
					hasMain = true
				}
			}

			if hasMain {
				continue
			}

			if xerr = instance.rpcDeleteRouteTable(ctx, artTmp.RouteTableId); xerr != nil {
				return xerr
			}
		}

		if xerr = instance.rpcDeleteRoute(ctx, rtTmp[0].RouteTableId, aws.String("0.0.0.0/0")); xerr != nil {
			return xerr
		}
	}

	return instance.rpcDeleteVpc(ctx, aws.String(an.ID))
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
func (instance *stack) CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (res *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%v)", req).WithStopwatch().Entering().Exiting()

	timings, xerr := instance.Timings()
	if xerr != nil {
		return nil, xerr
	}

	if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
		return nil, fail.Wrap(err, "error parsing requested CIDR")
	}

	resp, xerr := instance.rpcCreateSubnet(ctx, aws.String(req.Name), aws.String(req.NetworkID), aws.String(instance.AwsConfig.Zone), aws.String(req.CIDR))
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && req.CleanOnFailure() {
			derr := instance.DeleteSubnet(context.Background(), aws.StringValue(resp.SubnetId))
			if derr != nil {
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

	if IsOperation(resp, "State", reflect.TypeOf("")) {
		retryErr := retry.WhileUnsuccessful(
			func() error {
				select {
				case <-ctx.Done():
					return retry.StopRetryError(ctx.Err())
				default:
				}

				descr, innerXErr := instance.rpcDescribeSubnetByID(ctx, resp.SubnetId)
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
	tables, xerr := instance.rpcDescribeRouteTables(ctx, aws.String("vpc-id"), []*string{aws.String(req.NetworkID)})
	if xerr != nil {
		return nil, xerr
	}
	if len(tables) < 1 {
		return nil, fail.InconsistentError("No Route Tables")
	}

	// First result should be the public interface
	if xerr = instance.rpcAssociateRouteTable(ctx, resp.SubnetId, tables[0].RouteTableId); xerr != nil {
		return nil, fail.Wrap(xerr, "failed to associate route tables to Subnet")
	}

	subnet, xerr := abstract.NewSubnet(abstract.WithName(req.Name))
	if xerr != nil {
		return nil, xerr
	}

	subnet.ID = aws.StringValue(resp.SubnetId)
	subnet.Network = req.NetworkID
	subnet.CIDR = req.CIDR
	subnet.Domain = req.Domain
	subnet.IPVersion = ipversion.IPv4

	// Make sure we log warnings
	_ = subnet.OK()

	return subnet, nil
}

// InspectSubnet returns information about the Subnet from AWS
func (instance *stack) InspectSubnet(ctx context.Context, id string) (_ *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	resp, xerr := instance.rpcDescribeSubnetByID(ctx, aws.String(id))
	if xerr != nil {
		return nil, xerr
	}

	return toAbstractSubnet(resp)
}

func toAbstractSubnet(in *ec2.Subnet) (*abstract.Subnet, fail.Error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	out, _ := abstract.NewSubnet()
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
func (instance *stack) InspectSubnetByName(ctx context.Context, networkRef, subnetName string) (_ *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if subnetName == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "('%s', '%s')", networkRef, subnetName).WithStopwatch().Entering().Exiting()

	timings, xerr := instance.Timings()
	if xerr != nil {
		return nil, xerr
	}

	req, xerr := instance.initEC2DescribeSubnetsInput(ctx, networkRef)
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

			resp, innerErr = instance.EC2Service.DescribeSubnets(req)
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
func (instance *stack) ListSubnets(ctx context.Context, networkRef string) (list []*abstract.Subnet, ferr fail.Error) {
	var emptySlice []*abstract.Subnet
	if valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network")).WithStopwatch().Entering().Exiting()

	timings, xerr := instance.Timings()
	if xerr != nil {
		return nil, xerr
	}

	query, xerr := instance.initEC2DescribeSubnetsInput(ctx, networkRef)
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

			subnets, innerErr = instance.EC2Service.DescribeSubnets(query)
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

func (instance *stack) initEC2DescribeSubnetsInput(ctx context.Context, networkRef string) (*ec2.DescribeSubnetsInput, fail.Error) {
	query := &ec2.DescribeSubnetsInput{}

	if networkRef != "" {
		n, xerr := instance.InspectNetwork(ctx, networkRef)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// if not found, try networkRef as a name
				n, xerr = instance.InspectNetworkByName(ctx, networkRef)
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
func (instance *stack) listSubnetIDs(ctx context.Context, networkRef string) (list []string, ferr fail.Error) { // nolint
	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network")).WithStopwatch().Entering().Exiting()

	timings, xerr := instance.Timings()
	if xerr != nil {
		return nil, xerr
	}

	req, xerr := instance.initEC2DescribeSubnetsInput(ctx, networkRef)
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

			subnets, innerErr = instance.EC2Service.DescribeSubnets(req)
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
func (instance *stack) DeleteSubnet(ctx context.Context, subnetParam iaasapi.SubnetIdentifier) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	as, subnetLabel, xerr := iaasapi.ValidateSubnetIdentifier(subnetParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.aws"), "(%s)", subnetLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	if as.ID != "" {
		as, xerr = instance.InspectSubnet(ctx, as.ID)
	} else {
		as, xerr = instance.InspectSubnetByName(ctx, as.Network, as.Name)
	}
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// If subnet is not found, considered as a success
			debug.IgnoreErrorWithContext(ctx, xerr)
			return nil
		default:
			return xerr
		}
	}

	// Disassociate route tables from subnet
	tables, xerr := instance.rpcDescribeRouteTables(ctx, aws.String("association.subnet-id"), []*string{aws.String(as.ID)})
	if xerr != nil {
		return fail.Wrap(xerr, "failed to find route tables of Subnet")
	}

	if len(tables) > 0 {
		for _, v := range tables {
			for _, a := range v.Associations {
				if aws.StringValue(a.SubnetId) == as.ID {
					xerr = instance.rpcDisassociateRouteTable(ctx, a.RouteTableAssociationId)
					if xerr != nil {
						return fail.Wrap(xerr, "failed to dissociate route tables from Subnet")
					}
				}
			}
		}
	}

	return instance.rpcDeleteSubnet(ctx, aws.String(as.ID))
}

// CreateVIP ...
func (instance *stack) CreateVIP(_ context.Context, networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	return nil, fail.NotImplementedError("CreateVIP() not implemented yet") // FIXME: Technical debt
}

func (instance *stack) AddPublicIPToVIP(context.Context, *abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

func (instance *stack) BindHostToVIP(context.Context, *abstract.VirtualIP, string) fail.Error {
	return fail.NotImplementedError("BindHostToVIP() not implemented yet") // FIXME: Technical debt
}

func (instance *stack) UnbindHostFromVIP(context.Context, *abstract.VirtualIP, string) fail.Error {
	return fail.NotImplementedError("UnbindHostToVIP() not implemented yet") // FIXME: Technical debt
}

func (instance *stack) DeleteVIP(context.Context, *abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("DeleteVIP() not implemented yet") // FIXME: Technical debt
}
