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
	"net"
	"reflect"

	netutils "github.com/CS-SI/SafeScale/v21/lib/utils/net"
	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	// "github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/ipversion"

	// "github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/retry"
	// propsv1 "github.com/CS-SI/SafeScale/v21/lib/server/resources/properties/v1"
)

const (
	tagNameLabel = "Name"
)

var (
	awsTagNameLabel = aws.String(tagNameLabel)
)

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (s stack) HasDefaultNetwork() (bool, fail.Error) {
	return false, nil
}

// GetDefaultNetwork returns the *abstract.Network corresponding to the default network
func (s stack) GetDefaultNetwork() (*abstract.Network, fail.Error) {
	return nil, fail.NotFoundError("no default network in stack")
}

// CreateNetwork creates a Network, ie a VPC in AWS terminology
func (s stack) CreateNetwork(req abstract.NetworkRequest) (res *abstract.Network, ferr fail.Error) {
	nullAN := abstract.NewNetwork()
	if valid.IsNil(s) {
		return nullAN, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%v)", req).WithStopwatch().Entering().Exiting()

	timings, xerr := s.Timings()
	if xerr != nil {
		return nullAN, xerr
	}

	// Check if network already there
	if _, xerr = s.rpcDescribeVpcByName(aws.String(req.Name)); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreError(xerr)
			// continue
		default:
			return nullAN, xerr
		}
	} else {
		return nullAN, fail.DuplicateError("a Network/VPC named '%s' already exists")
	}

	// if not, create the network/VPC
	theVpc, xerr := s.rpcCreateVpc(aws.String(req.Name), aws.String(req.CIDR))
	if xerr != nil {
		return nullAN, fail.Wrap(xerr, "failed to create VPC")
	}

	// wait until available status
	if IsOperation(theVpc, "State", reflect.TypeOf("")) {
		retryErr := retry.WhileUnsuccessful(
			func() error {
				vpcTmp, innerXErr := s.rpcDescribeVpcByID(theVpc.VpcId)
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
				return nullAN, fail.Wrap(fail.Cause(retryErr), "stopping retries")
			case *fail.ErrTimeout:
				return nullAN, fail.Wrap(fail.Cause(retryErr), "timeout")
			default:
				return nullAN, retryErr
			}
		}
	}

	defer func() {
		if ferr != nil && !req.KeepOnFailure {
			if theVpc != nil {
				derr := s.DeleteNetwork(aws.StringValue(theVpc.VpcId))
				if derr != nil {
					_ = ferr.AddConsequence(derr)
				}
			}
		}
	}()

	gw, xerr := s.rpcCreateInternetGateway()
	if xerr != nil {
		return nullAN, fail.Wrap(xerr, "failed to create internet gateway")
	}

	if xerr = s.rpcAttachInternetGateway(theVpc.VpcId, gw.InternetGatewayId); xerr != nil {
		return nullAN, fail.Wrap(xerr, "failed to attach internet gateway to Network")
	}

	defer func() {
		if ferr != nil && !req.KeepOnFailure {
			if derr := s.rpcDetachInternetGateway(theVpc.VpcId, gw.InternetGatewayId); derr != nil {
				_ = ferr.AddConsequence(normalizeError(derr))
			}
		}
	}()

	tables, xerr := s.rpcDescribeRouteTables(aws.String("vpc-id"), []*string{theVpc.VpcId})
	if xerr != nil {
		return nullAN, xerr
	}
	if len(tables) < 1 {
		return nullAN, fail.InconsistentError("no Route Tables")
	}

	if xerr = s.rpcCreateRoute(gw.InternetGatewayId, tables[0].RouteTableId, aws.String("0.0.0.0/0")); xerr != nil {
		return nullAN, fail.Wrap(xerr, "failed to create route")
	}

	defer func() {
		if ferr != nil && !req.KeepOnFailure {
			if derr := s.rpcDeleteRoute(tables[0].RouteTableId, aws.String("0.0.0.0/0")); derr != nil {
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
func (s stack) InspectNetwork(id string) (_ *abstract.Network, ferr fail.Error) {
	nullAN := abstract.NewNetwork()
	if valid.IsNil(s) {
		return nullAN, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAN, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	resp, xerr := s.rpcDescribeVpcByID(aws.String(id))
	if xerr != nil {
		return nullAN, xerr
	}

	anet, xerr := toAbstractNetwork(resp)
	if xerr != nil {
		return nullAN, xerr
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
func (s stack) InspectNetworkByName(name string) (_ *abstract.Network, ferr fail.Error) {
	nullAN := abstract.NewNetwork()
	if valid.IsNil(s) {
		return nullAN, fail.InvalidInstanceError()
	}
	if name == "" {
		return nullAN, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "('%s')", name).WithStopwatch().Entering().Exiting()

	resp, xerr := s.rpcDescribeVpcByName(aws.String(name))
	if xerr != nil {
		return nullAN, xerr
	}

	anet, xerr := toAbstractNetwork(resp)
	if xerr != nil {
		return nullAN, xerr
	}

	return anet, nil
}

// ListNetworks ...
func (s stack) ListNetworks() (_ []*abstract.Network, ferr fail.Error) {
	var emptySlice []*abstract.Network
	if valid.IsNil(s) {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network")).WithStopwatch().Entering().Exiting()

	resp, xerr := s.rpcDescribeVpcs(nil)
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
func (s stack) DeleteNetwork(id string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	var xerr fail.Error
	if _, xerr = s.InspectNetwork(id); xerr != nil {
		return xerr
	}

	gwTmp, xerr := s.rpcDescribeInternetGateways(aws.String(id), nil)
	if xerr != nil {
		return xerr
	}

	for _, agwTmp := range gwTmp {
		for _, att := range agwTmp.Attachments {
			if aws.StringValue(att.VpcId) == id {
				if xerr = s.rpcDetachInternetGateway(att.VpcId, agwTmp.InternetGatewayId); xerr != nil {
					return xerr
				}

				if xerr = s.rpcDeleteInternetGateway(agwTmp.InternetGatewayId); xerr != nil {
					return xerr
				}
			}
		}
	}

	rtTmp, xerr := s.rpcDescribeRouteTables(aws.String("vpc-id"), []*string{aws.String(id)})
	if xerr != nil {
		return xerr
	}

	if len(rtTmp) > 0 {
		for _, artTmp := range rtTmp {
			hasMain := false

			// Dissociate
			for _, rta := range artTmp.Associations {
				if !aws.BoolValue(rta.Main) {
					if xerr = s.rpcDisassociateRouteTable(rta.RouteTableAssociationId); xerr != nil {
						return xerr
					}
				} else {
					hasMain = true
				}
			}

			if hasMain {
				continue
			}

			if xerr = s.rpcDeleteRouteTable(artTmp.RouteTableId); xerr != nil {
				return xerr
			}
		}

		if xerr = s.rpcDeleteRoute(rtTmp[0].RouteTableId, aws.String("0.0.0.0/0")); xerr != nil {
			return xerr
		}
	}

	return s.rpcDeleteVpc(aws.String(id))
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
func (s stack) CreateSubnet(req abstract.SubnetRequest) (res *abstract.Subnet, ferr fail.Error) {
	nullAS := abstract.NewSubnet()
	if valid.IsNil(s) {
		return nullAS, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%v)", req).WithStopwatch().Entering().Exiting()

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
		return nullAS, fail.Wrap(err, "error parsing requested CIDR")
	}

	resp, xerr := s.rpcCreateSubnet(aws.String(req.Name), aws.String(req.NetworkID), aws.String(s.AwsConfig.Zone), aws.String(req.CIDR))
	if xerr != nil {
		return nullAS, xerr
	}

	defer func() {
		if ferr != nil && !req.KeepOnFailure {
			if derr := s.DeleteSubnet(aws.StringValue(resp.SubnetId)); derr != nil {
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

	if IsOperation(resp, "State", reflect.TypeOf("")) {
		retryErr := retry.WhileUnsuccessful(
			func() error {
				descr, innerXErr := s.rpcDescribeSubnetByID(resp.SubnetId)
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
				return nullAS, fail.Wrap(fail.Cause(retryErr), "stopping retries")
			case *fail.ErrTimeout:
				return nullAS, fail.Wrap(fail.Cause(retryErr), "timeout")
			default:
				return nullAS, retryErr
			}
		}
	}
	tables, xerr := s.rpcDescribeRouteTables(aws.String("vpc-id"), []*string{aws.String(req.NetworkID)})
	if xerr != nil {
		return nullAS, xerr
	}
	if len(tables) < 1 {
		return nil, fail.InconsistentError("No Route Tables")
	}

	// First result should be the public interface
	if xerr = s.rpcAssociateRouteTable(resp.SubnetId, tables[0].RouteTableId); xerr != nil {
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
func (s stack) InspectSubnet(id string) (_ *abstract.Subnet, ferr fail.Error) {
	nullAS := abstract.NewSubnet()
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAS, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	resp, xerr := s.rpcDescribeSubnetByID(aws.String(id))
	if xerr != nil {
		return nullAS, xerr
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
func (s stack) InspectSubnetByName(networkRef, subnetName string) (_ *abstract.Subnet, ferr fail.Error) {
	nullAS := abstract.NewSubnet()
	if valid.IsNil(s) {
		return nullAS, fail.InvalidInstanceError()
	}
	if subnetName == "" {
		return nullAS, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "('%s', '%s')", networkRef, subnetName).WithStopwatch().Entering().Exiting()

	timings, xerr := s.Timings()
	if xerr != nil {
		return nullAS, xerr
	}

	req, xerr := s.initEC2DescribeSubnetsInput(networkRef)
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
func (s stack) ListSubnets(networkRef string) (list []*abstract.Subnet, ferr fail.Error) {
	var emptySlice []*abstract.Subnet
	if valid.IsNil(s) {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network")).WithStopwatch().Entering().Exiting()

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	query, xerr := s.initEC2DescribeSubnetsInput(networkRef)
	if xerr != nil {
		return nil, xerr
	}

	var subnets *ec2.DescribeSubnetsOutput
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
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

func (s stack) initEC2DescribeSubnetsInput(networkRef string) (*ec2.DescribeSubnetsInput, fail.Error) {
	query := &ec2.DescribeSubnetsInput{}

	if networkRef != "" {
		n, xerr := s.InspectNetwork(networkRef)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// if not found, try networkRef as a name
				n, xerr = s.InspectNetworkByName(networkRef)
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
func (s stack) listSubnetIDs(networkRef string) (list []string, ferr fail.Error) { // nolint
	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network")).WithStopwatch().Entering().Exiting()

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	req, xerr := s.initEC2DescribeSubnetsInput(networkRef)
	if xerr != nil {
		return nil, xerr
	}

	var subnets *ec2.DescribeSubnetsOutput
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
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
func (s stack) DeleteSubnet(id string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	// Disassociate route tables from subnet
	tables, xerr := s.rpcDescribeRouteTables(aws.String("association.subnet-id"), []*string{aws.String(id)})
	if xerr != nil {
		return fail.Wrap(xerr, "failed to find route tables of Subnet")
	}

	if len(tables) > 0 {
		for _, v := range tables {
			for _, a := range v.Associations {
				if aws.StringValue(a.SubnetId) == id {
					xerr = s.rpcDisassociateRouteTable(a.RouteTableAssociationId)
					if xerr != nil {
						return fail.Wrap(xerr, "failed to dissociate route tables from Subnet")
					}
				}
			}
		}
	}

	return s.rpcDeleteSubnet(aws.String(id))
}

// BindSecurityGroupToSubnet binds a security group to a network
// No bind of Security Group to Subnet at AWS; so always succeed
func (s *stack) BindSecurityGroupToSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if subnetID == "" {
		return fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	return nil
}

// UnbindSecurityGroupFromSubnet unbinds a security group from a host
// No bind of Security Group to Subnet at AWS; so always succeed
func (s *stack) UnbindSecurityGroupFromSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if subnetID == "" {
		return fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	return nil
}

// CreateVIP ...
func (s *stack) CreateVIP(networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	return nil, fail.NotImplementedError("CreateVIP() not implemented yet") // FIXME: Technical debt
}

func (s *stack) AddPublicIPToVIP(*abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

func (s *stack) BindHostToVIP(*abstract.VirtualIP, string) fail.Error {
	return fail.NotImplementedError("BindHostToVIP() not implemented yet") // FIXME: Technical debt
}

func (s *stack) UnbindHostFromVIP(*abstract.VirtualIP, string) fail.Error {
	return fail.NotImplementedError("UnbindHostToVIP() not implemented yet") // FIXME: Technical debt
}

func (s *stack) DeleteVIP(*abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("DeleteVIP() not implemented yet") // FIXME: Technical debt
}
