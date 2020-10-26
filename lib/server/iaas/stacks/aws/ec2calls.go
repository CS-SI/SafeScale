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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

func (s stack) callEC2CreateInternetGateway() (*ec2.CreateInternetGatewayOutput, fail.Error) {
	var gw *ec2.CreateInternetGatewayOutput
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			gw, innerErr = s.EC2Service.CreateInternetGateway(&ec2.CreateInternetGatewayInput{})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return &ec2.CreateInternetGatewayOutput{}, xerr
	}
	return gw, nil
}

func (s stack) callEC2CreateRoute(internetGatewayID, routeTableID, cidr *string) fail.Error {
	if internetGatewayID == nil {
		return fail.InvalidParameterError("internetGatewayID", "cannot be nil")
	}
	if routeTableID == nil {
		return fail.InvalidParameterError("routeTableID", "cannot be nil")
	}
	if cidr == nil {
		return fail.InvalidParameterError("gatewayID", "cannot be nil")
	}

	createRouteInput := ec2.CreateRouteInput{
		DestinationCidrBlock: cidr,
		GatewayId:            internetGatewayID,
		RouteTableId:         routeTableID,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.EC2Service.CreateRoute(&createRouteInput)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

func (s stack) callEC2AttachInternetGateway(vpcID, internetGatewayID *string) fail.Error {
	if vpcID == nil {
		return fail.InvalidParameterError("vpcID", "cannot be nil")
	}
	if internetGatewayID == nil {
		return fail.InvalidParameterError("internetGatewayID", "cannot be nil")
	}

	attachInternetGatewayInput := ec2.AttachInternetGatewayInput{
		VpcId:             vpcID,
		InternetGatewayId: internetGatewayID,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.EC2Service.AttachInternetGateway(&attachInternetGatewayInput)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

func (s stack) callEC2DescribeVpcsForID(id *string) (*ec2.DescribeVpcsOutput, fail.Error) {
	if id == nil {
		return &ec2.DescribeVpcsOutput{}, fail.InvalidParameterError("id", "cannot be nil")
	}

	query := ec2.DescribeVpcsInput{
		VpcIds: []*string{id},
	}
	var resp *ec2.DescribeVpcsOutput
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.DescribeVpcs(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return &ec2.DescribeVpcsOutput{}, xerr
	}
	if len(resp.Vpcs) == 0 {
		return &ec2.DescribeVpcsOutput{}, fail.NotFoundError("failed to find Network/VPC %s", aws.StringValue(id))
	}

	return resp, nil
}

func (s stack) callEC2DescribeVpcsForName(name *string) (*ec2.DescribeVpcsOutput, fail.Error) {
	query := ec2.DescribeVpcsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:" + tagNameLabel),
				Values: []*string{name},
			},
		},
	}
	var resp *ec2.DescribeVpcsOutput
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.DescribeVpcs(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return &ec2.DescribeVpcsOutput{}, xerr
	}
	if len(resp.Vpcs) == 0 {
		return &ec2.DescribeVpcsOutput{}, fail.NotFoundError("failed to find a Network/VPC named '%s'", name)
	}

	return resp, nil
}

func (s stack) callEC2CreateVpc(cidr *string) (*ec2.CreateVpcOutput, fail.Error) {
	if cidr == nil {
		return &ec2.CreateVpcOutput{}, fail.InvalidParameterError("cidr", "cannot be nil")
	}

	query := ec2.CreateVpcInput{
		CidrBlock: cidr,
	}
	var resp *ec2.CreateVpcOutput
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.CreateVpc(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return &ec2.CreateVpcOutput{}, xerr
	}
	return resp, nil
}

func (s stack) callEC2DetachInternetGateway(vpcID, internetGatewayID *string) fail.Error {
	if vpcID == nil {
		return fail.InvalidParameterError("vpcID", "cannot be nil")
	}
	if internetGatewayID == nil {
		return fail.InvalidParameterError("internetGatewayID", "cannot be nil")
	}

	query := ec2.DetachInternetGatewayInput{
		InternetGatewayId: internetGatewayID,
		VpcId:             vpcID,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.EC2Service.DetachInternetGateway(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

func (s stack) callEC2DeleteRoute(routeTableID, cidr *string) fail.Error {
	if routeTableID == nil {
		return fail.InvalidParameterError("routeTableId", "cannot be nil")
	}
	if cidr == nil {
		return fail.InvalidParameterError("cidr", "cannot be nil")
	}
	query := ec2.DeleteRouteInput{
		DestinationCidrBlock: cidr,
		RouteTableId:         routeTableID,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.EC2Service.DeleteRoute(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

func (s stack) callEC2DescribeVpcs() (*ec2.DescribeVpcsOutput, fail.Error) {
	var resp *ec2.DescribeVpcsOutput
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.DescribeVpcs(&ec2.DescribeVpcsInput{})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return &ec2.DescribeVpcsOutput{}, xerr
	}
	return resp, nil
}

func (s stack) callEC2DeleteVpc(id *string) fail.Error {
	if id == nil {
		return fail.InvalidParameterError("id", "cannot be nil")
	}

	query := ec2.DeleteVpcInput{
		VpcId: id,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.EC2Service.DeleteVpc(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

func (s stack) callEC2DeleteRouteTable(id *string) fail.Error {
	if id == nil {
		return fail.InvalidParameterError("id", "cannot be nil")
	}

	deleteRouteTable := ec2.DeleteRouteTableInput{
		RouteTableId: id,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.EC2Service.DeleteRouteTable(&deleteRouteTable)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

func (s stack) callEC2DissassociateRouteTable(id *string) fail.Error {
	if id == nil {
		return fail.InvalidParameterError("id", "cannot be nil")
	}

	disassociateRouteTableInput := ec2.DisassociateRouteTableInput{
		AssociationId: id,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.EC2Service.DisassociateRouteTable(&disassociateRouteTableInput)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

func (s stack) callEC2DeleteInternetGateway(id *string) fail.Error {
	if id == nil {
		return fail.InvalidParameterError("id", "cannot be nil")
	}

	query := ec2.DeleteInternetGatewayInput{
		InternetGatewayId: id,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.EC2Service.DeleteInternetGateway(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

func (s stack) callEC2DescribeInternetGateways() (*ec2.DescribeInternetGatewaysOutput, fail.Error) {
	var resp *ec2.DescribeInternetGatewaysOutput
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.DescribeInternetGateways(&ec2.DescribeInternetGatewaysInput{})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return &ec2.DescribeInternetGatewaysOutput{}, xerr
	}
	return resp, nil
}

func (s stack) callEC2DescribeSubnet(id *string) (*ec2.Subnet, fail.Error) {
	if id == nil {
		return &ec2.Subnet{}, fail.InvalidParameterError("id", "cannot be nil")
	}

	resp, xerr := s.callEC2DescribeSubnets([]*string{id})
	if xerr != nil {
		return &ec2.Subnet{}, xerr
	}
	if len(resp.Subnets) == 0 {
		return &ec2.Subnet{}, fail.NotFoundError("failed to find a Subnet %s", aws.StringValue(id))
	}
	if len(resp.Subnets) > 1 {
		return &ec2.Subnet{}, fail.InconsistentError("provider returned more than one Subnet with id %s", id)
	}

	return resp.Subnets[0], nil
}

func (s stack) callEC2DescribeSubnets(ids []*string) (*ec2.DescribeSubnetsOutput, fail.Error) {
	var resp *ec2.DescribeSubnetsOutput
	if ids == nil {
		return resp, fail.InvalidParameterError("id", "cannot be nil")
	}
	var query ec2.DescribeSubnetsInput
	if len(ids) > 0 {
		query.SubnetIds = ids
	}

	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.DescribeSubnets(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return &ec2.DescribeSubnetsOutput{}, xerr
	}
	return resp, nil
}

func (s stack) callEC2CreateSubnet(vpcID, azID, cidr *string) (*ec2.CreateSubnetOutput, fail.Error) {
	var resp *ec2.CreateSubnetOutput
	if vpcID == nil {
		return resp, fail.InvalidParameterError("vpcID", "cannot be nil")
	}
	if azID == nil {
		return resp, fail.InvalidParameterError("azID", "cannot be nil")
	}
	if cidr == nil {
		return resp, fail.InvalidParameterError("cidr", "cannot be nil")
	}

	query := ec2.CreateSubnetInput{
		CidrBlock:        cidr,
		VpcId:            vpcID,
		AvailabilityZone: azID,
	}
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.CreateSubnet(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return &ec2.CreateSubnetOutput{}, xerr
	}
	return resp, nil
}

func (s stack) callEC2AssociateRouteTable(subnetID, routeID *string) fail.Error {
	if subnetID == nil {
		return fail.InvalidParameterError("subnetID", "cannot be nil")
	}
	if routeID == nil {
		return fail.InvalidParameterError("routeID", "cannot be nil")
	}

	query := ec2.AssociateRouteTableInput{
		RouteTableId: routeID,
		SubnetId:     subnetID,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.EC2Service.AssociateRouteTable(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)

}

func (s stack) callEC2DescribeRouteTables(key string, values []*string) (*ec2.DescribeRouteTablesOutput, fail.Error) {
	nullOut := &ec2.DescribeRouteTablesOutput{}
	if key == "" {
		return nullOut, fail.InvalidParameterError("key", "cannot be empty string")
	}
	if len(values) == 0 {
		return nullOut, fail.InvalidParameterError("values", "cannot be empty slice")
	}

	query := ec2.DescribeRouteTablesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String(key),
				Values: values,
			},
		},
	}
	var tables *ec2.DescribeRouteTablesOutput
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			tables, innerErr = s.EC2Service.DescribeRouteTables(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return &ec2.DescribeRouteTablesOutput{}, xerr
	}
	return tables, nil
}

func (s stack) callEC2DisassociateRouteTable(id *string) fail.Error {
	query := ec2.DisassociateRouteTableInput{
		AssociationId: id,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.EC2Service.DisassociateRouteTable(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

func (s stack) callEC2DeleteSubnet(id *string) fail.Error {
	query := ec2.DeleteSubnetInput{
		SubnetId: id,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.EC2Service.DeleteSubnet(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}
