/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"encoding/base64"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

func validateAWSString(stringContent *string, stringLabel string, notEmpty bool) fail.Error {
	if stringContent == nil {
		return fail.InvalidParameterError(stringLabel, "cannot be nil")
	}
	if notEmpty && aws.StringValue(stringContent) == "" {
		return fail.InvalidParameterError(stringLabel, "cannot be empty AWS String")
	}
	return nil
}

func (s stack) rpcCreateInternetGateway() (*ec2.InternetGateway, fail.Error) {
	var gw *ec2.CreateInternetGatewayOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			gw, err = s.EC2Service.CreateInternetGateway(&ec2.CreateInternetGatewayInput{})
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &ec2.InternetGateway{}, xerr
	}
	return gw.InternetGateway, nil
}

func (s stack) rpcCreateRoute(internetGatewayID, routeTableID, cidr *string) fail.Error {
	if xerr := validateAWSString(internetGatewayID, "internetGatewayID", true); xerr != nil {
		return xerr
	}
	if xerr := validateAWSString(routeTableID, "routeTableID", true); xerr != nil {
		return xerr
	}
	if xerr := validateAWSString(cidr, "cidr", true); xerr != nil {
		return xerr
	}

	createRouteInput := ec2.CreateRouteInput{
		DestinationCidrBlock: cidr,
		GatewayId:            internetGatewayID,
		RouteTableId:         routeTableID,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.CreateRoute(&createRouteInput)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcAttachInternetGateway(vpcID, internetGatewayID *string) fail.Error {
	if xerr := validateAWSString(vpcID, "vpcID", true); xerr != nil {
		return xerr
	}
	if xerr := validateAWSString(internetGatewayID, "internetGatewayID", true); xerr != nil {
		return xerr
	}

	attachInternetGatewayInput := ec2.AttachInternetGatewayInput{
		VpcId:             vpcID,
		InternetGatewayId: internetGatewayID,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.AttachInternetGateway(&attachInternetGatewayInput)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeVpcs(ids []*string) ([]*ec2.Vpc, fail.Error) {
	var request ec2.DescribeVpcsInput
	if len(ids) > 0 {
		request.VpcIds = ids
	}
	var resp *ec2.DescribeVpcsOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeVpcs(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.Vpc{}, xerr
	}
	return resp.Vpcs, nil
}

func (s stack) rpcDescribeVpcByID(id *string) (*ec2.Vpc, fail.Error) {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return &ec2.Vpc{}, xerr
	}

	resp, xerr := s.rpcDescribeVpcs([]*string{id})
	if xerr != nil {
		return &ec2.Vpc{}, xerr
	}
	if len(resp) == 0 {
		return &ec2.Vpc{}, fail.NotFoundError("failed to find Network/VPC with ID %s", aws.StringValue(id))
	}
	if len(resp) > 1 {
		return &ec2.Vpc{}, fail.InconsistentError("found more than 1 NetworkVPC with ID %s", aws.StringValue(id))
	}
	return resp[0], nil
}

func (s stack) rpcDescribeVpcByName(name *string) (*ec2.Vpc, fail.Error) {
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return &ec2.Vpc{}, xerr
	}

	request := ec2.DescribeVpcsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:" + tagNameLabel),
				Values: []*string{name},
			},
		},
	}
	var resp *ec2.DescribeVpcsOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeVpcs(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &ec2.Vpc{}, xerr
	}
	if len(resp.Vpcs) == 0 {
		return &ec2.Vpc{}, fail.NotFoundError("failed to find a Network/VPC named '%s'", aws.StringValue(name))
	}
	if len(resp.Vpcs) > 1 {
		return &ec2.Vpc{}, fail.InconsistentError("found more than 1 NetworkVPC named '%s'", aws.StringValue(name))
	}

	return resp.Vpcs[0], nil
}

func (s stack) rpcCreateVpc(name, cidr *string) (*ec2.Vpc, fail.Error) {
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return &ec2.Vpc{}, xerr
	}
	if xerr := validateAWSString(cidr, "cidr", true); xerr != nil {
		return &ec2.Vpc{}, xerr
	}

	request := ec2.CreateVpcInput{
		CidrBlock: cidr,
	}
	var resp *ec2.CreateVpcOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.CreateVpc(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &ec2.Vpc{}, xerr
	}

	defer func() {
		if xerr != nil {
			if derr := s.rpcDeleteVpc(resp.Vpc.VpcId); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Network/VPC %s", aws.StringValue(resp.Vpc.VpcId)))
			}
		}
	}()

	// resource tagging
	tags := []*ec2.Tag{
		{
			Key:   awsTagNameLabel,
			Value: name,
		},
	}
	if xerr = s.rpcCreateTags([]*string{resp.Vpc.VpcId}, tags); xerr != nil {
		return &ec2.Vpc{}, xerr
	}

	return resp.Vpc, nil
}

func (s stack) rpcCreateTags(resources []*string, tags []*ec2.Tag) fail.Error {
	if len(resources) == 0 {
		return fail.InvalidParameterError("resources", "cannot be an empty slice")
	}
	if len(tags) == 0 {
		return nil
	}

	request := ec2.CreateTagsInput{
		Resources: resources,
		Tags:      tags,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.CreateTags(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteVpc(id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	request := ec2.DeleteVpcInput{
		VpcId: id,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.DeleteVpc(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDetachInternetGateway(vpcID, internetGatewayID *string) fail.Error {
	if xerr := validateAWSString(vpcID, "vpcID", true); xerr != nil {
		return xerr
	}
	if xerr := validateAWSString(internetGatewayID, "internetGatewayID", true); xerr != nil {
		return xerr
	}

	request := ec2.DetachInternetGatewayInput{
		InternetGatewayId: internetGatewayID,
		VpcId:             vpcID,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.DetachInternetGateway(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteRoute(routeTableID, cidr *string) fail.Error {
	if xerr := validateAWSString(routeTableID, "routeTableID", true); xerr != nil {
		return xerr
	}
	if xerr := validateAWSString(cidr, "cidr", true); xerr != nil {
		return xerr
	}

	request := ec2.DeleteRouteInput{
		DestinationCidrBlock: cidr,
		RouteTableId:         routeTableID,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.DeleteRoute(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteRouteTable(id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	deleteRouteTable := ec2.DeleteRouteTableInput{
		RouteTableId: id,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.DeleteRouteTable(&deleteRouteTable)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteInternetGateway(id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	request := ec2.DeleteInternetGatewayInput{
		InternetGatewayId: id,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.DeleteInternetGateway(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeInternetGateways(vpcID *string, ids []*string) ([]*ec2.InternetGateway, fail.Error) {
	var filters []*ec2.Filter
	if vpcID != nil && aws.StringValue(vpcID) != "" {
		filters = append(filters, &ec2.Filter{
			Name:   aws.String("attachment.vpc-id"),
			Values: []*string{vpcID},
		})
	}
	if len(ids) > 0 {
		filters = append(filters, &ec2.Filter{
			Name:   aws.String("internet-gateway-id"),
			Values: ids,
		})
	}
	request := ec2.DescribeInternetGatewaysInput{
		Filters: filters,
	}
	var resp *ec2.DescribeInternetGatewaysOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeInternetGateways(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.InternetGateway{}, xerr
	}
	return resp.InternetGateways, nil
}

func (s stack) rpcDescribeSubnetByID(id *string) (*ec2.Subnet, fail.Error) {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return &ec2.Subnet{}, xerr
	}

	resp, xerr := s.rpcDescribeSubnets([]*string{id})
	if xerr != nil {
		return &ec2.Subnet{}, xerr
	}
	if len(resp) == 0 {
		return &ec2.Subnet{}, fail.NotFoundError("failed to find a Subnet with ID %s", aws.StringValue(id))
	}
	if len(resp) > 1 {
		return &ec2.Subnet{}, fail.InconsistentError("provider returned more than one Subnet with id %s", aws.StringValue(id))
	}

	return resp[0], nil
}

func (s stack) rpcCreateSubnet(name, vpcID, azID, cidr *string) (*ec2.Subnet, fail.Error) {
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return &ec2.Subnet{}, xerr
	}
	if xerr := validateAWSString(vpcID, "vpcID", true); xerr != nil {
		return &ec2.Subnet{}, xerr
	}
	if xerr := validateAWSString(azID, "azID", true); xerr != nil {
		return &ec2.Subnet{}, xerr
	}
	if xerr := validateAWSString(cidr, "cidr", true); xerr != nil {
		return &ec2.Subnet{}, xerr
	}

	request := ec2.CreateSubnetInput{
		CidrBlock:        cidr,
		VpcId:            vpcID,
		AvailabilityZone: azID,
	}
	var resp *ec2.CreateSubnetOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.CreateSubnet(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &ec2.Subnet{}, xerr
	}

	defer func() {
		if xerr != nil {
			if derr := s.rpcDeleteSubnet(resp.Subnet.SubnetId); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Subnet %s", aws.StringValue(resp.Subnet.SubnetId)))
			}
		}
	}()

	tags := []*ec2.Tag{
		{
			Key:   awsTagNameLabel,
			Value: name,
		},
	}
	if xerr = s.rpcCreateTags([]*string{resp.Subnet.SubnetId}, tags); xerr != nil {
		return &ec2.Subnet{}, xerr
	}

	return resp.Subnet, nil
}

func (s stack) rpcAssociateRouteTable(subnetID, routeID *string) fail.Error {
	if xerr := validateAWSString(subnetID, "subnetID", true); xerr != nil {
		return xerr
	}
	if xerr := validateAWSString(routeID, "routeID", true); xerr != nil {
		return xerr
	}

	request := ec2.AssociateRouteTableInput{
		RouteTableId: routeID,
		SubnetId:     subnetID,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.AssociateRouteTable(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeRouteTables(key *string, values []*string) ([]*ec2.RouteTable, fail.Error) {
	var emptySlice []*ec2.RouteTable
	if xerr := validateAWSString(key, "key", true); xerr != nil {
		return emptySlice, xerr
	}
	if len(values) == 0 {
		return emptySlice, fail.InvalidParameterError("values", "cannot be empty slice")
	}

	request := ec2.DescribeRouteTablesInput{
		Filters: []*ec2.Filter{
			{
				Name:   key,
				Values: values,
			},
		},
	}
	var resp *ec2.DescribeRouteTablesOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeRouteTables(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return emptySlice, xerr
	}
	return resp.RouteTables, nil
}

func (s stack) rpcDisassociateRouteTable(id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	request := ec2.DisassociateRouteTableInput{
		AssociationId: id,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.DisassociateRouteTable(&request)
			return normalizeError(err)
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteSubnet(id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	request := ec2.DeleteSubnetInput{
		SubnetId: id,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.DeleteSubnet(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteSecurityGroup(id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	request := ec2.DeleteSecurityGroupInput{
		GroupId: id,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.DeleteSecurityGroup(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcCreateSecurityGroup(networkID, name, description *string) (*string, fail.Error) {
	if xerr := validateAWSString(networkID, "networkID", true); xerr != nil {
		return aws.String(""), xerr
	}
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return aws.String(""), xerr
	}
	if xerr := validateAWSString(description, "description", false); xerr != nil {
		return aws.String(""), xerr
	}

	request := ec2.CreateSecurityGroupInput{
		Description: description,
		GroupName:   name,
		VpcId:       networkID,
	}
	var resp *ec2.CreateSecurityGroupOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.CreateSecurityGroup(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return aws.String(""), xerr
	}
	return resp.GroupId, nil
}

func (s stack) rpcDescribeSecurityGroups(networkID *string, ids []*string) ([]*ec2.SecurityGroup, fail.Error) {
	var request ec2.DescribeSecurityGroupsInput
	if aws.StringValue(networkID) != "" {
		request.Filters = []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{networkID},
			},
		}
	}
	if len(ids) > 0 {
		request.GroupIds = ids
	}
	var resp *ec2.DescribeSecurityGroupsOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeSecurityGroups(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.SecurityGroup{}, xerr
	}
	if resp == nil {
		return []*ec2.SecurityGroup{}, fail.NotFoundError("failed to find Security Groups")
	}
	return resp.SecurityGroups, nil
}

func (s stack) rpcDescribeSecurityGroupByID(id *string) (*ec2.SecurityGroup, fail.Error) {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return &ec2.SecurityGroup{}, xerr
	}

	resp, xerr := s.rpcDescribeSecurityGroups(aws.String(""), []*string{id})
	if xerr != nil {
		return &ec2.SecurityGroup{}, xerr
	}
	if len(resp) == 0 {
		return &ec2.SecurityGroup{}, fail.NotFoundError("failed to find a Security Group with ID %s", aws.StringValue(id))
	}
	if len(resp) > 1 {
		return &ec2.SecurityGroup{}, fail.InconsistentError("found more than one Security Group with ID %s", aws.StringValue(id))
	}
	return resp[0], nil
}

func (s stack) rpcDescribeSecurityGroupByName(networkID, name *string) (*ec2.SecurityGroup, fail.Error) {
	if xerr := validateAWSString(networkID, "networkID", true); xerr != nil {
		return &ec2.SecurityGroup{}, xerr
	}
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return &ec2.SecurityGroup{}, xerr
	}

	request := ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("group-name"),
				Values: []*string{name},
			},
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{networkID},
			},
		},
	}
	var resp *ec2.DescribeSecurityGroupsOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeSecurityGroups(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &ec2.SecurityGroup{}, xerr
	}
	if resp == nil {
		return &ec2.SecurityGroup{}, fail.NotFoundError("failed to find Security Groups")
	}
	if len(resp.SecurityGroups) == 0 {
		return &ec2.SecurityGroup{}, fail.NotFoundError("failed to find a Security Group named '%s' in Network %s", aws.StringValue(name), aws.StringValue(networkID))
	}
	if len(resp.SecurityGroups) > 1 {
		return &ec2.SecurityGroup{}, fail.InconsistentError("found more than one Security Group named '%s' in Network %s", aws.StringValue(name), aws.StringValue(networkID))
	}
	return resp.SecurityGroups[0], nil
}

func (s stack) rpcRevokeSecurityGroupIngress(id *string, ingress []*ec2.IpPermission) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}
	if len(ingress) == 0 {
		return fail.InvalidParameterError("ingress", "cannot be empty slice")
	}

	request := ec2.RevokeSecurityGroupIngressInput{
		GroupId:       id,
		IpPermissions: ingress,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.RevokeSecurityGroupIngress(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcRevokeSecurityGroupEgress(id *string, egress []*ec2.IpPermission) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}
	if len(egress) == 0 {
		return fail.InvalidParameterError("egress", "cannot be empty slice")
	}

	request := ec2.RevokeSecurityGroupEgressInput{
		GroupId:       id,
		IpPermissions: egress,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.RevokeSecurityGroupEgress(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcAuthorizeSecurityGroupIngress(id *string, ingress []*ec2.IpPermission) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}
	if len(ingress) == 0 {
		return fail.InvalidParameterError("ingress", "cannot be empty slice")
	}

	request := ec2.AuthorizeSecurityGroupIngressInput{
		GroupId:       id,
		IpPermissions: ingress,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.AuthorizeSecurityGroupIngress(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcAuthorizeSecurityGroupEgress(id *string, egress []*ec2.IpPermission) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}
	if len(egress) == 0 {
		return fail.InvalidParameterError("egress", "cannot be empty slice")
	}

	request := ec2.AuthorizeSecurityGroupEgressInput{
		GroupId:       id,
		IpPermissions: egress,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.AuthorizeSecurityGroupEgress(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDisassociateAddress(id *string) fail.Error { // nolint
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	request := ec2.DisassociateAddressInput{
		AssociationId: id,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.DisassociateAddress(&request)
			return err
		}, normalizeError,
	)
}

func (s stack) rpcReleaseAddress(id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	request := ec2.ReleaseAddressInput{
		AllocationId: id,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.ReleaseAddress(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeInstanceByID(id *string) (*ec2.Instance, fail.Error) {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return &ec2.Instance{}, xerr
	}

	resp, xerr := s.rpcDescribeInstances([]*string{id})
	if xerr != nil {
		return &ec2.Instance{}, xerr
	}
	if len(resp) == 0 {
		return &ec2.Instance{}, fail.NotFoundError("failed to find an instance with ID %s", aws.StringValue(id))
	}
	if len(resp) > 1 {
		return &ec2.Instance{}, fail.InconsistentError("found more than one instance with ID %s", aws.StringValue(id))
	}
	return resp[0], nil
}

func (s stack) rpcDescribeInstanceByName(name *string) (*ec2.Instance, fail.Error) {
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return &ec2.Instance{}, xerr
	}

	request := ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:" + tagNameLabel),
				Values: []*string{name},
			},
		},
	}
	var resp *ec2.DescribeInstancesOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeInstances(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &ec2.Instance{}, xerr
	}
	if len(resp.Reservations) == 0 {
		return &ec2.Instance{}, fail.NotFoundError("failed to find a Host named '%s'", aws.StringValue(name))
	}

	var (
		found    int
		instance *ec2.Instance
	)
	for _, v := range resp.Reservations {
		for _, i := range v.Instances {
			state, xerr := toHostState(i.State)
			if xerr != nil {
				logrus.Errorf("found instance '%s' with unmanaged state '%d', ignoring", aws.StringValue(i.InstanceId), aws.Int64Value(i.State.Code)&0xff)
				continue
			}
			if state != hoststate.Terminated {
				instance = i
				found++
			}
		}
	}
	if found == 0 {
		return &ec2.Instance{}, fail.NotFoundError("failed to find a Host named '%s'", aws.StringValue(name))
	}
	if found > 1 {
		return &ec2.Instance{}, fail.InconsistentError("found more than one Host named '%s'", aws.StringValue(name))
	}
	return instance, nil
}

func (s stack) rpcTerminateInstance(id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	request := ec2.TerminateInstancesInput{
		InstanceIds: []*string{id},
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.TerminateInstances(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeAddresses(ids []*string) ([]*ec2.Address, fail.Error) {
	var request ec2.DescribeAddressesInput
	if len(ids) > 0 {
		for _, v := range ids {
			request.Filters = append(request.Filters, &ec2.Filter{
				Name:   aws.String("instance-id"),
				Values: []*string{v},
			})
		}
	}
	var resp *ec2.DescribeAddressesOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeAddresses(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.Address{}, xerr
	}
	return resp.Addresses, nil
}

func (s stack) rpcDescribeInstances(ids []*string) ([]*ec2.Instance, fail.Error) {
	var request ec2.DescribeInstancesInput
	if len(ids) > 0 {
		request.InstanceIds = ids
	}
	var resp *ec2.DescribeInstancesOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeInstances(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.Instance{}, xerr
	}

	var nbInstance int
	for _, v := range resp.Reservations {
		nbInstance += len(v.Instances)
	}
	out := make([]*ec2.Instance, 0, nbInstance)
	for _, v := range resp.Reservations {
		for _, i := range v.Instances {
			_ = ec2.InstanceState{}
			state, xerr := toHostState(i.State)
			if xerr != nil {
				logrus.Errorf("found instance '%s' with unmanaged state '%d', ignoring", aws.StringValue(i.InstanceId), aws.Int64Value(i.State.Code)&0xff)
				continue
			}
			if state != hoststate.Terminated {
				out = append(out, i)
			}
		}
	}
	return out, nil
}

func (s stack) rpcImportKeyPair(name *string, pubKey []byte) fail.Error {
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return xerr
	}

	request := ec2.ImportKeyPairInput{
		KeyName:           name,
		PublicKeyMaterial: pubKey,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.ImportKeyPair(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeKeyPairs(ids []*string) ([]*ec2.KeyPairInfo, fail.Error) {
	request := ec2.DescribeKeyPairsInput{}
	if len(ids) > 0 {
		request.KeyPairIds = ids
	}
	var resp *ec2.DescribeKeyPairsOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeKeyPairs(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.KeyPairInfo{}, xerr
	}
	return resp.KeyPairs, nil
}

func (s stack) rpcDescribeKeyPairByID(id *string) (*ec2.KeyPairInfo, fail.Error) {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return &ec2.KeyPairInfo{}, xerr
	}

	resp, xerr := s.rpcDescribeKeyPairs([]*string{id})
	if xerr != nil {
		return &ec2.KeyPairInfo{}, xerr
	}
	if len(resp) == 0 {
		return &ec2.KeyPairInfo{}, fail.NotFoundError("failed to find a KeyPair with ID %s", aws.StringValue(id))
	}
	if len(resp) > 1 {
		return &ec2.KeyPairInfo{}, fail.InconsistentError("found more than 1 KeyPair with ID %s", aws.StringValue(id))
	}
	return resp[0], nil
}

func (s stack) rpcDescribeKeyPairByName(name *string) (*ec2.KeyPairInfo, fail.Error) {
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return &ec2.KeyPairInfo{}, xerr
	}

	request := ec2.DescribeKeyPairsInput{
		KeyNames: []*string{name},
	}
	var resp *ec2.DescribeKeyPairsOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeKeyPairs(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &ec2.KeyPairInfo{}, xerr
	}
	if len(resp.KeyPairs) == 0 {
		return &ec2.KeyPairInfo{}, fail.NotFoundError("failed to find a KeyPair named '%s'", aws.StringValue(name))
	}
	if len(resp.KeyPairs) > 1 {
		return &ec2.KeyPairInfo{}, fail.InconsistentError("found more than 1 KeyPair named '%s'", aws.StringValue(name))
	}
	return resp.KeyPairs[0], nil
}

func (s stack) rpcDeleteKeyPair(id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	request := ec2.DeleteKeyPairInput{
		KeyName: id,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.DeleteKeyPair(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeAvailabilityZones(ids []*string) ([]*ec2.AvailabilityZone, fail.Error) {
	var request ec2.DescribeAvailabilityZonesInput
	if len(ids) > 0 {
		request.ZoneIds = ids
	}
	var resp *ec2.DescribeAvailabilityZonesOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeAvailabilityZones(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.AvailabilityZone{}, xerr
	}
	return resp.AvailabilityZones, nil
}

func (s stack) rpcDescribeRegions(names []*string) ([]*ec2.Region, fail.Error) {
	var request ec2.DescribeRegionsInput
	if len(names) > 0 {
		request.RegionNames = names
	}
	var resp *ec2.DescribeRegionsOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeRegions(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.Region{}, xerr
	}
	return resp.Regions, nil
}

func (s stack) rpcDescribeImages(ids []*string) ([]*ec2.Image, fail.Error) {
	var request ec2.DescribeImagesInput
	if len(ids) > 0 {
		request.ImageIds = ids
	} else {
		request.Filters = []*ec2.Filter{
			{
				Name:   aws.String("architecture"),
				Values: []*string{aws.String("x86_64")},
			},
			{
				Name:   aws.String("state"),
				Values: []*string{aws.String("available")},
			},
		}

		// Added filtering by owner-id
		request.Filters = append(request.Filters, createFilters()...)
	}
	var resp *ec2.DescribeImagesOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeImages(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.Image{}, xerr
	}
	return resp.Images, nil
}

func (s stack) rpcDescribeImageByID(id *string) (*ec2.Image, fail.Error) {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return &ec2.Image{}, xerr
	}

	resp, xerr := s.rpcDescribeImages([]*string{id})
	if xerr != nil {
		return &ec2.Image{}, xerr
	}
	if len(resp) == 0 {
		return &ec2.Image{}, fail.NotFoundError("failed to find an Image with ID %s", aws.StringValue(id))
	}
	if len(resp) > 1 {
		return &ec2.Image{}, fail.InconsistentError("found more than one Image with ID %s", aws.StringValue(id))
	}
	return resp[0], nil
}

func (s stack) rpcModifyInstanceSecurityGroups(id *string, sgIDs []*string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}
	if len(sgIDs) == 0 {
		return fail.InvalidParameterError("sgIDs", "cannot be empty slice")
	}

	request := ec2.ModifyInstanceAttributeInput{
		InstanceId: id,
		Groups:     sgIDs,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.ModifyInstanceAttribute(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcGetProducts(ids []*string) ([]aws.JSONValue, fail.Error) {
	var emptySlice []aws.JSONValue
	filters := make([]*pricing.Filter, 0, 2+len(ids))
	filters = append(filters, []*pricing.Filter{
		// {
		// 	Field: aws.String("ServiceCode"),
		// 	Type:  aws.String("TERM_MATCH"),
		// 	Value: aws.String("AmazonEC2"),
		// },
		{
			Field: aws.String("operatingSystem"),
			Type:  aws.String("TERM_MATCH"),
			Value: aws.String("Linux"),
		},
	}...)
	if len(ids) > 0 {
		for _, v := range ids {
			filters = append(filters, &pricing.Filter{
				Field: aws.String("instanceType"),
				Type:  aws.String("TERM_MATCH"),
				Value: v,
			})
		}
	}
	request := pricing.GetProductsInput{
		Filters: filters,
		// MaxResults:  aws.Int64(100),
		ServiceCode: aws.String("AmazonEC2"),
	}
	var resp *pricing.GetProductsOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.PricingService.GetProducts(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return emptySlice, xerr
	}

	if len(resp.PriceList) == 0 {
		if len(ids) > 0 {
			return emptySlice, fail.NotFoundError("failed to find products")
		}
		return emptySlice, nil
	}
	return resp.PriceList, nil
}

func (s stack) rpcGetProductByID(id *string) (aws.JSONValue, fail.Error) {
	nullValue := aws.JSONValue{}
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return nullValue, xerr
	}

	resp, xerr := s.rpcGetProducts([]*string{id})
	if xerr != nil {
		return nullValue, xerr
	}
	if len(resp) > 1 {
		return nullValue, fail.InconsistentError("found more than one product with ID %s", aws.StringValue(id))
	}
	return resp[0], nil
}

func (s stack) rpcDescribeInstanceTypes(ids []*string) ([]*ec2.InstanceTypeInfo, fail.Error) {
	var emptySlice []*ec2.InstanceTypeInfo
	request := ec2.DescribeInstanceTypesInput{}
	if len(ids) > 0 {
		request.InstanceTypes = ids
	} else {
		request.Filters = []*ec2.Filter{
			{ // keep only x86_64 processor architecture
				Name:   aws.String("processor-info.supported-architecture"),
				Values: []*string{aws.String("x86_64")},
			},
			{ // filter instances that are burstable, stable performance are preferred
				Name:   aws.String("burstable-performance-supported"),
				Values: []*string{aws.String("false")},
			},
		}
	}

	var out []*ec2.InstanceTypeInfo
	for {
		var resp *ec2.DescribeInstanceTypesOutput
		xerr := stacks.RetryableRemoteCall(
			func() (err error) {
				resp, err = s.EC2Service.DescribeInstanceTypes(&request)
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			return emptySlice, xerr
		}

		if len(resp.InstanceTypes) == 0 {
			if len(ids) > 0 {
				return emptySlice, fail.NotFoundError("failed to find instance types")
			}
			return emptySlice, nil
		}
		for _, v := range resp.InstanceTypes {
			it := strings.ToLower(aws.StringValue(v.InstanceType))
			// exclude special types like Inf* (optimized for inference) or Mac* (macOS) or f1.*
			if strings.HasPrefix(it, "inf1.") || strings.HasPrefix(it, "mac1.") || strings.HasPrefix(it, "f1.") {
				continue
			}
			out = append(out, v)
		}

		if resp.NextToken == nil {
			break
		}
		request.NextToken = resp.NextToken
	}
	return out, nil
}

func (s stack) rpcDescribeInstanceTypeByID(id *string) (*ec2.InstanceTypeInfo, fail.Error) {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return &ec2.InstanceTypeInfo{}, xerr
	}

	resp, xerr := s.rpcDescribeInstanceTypes([]*string{id})
	if xerr != nil {
		return &ec2.InstanceTypeInfo{}, xerr
	}
	if len(resp) > 1 {
		return &ec2.InstanceTypeInfo{}, fail.InconsistentError("found more than one instance type with ID %s", aws.StringValue(id))
	}
	return resp[0], nil
}

func (s stack) rpcDescribeSpotPriceHistory(zone, templateID *string) ([]*ec2.SpotPrice, fail.Error) {
	var emptySlice []*ec2.SpotPrice
	if xerr := validateAWSString(zone, "zone", true); xerr != nil {
		return emptySlice, xerr
	}
	if xerr := validateAWSString(templateID, "templateID", true); xerr != nil {
		return emptySlice, xerr
	}

	request := ec2.DescribeSpotPriceHistoryInput{
		AvailabilityZone:    zone,
		InstanceTypes:       []*string{templateID},
		ProductDescriptions: []*string{aws.String("Linux/UNIX")},
	}
	var resp *ec2.DescribeSpotPriceHistoryOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeSpotPriceHistory(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return emptySlice, xerr
	}
	if len(resp.SpotPriceHistory) == 0 {
		return emptySlice, nil
	}
	return resp.SpotPriceHistory, nil
}

func (s stack) rpcRequestSpotInstance(price, zone, subnetID *string, publicIP *bool, templateID, imageID, keypairName *string, userdata []byte) (*ec2.SpotInstanceRequest, fail.Error) {
	nullInstance := &ec2.SpotInstanceRequest{}
	if xerr := validateAWSString(zone, "zone", true); xerr != nil {
		return nullInstance, xerr
	}
	if xerr := validateAWSString(templateID, "templateID", true); xerr != nil {
		return nullInstance, xerr
	}
	if xerr := validateAWSString(imageID, "imageID", true); xerr != nil {
		return nullInstance, xerr
	}
	if xerr := validateAWSString(keypairName, "keypairName", true); xerr != nil {
		return nullInstance, xerr
	}
	if publicIP == nil {
		publicIP = aws.Bool(false)
	}

	request := ec2.RequestSpotInstancesInput{
		InstanceCount: aws.Int64(1),
		LaunchSpecification: &ec2.RequestSpotLaunchSpecification{
			ImageId:      imageID,
			InstanceType: templateID,
			KeyName:      keypairName,
			NetworkInterfaces: []*ec2.InstanceNetworkInterfaceSpecification{
				{
					DeviceIndex:              aws.Int64(int64(0)),
					SubnetId:                 subnetID,
					AssociatePublicIpAddress: publicIP,
				},
			},
			Placement: &ec2.SpotPlacement{
				AvailabilityZone: zone,
			},
			UserData: aws.String(base64.StdEncoding.EncodeToString(userdata)),
		},
		SpotPrice: price, // FIXME: Round up
		Type:      aws.String("one-time"),
	}
	var resp *ec2.RequestSpotInstancesOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.RequestSpotInstances(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nullInstance, xerr
	}
	if len(resp.SpotInstanceRequests) == 0 {
		return nullInstance, nil
	}
	return resp.SpotInstanceRequests[0], nil
}

func (s stack) rpcRunInstance(name, zone, subnetID, templateID, imageID, keypairName *string, publicIP *bool, userdata []byte) (*ec2.Instance, fail.Error) {
	nullInstance := &ec2.Instance{}
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return nullInstance, xerr
	}
	if xerr := validateAWSString(zone, "zone", true); xerr != nil {
		return nullInstance, xerr
	}
	if xerr := validateAWSString(subnetID, "subnetID", true); xerr != nil {
		return nullInstance, xerr
	}
	if xerr := validateAWSString(templateID, "templateID", true); xerr != nil {
		return nullInstance, xerr
	}
	if xerr := validateAWSString(imageID, "imageID", true); xerr != nil {
		return nullInstance, xerr
	}
	if xerr := validateAWSString(keypairName, "keypairName", true); xerr != nil {
		return nullInstance, xerr
	}
	if publicIP == nil {
		publicIP = aws.Bool(false)
	}

	request := ec2.RunInstancesInput{
		ImageId:      imageID,
		InstanceType: templateID,
		KeyName:      keypairName,
		MaxCount:     aws.Int64(1),
		MinCount:     aws.Int64(1),
		Placement: &ec2.Placement{
			AvailabilityZone: zone,
		},
		NetworkInterfaces: []*ec2.InstanceNetworkInterfaceSpecification{
			{
				DeviceIndex:              aws.Int64(int64(0)),
				SubnetId:                 subnetID,
				AssociatePublicIpAddress: publicIP,
			},
		},
		TagSpecifications: []*ec2.TagSpecification{
			{
				ResourceType: aws.String("instance"),
				Tags: []*ec2.Tag{
					{
						Key:   awsTagNameLabel,
						Value: name,
					},
				},
			},
		},
		UserData: aws.String(base64.StdEncoding.EncodeToString(userdata)),
	}
	var resp *ec2.Reservation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.RunInstances(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nullInstance, xerr
	}
	if len(resp.Instances) == 0 {
		return nullInstance, nil
	}

	defer func() {
		if xerr != nil {
			ids := make([]*string, 0, len(resp.Instances))
			for _, v := range resp.Instances {
				ids = append(ids, v.InstanceId)
			}
			if _, derr := s.rpcTerminateInstances(ids); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete instances"))
			}
		}
	}()

	if len(resp.Instances) > 1 {
		return nullInstance, fail.InconsistentError("created more than one instance")
	}

	instance := resp.Instances[0]
	xerr = stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.ModifyInstanceAttribute(&ec2.ModifyInstanceAttributeInput{
				InstanceId:      instance.InstanceId,
				SourceDestCheck: &ec2.AttributeBooleanValue{Value: aws.Bool(false)},
			})
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	return instance, nil
}

func (s stack) rpcTerminateInstances(ids []*string) ([]*ec2.InstanceStateChange, fail.Error) {
	var emptySlice []*ec2.InstanceStateChange
	if len(ids) == 0 {
		return emptySlice, fail.InvalidParameterError("ids", "cannot be empty slice")
	}

	request := ec2.TerminateInstancesInput{
		InstanceIds: ids,
	}
	var resp *ec2.TerminateInstancesOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.TerminateInstances(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return emptySlice, xerr
	}
	if len(resp.TerminatingInstances) == 0 {
		if len(ids) > 0 {
			return emptySlice, fail.NotFoundError("failed to find instances to terminate")
		}
		return emptySlice, nil
	}
	return resp.TerminatingInstances, nil
}

func (s stack) rpcStartInstances(ids []*string) fail.Error {
	if len(ids) == 0 {
		return fail.InvalidParameterError("ids", "cannot be empty slice")
	}

	request := ec2.StartInstancesInput{
		InstanceIds: ids,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.StartInstances(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcRebootInstances(ids []*string) fail.Error {
	if len(ids) == 0 {
		return fail.InvalidParameterError("ids", "cannot be empty slice")
	}

	request := ec2.RebootInstancesInput{
		InstanceIds: ids,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.RebootInstances(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeSubnets(ids []*string) ([]*ec2.Subnet, fail.Error) {
	var emptySlice []*ec2.Subnet
	if len(ids) == 0 {
		return emptySlice, fail.InvalidParameterError("ids", "cannot be empty slice")
	}

	// FIXME: use NextToken to get all subnets (only the 100 first are currently recovered)
	request := ec2.DescribeSubnetsInput{
		SubnetIds: ids,
	}
	out := make([]*ec2.Subnet, 0, 100)
	for {
		var resp *ec2.DescribeSubnetsOutput
		xerr := stacks.RetryableRemoteCall(
			func() (err error) {
				resp, err = s.EC2Service.DescribeSubnets(&request)
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			return emptySlice, xerr
		}
		if len(resp.Subnets) == 0 {
			break
		}

		out = append(out, resp.Subnets...)
		if resp.NextToken == nil {
			break
		}

		request.NextToken = resp.NextToken
	}
	if len(out) == 0 {
		if len(ids) > 0 {
			return emptySlice, fail.NotFoundError("failed to find Subnets")
		}
	}

	return out, nil
}

func (s stack) rpcStopInstances(ids []*string, force *bool) fail.Error {
	if len(ids) == 0 {
		return fail.InvalidParameterError("ids", "cannot be empty slice")
	}
	if force == nil {
		force = aws.Bool(false)
	}

	request := ec2.StopInstancesInput{
		Force:       force,
		InstanceIds: ids,
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.StopInstances(&request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeNetworkInterfacesOfVM(id *string) ([]*ec2.NetworkInterface, fail.Error) {
	var emptySlice []*ec2.NetworkInterface
	request := ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("attachment.instance-id"),
				Values: []*string{id},
			},
		},
	}
	var resp *ec2.DescribeNetworkInterfacesOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeNetworkInterfaces(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return emptySlice, xerr
	}
	if len(resp.NetworkInterfaces) == 0 {
		return emptySlice, nil
	}
	return resp.NetworkInterfaces, nil
}

func (s stack) rpcModifySecurityGroupsOfNetworkInterface(id *string, sgs []*string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}
	request := ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: id,
		Groups:             sgs,
	}
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			_, err = s.EC2Service.ModifyNetworkInterfaceAttribute(&request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}
	return nil
}
