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
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
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

func (s stack) rpcCreateInternetGateway(ctx context.Context) (*ec2.InternetGateway, fail.Error) {
	var gw *ec2.CreateInternetGatewayOutput
	xerr := stacks.RetryableRemoteCall(ctx,
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

func (s stack) rpcCreateRoute(ctx context.Context, internetGatewayID, routeTableID, cidr *string) fail.Error {
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
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.CreateRoute(&createRouteInput)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcAttachInternetGateway(ctx context.Context, vpcID, internetGatewayID *string) fail.Error {
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
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.AttachInternetGateway(&attachInternetGatewayInput)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeVpcs(ctx context.Context, ids []*string) ([]*ec2.Vpc, fail.Error) {
	var req ec2.DescribeVpcsInput
	if len(ids) > 0 {
		req.VpcIds = ids
	}
	var resp *ec2.DescribeVpcsOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeVpcs(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.Vpc{}, xerr
	}
	return resp.Vpcs, nil
}

func (s stack) rpcDescribeVpcByID(ctx context.Context, id *string) (*ec2.Vpc, fail.Error) {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return &ec2.Vpc{}, xerr
	}

	resp, xerr := s.rpcDescribeVpcs(ctx, []*string{id})
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

func (s stack) rpcDescribeVpcByName(ctx context.Context, name *string) (*ec2.Vpc, fail.Error) {
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return &ec2.Vpc{}, xerr
	}

	req := ec2.DescribeVpcsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:" + tagNameLabel),
				Values: []*string{name},
			},
		},
	}
	var resp *ec2.DescribeVpcsOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeVpcs(&req)
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

func (s stack) rpcCreateVpc(ctx context.Context, name, cidr *string) (_ *ec2.Vpc, ferr fail.Error) {
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return &ec2.Vpc{}, xerr
	}
	if xerr := validateAWSString(cidr, "cidr", true); xerr != nil {
		return &ec2.Vpc{}, xerr
	}

	req := ec2.CreateVpcInput{
		CidrBlock: cidr,
	}
	var resp *ec2.CreateVpcOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.CreateVpc(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &ec2.Vpc{}, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := s.rpcDeleteVpc(context.Background(), resp.Vpc.VpcId); derr != nil {
				_ = ferr.AddConsequence(
					fail.Wrap(
						derr, "cleaning up on failure, failed to delete Network/VPC %s",
						aws.StringValue(resp.Vpc.VpcId),
					),
				)
			}
		}
	}()

	// resource tagging
	tags := []*ec2.Tag{
		{
			Key:   awsTagNameLabel,
			Value: name,
		},
		{
			Key:   aws.String("ManagedBy"),
			Value: aws.String("safescale"),
		},
		{
			Key:   aws.String("DeclaredInBucket"),
			Value: aws.String(s.Config.MetadataBucketName),
		},
		{
			Key:   aws.String("CreationDate"),
			Value: aws.String(time.Now().Format(time.RFC3339)),
		},
	}
	xerr = s.rpcCreateTags(ctx, []*string{resp.Vpc.VpcId}, tags)
	if xerr != nil {
		return &ec2.Vpc{}, xerr
	}

	return resp.Vpc, nil
}

func (s stack) rpcCreateTags(ctx context.Context, resources []*string, tags []*ec2.Tag) fail.Error {
	if len(resources) == 0 {
		return fail.InvalidParameterError("resources", "cannot be an empty slice")
	}
	if len(tags) == 0 {
		return nil
	}

	req := ec2.CreateTagsInput{
		Resources: resources,
		Tags:      tags,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.CreateTags(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteTags(ctx context.Context, resources []*string, tags []*ec2.Tag) fail.Error {
	if len(resources) == 0 {
		return fail.InvalidParameterError("resources", "cannot be an empty slice")
	}
	if len(tags) == 0 {
		return nil
	}

	req := ec2.DeleteTagsInput{
		Resources: resources,
		Tags:      tags,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.DeleteTags(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteVpc(ctx context.Context, id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	req := ec2.DeleteVpcInput{
		VpcId: id,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.DeleteVpc(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDetachInternetGateway(ctx context.Context, vpcID, internetGatewayID *string) fail.Error {
	if xerr := validateAWSString(vpcID, "vpcID", true); xerr != nil {
		return xerr
	}
	if xerr := validateAWSString(internetGatewayID, "internetGatewayID", true); xerr != nil {
		return xerr
	}

	req := ec2.DetachInternetGatewayInput{
		InternetGatewayId: internetGatewayID,
		VpcId:             vpcID,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.DetachInternetGateway(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteRoute(ctx context.Context, routeTableID, cidr *string) fail.Error {
	if xerr := validateAWSString(routeTableID, "routeTableID", true); xerr != nil {
		return xerr
	}
	if xerr := validateAWSString(cidr, "cidr", true); xerr != nil {
		return xerr
	}

	req := ec2.DeleteRouteInput{
		DestinationCidrBlock: cidr,
		RouteTableId:         routeTableID,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.DeleteRoute(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteRouteTable(ctx context.Context, id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	deleteRouteTable := ec2.DeleteRouteTableInput{
		RouteTableId: id,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.DeleteRouteTable(&deleteRouteTable)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteInternetGateway(ctx context.Context, id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	req := ec2.DeleteInternetGatewayInput{
		InternetGatewayId: id,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.DeleteInternetGateway(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeInternetGateways(ctx context.Context, vpcID *string, ids []*string) ([]*ec2.InternetGateway, fail.Error) {
	var filters []*ec2.Filter
	if vpcID != nil && aws.StringValue(vpcID) != "" {
		filters = append(
			filters, &ec2.Filter{
				Name:   aws.String("attachment.vpc-id"),
				Values: []*string{vpcID},
			},
		)
	}
	if len(ids) > 0 {
		filters = append(
			filters, &ec2.Filter{
				Name:   aws.String("internet-gateway-id"),
				Values: ids,
			},
		)
	}
	req := ec2.DescribeInternetGatewaysInput{
		Filters: filters,
	}
	var resp *ec2.DescribeInternetGatewaysOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeInternetGateways(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.InternetGateway{}, xerr
	}
	return resp.InternetGateways, nil
}

func (s stack) rpcDescribeSubnetByID(ctx context.Context, id *string) (*ec2.Subnet, fail.Error) {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return &ec2.Subnet{}, xerr
	}

	resp, xerr := s.rpcDescribeSubnets(ctx, []*string{id})
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

func (s stack) rpcCreateSubnet(ctx context.Context, name, vpcID, azID, cidr *string) (_ *ec2.Subnet, ferr fail.Error) {
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

	req := ec2.CreateSubnetInput{
		CidrBlock:        cidr,
		VpcId:            vpcID,
		AvailabilityZone: azID,
	}
	var resp *ec2.CreateSubnetOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.CreateSubnet(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &ec2.Subnet{}, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := s.rpcDeleteSubnet(context.Background(), resp.Subnet.SubnetId); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Subnet %s", aws.StringValue(resp.Subnet.SubnetId)))
			}
		}
	}()

	tags := []*ec2.Tag{
		{
			Key:   awsTagNameLabel,
			Value: name,
		},
		{
			Key:   aws.String("ManagedBy"),
			Value: aws.String("safescale"),
		},
		{
			Key:   aws.String("DeclaredInBucket"),
			Value: aws.String(s.Config.MetadataBucketName),
		},
		{
			Key:   aws.String("CreationDate"),
			Value: aws.String(time.Now().Format(time.RFC3339)),
		},
	}
	if xerr = s.rpcCreateTags(ctx, []*string{resp.Subnet.SubnetId}, tags); xerr != nil {
		return &ec2.Subnet{}, xerr
	}

	return resp.Subnet, nil
}

func (s stack) rpcAssociateRouteTable(ctx context.Context, subnetID, routeID *string) fail.Error {
	if xerr := validateAWSString(subnetID, "subnetID", true); xerr != nil {
		return xerr
	}
	if xerr := validateAWSString(routeID, "routeID", true); xerr != nil {
		return xerr
	}

	req := ec2.AssociateRouteTableInput{
		RouteTableId: routeID,
		SubnetId:     subnetID,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.AssociateRouteTable(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeRouteTables(ctx context.Context, key *string, values []*string) ([]*ec2.RouteTable, fail.Error) {
	var emptySlice []*ec2.RouteTable
	if xerr := validateAWSString(key, "key", true); xerr != nil {
		return emptySlice, xerr
	}
	if len(values) == 0 {
		return emptySlice, fail.InvalidParameterError("values", "cannot be empty slice")
	}

	req := ec2.DescribeRouteTablesInput{
		Filters: []*ec2.Filter{
			{
				Name:   key,
				Values: values,
			},
		},
	}
	var resp *ec2.DescribeRouteTablesOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeRouteTables(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return emptySlice, xerr
	}
	return resp.RouteTables, nil
}

func (s stack) rpcDisassociateRouteTable(ctx context.Context, id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	req := ec2.DisassociateRouteTableInput{
		AssociationId: id,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.DisassociateRouteTable(&req)
			return normalizeError(err)
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteSubnet(ctx context.Context, id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	req := ec2.DeleteSubnetInput{
		SubnetId: id,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.DeleteSubnet(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteSecurityGroup(ctx context.Context, id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	req := ec2.DeleteSecurityGroupInput{
		GroupId: id,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.DeleteSecurityGroup(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcCreateSecurityGroup(ctx context.Context, networkID, name, description *string) (*string, fail.Error) {
	if xerr := validateAWSString(networkID, "networkID", true); xerr != nil {
		return aws.String(""), xerr
	}
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return aws.String(""), xerr
	}
	if xerr := validateAWSString(description, "description", false); xerr != nil {
		return aws.String(""), xerr
	}

	req := ec2.CreateSecurityGroupInput{
		Description: description,
		GroupName:   name,
		VpcId:       networkID,
	}
	var resp *ec2.CreateSecurityGroupOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.CreateSecurityGroup(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return aws.String(""), xerr
	}
	return resp.GroupId, nil
}

func (s stack) rpcDescribeSecurityGroups(ctx context.Context, networkID *string, ids []*string) ([]*ec2.SecurityGroup, fail.Error) {
	var req ec2.DescribeSecurityGroupsInput
	if aws.StringValue(networkID) != "" {
		req.Filters = []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{networkID},
			},
		}
	}
	if len(ids) > 0 {
		req.GroupIds = ids
	}
	var resp *ec2.DescribeSecurityGroupsOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeSecurityGroups(&req)
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

func (s stack) rpcDescribeSecurityGroupByID(ctx context.Context, id *string) (*ec2.SecurityGroup, fail.Error) {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return &ec2.SecurityGroup{}, xerr
	}

	resp, xerr := s.rpcDescribeSecurityGroups(ctx, aws.String(""), []*string{id})
	if xerr != nil {
		return &ec2.SecurityGroup{}, xerr
	}
	if len(resp) == 0 {
		return &ec2.SecurityGroup{}, fail.NotFoundError(
			"failed to find a Security Group with ID %s", aws.StringValue(id),
		)
	}
	if len(resp) > 1 {
		return &ec2.SecurityGroup{}, fail.InconsistentError(
			"found more than one Security Group with ID %s", aws.StringValue(id),
		)
	}
	return resp[0], nil
}

func (s stack) rpcDescribeSecurityGroupByName(ctx context.Context, networkID, name *string) (*ec2.SecurityGroup, fail.Error) {
	if xerr := validateAWSString(networkID, "networkID", true); xerr != nil {
		return &ec2.SecurityGroup{}, xerr
	}
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return &ec2.SecurityGroup{}, xerr
	}

	req := ec2.DescribeSecurityGroupsInput{
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
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeSecurityGroups(&req)
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
		return &ec2.SecurityGroup{}, fail.NotFoundError(
			"failed to find a Security Group named '%s' in Network %s", aws.StringValue(name),
			aws.StringValue(networkID),
		)
	}
	if len(resp.SecurityGroups) > 1 {
		return &ec2.SecurityGroup{}, fail.InconsistentError(
			"found more than one Security Group named '%s' in Network %s", aws.StringValue(name),
			aws.StringValue(networkID),
		)
	}
	return resp.SecurityGroups[0], nil
}

func (s stack) rpcRevokeSecurityGroupIngress(ctx context.Context, id *string, ingress []*ec2.IpPermission) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}
	if len(ingress) == 0 {
		return fail.InvalidParameterError("ingress", "cannot be empty slice")
	}

	req := ec2.RevokeSecurityGroupIngressInput{
		GroupId:       id,
		IpPermissions: ingress,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.RevokeSecurityGroupIngress(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcRevokeSecurityGroupEgress(ctx context.Context, id *string, egress []*ec2.IpPermission) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}
	if len(egress) == 0 {
		return fail.InvalidParameterError("egress", "cannot be empty slice")
	}

	req := ec2.RevokeSecurityGroupEgressInput{
		GroupId:       id,
		IpPermissions: egress,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.RevokeSecurityGroupEgress(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcAuthorizeSecurityGroupIngress(ctx context.Context, id *string, ingress []*ec2.IpPermission) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}
	if len(ingress) == 0 {
		return fail.InvalidParameterError("ingress", "cannot be empty slice")
	}

	req := ec2.AuthorizeSecurityGroupIngressInput{
		GroupId:       id,
		IpPermissions: ingress,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.AuthorizeSecurityGroupIngress(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcAuthorizeSecurityGroupEgress(ctx context.Context, id *string, egress []*ec2.IpPermission) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}
	if len(egress) == 0 {
		return fail.InvalidParameterError("egress", "cannot be empty slice")
	}

	req := ec2.AuthorizeSecurityGroupEgressInput{
		GroupId:       id,
		IpPermissions: egress,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.AuthorizeSecurityGroupEgress(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcAllocateAddress(ctx context.Context, description string) (allocID *string, publicIP *string, ferr fail.Error) {
	req := ec2.AllocateAddressInput{}
	var resp *ec2.AllocateAddressOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.AllocateAddress(&req)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, nil, xerr
	}
	if resp == nil {
		return nil, nil, fail.InconsistentError("nil response received from Cloud Provider")
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := s.rpcReleaseAddress(context.Background(), resp.AllocationId)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to release Elastic IP"))
			}
		}
	}()

	tags := []*ec2.Tag{
		{
			Key:   aws.String("Name"),
			Value: aws.String(description),
		},
		{
			Key:   aws.String("ManagedBy"),
			Value: aws.String("safescale"),
		},
		{
			Key:   aws.String("DeclaredInBucket"),
			Value: aws.String(s.Config.MetadataBucketName),
		},
		{
			Key:   aws.String("CreationDate"),
			Value: aws.String(time.Now().Format(time.RFC3339)),
		},
	}
	xerr = s.rpcCreateTags(ctx, []*string{resp.AllocationId}, tags)
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to name Elastic IP")
	}

	return resp.AllocationId, resp.PublicIp, nil
}

func (s stack) rpcReleaseAddress(ctx context.Context, id *string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	req := ec2.ReleaseAddressInput{
		AllocationId: id,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.ReleaseAddress(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcAssociateAddress(ctx context.Context, nicID, addressID *string) (*string, fail.Error) { // nolint
	if xerr := validateAWSString(nicID, "nicID", true); xerr != nil {
		return nil, xerr
	}
	if xerr := validateAWSString(addressID, "addressIDÒ", true); xerr != nil {
		return nil, xerr
	}

	req := ec2.AssociateAddressInput{
		AllocationId:       addressID,
		NetworkInterfaceId: nicID,
	}
	var resp *ec2.AssociateAddressOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.AssociateAddress(&req)
			return err
		}, normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	if resp == nil || resp.AssociationId == nil || aws.StringValue(resp.AssociationId) == "" {
		return nil, fail.InconsistentError("invalid empty response from Cloud Provider")
	}
	return resp.AssociationId, nil
}

func (s stack) rpcDisassociateAddress(ctx context.Context, id *string) fail.Error { // nolint
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	req := ec2.DisassociateAddressInput{
		AssociationId: id,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.DisassociateAddress(&req)
			return err
		}, normalizeError,
	)
}

func (s stack) rpcDescribeAddressByIP(ctx context.Context, ip *string) (*ec2.Address, fail.Error) {
	if xerr := validateAWSString(ip, "ip", true); xerr != nil {
		return nil, xerr
	}

	req := ec2.DescribeAddressesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("public-ip"),
				Values: []*string{ip},
			},
		},
	}
	var resp *ec2.DescribeAddressesOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeAddresses(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	if len(resp.Addresses) == 0 {
		return nil, fail.NotFoundError("failed to find Elastic IP '%s'", aws.StringValue(ip))
	}
	if len(resp.Addresses) > 1 {
		return nil, fail.InconsistentError("more than one Elastic IP '%s' returned by the Cloud Provider", aws.StringValue(ip))
	}
	return resp.Addresses[0], nil
}

func (s stack) rpcDescribeInstanceByID(ctx context.Context, id *string) (*ec2.Instance, fail.Error) {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return &ec2.Instance{}, xerr
	}

	resp, xerr := s.rpcDescribeInstances(ctx, []*string{id})
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

func (s stack) rpcDescribeInstanceByName(ctx context.Context, name *string) (*ec2.Instance, fail.Error) {
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return &ec2.Instance{}, xerr
	}

	req := ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:" + tagNameLabel),
				Values: []*string{name},
			},
		},
	}
	var resp *ec2.DescribeInstancesOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeInstances(&req)
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
				logrus.WithContext(ctx).Errorf(
					"found instance '%s' with unmanaged state '%d', ignoring", aws.StringValue(i.InstanceId),
					aws.Int64Value(i.State.Code)&0xff,
				)
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

func (s stack) rpcDescribeAddresses(ctx context.Context, ids []*string) ([]*ec2.Address, fail.Error) {
	var req ec2.DescribeAddressesInput
	if len(ids) > 0 {
		for _, v := range ids {
			req.Filters = append(
				req.Filters, &ec2.Filter{
					Name:   aws.String("instance-id"),
					Values: []*string{v},
				},
			)
		}
	}
	var resp *ec2.DescribeAddressesOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeAddresses(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.Address{}, xerr
	}
	return resp.Addresses, nil
}

func (s stack) rpcDescribeInstances(ctx context.Context, ids []*string) ([]*ec2.Instance, fail.Error) {
	var req ec2.DescribeInstancesInput
	if len(ids) > 0 {
		req.InstanceIds = ids
	}
	var resp *ec2.DescribeInstancesOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeInstances(&req)
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
				logrus.WithContext(ctx).Errorf("found instance '%s' with unmanaged state '%d', ignoring", aws.StringValue(i.InstanceId),
					aws.Int64Value(i.State.Code)&0xff)
				continue
			}
			if state != hoststate.Terminated {
				out = append(out, i)
			}
		}
	}
	return out, nil
}

func (s stack) rpcImportKeyPair(ctx context.Context, name *string, pubKey []byte) fail.Error {
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return xerr
	}

	req := ec2.ImportKeyPairInput{
		KeyName:           name,
		PublicKeyMaterial: pubKey,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.ImportKeyPair(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeKeyPairs(ctx context.Context, ids []*string) ([]*ec2.KeyPairInfo, fail.Error) {
	req := ec2.DescribeKeyPairsInput{}
	if len(ids) > 0 {
		req.KeyPairIds = ids
	}
	var resp *ec2.DescribeKeyPairsOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeKeyPairs(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.KeyPairInfo{}, xerr
	}
	return resp.KeyPairs, nil
}

func (s stack) rpcDescribeKeyPairByID(ctx context.Context, id *string) (*ec2.KeyPairInfo, fail.Error) {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return &ec2.KeyPairInfo{}, xerr
	}

	resp, xerr := s.rpcDescribeKeyPairs(ctx, []*string{id})
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

func (s stack) rpcDescribeKeyPairByName(ctx context.Context, name *string) (*ec2.KeyPairInfo, fail.Error) {
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return &ec2.KeyPairInfo{}, xerr
	}

	req := ec2.DescribeKeyPairsInput{
		KeyNames: []*string{name},
	}
	var resp *ec2.DescribeKeyPairsOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeKeyPairs(&req)
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

func (s stack) rpcDeleteKeyPair(ctx context.Context, name *string) fail.Error {
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return xerr
	}

	req := ec2.DeleteKeyPairInput{
		KeyName: name,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.DeleteKeyPair(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeAvailabilityZones(ctx context.Context, ids []*string) ([]*ec2.AvailabilityZone, fail.Error) {
	var req ec2.DescribeAvailabilityZonesInput
	if len(ids) > 0 {
		req.ZoneIds = ids
	}
	var resp *ec2.DescribeAvailabilityZonesOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeAvailabilityZones(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.AvailabilityZone{}, xerr
	}
	return resp.AvailabilityZones, nil
}

func (s stack) rpcDescribeRegions(ctx context.Context, names []*string) ([]*ec2.Region, fail.Error) {
	var req ec2.DescribeRegionsInput
	if len(names) > 0 {
		req.RegionNames = names
	}
	var resp *ec2.DescribeRegionsOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeRegions(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.Region{}, xerr
	}
	return resp.Regions, nil
}

func rpcDescribeImagesByOwner(ctx context.Context, s stack, ids []*string, filters []*ec2.Filter) ([]*ec2.Image, fail.Error) {
	var req ec2.DescribeImagesInput
	if len(ids) > 0 {
		req.ImageIds = ids
	}
	req.Filters = filters

	countDecodingProblems := 0

	var resp *ec2.DescribeImagesOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeImages(&req)
			if err != nil {
				if awe, ok := err.(awserr.Error); ok {
					if awe.Code() == request.ErrCodeSerialization {
						countDecodingProblems++
						if countDecodingProblems > 1 {
							return retry.StopRetryError(err, "too many decoding errors")
						}
					}
				}

				return err
			}

			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.Image{}, xerr
	}

	return resp.Images, nil
}

func (s stack) rpcDescribeImages(ctx context.Context, ids []*string) ([]*ec2.Image, fail.Error) {
	var req ec2.DescribeImagesInput
	if len(ids) > 0 {
		req.ImageIds = ids
	}

	req.Filters = []*ec2.Filter{}
	// Default filters
	req.Filters = append(req.Filters, createFilters()...)
	// Added filtering by owner-id
	req.Filters = append(req.Filters, filterOwners(s)...)

	countDecodingProblems := 0
	var decodingProblems bool

	var resp *ec2.DescribeImagesOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeImages(&req)
			if err != nil {
				if awe, ok := err.(awserr.Error); ok {
					if awe.Code() == "SerializationError" {
						decodingProblems = true
						countDecodingProblems++
						if countDecodingProblems > 1 {
							return retry.StopRetryError(err, "too many decoding errors")
						}
					}
				}

				return err
			}

			// no error, forget about decoding problems
			decodingProblems = false

			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		if !decodingProblems {
			return []*ec2.Image{}, xerr
		}
	}

	// either we had decoding problems or everything is ok
	if decodingProblems {
		for _, owner := range filterOwners(s) {
			var filters []*ec2.Filter
			filters = append(filters, createFilters()...)
			filters = append(filters, owner)
			newImages, err := rpcDescribeImagesByOwner(ctx, s, ids, filters)
			if err != nil {
				continue
			}

			if len(newImages) > 0 {
				resp.Images = append(resp.Images, newImages...)
			}
		}

		return resp.Images, nil
	}

	// everything ok
	return resp.Images, nil
}

func (s stack) rpcDescribeImageByID(ctx context.Context, id *string) (*ec2.Image, fail.Error) {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return &ec2.Image{}, xerr
	}

	resp, xerr := s.rpcDescribeImages(ctx, []*string{id})
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

// FIXME: typeOfferings s.EC2Service.DescribeInstanceTypeOfferings
func (s stack) rpcDescribeInstanceTypeOfferings(ctx context.Context, az *string) (*ec2.DescribeInstanceTypeOfferingsOutput, fail.Error) {
	filters := []*ec2.Filter{
		{
			Name:   aws.String("location"),
			Values: []*string{az},
		},
	}
	req := ec2.DescribeInstanceTypeOfferingsInput{
		Filters:      filters,
		LocationType: aws.String(ec2.LocationTypeAvailabilityZone),
	}

	var offerings *ec2.DescribeInstanceTypeOfferingsOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			var err error
			offerings, err = s.EC2Service.DescribeInstanceTypeOfferings(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	return offerings, nil
}

func (s stack) rpcModifyInstanceSecurityGroups(ctx context.Context, id *string, sgIDs []*string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}
	if len(sgIDs) == 0 {
		return fail.InvalidParameterError("sgIDs", "cannot be empty slice")
	}

	req := ec2.ModifyInstanceAttributeInput{
		InstanceId: id,
		Groups:     sgIDs,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.ModifyInstanceAttribute(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcGetProducts(ctx context.Context, ids []*string) ([]aws.JSONValue, fail.Error) {
	filters := make([]*pricing.Filter, 0, 2+len(ids))
	filters = append(
		filters, []*pricing.Filter{
			{
				Field: aws.String("operatingSystem"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("Linux"),
			},
		}...,
	)
	if len(ids) > 0 {
		for _, v := range ids {
			filters = append(
				filters, &pricing.Filter{
					Field: aws.String("instanceType"),
					Type:  aws.String("TERM_MATCH"),
					Value: v,
				},
			)
		}
	}
	req := pricing.GetProductsInput{
		Filters: filters,
		// MaxResults:  aws.Int64(100),
		ServiceCode: aws.String("AmazonEC2"),
	}
	var resp *pricing.GetProductsOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.PricingService.GetProducts(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	if len(resp.PriceList) == 0 {
		if len(ids) > 0 {
			return nil, fail.NotFoundError("failed to find products")
		}
		return nil, nil
	}

	return resp.PriceList, nil
}

func (s stack) rpcGetProductByID(ctx context.Context, id *string) (aws.JSONValue, fail.Error) {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return nil, xerr
	}

	resp, xerr := s.rpcGetProducts(ctx, []*string{id})
	if xerr != nil {
		return nil, xerr
	}
	if len(resp) > 1 {
		return nil, fail.InconsistentError("found more than one product with ID %s", aws.StringValue(id))
	}
	return resp[0], nil
}

func (s stack) rpcDescribeInstanceTypes(ctx context.Context, ids []*string) ([]*ec2.InstanceTypeInfo, fail.Error) {
	var emptySlice []*ec2.InstanceTypeInfo
	req := ec2.DescribeInstanceTypesInput{}
	if len(ids) > 0 {
		req.InstanceTypes = ids
	} else {
		req.Filters = []*ec2.Filter{
			{
				// keep only x86_64 processor architecture
				Name:   aws.String("processor-info.supported-architecture"),
				Values: []*string{aws.String("x86_64")},
			},
			{
				// filter instances that are burstable, stable performance are preferred
				Name:   aws.String("burstable-performance-supported"),
				Values: []*string{aws.String("false")},
			},
		}
	}

	var out []*ec2.InstanceTypeInfo
	for {
		var resp *ec2.DescribeInstanceTypesOutput
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				resp, err = s.EC2Service.DescribeInstanceTypes(&req)
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
		req.NextToken = resp.NextToken
	}
	return out, nil
}

func (s stack) rpcDescribeInstanceTypeByID(ctx context.Context, id *string) (*ec2.InstanceTypeInfo, fail.Error) {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return &ec2.InstanceTypeInfo{}, xerr
	}

	resp, xerr := s.rpcDescribeInstanceTypes(ctx, []*string{id})
	if xerr != nil {
		return &ec2.InstanceTypeInfo{}, xerr
	}
	if len(resp) > 1 {
		return &ec2.InstanceTypeInfo{}, fail.InconsistentError(
			"found more than one instance type with ID %s", aws.StringValue(id),
		)
	}
	return resp[0], nil
}

func (s stack) rpcDescribeSpotPriceHistory(ctx context.Context, zone, templateID *string) ([]*ec2.SpotPrice, fail.Error) {
	var emptySlice []*ec2.SpotPrice
	if xerr := validateAWSString(zone, "zone", true); xerr != nil {
		return emptySlice, xerr
	}
	if xerr := validateAWSString(templateID, "templateID", true); xerr != nil {
		return emptySlice, xerr
	}

	req := ec2.DescribeSpotPriceHistoryInput{
		AvailabilityZone:    zone,
		InstanceTypes:       []*string{templateID},
		ProductDescriptions: []*string{aws.String("Linux/UNIX")},
	}
	var resp *ec2.DescribeSpotPriceHistoryOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeSpotPriceHistory(&req)
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

func (s stack) rpcRequestSpotInstance(ctx context.Context, price, zone, subnetID *string, publicIP *bool, templateID, imageID, keypairName *string, userdata []byte) (*ec2.SpotInstanceRequest, fail.Error) {
	if xerr := validateAWSString(zone, "zone", true); xerr != nil {
		return nil, xerr
	}
	if xerr := validateAWSString(templateID, "templateID", true); xerr != nil {
		return nil, xerr
	}
	if xerr := validateAWSString(imageID, "imageID", true); xerr != nil {
		return nil, xerr
	}
	if xerr := validateAWSString(keypairName, "keypairName", true); xerr != nil {
		return nil, xerr
	}
	if publicIP == nil {
		publicIP = aws.Bool(false)
	}

	req := ec2.RequestSpotInstancesInput{
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
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.RequestSpotInstances(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	if len(resp.SpotInstanceRequests) == 0 {
		return nil, fail.NotAvailableError("no spot instances available")
	}
	return resp.SpotInstanceRequests[0], nil
}

func (s stack) rpcCreateInstance(ctx context.Context, name, zone, subnetID, templateID, imageID *string, diskSize int, keypairName *string, publicIP *bool, userdata []byte) (_ *ec2.Instance, ferr fail.Error) {
	if xerr := validateAWSString(name, "name", true); xerr != nil {
		return nil, xerr
	}
	if xerr := validateAWSString(zone, "zone", true); xerr != nil {
		return nil, xerr
	}
	if xerr := validateAWSString(subnetID, "subnetID", true); xerr != nil {
		return nil, xerr
	}
	if xerr := validateAWSString(templateID, "templateID", true); xerr != nil {
		return nil, xerr
	}
	if xerr := validateAWSString(imageID, "imageID", true); xerr != nil {
		return nil, xerr
	}
	if xerr := validateAWSString(keypairName, "keypairName", true); xerr != nil {
		return nil, xerr
	}
	if publicIP == nil {
		publicIP = aws.Bool(false)
	}

	// Create Network Interface
	description := aws.StringValue(name) + " network interface"
	nic, xerr := s.rpcCreateNetworkInterface(ctx, subnetID, description)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create network interface for instance '%s'", aws.StringValue(name))
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := s.rpcDeleteNetworkInterface(context.Background(), nic.NetworkInterfaceId)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete network interface"))
			}
		}
	}()

	// If PublicIP is requested, satisfy the req
	if aws.BoolValue(publicIP) {
		// Allocate Elastic IP
		description := fmt.Sprintf(
			"elasticip--%s--%s", aws.StringValue(nic.NetworkInterfaceId), aws.StringValue(name),
		) // Make each description unique
		addrAllocID, _, xerr := s.rpcAllocateAddress(ctx, description)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to allocate Elastic IP")
		}

		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil {
				derr := s.rpcReleaseAddress(context.Background(), addrAllocID)
				if derr != nil {
					_ = ferr.AddConsequence(
						fail.Wrap(
							derr, "cleaning up on failure, failed to release Elastic IP %s", addrAllocID,
						),
					)
				}
			}
		}()

		// Attach the Elastic IP to the NetworkInterface
		attachID, xerr := s.rpcAssociateAddress(ctx, nic.NetworkInterfaceId, addrAllocID)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to attach Elastic IP to network interface")
		}

		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil {
				derr := s.rpcDisassociateAddress(context.Background(), attachID)
				if derr != nil {
					_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to detach Elastic IP from network interface"))
				}
			}
		}()
	}

	// Request now the creation and start of new instance with the previously created interface
	req := ec2.RunInstancesInput{
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
				NetworkInterfaceId:  nic.NetworkInterfaceId,
				DeviceIndex:         aws.Int64(int64(0)),
				DeleteOnTermination: aws.Bool(false),
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
					{
						Key:   aws.String("ManagedBy"),
						Value: aws.String("safescale"),
					},
					{
						Key:   aws.String("DeclaredInBucket"),
						Value: aws.String(s.Config.MetadataBucketName),
					},
					{
						Key:   aws.String("Image"),
						Value: imageID,
					},
					{
						Key:   aws.String("Template"),
						Value: templateID,
					},
					{
						Key:   aws.String("CreationDate"),
						Value: aws.String(time.Now().Format(time.RFC3339)),
					},
				},
			},
		},
		UserData: aws.String(base64.StdEncoding.EncodeToString(userdata)),
	}

	if diskSize != 0 {
		req.BlockDeviceMappings = []*ec2.BlockDeviceMapping{
			{
				DeviceName: aws.String("/dev/sda1"),
				Ebs: &ec2.EbsBlockDevice{
					VolumeSize: aws.Int64(int64(diskSize)),
				},
			}}
	}

	var resp *ec2.Reservation
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.RunInstances(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	if len(resp.Instances) == 0 {
		return nil, fail.InconsistentError("invalid empty response from Cloud Provider")
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			for _, v := range resp.Instances {
				derr := s.rpcTerminateInstance(context.Background(), v)
				if derr != nil {
					_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete instance %s", v.InstanceId))
				}
			}
		}
	}()

	if len(resp.Instances) > 1 {
		return nil, fail.InconsistentError("more than one instance has been created by Cloud Provider")
	}

	instance := resp.Instances[0]
	xerr = stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.ModifyInstanceAttribute(
				&ec2.ModifyInstanceAttributeInput{
					InstanceId:      instance.InstanceId,
					SourceDestCheck: &ec2.AttributeBooleanValue{Value: aws.Bool(false)},
				},
			)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	return instance, nil
}

func (s stack) rpcTerminateInstance(ctx context.Context, instance *ec2.Instance) fail.Error {
	if instance == nil {
		return fail.InvalidParameterCannotBeNilError("instance")
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	var nics []*string
	for _, v := range instance.NetworkInterfaces {
		// Detach and release Elastic IP from the network interface if needed
		if v.Association != nil {
			if ip := aws.StringValue(v.Association.PublicIp); ip != "" {
				address, xerr := s.rpcDescribeAddressByIP(ctx, v.Association.PublicIp)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// continue
						debug.IgnoreError(xerr)
					default:
						return fail.Wrap(xerr, "failed to req information about Elastic IP '%s'", ip)
					}
				} else {
					xerr = s.rpcDisassociateAddress(ctx, address.AssociationId)
					if xerr != nil {
						return fail.Wrap(xerr, "failed to disassociate Elastic IP '%s' from interface", ip)
					}

					xerr = s.rpcReleaseAddress(ctx, address.AllocationId)
					if xerr != nil {
						return fail.Wrap(xerr, "failed to release Elastic IP '%s'", ip)
					}
				}
			}
		}

		// inventory network interface to delete eventually
		nics = append(nics, v.NetworkInterfaceId)
	}

	// now request to delete instance
	req := ec2.TerminateInstancesInput{
		InstanceIds: []*string{instance.InstanceId},
	}
	var resp *ec2.TerminateInstancesOutput
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.TerminateInstances(&req)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}
	if len(resp.TerminatingInstances) == 0 {
		return fail.NotFoundError(
			"failed to find instance %s wanted to terminate", aws.StringValue(instance.InstanceId),
		)
	}

	// Wait for effective removal of host (status terminated)
	retryErr := retry.WhileUnsuccessful(
		func() error {
			resp, innerXErr := s.rpcDescribeInstances(ctx, []*string{instance.InstanceId})
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// if Host is not found, consider operation as successful
					return nil
				default:
					return innerXErr
				}
			}
			if len(resp) == 0 {
				return nil
			}
			if len(resp) > 1 {
				return retry.StopRetryError(fail.InconsistentError("more than one instance has been stopped"))
			}

			state, xerr := toHostState(resp[0].State)
			if xerr != nil {
				return fail.NewErrorWithCause(xerr, "failed to convert instance state")
			}

			if state != hoststate.Terminated {
				return fail.NewError("not in terminated state (current state: %s)", state.String())
			}

			return nil
		},
		timings.NormalDelay(),
		timings.HostCleanupTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return fail.Wrap(
				fail.Cause(retryErr), "timeout waiting to get host %s information after %v", instance.InstanceId, timings.HostCleanupTimeout(),
			)
		default:
			return retryErr
		}
	}

	for _, v := range nics {
		// Delete network interface
		xerr = s.rpcDeleteNetworkInterface(ctx, v)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound, *fail.ErrInvalidRequest:
				debug.IgnoreError(xerr)
			default:
				return fail.Wrap(xerr, "failed to delete network interface %s from instance", aws.StringValue(v))
			}
		}
	}

	return nil
}

func (s stack) rpcStartInstances(ctx context.Context, ids []*string) fail.Error {
	if len(ids) == 0 {
		return fail.InvalidParameterError("ids", "cannot be empty slice")
	}

	req := ec2.StartInstancesInput{
		InstanceIds: ids,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.StartInstances(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcRebootInstances(ctx context.Context, ids []*string) fail.Error {
	if len(ids) == 0 {
		return fail.InvalidParameterError("ids", "cannot be empty slice")
	}

	req := ec2.RebootInstancesInput{
		InstanceIds: ids,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.RebootInstances(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeSubnets(ctx context.Context, ids []*string) ([]*ec2.Subnet, fail.Error) {
	var emptySlice []*ec2.Subnet
	if len(ids) == 0 {
		return emptySlice, fail.InvalidParameterError("ids", "cannot be empty slice")
	}

	// FIXME: use NextToken to get all subnets (only the 100 first are currently recovered)
	req := ec2.DescribeSubnetsInput{
		SubnetIds: ids,
	}
	out := make([]*ec2.Subnet, 0, 100)
	for {
		var resp *ec2.DescribeSubnetsOutput
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				resp, err = s.EC2Service.DescribeSubnets(&req)
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

		req.NextToken = resp.NextToken
	}
	if len(out) == 0 {
		if len(ids) > 0 {
			return emptySlice, fail.NotFoundError("failed to find Subnets")
		}
	}

	return out, nil
}

func (s stack) rpcStopInstances(ctx context.Context, ids []*string, gracefully *bool) fail.Error {
	if len(ids) == 0 {
		return fail.InvalidParameterError("ids", "cannot be empty slice")
	}
	if gracefully == nil {
		gracefully = aws.Bool(true)
	}

	force := aws.Bool(!aws.BoolValue(gracefully))
	req := ec2.StopInstancesInput{
		Force:       force,
		InstanceIds: ids,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.StopInstances(&req)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeNetworkInterfacesOfInstance(ctx context.Context, id *string) ([]*ec2.NetworkInterface, fail.Error) {
	var emptySlice []*ec2.NetworkInterface
	req := ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("attachment.instance-id"),
				Values: []*string{id},
			},
		},
	}
	var resp *ec2.DescribeNetworkInterfacesOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeNetworkInterfaces(&req)
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

func (s stack) rpcModifySecurityGroupsOfNetworkInterface(ctx context.Context, id *string, sgs []*string) fail.Error {
	if xerr := validateAWSString(id, "id", true); xerr != nil {
		return xerr
	}

	req := ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: id,
		Groups:             sgs,
	}
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			_, err = s.EC2Service.ModifyNetworkInterfaceAttribute(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}
	return nil
}

func (s stack) rpcCreateNetworkInterface(ctx context.Context, subnetID *string, description string) (*ec2.NetworkInterface, fail.Error) {
	if xerr := validateAWSString(subnetID, "subnetID", true); xerr != nil {
		return nil, xerr
	}

	req := ec2.CreateNetworkInterfaceInput{
		Description: aws.String(description),
		SubnetId:    subnetID,
	}
	var resp *ec2.CreateNetworkInterfaceOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.CreateNetworkInterface(&req)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	if resp == nil {
		return nil, fail.InconsistentError("nil response received from Cloud Provider")
	}
	return resp.NetworkInterface, nil
}

func (s stack) rpcDeleteNetworkInterface(ctx context.Context, nicID *string) fail.Error {
	if xerr := validateAWSString(nicID, "nicID", true); xerr != nil {
		return xerr
	}

	req := ec2.DeleteNetworkInterfaceInput{
		NetworkInterfaceId: nicID,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			_, innerErr = s.EC2Service.DeleteNetworkInterface(&req)
			return innerErr
		},
		normalizeError,
	)
}

func (s stack) rpcAttachNetworkInterface(ctx context.Context, instanceID, nicID *string) (*string, fail.Error) {
	if xerr := validateAWSString(instanceID, "instanceID", true); xerr != nil {
		return nil, xerr
	}
	if xerr := validateAWSString(nicID, "nicID", true); xerr != nil {
		return nil, xerr
	}

	req := ec2.AttachNetworkInterfaceInput{
		InstanceId:         instanceID,
		NetworkInterfaceId: nicID,
	}
	var resp *ec2.AttachNetworkInterfaceOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.AttachNetworkInterface(&req)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	if resp == nil || resp.AttachmentId == nil || aws.StringValue(resp.AttachmentId) == "" {
		return nil, fail.NewError("inconsistent response from Cloud Provider")
	}
	return resp.AttachmentId, nil
}

func (s stack) rpcDetachNetworkInterface(ctx context.Context, attachmentID *string) fail.Error {
	if xerr := validateAWSString(attachmentID, "attachmentID", true); xerr != nil {
		return xerr
	}

	req := ec2.DetachNetworkInterfaceInput{
		AttachmentId: attachmentID,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			_, innerErr = s.EC2Service.DetachNetworkInterface(&req)
			return innerErr
		},
		normalizeError,
	)
}

func (s stack) rpcDescribeNetworkInterface(ctx context.Context, nicID *string) (*ec2.NetworkInterface, fail.Error) {
	req := ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []*string{nicID},
	}
	var resp *ec2.DescribeNetworkInterfacesOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeNetworkInterfaces(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	if len(resp.NetworkInterfaces) == 0 {
		return nil, fail.NotFoundError("failed to find Network Interface with id %s", aws.StringValue(nicID))
	}
	if len(resp.NetworkInterfaces) > 1 {
		return nil, fail.InconsistentError("failed several Network Interface with id %s", aws.StringValue(nicID))
	}
	return resp.NetworkInterfaces[0], nil
}

func (s stack) rpcDescribeVolumes(ctx context.Context, ids []*string) ([]*ec2.Volume, fail.Error) {
	var req ec2.DescribeVolumesInput
	if len(ids) > 0 {
		req.VolumeIds = ids
	}
	var resp *ec2.DescribeVolumesOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeVolumes(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []*ec2.Volume{}, xerr
	}
	if len(resp.Volumes) == 0 {
		return []*ec2.Volume{}, nil
	}
	return resp.Volumes, nil
}

func (s stack) rpcDescribeVolumeByID(ctx context.Context, id *string) (*ec2.Volume, fail.Error) {
	if id == nil {
		return &ec2.Volume{}, fail.InvalidParameterCannotBeNilError("id")
	}
	if aws.StringValue(id) == "" {
		return &ec2.Volume{}, fail.InvalidParameterError("id", "cannot be empty AWS String")
	}

	resp, xerr := s.rpcDescribeVolumes(ctx, []*string{id})
	if xerr != nil {
		return &ec2.Volume{}, xerr
	}
	if len(resp) == 0 {
		return &ec2.Volume{}, fail.NotFoundError("failed to find a Volume with ID %s", aws.StringValue(id))
	}
	if len(resp) > 1 {
		return &ec2.Volume{}, fail.InconsistentError("found more than one Volume with ID %s", aws.StringValue(id))
	}

	return resp[0], nil
}

// rpcDescribeVolumeByName returns information about a volume identified by its name
func (s stack) rpcDescribeVolumeByName(ctx context.Context, name *string) (*ec2.Volume, fail.Error) {
	if name == nil {
		return &ec2.Volume{}, fail.InvalidParameterCannotBeNilError("name")
	}
	if aws.StringValue(name) == "" {
		return &ec2.Volume{}, fail.InvalidParameterError("name", "cannot be empty AWS String")
	}

	req := ec2.DescribeVolumesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:Name"),
				Values: []*string{name},
			},
		},
	}
	var resp *ec2.DescribeVolumesOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeVolumes(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	if len(resp.Volumes) == 0 {
		return nil, fail.NotFoundError("failed to find a volume with name '%s'", aws.StringValue(name))
	}
	if len(resp.Volumes) > 1 {
		return &ec2.Volume{}, fail.InconsistentError("found more than one Volume with name '%s'", aws.StringValue(name))
	}

	return resp.Volumes[0], nil
}

func (s stack) rpcCreateVolume(ctx context.Context, name *string, size int64, speed string) (_ *ec2.Volume, ferr fail.Error) {
	if name == nil {
		return &ec2.Volume{}, fail.InvalidParameterCannotBeNilError("name")
	}
	if aws.StringValue(name) == "" {
		return &ec2.Volume{}, fail.InvalidParameterError("name", "cannot be empty AWS String")
	}
	if size <= 0 {
		return &ec2.Volume{}, fail.InvalidParameterError("size", "cannot be negative or 0 integer")
	}

	req := ec2.CreateVolumeInput{
		Size:             aws.Int64(size),
		VolumeType:       aws.String(speed),
		AvailabilityZone: aws.String(s.AwsConfig.Zone),
	}
	var resp *ec2.Volume
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.CreateVolume(&req)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return &ec2.Volume{}, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := s.rpcDeleteVolume(context.Background(), resp.VolumeId); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Volume '%s'", name))
			}
		}
	}()

	tags := []*ec2.Tag{
		{
			Key:   awsTagNameLabel,
			Value: name,
		},
		{
			Key:   aws.String("ManagedBy"),
			Value: aws.String("safescale"),
		},
		{
			Key:   aws.String("DeclaredInBucket"),
			Value: aws.String(s.Config.MetadataBucketName),
		},
		{
			Key:   aws.String("CreationDate"),
			Value: aws.String(time.Now().Format(time.RFC3339)),
		},
	}
	if xerr := s.rpcCreateTags(ctx, []*string{resp.VolumeId}, tags); xerr != nil {
		return nil, xerr
	}

	return resp, nil
}

func (s stack) rpcDeleteVolume(ctx context.Context, id *string) fail.Error {
	if id == nil {
		return fail.InvalidParameterCannotBeNilError("id")
	}
	if *id == "" {
		return fail.InvalidParameterError("id", "cannot be empty AWS String")
	}

	req := ec2.DeleteVolumeInput{
		VolumeId: id,
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.DeleteVolume(&req)
			return err
		},
		normalizeError,
	)
}
