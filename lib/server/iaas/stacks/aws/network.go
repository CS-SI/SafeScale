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
	"net"
	"reflect"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/userdata"
	"github.com/CS-SI/SafeScale/lib/utils/cidr"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"

	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/abstract/properties/v1"
)

func (s *Stack) CreateVIP(string, string) (*abstract.VirtualIP, error) {
	return nil, fail.NotImplementedError("CreateVIP() not implemented yet") // FIXME: Technical debt
}

func (s *Stack) AddPublicIPToVIP(*abstract.VirtualIP) error {
	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

func (s *Stack) BindHostToVIP(*abstract.VirtualIP, string) error {
	return fail.NotImplementedError("BindHostToVIP() not implemented yet") // FIXME: Technical debt
}

func (s *Stack) UnbindHostFromVIP(*abstract.VirtualIP, string) error {
	return fail.NotImplementedError("UnbindHostToVIP() not implemented yet") // FIXME: Technical debt
}

func (s *Stack) DeleteVIP(*abstract.VirtualIP) error {
	return fail.NotImplementedError("DeleteVIP() not implemented yet") // FIXME: Technical debt
}

func (s *Stack) CreateNetwork(req abstract.NetworkRequest) (res *abstract.Network, err error) {
	logrus.Warnf("CreateNetwork invocation")

	var theVpc *ec2.Vpc

	// Check if network already there
	out, err := s.EC2Service.DescribeVpcs(&ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, err
	}

	for _, vpc := range out.Vpcs {
		vpcnet := abstract.Network{}
		vpcnet.CIDR = aws.StringValue(vpc.CidrBlock)
		vpcnet.ID = aws.StringValue(vpc.VpcId)
		for _, tag := range vpc.Tags {
			if aws.StringValue(tag.Key) == "Name" {
				if aws.StringValue(tag.Value) == s.AwsConfig.NetworkName {
					theVpc = vpc
					break
				}
			}
		}
		if theVpc != nil {
			break
		}
	}

	// if not, create the network
	if theVpc == nil {
		vpcOut, err := s.EC2Service.CreateVpc(
			&ec2.CreateVpcInput{
				CidrBlock: aws.String(req.CIDR),
			},
		)
		if err != nil {
			return nil, fail.Wrap(err, "Error creating VPC")
		}

		theVpc = vpcOut.Vpc
	}

	// wait until available status
	if IsOperation(theVpc, "State", reflect.TypeOf("")) {
		retryErr := retry.WhileUnsuccessful(
			func() error {
				vpcTmp, err := s.EC2Service.DescribeVpcs(
					&ec2.DescribeVpcsInput{
						VpcIds: []*string{theVpc.VpcId},
					},
				)
				if err != nil {
					return err
				}

				if aws.StringValue(vpcTmp.Vpcs[0].State) != "available" {
					return fail.Errorf(fmt.Sprintf("not ready"), nil)
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
	_, err = s.EC2Service.CreateTags(
		&ec2.CreateTagsInput{
			Resources: []*string{theVpc.VpcId},
			Tags: []*ec2.Tag{
				{
					Key:   aws.String("Name"),
					Value: aws.String(s.AwsConfig.NetworkName),
				},
			},
		},
	)
	if err != nil {
		logrus.Warn("Error creating tags")
	}

	defer func() {
		if err != nil {
			if theVpc != nil {
				derr := s.DeleteNetwork(aws.StringValue(theVpc.VpcId))
				if derr != nil {
					err = fail.AddConsequence(err, derr)
				}
			}
		}
	}()

	// FIXME: Create private and public subnets here...
	_, parentNet, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return nil, fail.Wrap(err, "error parsing requested CIDR")
	}

	var subnets []*net.IPNet
	var subnetsResult []*ec2.CreateSubnetOutput

	if s.Config.BuildSubnetworks {
		logrus.Warn("We should build subnetworks")
		publicSubnetCidr, err := cidr.Subnet(parentNet, 1, 0)
		if err != nil {
			return nil, fail.Wrap(err, "error preparing a public subnet")
		}
		subnets = append(subnets, publicSubnetCidr)

		privateSubnetCidr, err := cidr.Subnet(parentNet, 1, 1)
		if err != nil {
			return nil, fail.Wrap(err, "error preparing a private subnet")
		}
		subnets = append(subnets, privateSubnetCidr)
	} else {
		logrus.Warn("We should NOT build subnetworks") // FIXME: AWS Remove message later
		subnets = append(subnets, parentNet)
	}

	defer func() {
		if err != nil {
			for _, snet := range subnetsResult {
				_, derr := s.EC2Service.DeleteSubnet(
					&ec2.DeleteSubnetInput{
						SubnetId: snet.Subnet.SubnetId,
					},
				)
				if derr != nil {
					err = fail.AddConsequence(err, derr)
				}
			}
		}
	}()

	for _, snCidr := range subnets {
		sn, err := s.EC2Service.CreateSubnet(
			&ec2.CreateSubnetInput{
				CidrBlock:        aws.String(snCidr.String()),
				VpcId:            theVpc.VpcId,
				AvailabilityZone: aws.String(s.AwsConfig.Zone),
			},
		)
		if err != nil {
			return nil, fail.Wrap(err, "error creating a subnet")
		}

		subnetsResult = append(subnetsResult, sn)
	}

	if len(subnetsResult) == 0 {
		return nil, fail.Errorf(fmt.Sprintf("unable to create any subnet"), nil)
	}

	var subnetIds []*string
	for _, snid := range subnetsResult {
		subnetIds = append(subnetIds, snid.Subnet.SubnetId)
	}

	_, err = s.EC2Service.CreateTags(
		&ec2.CreateTagsInput{
			Resources: subnetIds,
			Tags: []*ec2.Tag{
				{
					Key:   aws.String("Name"),
					Value: aws.String(req.Name),
				},
			},
		},
	)
	if err != nil {
		logrus.Warn("Error creating tags")
	}

	for _, sn := range subnetsResult {
		if IsOperation(sn.Subnet, "State", reflect.TypeOf("")) {
			retryErr := retry.WhileUnsuccessful(
				func() error {
					snTmp, err := s.EC2Service.DescribeSubnets(
						&ec2.DescribeSubnetsInput{
							SubnetIds: []*string{sn.Subnet.SubnetId},
						},
					)
					if err != nil {
						return err
					}

					if aws.StringValue(snTmp.Subnets[0].State) != "available" {
						return fail.Errorf(fmt.Sprintf("not ready"), nil)
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
	}

	gw, err := s.EC2Service.CreateInternetGateway(&ec2.CreateInternetGatewayInput{})
	if err != nil {
		return nil, fail.Wrap(err, "error creating internet gateway")
	}
	defer func() {
		if err != nil {
			_, derr := s.EC2Service.DeleteInternetGateway(
				&ec2.DeleteInternetGatewayInput{
					InternetGatewayId: gw.InternetGateway.InternetGatewayId,
				},
			)
			if derr != nil {
				err = fail.AddConsequence(err, derr)
			}
		}
	}()

	_, err = s.EC2Service.AttachInternetGateway(
		&ec2.AttachInternetGatewayInput{
			VpcId:             theVpc.VpcId,
			InternetGatewayId: gw.InternetGateway.InternetGatewayId,
		},
	)
	if err != nil {
		return nil, fail.Wrap(err, "error attaching internet gateway")
	}

	defer func() {
		if err != nil {
			_, derr := s.EC2Service.DetachInternetGateway(
				&ec2.DetachInternetGatewayInput{
					InternetGatewayId: gw.InternetGateway.InternetGatewayId,
					VpcId:             theVpc.VpcId,
				},
			)
			if derr != nil {
				err = fail.AddConsequence(err, derr)
			}
		}
	}()

	table, err := s.EC2Service.DescribeRouteTables(
		&ec2.DescribeRouteTablesInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name: aws.String("vpc-id"),
					Values: []*string{
						theVpc.VpcId,
					},
				},
			},
		},
	)
	if err != nil || len(table.RouteTables) < 1 {
		return nil, fail.Wrap(err, "No RouteTables")
	}

	_, err = s.EC2Service.CreateRoute(
		&ec2.CreateRouteInput{
			DestinationCidrBlock: aws.String("0.0.0.0/0"),
			GatewayId:            gw.InternetGateway.InternetGatewayId,
			RouteTableId:         table.RouteTables[0].RouteTableId,
		},
	)
	if err != nil {
		return nil, fail.Wrap(err, "CreateRoute")
	}

	defer func() {
		if err != nil {
			_, derr := s.EC2Service.DeleteRoute(
				&ec2.DeleteRouteInput{
					DestinationCidrBlock: aws.String("0.0.0.0/0"),
					RouteTableId:         table.RouteTables[0].RouteTableId,
				},
			)
			if derr != nil {
				err = fail.AddConsequence(err, derr)
			}
		}
	}()

	// First result should be the public interface
	sn := subnetsResult[0]
	art, err := s.EC2Service.AssociateRouteTable(
		&ec2.AssociateRouteTableInput{
			RouteTableId: table.RouteTables[0].RouteTableId,
			SubnetId:     sn.Subnet.SubnetId,
		},
	)
	if err != nil {
		return nil, fail.Wrap(err, "AssociateRouteTable")
	}

	defer func() {
		if err != nil {
			_, derr := s.EC2Service.DisassociateRouteTable(
				&ec2.DisassociateRouteTableInput{
					AssociationId: art.AssociationId,
				},
			)
			if derr != nil {
				err = fail.AddConsequence(err, derr)
			}
		}
	}()

	defer func() {
		if err != nil {
			_, derr := s.EC2Service.DeleteRouteTable(
				&ec2.DeleteRouteTableInput{
					RouteTableId: table.RouteTables[0].RouteTableId,
				},
			)
			if derr != nil {
				err = fail.AddConsequence(err, derr)
			}
		}
	}()

	// FIXME: Add properties and GatewayID
	subnet := abstract.NewNetwork()
	subnet.ID = aws.StringValue(sn.Subnet.SubnetId)
	subnet.Name = req.Name
	subnet.CIDR = req.CIDR // FIXME: AWS Storing parent CIDR
	subnet.IPVersion = ipversion.IPv4

	for _, sn := range subnetsResult {
		subnet.Subnetworks = append(
			subnet.Subnetworks, abstract.SubNetwork{
				CIDR: aws.StringValue(sn.Subnet.CidrBlock),
				ID:   aws.StringValue(sn.Subnet.SubnetId),
			},
		)
	}

	// Make sure we log warnings
	_ = subnet.OK()

	return subnet, nil
}

func (s *Stack) GetNetwork(id string) (*abstract.Network, error) {
	nets, err := s.ListNetworks()
	if err != nil {
		return nil, err
	}

	for _, vpcnet := range nets {
		if vpcnet.ID == id {
			return vpcnet, nil
		}
	}

	return nil, abstract.ResourceNotFoundError("Network", id)
}

func (s *Stack) GetNetworkByName(name string) (*abstract.Network, error) {
	nets, err := s.ListNetworks()
	if err != nil {
		return nil, err
	}

	for _, vpcnet := range nets {
		if vpcnet.Name == name {
			return vpcnet, nil
		}
	}

	return nil, abstract.ResourceNotFoundError("Network", name)
}

func (s *Stack) ListNetworks() ([]*abstract.Network, error) {
	out, err := s.EC2Service.DescribeVpcs(&ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, err
	}
	var nets []*abstract.Network
	for _, vpc := range out.Vpcs {
		vpcnet := abstract.Network{}
		vpcnet.ID = aws.StringValue(vpc.VpcId)
		vpcnet.CIDR = aws.StringValue(vpc.CidrBlock)
		for _, tag := range vpc.Tags {
			if aws.StringValue(tag.Key) == "Name" {
				if aws.StringValue(tag.Value) != "" {
					vpcnet.Name = aws.StringValue(tag.Value)
				}
			}
		}
		nets = append(nets, &vpcnet)
	}

	subns, err := s.EC2Service.DescribeSubnets(&ec2.DescribeSubnetsInput{})
	if err != nil {
		return nil, err
	}

	for _, subn := range subns.Subnets {
		vpcnet := abstract.Network{}
		vpcnet.ID = aws.StringValue(subn.SubnetId)
		vpcnet.CIDR = aws.StringValue(subn.CidrBlock)
		vpcnet.Subnet = true
		vpcnet.Parent = aws.StringValue(subn.VpcId)
		for _, tag := range subn.Tags {
			if aws.StringValue(tag.Key) == "Name" {
				if aws.StringValue(tag.Value) != "" {
					vpcnet.Name = aws.StringValue(tag.Value)
				}
			}
		}
		nets = append(nets, &vpcnet)
	}

	return nets, nil
}

func (s *Stack) DeleteNetwork(id string) error {
	logrus.Warnf("Beginning deletion of network: %s", id)

	vpcnet, err := s.GetNetwork(id)
	if err != nil {
		return err
	}

	addrs, _ := s.EC2Service.DescribeAddresses(
		&ec2.DescribeAddressesInput{
			Filters: []*ec2.Filter{
				{
					Name: aws.String("domain"),
					Values: []*string{
						aws.String("vpc"),
					},
				},
				{
					Name: aws.String("instance-id"),
					Values: []*string{
						aws.String(vpcnet.GatewayID),
					},
				},
			},
		},
	)

	for _, addr := range addrs.Addresses {
		_, err = s.EC2Service.DisassociateAddress(
			&ec2.DisassociateAddressInput{
				AssociationId: addr.AssociationId,
			},
		)
		if err != nil {
			return err
		}
		_, err = s.EC2Service.ReleaseAddress(
			&ec2.ReleaseAddressInput{
				AllocationId: addr.AllocationId,
			},
		)
		if err != nil {
			return err
		}
	}

	snTmp, err := s.EC2Service.DescribeSubnets(&ec2.DescribeSubnetsInput{})
	if err != nil {
		return err
	}

	logrus.Warn(spew.Sdump(vpcnet))

	var vpcId *string

	for _, asnTmp := range snTmp.Subnets {
		logrus.Warnf("Comparing %s to %s", aws.StringValue(asnTmp.VpcId), vpcnet.Parent)
		if aws.StringValue(asnTmp.VpcId) == vpcnet.Parent {
			vpcId = asnTmp.VpcId
			logrus.Warnf("Actually trying to delete subnetwork %s", aws.StringValue(asnTmp.SubnetId))
			_, err = s.EC2Service.DeleteSubnet(
				&ec2.DeleteSubnetInput{
					SubnetId: asnTmp.SubnetId,
				},
			)
			if err != nil {
				return err
			}
		}
	}

	logrus.Warnf("Reached gateway delete call")

	gwTmp, err := s.EC2Service.DescribeInternetGateways(&ec2.DescribeInternetGatewaysInput{})
	if err != nil {
		return err
	}

	for _, agwTmp := range gwTmp.InternetGateways {
		for _, att := range agwTmp.Attachments {
			if aws.StringValue(att.VpcId) == vpcnet.Parent {
				_, err = s.EC2Service.DetachInternetGateway(
					&ec2.DetachInternetGatewayInput{
						InternetGatewayId: agwTmp.InternetGatewayId,
						VpcId:             att.VpcId,
					},
				)
				if err != nil {
					return err
				}

				_, err = s.EC2Service.DeleteInternetGateway(
					&ec2.DeleteInternetGatewayInput{
						InternetGatewayId: agwTmp.InternetGatewayId,
					},
				)
				if err != nil {
					return err
				}
			}
		}
	}

	logrus.Warnf("Reached Route delete call")

	rtTmp, err := s.EC2Service.DescribeRouteTables(&ec2.DescribeRouteTablesInput{})
	if err != nil {
		return err
	}

	for _, artTmp := range rtTmp.RouteTables {
		if aws.StringValue(artTmp.VpcId) == vpcnet.Parent {
			hasMain := false
			// Dissociate
			for _, rta := range artTmp.Associations {
				if !aws.BoolValue(rta.Main) {
					_, err = s.EC2Service.DisassociateRouteTable(
						&ec2.DisassociateRouteTableInput{
							AssociationId: rta.RouteTableAssociationId,
						},
					)
					if err != nil {
						return err
					}
				} else {
					hasMain = true
				}
			}

			if hasMain {
				continue
			}

			_, err = s.EC2Service.DeleteRouteTable(
				&ec2.DeleteRouteTableInput{
					RouteTableId: artTmp.RouteTableId,
				},
			)
			if err != nil {
				return err
			}
		}
	}

	logrus.Warnf("Reached Route Table delete call")

	table, err := s.EC2Service.DescribeRouteTables(
		&ec2.DescribeRouteTablesInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name: aws.String("vpc-id"),
					Values: []*string{
						vpcId,
					},
				},
			},
		},
	)
	if err != nil {
		return err
	}

	if table != nil {
		if len(table.RouteTables) > 0 {
			_, err = s.EC2Service.DeleteRoute(
				&ec2.DeleteRouteInput{
					DestinationCidrBlock: aws.String("0.0.0.0/0"),
					RouteTableId:         table.RouteTables[0].RouteTableId,
				},
			)
			if err != nil {
				return err
			}
		}
	}

	logrus.Warnf("Reached DeleteVpc call")

	_, err = s.EC2Service.DeleteVpc(
		&ec2.DeleteVpcInput{
			VpcId: aws.String(vpcnet.Parent),
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func getAwsInstanceState(state *ec2.InstanceState) (hoststate.Enum, error) {
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
		return hoststate.ERROR, fail.Errorf(fmt.Sprintf("unexpected host state"), nil)
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
	return hoststate.ERROR, fail.Errorf(fmt.Sprintf("unexpected host state"), nil)
}

func (s *Stack) CreateGateway(req abstract.GatewayRequest, sizing *abstract.SizingRequirements) (_ *abstract.Host, _ *userdata.Content, err error) {
	gwname := strings.Split(req.Name, ".")[0] // req.Name may contain a FQDN...
	if gwname == "" {
		gwname = "gw-" + req.Network.Name
	}

	hostReq := abstract.HostRequest{
		ImageID:      req.ImageID,
		KeyPair:      req.KeyPair,
		HostName:     req.Name,
		ResourceName: gwname,
		TemplateID:   req.TemplateID,
		Networks:     []*abstract.Network{req.Network},
		PublicIP:     true,
	}
	if sizing != nil && sizing.MinDiskSize > 0 {
		hostReq.DiskSize = sizing.MinDiskSize
	}
	host, userData, err := s.CreateHost(hostReq)
	if err != nil {
		switch err.(type) {
		case *fail.ErrInvalidRequest:
			return nil, userData, err
		default:
			return nil, userData, fail.Errorf(fmt.Sprintf("error creating gateway : %s", err), err)
		}
	}

	defer func() {
		if err != nil {
			derr := s.DeleteHost(host.ID)
			if derr != nil {
				err = fail.AddConsequence(err, derr)
			}
		}
	}()

	// Updates Host Property propsv1.HostSizing
	err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(
		func(v data.Clonable) error {
			hostSizingV1 := v.(*propsv1.HostSizing)
			hostSizingV1.Template = req.TemplateID
			return nil
		},
	)
	if err != nil {
		return nil, userData, err
	}

	// FIXME: AWS Add routing if network is splitted...
	// FIXME: AWS Update gateway id in network

	return host, userData, err
}

func (s *Stack) DeleteGateway(ref string) error {
	return s.DeleteHost(ref)
}
