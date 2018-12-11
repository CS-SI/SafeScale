/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/CS-SI/SafeScale/providers/model"
)

// CreateGateway ...
func (c *Client) CreateGateway(req model.GatewayRequest) (*model.Host, error) {
	return nil, fmt.Errorf("aws.CreateGateway() isn't available by design")
}

// DeleteGateway ...
func (c *Client) DeleteGateway(string) error {
	return fmt.Errorf("aws.DeleteGateway() isn't available by design")
}

// GetNetworkByName ...
func (c *Client) GetNetworkByName(name string) (*model.Network, error) {
	panic("implement me")
}

// CreateNetwork creates a network
func (c *Client) CreateNetwork(req model.NetworkRequest) (*model.Network, error) {
	vpcOut, err := c.EC2.CreateVpc(&ec2.CreateVpcInput{
		CidrBlock: aws.String(req.CIDR),
	})
	if err != nil {
		return nil, err
	}

	sn, err := c.EC2.CreateSubnet(&ec2.CreateSubnetInput{
		CidrBlock: aws.String(req.CIDR),
		VpcId:     vpcOut.Vpc.VpcId,
	})
	if err != nil {
		c.DeleteNetwork(*vpcOut.Vpc.VpcId)
		return nil, err
	}
	gw, err := c.EC2.CreateInternetGateway(&ec2.CreateInternetGatewayInput{})
	if err != nil {
		c.DeleteNetwork(*vpcOut.Vpc.VpcId)
		return nil, err
	}
	_, err = c.EC2.AttachInternetGateway(&ec2.AttachInternetGatewayInput{
		VpcId:             vpcOut.Vpc.VpcId,
		InternetGatewayId: gw.InternetGateway.InternetGatewayId,
	})
	if err != nil {
		c.DeleteNetwork(*vpcOut.Vpc.VpcId)
		return nil, err
	}
	table, err := c.EC2.DescribeRouteTables(&ec2.DescribeRouteTablesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name: aws.String("vpc-id"),
				Values: []*string{
					vpcOut.Vpc.VpcId,
				},
			},
		},
	})
	if err != nil || len(table.RouteTables) < 1 {
		return nil, err
	}

	if err != nil {
		c.DeleteNetwork(*vpcOut.Vpc.VpcId)
		return nil, err
	}
	_, err = c.EC2.CreateRoute(&ec2.CreateRouteInput{
		DestinationCidrBlock: aws.String("0.0.0.0/0"),
		GatewayId:            gw.InternetGateway.InternetGatewayId,
		RouteTableId:         table.RouteTables[0].RouteTableId,
	})
	if err != nil {
		c.DeleteNetwork(*vpcOut.Vpc.VpcId)
		return nil, err
	}
	_, err = c.EC2.AssociateRouteTable(&ec2.AssociateRouteTableInput{
		RouteTableId: table.RouteTables[0].RouteTableId,
		SubnetId:     sn.Subnet.SubnetId,
	})
	if err != nil {
		c.DeleteNetwork(*vpcOut.Vpc.VpcId)
		return nil, err
	}

	net := model.NewNetwork()
	net.CIDR = pStr(vpcOut.Vpc.CidrBlock)
	net.ID = pStr(vpcOut.Vpc.VpcId)
	net.Name = req.Name
	net.IPVersion = req.IPVersion
	//net.GatewayID: host.ID

	return net, nil
}

// GetNetwork returns the network identified by id
func (c *Client) GetNetwork(id string) (*model.Network, error) {
	out, err := c.EC2.DescribeVpcs(&ec2.DescribeVpcsInput{
		VpcIds: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, err
	}
	net := model.NewNetwork()
	net.CIDR = pStr(out.Vpcs[0].CidrBlock)
	net.ID = pStr(out.Vpcs[0].VpcId)
	return net, nil
}

// ListNetworks lists available networks
func (c *Client) ListNetworks() ([]*model.Network, error) {
	out, err := c.EC2.DescribeVpcs(&ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, err
	}
	nets := []*model.Network{}
	for _, vpc := range out.Vpcs {
		net, err := c.GetNetwork(*vpc.VpcId)
		if err != nil {
			return nil, err
		}
		net.CIDR = *vpc.CidrBlock
		net.CIDR = *vpc.VpcId
		nets = append(nets, net)
	}
	return nets, nil
}

// DeleteNetwork deletes the network identified by id
func (c *Client) DeleteNetwork(id string) error {
	// net, err := c.getNetwork(id)
	// if err == nil {
	// 	c.DeleteHost(net.GatewayID)
	// 	addrs, _ := c.EC2.DescribeAddresses(&ec2.DescribeAddressesInput{
	// 		Filters: []*ec2.Filter{
	// 			{
	// 				Name: aws.String("domain"),
	// 				Values: []*string{
	// 					aws.String("vpc"),
	// 				},
	// 			},
	// 			{
	// 				Name: aws.String("instance-id"),
	// 				Values: []*string{
	// 					aws.String(net.GatewayID),
	// 				},
	// 			},
	// 		},
	// 	})
	// 	for _, addr := range addrs.Addresses {
	// 		c.EC2.DisassociateAddress(&ec2.DisassociateAddressInput{
	// 			AssociationId: addr.AssociationId,
	// 		})
	// 		c.EC2.ReleaseAddress(&ec2.ReleaseAddressInput{
	// 			AllocationId: addr.AllocationId,
	// 		})
	// 	}
	// }

	_, err := c.EC2.DeleteVpc(&ec2.DeleteVpcInput{
		VpcId: aws.String(id),
	})
	return err
}

func (c *Client) getSubnets(networks []*model.Network) ([]*ec2.Subnet, error) {
	filters := []*ec2.Filter{}
	for _, net := range networks {
		filters = append(filters, &ec2.Filter{
			Name:   aws.String("vpc-id"),
			Values: []*string{&net.ID},
		})
	}
	out, err := c.EC2.DescribeSubnets(&ec2.DescribeSubnetsInput{
		Filters: filters,
	})
	if err != nil {
		return nil, err
	}
	return out.Subnets, nil

}
