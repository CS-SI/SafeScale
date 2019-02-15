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

	log "github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/iaas/providers"

)

// CreateNetwork creates a network
func (s *Stack) CreateNetwork(req resources.NetworkRequest) (*resources.Network, error) {
	vpcOut, err := s.EC2.CreateVpc(&ec2.CreateVpcInput{
		CidrBlock: aws.String(req.CIDR),
	})
	if err != nil {
		return nil, err
	}

	// Starting from here, delete vpc if exiting with error
	defer func() {
		if err != nil {
			derr := s.DeleteNetwork(*vpcOut.Vpc.VpcId)
			if derr != nil {
				log.Debugf("%+v", err)
			}
		}
	}()

	sn, err := s.EC2.CreateSubnet(&ec2.CreateSubnetInput{
		CidrBlock: aws.String(req.CIDR),
		VpcId:     vpcOut.Vpc.VpcId,
	})
	if err != nil {
		return nil, err
	}

	gw, err := s.EC2.CreateInternetGateway(&ec2.CreateInternetGatewayInput{})
	if err != nil {
		s.DeleteNetwork(*vpcOut.Vpc.VpcId)
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
	if err != nil {
		c.DeleteNetwork(*vpcOut.Vpc.VpcId)
		return nil, err
	}
	if len(table.RouteTables) < 1 {
		// TODO, err is nil here !
		return nil, err
	}

	_, err = c.EC2.CreateRoute(&ec2.CreateRouteInput{
		DestinationCidrBlock: aws.String("0.0.0.0/0"),
		GatewayId:            gw.InternetGateway.InternetGatewayId,
		RouteTableId:         table.RouteTables[0].RouteTableId,
	})
	if err != nil {
		return nil, err
	}
	_, err = c.EC2.AssociateRouteTable(&ec2.AssociateRouteTableInput{
		RouteTableId: table.RouteTables[0].RouteTableId,
		SubnetId:     sn.Subnet.SubnetId,
	})
	if err != nil {
		return nil, err
	}

	req.GWRequest.PublicIP = true
	req.GWRequest.IsGateway = true
	req.GWRequest.NetworkIDs = append(req.GWRequest.NetworkIDs, *vpcOut.Vpc.VpcId)
	host, err := c.CreateHost(req.GWRequest)
	if err != nil {
		return nil, wrapError("Error creating network", err)
	}
	net := providers.Network{
		CIDR:      pStr(vpcOut.Vpc.CidrBlock),
		ID:        pStr(vpcOut.Vpc.VpcId),
		Name:      req.Name,
		IPVersion: req.IPVersion,
		GatewayID: host.ID,
	}
	return &net, nil
}

// GetNetwork returns the network identified by id
func (s *Stack) GetNetwork(id string) (*resources.Network, error) {
	net, err := c.getNetwork(id)
	if err != nil {
		return nil, err
	}
	out, err := c.EC2.DescribeVpcs(&ec2.DescribeVpcsInput{
		VpcIds: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, err
	}
	net.CIDR = *out.Vpcs[0].CidrBlock
	net.ID = *out.Vpcs[0].VpcId
	return net, nil
}

// ListNetworks lists available networks
func (s *Stack) ListNetworks() ([]resources.Network, error) {
	out, err := c.EC2.DescribeVpcs(&ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, err
	}
	nets := []resources.Network{}
	for _, vpc := range out.Vpcs {
		net, err := c.getNetwork(*vpc.VpcId)
		if err != nil {
			return nil, err
		}
		net.CIDR = *vpc.CidrBlock
		net.CIDR = *vpc.VpcId
		nets = append(nets, *net)
	}
	return nets, nil

}

// DeleteNetwork deletes the network identified by id
func (s *Stack) DeleteNetwork(id string) error {
	net, err := c.getNetwork(id)
	if err == nil {
		c.DeleteHost(net.GatewayID)
		addrs, _ := c.EC2.DescribeAddresses(&ec2.DescribeAddressesInput{
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
						aws.String(net.GatewayID),
					},
				},
			},
		})
		for _, addr := range addrs.Addresses {
			c.EC2.DisassociateAddress(&ec2.DisassociateAddressInput{
				AssociationId: addr.AssociationId,
			})
			c.EC2.ReleaseAddress(&ec2.ReleaseAddressInput{
				AllocationId: addr.AllocationId,
			})
		}
	}

	_, err = c.EC2.DeleteVpc(&ec2.DeleteVpcInput{
		VpcId: aws.String(id),
	})
	return err
}

// CreateGateway exists only to comply with api.ClientAPI interface
func (s *Stack) CreateGateway(req resources.GatewayRequest) (*resources.Host, error) {
	return nil, fmt.Errorf("aws.CreateGateway() isn't available by design")
}

// DeleteGateway exists only to comply with api.ClientAPI interface
func (s *Stack) DeleteGateway(networkID string) error {
	return fmt.Errorf("aws.DeleteGateway() isn't available by design")
}

func (s *Stack) getSubnets(vpcIDs []*resources.Network) ([]*ec2.Subnet, error) {
	filters := []*ec2.Filter{}
	for _, vpc := range vpcIDs {
		filters = append(filters, &ec2.Filter{
			Name:   aws.String("vpc-id"),
			Values: []*string{&vpc.ID},
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
