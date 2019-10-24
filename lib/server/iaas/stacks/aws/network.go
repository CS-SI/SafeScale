package aws

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (s *Stack) CreateNetwork(req resources.NetworkRequest) (res *resources.Network, err error) {
	vpcOut, err := s.EC2Service.CreateVpc(&ec2.CreateVpcInput{
		CidrBlock: aws.String(req.CIDR),
	})
	if err != nil {
		return nil, errors.WithMessage(err, "Creating VPC")
	}

	// FIXME Use tags instead of name
	_, err = s.EC2Service.CreateTags(&ec2.CreateTagsInput{
		Resources: []*string{vpcOut.Vpc.VpcId},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String("Name"),
				Value: aws.String(req.Name),
			},
		},
	})

	defer func() {
		if err != nil {
			if vpcOut != nil {
				_ = s.DeleteNetwork(aws.StringValue(vpcOut.Vpc.VpcId))
			}
		}
	}()

	sn, err := s.EC2Service.CreateSubnet(&ec2.CreateSubnetInput{
		CidrBlock: aws.String(req.CIDR),
		VpcId:     vpcOut.Vpc.VpcId,
	})
	if err != nil {
		return nil, errors.Wrap(err, "CreateSubnet")
	}
	gw, err := s.EC2Service.CreateInternetGateway(&ec2.CreateInternetGatewayInput{})
	if err != nil {
		return nil, errors.WithMessage(err, "CreateInternetGateway")
	}
	_, err = s.EC2Service.AttachInternetGateway(&ec2.AttachInternetGatewayInput{
		VpcId:             vpcOut.Vpc.VpcId,
		InternetGatewayId: gw.InternetGateway.InternetGatewayId,
	})
	if err != nil {
		return nil, errors.WithMessage(err, "AttachInternetGateway")
	}
	table, err := s.EC2Service.DescribeRouteTables(&ec2.DescribeRouteTablesInput{
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
		return nil, errors.WithMessage(err, "No RouteTables")
	}

	_, err = s.EC2Service.CreateRoute(&ec2.CreateRouteInput{
		DestinationCidrBlock: aws.String("0.0.0.0/0"),
		GatewayId:            gw.InternetGateway.InternetGatewayId,
		RouteTableId:         table.RouteTables[0].RouteTableId,
	})
	if err != nil {
		return nil, errors.WithMessage(err, "CreateRoute")
	}
	_, err = s.EC2Service.AssociateRouteTable(&ec2.AssociateRouteTableInput{
		RouteTableId: table.RouteTables[0].RouteTableId,
		SubnetId:     sn.Subnet.SubnetId,
	})
	if err != nil {
		return nil, errors.WithMessage(err, "AssociateRouteTable")
	}

	/*
		req.GWRequest.PublicIP = true
		req.GWRequest.IsGateway = true
		req.GWRequest.NetworkIDs = append(req.GWRequest.NetworkIDs, *vpcOut.Vpc.VpcId)
		host, err := s.CreateHost(req.GWRequest)
		if err != nil {
			s.DeleteNetwork(*vpcOut.Vpc.VpcId)
			return nil, wrapError("Error creating network", err)
		}
		net := resources.Network{
			CIDR:      pStr(vpcOut.Vpc.CidrBlock),
			ID:        pStr(vpcOut.Vpc.VpcId),
			Name:      req.Name,
			IPVersion: req.IPVersion,
			GatewayID: host.ID,
		}
		err = s.saveNetwork(net)
		if err != nil {
			s.DeleteNetwork(*vpcOut.Vpc.VpcId)
			return nil, err
		}

	*/

	return nil, nil
}

func (s *Stack) GetNetwork(id string) (*resources.Network, error) {
	out, err := s.EC2Service.DescribeVpcs(&ec2.DescribeVpcsInput{
		VpcIds: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, err
	}

	for _, vpc := range out.Vpcs {
		net := resources.Network{}
		net.CIDR = aws.StringValue(vpc.CidrBlock)
		net.ID = aws.StringValue(vpc.VpcId)
		return &net, nil
	}

	return nil, resources.ResourceNotFoundError("Network", id)
}

func (s *Stack) GetNetworkByName(name string) (*resources.Network, error) {
	// FIXME Does it have name ?
	out, err := s.EC2Service.DescribeVpcs(&ec2.DescribeVpcsInput{
		VpcIds: []*string{aws.String(name)},
	})
	if err != nil {
		return nil, err
	}

	if out != nil {
		for _, vpc := range out.Vpcs {
			net := resources.Network{}
			net.CIDR = aws.StringValue(vpc.CidrBlock)
			net.ID = aws.StringValue(vpc.VpcId)
			return &net, nil
		}
	}

	return nil, resources.ResourceNotFoundError("Network", name)
}

func (s *Stack) ListNetworks() ([]*resources.Network, error) {
	out, err := s.EC2Service.DescribeVpcs(&ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, err
	}
	var nets []*resources.Network
	for _, vpc := range out.Vpcs {
		net := resources.Network{}
		net.ID = aws.StringValue(vpc.VpcId)
		net.CIDR = aws.StringValue(vpc.CidrBlock)
		for _, tag := range vpc.Tags {
			if aws.StringValue(tag.Key) == "Name" {
				if aws.StringValue(tag.Value) != "" {
					net.Name = aws.StringValue(tag.Value)
				}
			}
		}
		nets = append(nets, &net)
	}
	return nets, nil
}

func (s *Stack) DeleteNetwork(id string) error {
	net, err := s.GetNetwork(id)
	if err != nil {
		return err
	}

	err = s.DeleteHost(net.GatewayID)
	if err != nil {
		return err
	}

	addrs, _ := s.EC2Service.DescribeAddresses(&ec2.DescribeAddressesInput{
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
		_, err = s.EC2Service.DisassociateAddress(&ec2.DisassociateAddressInput{
			AssociationId: addr.AssociationId,
		})
		if err != nil {
			logrus.Warn(err)
		}
		_, err = s.EC2Service.ReleaseAddress(&ec2.ReleaseAddressInput{
			AllocationId: addr.AllocationId,
		})
		if err != nil {
			logrus.Warn(err)
		}
	}

	_, err = s.EC2Service.DeleteVpc(&ec2.DeleteVpcInput{
		VpcId: aws.String(id),
	})
	return err
}
