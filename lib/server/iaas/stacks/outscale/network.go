/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package outscale

import (
	"fmt"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/outscale/osc-sdk-go/oapi"
	"github.com/sirupsen/logrus"
)

func (s *Stack) deleteSubnetOnError(err error, subnet *oapi.Subnet) error {
	if err == nil {
		return nil
	}
	_, err2 := s.client.POST_DeleteSubnet(oapi.DeleteSubnetRequest{
		SubnetId: subnet.SubnetId,
	})
	if err2 != nil {
		return scerr.Wrap(err, err2.Error())
	}
	return err
}

func (s *Stack) createSubnet(req resources.NetworkRequest, vpcID string) (*oapi.Subnet, error) {
	//Create a subnet with the same CIDR than the network
	resSubnet, err := s.client.POST_CreateSubnet(oapi.CreateSubnetRequest{
		IpRange:       req.CIDR,
		NetId:         vpcID,
		SubregionName: s.Options.Compute.Subregion,
	})
	if err != nil {
		return nil, err
	}
	if resSubnet == nil || resSubnet.OK == nil {
		return nil, s.deleteSubnetOnError(scerr.InconsistentError("invalid provider response"), &resSubnet.OK.Subnet)
	}
	err = s.setResourceTags(resSubnet.OK.Subnet.SubnetId, map[string]string{
		"name": req.Name,
	})

	if err != nil {
		return nil, s.deleteSubnetOnError(err, &resSubnet.OK.Subnet)
	}
	//Prevent automatic assignment of public ip to VM created in the subnet
	_, err = s.updateSubnet(UpdateSubnetRequest{
		MapPublicIpOnLaunch: false,
		SubnetId:            resSubnet.OK.Subnet.SubnetId,
	})
	if err != nil {
		return nil, s.deleteSubnetOnError(err, &resSubnet.OK.Subnet)
	}
	return &resSubnet.OK.Subnet, nil
}

// CreateNetwork creates a network named name
func (s *Stack) CreateNetwork(req resources.NetworkRequest) (*resources.Network, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	//update defaut security group to allow external trafic
	secgroup, err := s.getNetworkSecurityGroup(s.Options.Network.VPCID)
	if err != nil {
		return nil, err
	}
	if secgroup == nil {
		return nil, err
	}

	subnet, err := s.createSubnet(req, s.Options.Network.VPCID)
	if err != nil {
		return nil, err
	}
	if subnet == nil {
		return nil, scerr.InconsistentError("Inconsistent provider response")
	}

	net := resources.NewNetwork()
	net.ID = subnet.SubnetId
	net.CIDR = subnet.IpRange
	net.IPVersion = ipversion.IPv4
	net.Name = req.Name

	return net, nil
}

func (s *Stack) getSubnet(id string) (*oapi.Subnet, error) {
	res, err := s.client.POST_ReadSubnets(oapi.ReadSubnetsRequest{
		Filters: oapi.FiltersSubnet{
			SubnetIds: []string{id},
		},
	})
	if err != nil {
		return nil, err
	}
	if res.OK == nil || len(res.OK.Subnets) > 1 {
		return nil, scerr.InconsistentError("Inconstent provider response")
	}
	if len(res.OK.Subnets) == 0 {
		return nil, nil
	}
	return &res.OK.Subnets[0], nil

}

func toNetwork(subnet *oapi.Subnet) *resources.Network {
	net := resources.NewNetwork()
	net.ID = subnet.SubnetId
	net.CIDR = subnet.IpRange
	net.IPVersion = ipversion.IPv4
	tags := unwrapTags(subnet.Tags)
	if name, ok := tags["name"]; ok {
		net.Name = name
	}
	return net
}

// GetNetwork returns the network identified by id
func (s *Stack) GetNetwork(id string) (*resources.Network, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	onet, err := s.getSubnet(id)
	if err != nil {
		return nil, err
	}
	if onet == nil {
		return nil, nil
	}

	return toNetwork(onet), nil
}

// GetNetworkByName returns the network identified by name)
func (s *Stack) GetNetworkByName(name string) (*resources.Network, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	res, err := s.client.POST_ReadSubnets(
		oapi.ReadSubnetsRequest{
			Filters: oapi.FiltersSubnet{
				NetIds: []string{s.Options.Network.VPCID},
			},
		},
	)
	if err != nil {
		return nil, err
	}
	if res == nil || len(res.OK.Subnets) == 0 {
		return nil, scerr.NotFoundError(fmt.Sprintf("No network named %s", name))
	}
	if len(res.OK.Subnets) > 1 {
		return nil, scerr.InconsistentError(fmt.Sprintf("Two network with the same name %s", name))
	}

	return toNetwork(&res.OK.Subnets[0]), nil
}

// ListNetworks lists all networks
func (s *Stack) ListNetworks() ([]*resources.Network, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	res, err := s.client.POST_ReadSubnets(oapi.ReadSubnetsRequest{
		Filters: oapi.FiltersSubnet{
			NetIds: []string{s.Options.Network.VPCID},
		},
	})
	if err != nil {
		return nil, err
	}
	if res == nil || res.OK == nil {
		return nil, nil
	}
	var nets []*resources.Network
	for _, onet := range res.OK.Subnets {
		nets = append(nets, toNetwork(&onet))
	}

	return nets, nil
}

// ListNetworks lists all networks
func (s *Stack) listNetworksByHost(hostID string) ([]*resources.Network, []oapi.Nic, error) {
	if s == nil {
		return nil, nil, scerr.InvalidInstanceError()
	}
	res, err := s.client.POST_ReadNics(oapi.ReadNicsRequest{
		Filters: oapi.FiltersNic{
			LinkNicVmIds: []string{hostID},
		},
	})
	if err != nil {
		return nil, nil, err
	}
	if res == nil || res.OK == nil {
		return nil, nil, scerr.InconsistentError("Inconsistent provider response")
	}

	var subnets []*resources.Network
	for _, nic := range res.OK.Nics {
		subnet, err := s.getSubnet(nic.SubnetId)
		if err != nil {
			return nil, nil, err
		}
		subnets = append(subnets, toNetwork(subnet))
	}
	return subnets, res.OK.Nics, nil

}

func (s *Stack) deleteSecurityGroup(onet *oapi.Net) error {
	res, err := s.client.POST_ReadSecurityGroups(oapi.ReadSecurityGroupsRequest{
		Filters: oapi.FiltersSecurityGroup{
			NetIds: []string{onet.NetId},
		},
	})
	if err != nil {
		return err
	}
	if res == nil || res.OK == nil || len(res.OK.SecurityGroups) == 0 {
		logrus.Warnf("No security group in network %s", onet.NetId)
		return nil
	}
	for _, sg := range res.OK.SecurityGroups {
		_, err = s.client.POST_DeleteSecurityGroup(oapi.DeleteSecurityGroupRequest{
			SecurityGroupId: sg.SecurityGroupId,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Stack) deleteSubnet(id string) error {
	//Delete subnets
	_, err := s.client.POST_DeleteSubnet(oapi.DeleteSubnetRequest{
		SubnetId: id,
	})
	return err

}

// DeleteNetwork deletes the network identified by id
func (s *Stack) DeleteNetwork(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	//Reads NIS that belong to the subnet
	res, err := s.client.POST_ReadNics(oapi.ReadNicsRequest{
		Filters: oapi.FiltersNic{
			SubnetIds: []string{id},
		},
	})
	if err != nil {
		logrus.Debugf("Error reading NICS :%v", err)
	}

	if res != nil && res.OK != nil && len(res.OK.Nics) > 0 {
		//Delete should succeed only when something goes wrong when deleting VMs
		err = s.deleteNics(res.OK.Nics)
		if err == nil {
			logrus.Debugf("Check if nothing goes wrong deleting a VM")
		}
	}

	return s.deleteSubnet(id)
}
