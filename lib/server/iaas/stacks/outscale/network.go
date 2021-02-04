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

package outscale

import (
	"fmt"

	"github.com/antihax/optional"
	"github.com/outscale-dev/osc-sdk-go/osc"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

func (s *Stack) createSubnet(req abstract.NetworkRequest, vpcID string) (_ *osc.Subnet, xerr fail.Error) {
	// Create a subnet with the same CIDR than the network
	createSubnetRequest := osc.CreateSubnetRequest{
		IpRange:       req.CIDR,
		NetId:         vpcID,
		SubregionName: s.Options.Compute.Subregion,
	}
	resSubnet, _, err := s.client.SubnetApi.CreateSubnet(
		s.auth, &osc.CreateSubnetOpts{
			CreateSubnetRequest: optional.NewInterface(createSubnetRequest),
		},
	)
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), fmt.Sprintf("failed to create network with CIDR '%s'", req.CIDR))
	}

	defer func() {
		if err != nil {
			if !fail.ImplementsCauser(err) {
				err = fail.Wrap(err, "")
			}

			deleteSubnetRequest := osc.DeleteSubnetRequest{
				SubnetId: resSubnet.Subnet.SubnetId,
			}

			_, _, derr := s.client.SubnetApi.DeleteSubnet(
				s.auth, &osc.DeleteSubnetOpts{
					DeleteSubnetRequest: optional.NewInterface(deleteSubnetRequest),
				},
			)
			if derr != nil {
				err = fail.AddConsequence(err, normalizeError(derr))
			}
		}
	}()

	err = s.setResourceTags(
		resSubnet.Subnet.SubnetId, map[string]string{
			"name": req.Name,
		},
	)
	if err != nil {
		return nil, err
	}
	// Prevent automatic assignment of public ip to VM created in the subnet
	updateSubnetRequest := osc.UpdateSubnetRequest{
		MapPublicIpOnLaunch: false,
		SubnetId:            resSubnet.Subnet.SubnetId,
	}
	_, _, err = s.client.SubnetApi.UpdateSubnet(
		s.auth, &osc.UpdateSubnetOpts{
			UpdateSubnetRequest: optional.NewInterface(updateSubnetRequest),
		},
	)
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), fmt.Sprintf("failed to create subnet '%s'", req.CIDR))
	}
	return &resSubnet.Subnet, nil
}

// CreateNetwork creates a network named name
func (s *Stack) CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	// Check if CIDR intersects with VPC cidr; if not, error
	vpc, err := s.getVpc(s.Options.Network.VPCID)
	if err != nil {
		return nil, fail.Errorf(fmt.Sprintf("cannot create subnet with CIDR '%s'", req.CIDR), err)
	}
	ok, err := utils.DoCIDRsIntersect(vpc.IpRange, req.CIDR)
	if err != nil {
		return nil, fail.Errorf(
			fmt.Sprintf(
				"cannot create subnet with CIDR '%s': not inside VPC CIDR '%s'", req.CIDR, vpc.IpRange,
			), nil,
		)
	}
	if !ok {
		return nil, fail.Errorf(
			fmt.Sprintf(
				"cannot create subnet with CIDR '%s': not inside VPC CIDR '%s'", req.CIDR, vpc.IpRange,
			), nil,
		)
	}
	if vpc.IpRange == req.CIDR {
		return nil, fail.Errorf(
			fmt.Sprintf(
				"cannot create subnet with CIDR '%s': identical to VPC CIDR, choose a subnet of '%s'", req.CIDR,
				vpc.IpRange,
			), nil,
		)
	}

	// update defaut security group to allow external trafic
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
		return nil, fail.InconsistentError("Inconsistent provider response")
	}

	net := abstract.NewNetwork()
	net.ID = subnet.SubnetId
	net.CIDR = subnet.IpRange
	net.IPVersion = ipversion.IPv4
	net.Name = req.Name

	return net, nil
}

func (s *Stack) getSubnet(id string) (*osc.Subnet, fail.Error) {
	readSubnetsRequest := osc.ReadSubnetsRequest{
		Filters: osc.FiltersSubnet{
			SubnetIds: []string{id},
		},
	}
	res, _, err := s.client.SubnetApi.ReadSubnets(
		s.auth, &osc.ReadSubnetsOpts{
			ReadSubnetsRequest: optional.NewInterface(readSubnetsRequest),
		},
	)
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), fmt.Sprintf("failed to get subnet '%s'", id))
	}
	if len(res.Subnets) > 1 {
		return nil, fail.InconsistentError("Inconstent provider response")
	}
	if len(res.Subnets) == 0 {
		return nil, nil
	}
	return &res.Subnets[0], nil

}

func toNetwork(subnet *osc.Subnet) *abstract.Network {
	net := abstract.NewNetwork()
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
func (s *Stack) GetNetwork(id string) (*abstract.Network, fail.Error) {
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
func (s *Stack) GetNetworkByName(name string) (*abstract.Network, fail.Error) {
	readSubnetsRequest := osc.ReadSubnetsRequest{
		Filters: osc.FiltersSubnet{
			NetIds: []string{s.Options.Network.VPCID},
		},
	}
	res, _, err := s.client.SubnetApi.ReadSubnets(
		s.auth, &osc.ReadSubnetsOpts{
			ReadSubnetsRequest: optional.NewInterface(readSubnetsRequest),
		},
	)
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), fmt.Sprintf("failed to get subnet '%s'", name))
	}
	if len(res.Subnets) == 0 {
		return nil, fail.NotFoundError(fmt.Sprintf("No network named %s", name))
	}
	var subnets []osc.Subnet
	for _, subnet := range res.Subnets {
		if getResourceTag(subnet.Tags, "name", "") == name {
			subnets = append(subnets, subnet)
		}
	}
	if len(subnets) > 1 {
		return nil, fail.InconsistentError(fmt.Sprintf("More than one subnet with name %s", name))
	}
	if len(subnets) == 0 {
		return nil, fail.NotFoundError(fmt.Sprintf("No subnet with name %s", name))
	}

	return toNetwork(&res.Subnets[0]), nil
}

// ListNetworks lists all networks
func (s *Stack) ListNetworks() ([]*abstract.Network, fail.Error) {
	readSubnetsRequest := osc.ReadSubnetsRequest{
		Filters: osc.FiltersSubnet{
			NetIds: []string{s.Options.Network.VPCID},
		},
	}
	res, _, err := s.client.SubnetApi.ReadSubnets(
		s.auth, &osc.ReadSubnetsOpts{
			ReadSubnetsRequest: optional.NewInterface(readSubnetsRequest),
		},
	)
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), "failed to list networks")
	}
	var nets []*abstract.Network
	for _, onet := range res.Subnets {
		theSubnet := onet
		nets = append(nets, toNetwork(&theSubnet))
	}

	return nets, nil
}

// ListNetworks lists all networks
func (s *Stack) listNetworksByHost(hostID string) ([]*abstract.Network, []osc.Nic, fail.Error) {
	readNicsRequest := osc.ReadNicsRequest{
		Filters: osc.FiltersNic{
			LinkNicVmIds: []string{hostID},
		},
	}
	res, _, err := s.client.NicApi.ReadNics(
		s.auth, &osc.ReadNicsOpts{
			ReadNicsRequest: optional.NewInterface(readNicsRequest),
		},
	)
	if err != nil {
		return nil, nil, fail.Wrap(normalizeError(err), fmt.Sprintf("failed to list networks of host '%s'", hostID))
	}

	var subnets []*abstract.Network
	for _, nic := range res.Nics {
		subnet, err := s.getSubnet(nic.SubnetId)
		if err != nil {
			return nil, nil, fail.Wrap(err, fmt.Sprintf("failed to list networks of host '%s'", hostID))
		}
		subnets = append(subnets, toNetwork(subnet))
	}
	return subnets, res.Nics, nil
}

func (s *Stack) deleteSecurityGroup(onet *osc.Net) error {
	readSecurityGroupsRequest := osc.ReadSecurityGroupsRequest{
		DryRun:  false,
		Filters: osc.FiltersSecurityGroup{},
	}
	res, _, err := s.client.SecurityGroupApi.ReadSecurityGroups(
		s.auth, &osc.ReadSecurityGroupsOpts{
			ReadSecurityGroupsRequest: optional.NewInterface(readSecurityGroupsRequest),
		},
	)
	if err != nil {
		return normalizeError(err)
	}
	if len(res.SecurityGroups) == 0 {
		logrus.Warnf("No security group in network %s", onet.NetId)
		return nil
	}
	for _, sg := range res.SecurityGroups {
		if sg.NetId != onet.NetId {
			break
		}
		deleteSecurityGroupRequest := osc.DeleteSecurityGroupRequest{
			SecurityGroupId: sg.SecurityGroupId,
		}
		_, _, err = s.client.SecurityGroupApi.DeleteSecurityGroup(
			s.auth, &osc.DeleteSecurityGroupOpts{
				DeleteSecurityGroupRequest: optional.NewInterface(deleteSecurityGroupRequest),
			},
		)
		if err != nil {
			return normalizeError(err)
		}
	}
	return nil
}

func (s *Stack) deleteSubnet(id string) error {
	// Delete subnets
	deleteSubnetRequest := osc.DeleteSubnetRequest{
		SubnetId: id,
	}
	_, _, err := s.client.SubnetApi.DeleteSubnet(
		s.auth, &osc.DeleteSubnetOpts{
			DeleteSubnetRequest: optional.NewInterface(deleteSubnetRequest),
		},
	)
	return normalizeError(err)
}

// DeleteNetwork deletes the network identified by id
func (s *Stack) DeleteNetwork(id string) error {
	// Reads NIS that belong to the subnet
	readNicsRequest := osc.ReadNicsRequest{
		Filters: osc.FiltersNic{
			SubnetIds: []string{id},
		},
	}
	res, _, err := s.client.NicApi.ReadNics(
		s.auth, &osc.ReadNicsOpts{
			ReadNicsRequest: optional.NewInterface(readNicsRequest),
		},
	)
	if err != nil {
		logrus.Debugf("Error reading NICS: %v", normalizeError(err))
	}

	if len(res.Nics) > 0 {
		// Delete should succeed only when something goes wrong when deleting VMs
		err = s.deleteNics(res.Nics)
		if err == nil {
			logrus.Debugf("Check if nothing goes wrong deleting a VM")
		}
	}

	return s.deleteSubnet(id)
}
