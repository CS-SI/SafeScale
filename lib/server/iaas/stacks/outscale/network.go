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
	"github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/antihax/optional"
	"github.com/outscale-dev/osc-sdk-go/osc"
	"github.com/sirupsen/logrus"
	"reflect"
)

func (s *Stack) createSubnet(req resources.NetworkRequest, vpcID string) (_ *osc.Subnet, err error) {
	// Create a subnet with the same CIDR than the network
	createSubnetRequest := osc.CreateSubnetRequest{
		IpRange:       req.CIDR,
		NetId:         vpcID,
		SubregionName: s.Options.Compute.Subregion,
	}
	resSubnet, _, err := s.client.SubnetApi.CreateSubnet(s.auth, &osc.CreateSubnetOpts{
		CreateSubnetRequest: optional.NewInterface(createSubnetRequest),
	})
	if err != nil {
		switch realErr := err.(type) {
		case osc.GenericOpenAPIError:
			switch model := realErr.Model().(type) {
			case osc.ErrorResponse:
				switch model.Errors[0].Code {
				case "9044":
					return nil, scerr.DuplicateError(fmt.Sprintf("there is already a network '%s'", req.CIDR))
				default:
					merr := model.Errors[0]
					reqId := model.ResponseContext.RequestId
					return nil, scerr.UnknownError(fmt.Sprintf("from outscale driver, code='%s', type='%s', details='%s', requestId='%s'", merr.Code, merr.Type, merr.Details, reqId))
				}
			default:
				return nil, scerr.UnknownError(fmt.Sprintf("from outscale driver, model='%s', error='%s'", reflect.TypeOf(realErr.Model()), realErr.Error()))
			}
		default:
			return nil, err
		}
	}

	defer func() {
		if err != nil {
			if !scerr.ImplementsCauser(err) {
				err = scerr.Wrap(err, "")
			}

			deleteSubnetRequest := osc.DeleteSubnetRequest{
				SubnetId: resSubnet.Subnet.SubnetId,
			}
			_, _, derr := s.client.SubnetApi.CreateSubnet(s.auth, &osc.CreateSubnetOpts{
				CreateSubnetRequest: optional.NewInterface(deleteSubnetRequest),
			})
			if derr != nil {
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	err = s.setResourceTags(resSubnet.Subnet.SubnetId, map[string]string{
		"name": req.Name,
	})

	if err != nil {
		return nil, err
	}
	// Prevent automatic assignment of public ip to VM created in the subnet
	updateSubnetRequest := osc.UpdateSubnetRequest{
		MapPublicIpOnLaunch: false,
		SubnetId:            resSubnet.Subnet.SubnetId,
	}
	_, _, err = s.client.SubnetApi.UpdateSubnet(s.auth, &osc.UpdateSubnetOpts{
		UpdateSubnetRequest: optional.NewInterface(updateSubnetRequest),
	})
	if err != nil {
		return nil, err
	}
	return &resSubnet.Subnet, nil
}

// CreateNetwork creates a network named name
func (s *Stack) CreateNetwork(req resources.NetworkRequest) (*resources.Network, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	// update defaut security group to allow external trafic
	secgroup, err := s.getNetworkSecurityGroup(s.Options.Network.VPCID)
	if err != nil {
		return nil, err
	}
	if secgroup == nil {
		return nil, err
	}

	// Check if CIDR intersects with VPC cidr; if not, error
	vpc, err := s.getVpc(s.Options.Network.VPCID)
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("cannot create subnet with CIDR '%s'", req.CIDR), err)
	}
	ok, err := utils.DoCIDRsIntersect(vpc.IpRange, req.CIDR)
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("cannot create subnet with CIDR '%s': not inside VPC CIDR '%s'", req.CIDR, vpc.IpRange), nil)
	}
	if !ok {
		return nil, scerr.Errorf(fmt.Sprintf("cannot create subnet with CIDR '%s': not inside VPC CIDR '%s'", req.CIDR, vpc.IpRange), nil)
	}
	if vpc.IpRange == req.CIDR {
		return nil, scerr.Errorf(fmt.Sprintf("cannot create subnet with CIDR '%s': identical to VPC CIDR, choose a subnet of '%s'", req.CIDR, vpc.IpRange), nil)
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

func (s *Stack) getSubnet(id string) (*osc.Subnet, error) {
	readSubnetsRequest := osc.ReadSubnetsRequest{
		Filters: osc.FiltersSubnet{
			SubnetIds: []string{id},
		},
	}
	res, _, err := s.client.SubnetApi.ReadSubnets(s.auth, &osc.ReadSubnetsOpts{
		ReadSubnetsRequest: optional.NewInterface(readSubnetsRequest),
	})
	if err != nil {
		return nil, err
	}
	if len(res.Subnets) > 1 {
		return nil, scerr.InconsistentError("Inconstent provider response")
	}
	if len(res.Subnets) == 0 {
		return nil, nil
	}
	return &res.Subnets[0], nil

}

func toNetwork(subnet *osc.Subnet) *resources.Network {
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
	readSubnetsRequest := osc.ReadSubnetsRequest{
		Filters: osc.FiltersSubnet{
			NetIds: []string{s.Options.Network.VPCID},
		},
	}
	res, _, err := s.client.SubnetApi.ReadSubnets(s.auth, &osc.ReadSubnetsOpts{
		ReadSubnetsRequest: optional.NewInterface(readSubnetsRequest),
	})
	if err != nil {
		return nil, err
	}
	if len(res.Subnets) == 0 {
		return nil, scerr.NotFoundError(fmt.Sprintf("No network named %s", name))
	}
	var subnets []osc.Subnet
	for _, subnet := range res.Subnets {
		if getResourceTag(subnet.Tags, "name", "") == name {
			subnets = append(subnets, subnet)
		}
	}
	if len(subnets) > 1 {
		return nil, scerr.InconsistentError(fmt.Sprintf("More than one subnet with name %s", name))
	}
	if len(subnets) == 0 {
		return nil, scerr.NotFoundError(fmt.Sprintf("No subnet with name %s", name))
	}

	return toNetwork(&res.Subnets[0]), nil
}

// ListNetworks lists all networks
func (s *Stack) ListNetworks() ([]*resources.Network, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	readSubnetsRequest := osc.ReadSubnetsRequest{
		Filters: osc.FiltersSubnet{
			NetIds: []string{s.Options.Network.VPCID},
		},
	}
	res, _, err := s.client.SubnetApi.ReadSubnets(s.auth, &osc.ReadSubnetsOpts{
		ReadSubnetsRequest: optional.NewInterface(readSubnetsRequest),
	})
	if err != nil {
		return nil, err
	}
	var nets []*resources.Network
	for _, onet := range res.Subnets {
		nets = append(nets, toNetwork(&onet))
	}

	return nets, nil
}

// ListNetworks lists all networks
func (s *Stack) listNetworksByHost(hostID string) ([]*resources.Network, []osc.Nic, error) {
	if s == nil {
		return nil, nil, scerr.InvalidInstanceError()
	}
	readNicsRequest := osc.ReadNicsRequest{
		Filters: osc.FiltersNic{
			LinkNicVmIds: []string{hostID},
		},
	}
	res, _, err := s.client.NicApi.ReadNics(s.auth, &osc.ReadNicsOpts{
		ReadNicsRequest: optional.NewInterface(readNicsRequest),
	})
	if err != nil {
		return nil, nil, err
	}

	var subnets []*resources.Network
	for _, nic := range res.Nics {
		subnet, err := s.getSubnet(nic.SubnetId)
		if err != nil {
			return nil, nil, err
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
	res, _, err := s.client.SecurityGroupApi.ReadSecurityGroups(s.auth, &osc.ReadSecurityGroupsOpts{
		ReadSecurityGroupsRequest: optional.NewInterface(readSecurityGroupsRequest),
	})
	if err != nil {
		return err
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
		_, _, err = s.client.SecurityGroupApi.DeleteSecurityGroup(s.auth, &osc.DeleteSecurityGroupOpts{
			DeleteSecurityGroupRequest: optional.NewInterface(deleteSecurityGroupRequest),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Stack) deleteSubnet(id string) error {
	// Delete subnets
	deleteSubnetRequest := osc.DeleteSubnetRequest{
		SubnetId: id,
	}
	_, _, err := s.client.SubnetApi.DeleteSubnet(s.auth, &osc.DeleteSubnetOpts{
		DeleteSubnetRequest: optional.NewInterface(deleteSubnetRequest),
	})
	return err
}

// DeleteNetwork deletes the network identified by id
func (s *Stack) DeleteNetwork(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	// Reads NIS that belong to the subnet
	readNicsRequest := osc.ReadNicsRequest{
		Filters: osc.FiltersNic{
			SubnetIds: []string{id},
		},
	}
	res, _, err := s.client.NicApi.ReadNics(s.auth, &osc.ReadNicsOpts{
		ReadNicsRequest: optional.NewInterface(readNicsRequest),
	})
	if err != nil {
		logrus.Debugf("Error reading NICS :%v", err)
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
