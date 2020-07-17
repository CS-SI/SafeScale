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
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"

	"github.com/antihax/optional"
	"github.com/outscale/osc-sdk-go/osc"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

func (s *Stack) createSubnet(req abstract.NetworkRequest, vpcID string) (_ *osc.Subnet, xerr fail.Error) {
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
		return nil, fail.Wrap(normalizeError(err), fmt.Sprintf("failed to create network with CIDR '%s'", req.CIDR))
	}

	defer func() {
		if xerr != nil {
			deleteSubnetRequest := osc.DeleteSubnetRequest{
				SubnetId: resSubnet.Subnet.SubnetId,
			}
			_, _, derr := s.client.SubnetApi.CreateSubnet(s.auth, &osc.CreateSubnetOpts{
				CreateSubnetRequest: optional.NewInterface(deleteSubnetRequest),
			})
			if derr != nil {
				_ = xerr.AddConsequence(normalizeError(derr))
			}
		}
	}()

	xerr = s.setResourceTags(resSubnet.Subnet.SubnetId, map[string]string{
		"name": req.Name,
	})
	if xerr != nil {
		return nil, xerr
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
		return nil, normalizeError(err)
	}
	return &resSubnet.Subnet, nil
}

// CreateNetwork creates a network named name
func (s *Stack) CreateNetwork(req abstract.NetworkRequest) (an *abstract.Network, xerr fail.Error) {
	emptyNetwork := abstract.NewNetwork()
	if s == nil {
		return emptyNetwork, fail.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stacks.outscale"), "(%v)", req).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	// Check if CIDR intersects with VPC cidr; if not, error
	vpc, xerr := s.getVpc(s.Options.Network.VPCID)
	if xerr != nil {
		return emptyNetwork, xerr
	}

//	ok, xerr := netutils.DoCIDRsIntersect(vpc.IpRange), req.CIDR)
	ok, err := netutils.CIDRString(vpc.IpRange).Contains(netutils.CIDRString(req.CIDR))
	if err != nil {
		return emptyNetwork, fail.Wrap(err, "failed to determine if network CIDR '%s' is inside VPC CIDR ('%s')", req.CIDR, vpc.IpRange)
	}
	if !ok {
		return emptyNetwork, fail.InvalidRequestError("network CIDR '%s' must be inside VPC CIDR ('%s')", req.CIDR, vpc.IpRange)
	}
	if vpc.IpRange == req.CIDR {
		return emptyNetwork, fail.InvalidRequestError("network CIDR '%s' cannot be equal to VPC CIDR ('%s')", req.CIDR, vpc.IpRange)
	}

	// update defaut security group to allow external trafic
	secgroup, xerr := s.getNetworkSecurityGroup(s.Options.Network.VPCID)
	if xerr != nil {
		return emptyNetwork, xerr
	}
	if secgroup == nil {
		return emptyNetwork, fail.InconsistentError("inconsistent provider response when reading network security group of VPC")
	}

	subnet, xerr := s.createSubnet(req, s.Options.Network.VPCID)
	if xerr != nil {
		return emptyNetwork, xerr
	}
	if subnet == nil {
		return emptyNetwork, fail.InconsistentError("inconsistent provider response on subnet creation")
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
	res, _, err := s.client.SubnetApi.ReadSubnets(s.auth, &osc.ReadSubnetsOpts{
		ReadSubnetsRequest: optional.NewInterface(readSubnetsRequest),
	})
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
func (s *Stack) GetNetwork(id string) (_ *abstract.Network, xerr fail.Error) {
	emptyNetwork := abstract.NewNetwork()
	if s == nil {
		return emptyNetwork, fail.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stacks.outscale"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	onet, xerr := s.getSubnet(id)
	if xerr != nil {
		return nil, xerr
	}
	// Defensive coding, should not happen
	if onet == nil {
		return nil, fail.NotFoundError("failed to find network '%s'", id)
	}

	return toNetwork(onet), nil
}

// GetNetworkByName returns the network identified by name)
func (s *Stack) GetNetworkByName(name string) (_ *abstract.Network, xerr fail.Error) {
	emptyNetwork := abstract.NewNetwork()
	if s == nil {
		return emptyNetwork, fail.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stacks.outscale"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	readSubnetsRequest := osc.ReadSubnetsRequest{
		Filters: osc.FiltersSubnet{
			NetIds: []string{s.Options.Network.VPCID},
		},
	}
	res, _, err := s.client.SubnetApi.ReadSubnets(s.auth, &osc.ReadSubnetsOpts{
		ReadSubnetsRequest: optional.NewInterface(readSubnetsRequest),
	})
	if err != nil {
		return emptyNetwork, normalizeError(err)
	}
	if len(res.Subnets) == 0 {
		return emptyNetwork, fail.NotFoundError(fmt.Sprintf("No network named %s", name))
	}
	var subnets []osc.Subnet
	for _, subnet := range res.Subnets {
		if getResourceTag(subnet.Tags, "name", "") == name {
			subnets = append(subnets, subnet)
		}
	}
	if len(subnets) > 1 {
		return emptyNetwork, fail.InconsistentError("found more than one subnet with name '%s'", name)
	}
	if len(subnets) == 0 {
		return emptyNetwork, fail.NotFoundError("failed to find subnet with name '%s'", name)
	}

	return toNetwork(&res.Subnets[0]), nil
}

// ListNetworks lists all networks
func (s *Stack) ListNetworks() (_ []*abstract.Network, xerr fail.Error) {
	emptyList := make([]*abstract.Network, 0)
	if s == nil {
		return emptyList, fail.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	readSubnetsRequest := osc.ReadSubnetsRequest{
		Filters: osc.FiltersSubnet{
			NetIds: []string{s.Options.Network.VPCID},
		},
	}
	res, _, err := s.client.SubnetApi.ReadSubnets(s.auth, &osc.ReadSubnetsOpts{
		ReadSubnetsRequest: optional.NewInterface(readSubnetsRequest),
	})
	if err != nil {
		return emptyList, normalizeError(err)
	}
	var nets []*abstract.Network
	for _, onet := range res.Subnets {
		nets = append(nets, toNetwork(&onet))
	}

	return nets, nil
}

// ListNetworks lists all networks
func (s *Stack) listNetworksByHost(hostID string) ([]*abstract.Network, []osc.Nic, fail.Error) {
	emptyNetworkSlice := make([]*abstract.Network, 0)
	emptyNicSlice := make([]osc.Nic, 0)
	if s == nil {
		return emptyNetworkSlice, emptyNicSlice, fail.InvalidInstanceError()
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
		return emptyNetworkSlice, emptyNicSlice, fail.Wrap(normalizeError(err), fmt.Sprintf("failed to list networks of host '%s'", hostID))
	}

	var subnets []*abstract.Network
	for _, nic := range res.Nics {
		subnet, err := s.getSubnet(nic.SubnetId)
		if err != nil {
			return emptyNetworkSlice, emptyNicSlice, fail.Wrap(err, fmt.Sprintf("failed to list networks of host '%s'", hostID))
		}
		subnets = append(subnets, toNetwork(subnet))
	}
	return subnets, res.Nics, nil
}

func (s *Stack) deleteSecurityGroup(onet *osc.Net) fail.Error {
	readSecurityGroupsRequest := osc.ReadSecurityGroupsRequest{
		DryRun:  false,
		Filters: osc.FiltersSecurityGroup{},
	}
	res, _, err := s.client.SecurityGroupApi.ReadSecurityGroups(s.auth, &osc.ReadSecurityGroupsOpts{
		ReadSecurityGroupsRequest: optional.NewInterface(readSecurityGroupsRequest),
	})
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
		_, _, err = s.client.SecurityGroupApi.DeleteSecurityGroup(s.auth, &osc.DeleteSecurityGroupOpts{
			DeleteSecurityGroupRequest: optional.NewInterface(deleteSecurityGroupRequest),
		})
		if err != nil {
			return normalizeError(err)
		}
	}
	return nil
}

func (s *Stack) deleteSubnet(id string) fail.Error {
	deleteSubnetRequest := osc.DeleteSubnetRequest{
		SubnetId: id,
	}
	_, _, err := s.client.SubnetApi.DeleteSubnet(s.auth, &osc.DeleteSubnetOpts{
		DeleteSubnetRequest: optional.NewInterface(deleteSubnetRequest),
	})
	return normalizeError(err)
}

// DeleteNetwork deletes the network identified by id
func (s *Stack) DeleteNetwork(id string) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stacks.outscale"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

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
		logrus.Debugf("Error reading NICS: %v", normalizeError(err))
	}

	if len(res.Nics) > 0 {
		// Delete should succeed only when something goes wrong when deleting VMs
		xerr = s.deleteNics(res.Nics)
		if xerr == nil {
			logrus.Debugf("Check if nothing goes wrong deleting a VM")
		}
	}

	return s.deleteSubnet(id)
}
