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
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/antihax/optional"
	"github.com/outscale/osc-sdk-go/osc"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
)

//func (s *Stack) createSubnet(req abstract.NetworkRequest, vpcID string) (_ *osc.Subnet, xerr fail.Error) {
//	// Create a subnet with the same IPRanges than the network
//	createSubnetRequest := osc.CreateSubnetRequest{
//		IpRange:       req.IPRanges,
//		NetId:         vpcID,
//		SubregionName: s.Options.Compute.Subregion,
//	}
//	resSubnet, _, err := s.client.SubnetApi.CreateSubnet(s.auth, &osc.CreateSubnetOpts{
//		CreateSubnetRequest: optional.NewInterface(createSubnetRequest),
//	})
//	if err != nil {
//		return nil, fail.Wrap(normalizeError(err), fmt.Sprintf("failed to create network with IPRanges '%s'", req.IPRanges))
//	}
//
//	defer func() {
//		if xerr != nil {
//			deleteSubnetRequest := osc.DeleteSubnetRequest{
//				SubnetId: resSubnet.Subnet.SubnetId,
//			}
//			_, _, derr := s.client.SubnetApi.CreateSubnet(s.auth, &osc.CreateSubnetOpts{
//				CreateSubnetRequest: optional.NewInterface(deleteSubnetRequest),
//			})
//			if derr != nil {
//				_ = xerr.AddConsequence(normalizeError(derr))
//			}
//		}
//	}()
//
//	xerr = s.setResourceTags(resSubnet.Subnet.SubnetId, map[string]string{
//		"name": req.Name,
//	})
//	if xerr != nil {
//		return nil, xerr
//	}
//	// Prevent automatic assignment of public ip to VM created in the subnet
//	updateSubnetRequest := osc.UpdateSubnetRequest{
//		MapPublicIpOnLaunch: false,
//		SubnetId:            resSubnet.Subnet.SubnetId,
//	}
//	_, _, err = s.client.SubnetApi.UpdateSubnet(s.auth, &osc.UpdateSubnetOpts{
//		UpdateSubnetRequest: optional.NewInterface(updateSubnetRequest),
//	})
//	if err != nil {
//		return nil, normalizeError(err)
//	}
//	return &resSubnet.Subnet, nil
//}

// CreateNetwork creates a network named name (in OutScale terminology, a Network corresponds to a VPC)
func (s *Stack) CreateNetwork(req abstract.NetworkRequest) (an *abstract.Network, xerr fail.Error) {
	emptyNetwork := abstract.NewNetwork()
	if s == nil {
		return emptyNetwork, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%v)", req).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	createNetRequest := osc.CreateNetRequest{
		IpRange: req.CIDR,
		Tenancy: s.Options.Compute.DefaultTenancy,
	}
	respNet, _, err := s.client.NetApi.CreateNet(s.auth, &osc.CreateNetOpts{
		CreateNetRequest: optional.NewInterface(createNetRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	onet := respNet.Net

	defer func() {
		if xerr != nil {
			derr := s.DeleteNetwork(onet.NetId)
			_ = xerr.AddConsequence(derr)
		}
	}()

	xerr = s.setResourceTags(onet.NetId, map[string]string{
		"name": req.Name,
	})
	if xerr != nil {
		return nil, xerr
	}

	//req := abstract.NetworkRequest{
	//	IPRanges:       cidr,
	//	DNSServers: s.configurationOptions.DNSList,
	//	Name:       name,
	//}

	// update default security group to allow external traffic
	securityGroup, xerr := s.getNetworkSecurityGroup(onet.NetId)
	if xerr != nil {
		return nil, xerr
	}

	xerr = s.updateDefaultSecurityRules(securityGroup)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to update default security group of Network/VPC")
	}

	xerr = s.createDHCPOptionSet(req, onet)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create DHCP options set of Network/VPC")
	}

	xerr = s.createInternetService(req, onet)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create Internet Service of Network/VPC")
	}

	return toNetwork(onet), nil
}

func (s Stack) createDHCPOptionSet(req abstract.NetworkRequest, net osc.Net) fail.Error {
	if len(req.DNSServers) == 0 {
		return nil
	}
	ntpServers, xerr := s.getDefaultDhcpNtpServers(net)
	if xerr != nil {
		return xerr
	}
	createDhcpOptionsRequest := osc.CreateDhcpOptionsRequest{
		NtpServers:        ntpServers,
		DomainNameServers: req.DNSServers,
	}
	dhcpOptions, _, err := s.client.DhcpOptionApi.CreateDhcpOptions(s.auth, &osc.CreateDhcpOptionsOpts{
		CreateDhcpOptionsRequest: optional.NewInterface(createDhcpOptionsRequest),
	})
	if err != nil {
		return normalizeError(err)
	}

	defer func() {
		if xerr != nil {
			derr := s.deleteDhcpOptions(net, false)
			_ = xerr.AddConsequence(derr)
		}
	}()

	dhcpOptionID := dhcpOptions.DhcpOptionsSet.DhcpOptionsSetId
	xerr = s.setResourceTags(dhcpOptionID, map[string]string{
		"name": req.Name,
	})
	if xerr != nil {
		return xerr
	}
	updateNetRequest := osc.UpdateNetRequest{
		DhcpOptionsSetId: dhcpOptionID,
	}
	_, _, err = s.client.NetApi.ReadNets(s.auth, &osc.ReadNetsOpts{
		ReadNetsRequest: optional.NewInterface(updateNetRequest),
	})
	return normalizeError(err)
}

func (s Stack) getDefaultDhcpNtpServers(net osc.Net) ([]string, fail.Error) {
	readDhcpOptionsRequest := osc.ReadDhcpOptionsRequest{
		Filters: osc.FiltersDhcpOptions{
			DhcpOptionsSetIds: []string{net.DhcpOptionsSetId},
		},
	}
	res, _, err := s.client.DhcpOptionApi.ReadDhcpOptions(s.auth, &osc.ReadDhcpOptionsOpts{
		ReadDhcpOptionsRequest: optional.NewInterface(readDhcpOptionsRequest),
	})
	if err != nil {
		return []string{}, normalizeError(err)
	}
	if len(res.DhcpOptionsSets) != 1 {
		return []string{}, fail.InconsistentError("inconsistent provider response")
	}
	return res.DhcpOptionsSets[0].NtpServers, nil
}

func (s Stack) deleteDhcpOptions(onet osc.Net, checkName bool) fail.Error {
	// Remove DHCP options
	namedDHCPOptions, xerr := s.checkDHCPOptionsName(onet)
	if xerr != nil {
		return xerr
	}

	// prevent deleting default dhcp options
	if checkName && !namedDHCPOptions {
		return nil
	}

	deleteDhcpOptionsRequest := osc.DeleteDhcpOptionsRequest{
		DhcpOptionsSetId: onet.DhcpOptionsSetId,
	}
	_, _, err := s.client.DhcpOptionApi.DeleteDhcpOptions(s.auth, &osc.DeleteDhcpOptionsOpts{
		DeleteDhcpOptionsRequest: optional.NewInterface(deleteDhcpOptionsRequest),
	})
	return normalizeError(err)
}

func (s Stack) checkDHCPOptionsName(onet osc.Net) (bool, fail.Error) {
	tags, xerr := s.getResourceTags(onet.DhcpOptionsSetId)
	if xerr != nil {
		return false, xerr
	}
	_, ok := tags["name"]
	return ok, nil
}

func (s Stack) createInternetService(req abstract.NetworkRequest, onet osc.Net) fail.Error {
	// Create internet service to allow internet access from VMs attached to the network
	isResp, _, err := s.client.InternetServiceApi.CreateInternetService(s.auth, nil)
	if err != nil {
		return normalizeError(err)
	}

	xerr := s.setResourceTags(isResp.InternetService.InternetServiceId, map[string]string{
		"name": req.Name,
	})
	if xerr != nil {
		return xerr
	}

	linkInternetServiceRequest := osc.LinkInternetServiceRequest{
		InternetServiceId: isResp.InternetService.InternetServiceId,
		NetId:             onet.NetId,
	}
	_, _, err = s.client.InternetServiceApi.LinkInternetService(s.auth, &osc.LinkInternetServiceOpts{
		LinkInternetServiceRequest: optional.NewInterface(linkInternetServiceRequest),
	})
	if err != nil {
		return normalizeError(err)
	}
	return s.updateRouteTable(onet, isResp.InternetService)
}

func (s Stack) updateRouteTable(onet osc.Net, is osc.InternetService) fail.Error {
	table, xerr := s.getDefaultRouteTable(onet)
	if xerr != nil {
		return xerr
	}
	createRouteRequest := osc.CreateRouteRequest{
		DestinationIpRange: "0.0.0.0/0",
		GatewayId:          is.InternetServiceId,
		RouteTableId:       table.RouteTableId,
	}
	_, _, err := s.client.RouteApi.CreateRoute(s.auth, &osc.CreateRouteOpts{
		CreateRouteRequest: optional.NewInterface(createRouteRequest),
	})
	return normalizeError(err)
}

func (s Stack) getDefaultRouteTable(onet osc.Net) (*osc.RouteTable, fail.Error) {
	readRouteTablesRequest := osc.ReadRouteTablesRequest{
		Filters: osc.FiltersRouteTable{
			NetIds: []string{onet.NetId},
		},
	}
	res, _, err := s.client.RouteTableApi.ReadRouteTables(s.auth, &osc.ReadRouteTablesOpts{
		ReadRouteTablesRequest: optional.NewInterface(readRouteTablesRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(res.RouteTables) != 1 {
		return nil, fail.InconsistentError("inconsistent provider response when trying to default route table")
	}
	return &res.RouteTables[0], nil
}

//func (s *Stack) getSubnet(id string) (*osc.Subnet, fail.Error) {
//	readSubnetsRequest := osc.ReadSubnetsRequest{
//		Filters: osc.FiltersSubnet{
//			SubnetIds: []string{id},
//		},
//	}
//	res, _, err := s.client.SubnetApi.ReadSubnets(s.auth, &osc.ReadSubnetsOpts{
//		ReadSubnetsRequest: optional.NewInterface(readSubnetsRequest),
//	})
//	if err != nil {
//		return nil, fail.Wrap(normalizeError(err), fmt.Sprintf("failed to get subnet '%s'", id))
//	}
//	if len(res.Subnets) > 1 {
//		return nil, fail.InconsistentError("Inconstent provider response")
//	}
//	if len(res.Subnets) == 0 {
//		return nil, nil
//	}
//	return &res.Subnets[0], nil
//
//}

func toNetwork(in osc.Net) *abstract.Network {
	out := abstract.NewNetwork()
	out.ID = in.NetId
	out.CIDR = in.IpRange
	tags := unwrapTags(in.Tags)
	if name, ok := tags["name"]; ok {
		out.Name = name
	}
	return out
}

// InspectNetwork returns the network identified by id
func (s *Stack) InspectNetwork(id string) (_ *abstract.Network, xerr fail.Error) {
	emptyNetwork := abstract.NewNetwork()
	if s == nil {
		return emptyNetwork, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	readNetsRequest := osc.ReadNetsRequest{
		Filters: osc.FiltersNet{
			NetIds: []string{id},
		},
	}
	resNet, _, err := s.client.NetApi.ReadNets(s.auth, &osc.ReadNetsOpts{
		ReadNetsRequest: optional.NewInterface(readNetsRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(resNet.Nets) == 0 {
		return nil, fail.NotFoundError("failed to find Network/VPC '%s'", id)
	}

	return toNetwork(resNet.Nets[0]), nil
}

// InspectNetworkByName returns the network identified by name)
func (s *Stack) InspectNetworkByName(name string) (_ *abstract.Network, xerr fail.Error) {
	emptyNetwork := abstract.NewNetwork()
	if s == nil {
		return emptyNetwork, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	readNetsRequest := osc.ReadNetsRequest{
		Filters: osc.FiltersNet{
			Tags: []string{fmt.Sprintf("%s=%s", "name", name)},
		},
	}
	res, _, err := s.client.NetApi.ReadNets(s.auth, &osc.ReadNetsOpts{
		ReadNetsRequest: optional.NewInterface(readNetsRequest),
	})
	if err != nil {
		return emptyNetwork, normalizeError(err)
	}
	if len(res.Nets) == 0 {
		return emptyNetwork, fail.NotFoundError("failed to find a Network/VPC with name '%s'", name)
	}

	return toNetwork(res.Nets[0]), nil
}

// ListNetworks lists all networks
func (s *Stack) ListNetworks() (_ []*abstract.Network, xerr fail.Error) {
	emptyList := make([]*abstract.Network, 0)
	if s == nil {
		return emptyList, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	readNetsRequest := osc.ReadNetsRequest{
		Filters: osc.FiltersNet{},
	}
	resNet, _, err := s.client.NetApi.ReadNets(s.auth, &osc.ReadNetsOpts{
		ReadNetsRequest: optional.NewInterface(readNetsRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(resNet.Nets) == 0 {
		return nil, fail.NotFoundError("no Network/VPC found")
	}

	var nets []*abstract.Network
	for _, v := range resNet.Nets {
		nets = append(nets, toNetwork(v))
	}

	return nets, nil
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

//func (s *Stack) deleteSubnet(id string) fail.Error {
//	deleteSubnetRequest := osc.DeleteSubnetRequest{
//		SubnetId: id,
//	}
//	_, _, err := s.client.SubnetApi.DeleteSubnet(s.auth, &osc.DeleteSubnetOpts{
//		DeleteSubnetRequest: optional.NewInterface(deleteSubnetRequest),
//	})
//	return normalizeError(err)
//}

// DeleteNetwork deletes the network identified by id
func (s *Stack) DeleteNetwork(id string) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
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
		// Remove should succeed only when something goes wrong when deleting VMs
		xerr = s.deleteNICs(res.Nics)
		if xerr == nil {
			logrus.Debugf("Check if nothing goes wrong deleting a VM")
		}
	}

	return nil
}

// CreateSubnet creates a Subnet
func (s *Stack) CreateSubnet(req abstract.SubnetRequest) (as *abstract.Subnet, xerr fail.Error) {
	emptySubnet := abstract.NewSubnet()
	if s == nil {
		return emptySubnet, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%v)", req).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	// Check if IPRanges intersects with VPC cidr; if not, error
	vpc, xerr := s.InspectNetwork(req.Network)
	if xerr != nil {
		return emptySubnet, xerr
	}

	//	ok, xerr := netutils.DoCIDRsIntersect(vpc.IpRange), req.IPRanges)
	ok, err := netutils.CIDRString(vpc.CIDR).Contains(netutils.CIDRString(req.CIDR))
	if err != nil {
		return emptySubnet, fail.Wrap(err, "failed to determine if network IPRanges '%s' is inside VPC IPRanges ('%s')", req.CIDR, vpc.CIDR)
	}
	if !ok {
		return emptySubnet, fail.InvalidRequestError("network IPRanges '%s' must be inside VPC IPRanges ('%s')", req.CIDR, vpc.CIDR)
	}
	if vpc.CIDR == req.CIDR {
		return emptySubnet, fail.InvalidRequestError("network IPRanges '%s' cannot be equal to VPC IPRanges ('%s')", req.CIDR, vpc.CIDR)
	}

	// Create a subnet with the same IPRanges than the network
	createSubnetRequest := osc.CreateSubnetRequest{
		IpRange:       req.CIDR,
		NetId:         vpc.ID,
		SubregionName: s.Options.Compute.Subregion,
	}
	resSubnet, _, err := s.client.SubnetApi.CreateSubnet(s.auth, &osc.CreateSubnetOpts{
		CreateSubnetRequest: optional.NewInterface(createSubnetRequest),
	})
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), fmt.Sprintf("failed to create network with IPRanges '%s'", req.CIDR))
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

	_ = osc.Subnet{}
	as = abstract.NewSubnet()
	as.ID = resSubnet.Subnet.SubnetId
	as.CIDR = resSubnet.Subnet.IpRange
	as.IPVersion = ipversion.IPv4
	as.Name = req.Name
	as.Network = resSubnet.Subnet.NetId

	return as, nil
}

// InspectSubnet returns the Subnet identified by id
func (s *Stack) InspectSubnet(id string) (_ *abstract.Subnet, xerr fail.Error) {
	emptySubnet := abstract.NewSubnet()
	if s == nil {
		return emptySubnet, fail.InvalidInstanceError()
	}
	if id == "" {
		return emptySubnet, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	readSubnetsRequest := osc.ReadSubnetsRequest{
		Filters: osc.FiltersSubnet{
			SubnetIds: []string{id},
		},
	}
	res, _, err := s.client.SubnetApi.ReadSubnets(s.auth, &osc.ReadSubnetsOpts{
		ReadSubnetsRequest: optional.NewInterface(readSubnetsRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(res.Subnets) > 1 {
		return nil, fail.InconsistentError("inconsistent provider response")
	}
	if len(res.Subnets) == 0 {
		return nil, fail.NotFoundError("failed to find subnet %s", id)
	}

	return toSubnet(res.Subnets[0]), nil
}

// InspectSubnetByName returns the Subnet identified by id
func (s *Stack) InspectSubnetByName(networkRef, subnetName string) (_ *abstract.Subnet, xerr fail.Error) {
	emptySubnet := abstract.NewSubnet()
	if s == nil {
		return emptySubnet, fail.InvalidInstanceError()
	}
	if subnetName == "" {
		return emptySubnet, fail.InvalidParameterError("subnetName", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s, %s)", networkRef, subnetName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	filters := osc.FiltersSubnet{
		SubnetIds: []string{subnetName},
	}

	var an *abstract.Network
	// If networkRef is not empty string, networkRef can be an ID or a Name; let's find out the ID of this network for sure
	if networkRef != "" {
		an, xerr = s.InspectNetwork(networkRef)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				an, xerr = s.InspectNetworkByName(networkRef)
			default:
				return nil, xerr
			}
		}
		if xerr != nil {
			return nil, xerr
		}
		if an != nil {
			filters.NetIds = []string{an.ID}
		}
	}

	// FIXME: embed in a retry.WhileCommunicationUnsuccessful...
	res, _, err := s.client.SubnetApi.ReadSubnets(s.auth, &osc.ReadSubnetsOpts{
		ReadSubnetsRequest: optional.NewInterface(osc.ReadSubnetsRequest{Filters: filters}),
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(res.Subnets) > 1 {
		return nil, fail.InconsistentError("inconsistent provider response")
	}
	if len(res.Subnets) == 0 {
		if an != nil {
			return nil, fail.NotFoundError("failed to find subnet '%s' in Network/VPC '%s'", subnetName, an.Name)
		}
		return nil, fail.NotFoundError("failed to find subnet '%s'", subnetName)
	}
	//
	return toSubnet(res.Subnets[0]), nil
}

func toSubnet(subnet osc.Subnet) *abstract.Subnet {
	out := abstract.NewSubnet()
	out.ID = subnet.SubnetId
	out.CIDR = subnet.IpRange
	out.IPVersion = ipversion.IPv4
	out.Network = subnet.NetId
	tags := unwrapTags(subnet.Tags)
	if name, ok := tags["name"]; ok {
		out.Name = name
	}
	return out
}

// ListSubnets lists all subnets
func (s *Stack) ListSubnets(networkRef string) (_ []*abstract.Subnet, xerr fail.Error) {
	emptyList := make([]*abstract.Subnet, 0)
	if s == nil {
		return emptyList, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	if networkRef == "" {
		networkRef = s.Options.Network.VPCID
	}
	if networkRef != "" {
		return nil, fail.InvalidParameterError("networkRef", "cannot be empty string if tenants does not set keyword 'VPCNAME'")
	}

	an, xerr := s.InspectNetwork(networkRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			if an, xerr = s.InspectNetworkByName(networkRef); xerr != nil {
				return emptyList, xerr
			}
		default:
			return emptyList, xerr
		}
	}

	readSubnetsRequest := osc.ReadSubnetsRequest{
		Filters: osc.FiltersSubnet{
			NetIds: []string{an.ID},
		},
	}
	res, _, err := s.client.SubnetApi.ReadSubnets(s.auth, &osc.ReadSubnetsOpts{
		ReadSubnetsRequest: optional.NewInterface(readSubnetsRequest),
	})
	if err != nil {
		return emptyList, normalizeError(err)
	}
	var subnets []*abstract.Subnet
	for _, v := range res.Subnets {
		subnets = append(subnets, toSubnet(v))
	}

	return subnets, nil
}

func (s *Stack) listSubnetsByHost(hostID string) ([]*abstract.Subnet, []osc.Nic, fail.Error) {
	var (
		emptySubnetSlice []*abstract.Subnet
		emptyNicSlice    []osc.Nic
	)

	if s == nil {
		return emptySubnetSlice, emptyNicSlice, fail.InvalidInstanceError()
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
		return emptySubnetSlice, emptyNicSlice, normalizeError(err)
	}

	var subnets []*abstract.Subnet
	for _, nic := range res.Nics {
		subnet, xerr := s.InspectSubnet(nic.SubnetId)
		if xerr != nil {
			return emptySubnetSlice, emptyNicSlice, xerr
		}
		subnets = append(subnets, subnet)
	}
	return subnets, res.Nics, nil
}

// DeleteSubnet deletes the subnet identified by id
func (s *Stack) DeleteSubnet(id string) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
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
		// Remove should succeed only when something goes wrong when deleting VMs
		xerr = s.deleteNICs(res.Nics)
		if xerr == nil {
			logrus.Debugf("Check if nothing goes wrong deleting a VM")
		}
	}

	deleteSubnetRequest := osc.DeleteSubnetRequest{
		SubnetId: id,
	}
	_, _, err = s.client.SubnetApi.DeleteSubnet(s.auth, &osc.DeleteSubnetOpts{
		DeleteSubnetRequest: optional.NewInterface(deleteSubnetRequest),
	})
	return normalizeError(err)
}

// BindSecurityGroupToSubnet binds a security group to a network
func (s *Stack) BindSecurityGroupToSubnet(ref string, sgParam stacks.SecurityGroupParameter) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}

	asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	asg, xerr = s.InspectSecurityGroup(asg)
	if xerr != nil {
		return xerr
	}

	return fail.NotImplementedError()
}

// UnbindSecurityGroupFromSubnet unbinds a security group from a host
func (s *Stack) UnbindSecurityGroupFromSubnet(ref string, sgParam stacks.SecurityGroupParameter) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}

	asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	asg, xerr = s.InspectSecurityGroup(asg)
	if xerr != nil {
		return xerr
	}

	return fail.NotImplementedError()
}
