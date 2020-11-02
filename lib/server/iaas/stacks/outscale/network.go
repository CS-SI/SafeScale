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
	"github.com/sirupsen/logrus"

	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
)

const tagNameLabel = "name"

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (s stack) HasDefaultNetwork() bool {
	if s.IsNull() {
		return false
	}
	return s.vpc != nil
}

// GetDefaultNetwork returns the *abstract.Network corresponding to the default network
func (s stack) GetDefaultNetwork() (*abstract.Network, fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if s.vpc == nil {
		return nil, fail.NotFoundError("no default Network in stack")
	}
	return s.vpc, nil
}

// CreateNetwork creates a network named name (in OutScale terminology, a Network corresponds to a VPC)
func (s stack) CreateNetwork(req abstract.NetworkRequest) (an *abstract.Network, xerr fail.Error) {
	nullAN := abstract.NewNetwork()
	if s.IsNull() {
		return nullAN, fail.InvalidInstanceError()
	}
	if req.CIDR == "" {
		req.CIDR = stacks.DefaultNetworkCIDR
	}
	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%v)", req).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	resp, xerr := s.rpcCreateNetwork(req.Name, req.CIDR)
	if xerr != nil {
		return nullAN, xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			if derr := s.DeleteNetwork(resp.NetId); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Network '%s'", req.Name))
			}
		}
	}()

	// update default security group to allow external traffic
	securityGroup, xerr := s.rpcReadSecurityGroupByName(resp.NetId, "default")
	if xerr != nil {
		return nullAN, xerr
	}

	xerr = s.updateDefaultSecurityRules(securityGroup)
	if xerr != nil {
		return nullAN, fail.Wrap(xerr, "failed to update default security group of Network/VPC")
	}

	if xerr = s.createDHCPOptionSet(req, resp); xerr != nil {
		return nullAN, fail.Wrap(xerr, "failed to create DHCP options set of Network/VPC")
	}

	if xerr = s.createInternetService(req, resp); xerr != nil {
		return nullAN, fail.Wrap(xerr, "failed to create Internet Service of Network/VPC")
	}

	return toAbstractNetwork(resp), nil
}

func (s stack) createDHCPOptionSet(req abstract.NetworkRequest, net osc.Net) fail.Error {
	if len(req.DNSServers) == 0 {
		return nil
	}

	ntpServers, xerr := s.getDefaultDhcpNtpServers(net)
	if xerr != nil {
		return xerr
	}

	resp, xerr := s.rpcCreateDhcpOptions(req.Name, req.DNSServers, ntpServers)
	if xerr != nil {
		return xerr
	}

	defer func() {
		if xerr != nil {
			derr := s.deleteDhcpOptions(net, false)
			_ = xerr.AddConsequence(derr)
		}
	}()

	return s.rpcUpdateNet(net.NetId, resp.DhcpOptionsSetId)
}

func (s stack) getDefaultDhcpNtpServers(net osc.Net) ([]string, fail.Error) {
	resp, xerr := s.rpcReadDhcpOptionsByID(net.DhcpOptionsSetId)
	if xerr != nil {
		return []string{}, xerr
	}
	if len(resp) != 1 {
		return []string{}, fail.InconsistentError("inconsistent provider response")
	}
	return resp[0].NtpServers, nil
}

func (s stack) deleteDhcpOptions(onet osc.Net, checkName bool) fail.Error {
	// Remove DHCP options
	namedDHCPOptions, xerr := s.checkDHCPOptionsName(onet)
	if xerr != nil {
		return xerr
	}

	// prevent deleting default dhcp options
	if checkName && !namedDHCPOptions {
		return nil
	}

	return s.rpcDeleteDhcpOptions(onet.DhcpOptionsSetId)
}

func (s stack) checkDHCPOptionsName(onet osc.Net) (bool, fail.Error) {
	tags, xerr := s.rpcReadTagsOfResource(onet.DhcpOptionsSetId)
	if xerr != nil {
		return false, xerr
	}
	_, ok := tags[tagNameLabel]
	return ok, nil
}

func (s stack) createInternetService(req abstract.NetworkRequest, onet osc.Net) fail.Error {
	// Create internet service to allow internet access from VMs attached to the network
	resp, xerr := s.rpcCreateInternetService(req.Name)
	if xerr != nil {
		return xerr
	}

	if xerr := s.rpcLinkInternetService(onet.NetId, resp.InternetServiceId); xerr != nil {
		return xerr
	}

	return s.updateRouteTable(onet, resp)
}

func (s stack) deleteInternetService(netID string) fail.Error {
	// Unlink and delete internet service
	resp, xerr := s.rpcReadInternetServices(nil)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// internet service not found
			logrus.Warnf("no internet service linked to network '%s': %v", netID, xerr)
			return nil
		default:
			return xerr
		}
	}

	// internet service found
	for _, ois := range resp {
		tags := unwrapTags(ois.Tags)
		if _, ok := tags[tagNameLabel]; ois.NetId != netID || !ok {
			continue
		}

		if xerr := s.rpcUnlinkInternetService(netID, ois.InternetServiceId); xerr != nil {
			return fail.Wrap(xerr, "failed to unlink Internet Service %s from Network %s", ois.InternetServiceId, netID)
		}

		if xerr := s.rpcDeleteInternetService(ois.InternetServiceId); xerr != nil {
			return fail.Wrap(xerr, "failed to delete Internet Service %s", ois.InternetServiceId)
		}
		break
	}

	return nil
}

func (s stack) updateRouteTable(onet osc.Net, is osc.InternetService) fail.Error {
	table, xerr := s.getDefaultRouteTable(onet.NetId)
	if xerr != nil {
		return xerr
	}

	return s.rpcCreateRoute(is.InternetServiceId, table.RouteTableId, "0.0.0.0/0")
}

func (s stack) getDefaultRouteTable(id string) (osc.RouteTable, fail.Error) {
	if id == "" {
		return osc.RouteTable{}, fail.InvalidParameterError("id", "cannot be empty string")
	}

	resp, xerr := s.rpcReadRouteTableOfNetwork(id)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return osc.RouteTable{}, fail.NotFoundError("failed to read RouteTable of Network with ID %s", id)
		default:
			return osc.RouteTable{}, xerr
		}
	}

	return resp, nil
}

func toAbstractNetwork(in osc.Net) *abstract.Network {
	out := abstract.NewNetwork()
	out.ID = in.NetId
	out.CIDR = in.IpRange
	tags := unwrapTags(in.Tags)
	if name, ok := tags[tagNameLabel]; ok {
		out.Name = name
	}
	return out
}

// InspectNetwork returns the network identified by id
func (s stack) InspectNetwork(id string) (_ *abstract.Network, xerr fail.Error) {
	nullAN := abstract.NewNetwork()
	if s.IsNull() {
		return nullAN, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAN, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	resp, xerr := s.rpcReadNetByID(id)
	if xerr != nil {
		return nullAN, xerr
	}

	return toAbstractNetwork(resp), nil
}

// InspectNetworkByName returns the network identified by name)
func (s stack) InspectNetworkByName(name string) (_ *abstract.Network, xerr fail.Error) {
	nullAN := abstract.NewNetwork()
	if s.IsNull() {
		return nullAN, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	resp, xerr := s.rpcReadNetByName(name)
	if xerr != nil {
		return nullAN, xerr
	}

	return toAbstractNetwork(resp), nil
}

// ListNetworks lists all networks
func (s stack) ListNetworks() (_ []*abstract.Network, xerr fail.Error) {
	var emptySlice []*abstract.Network
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	resp, xerr := s.rpcReadNets(nil)
	if xerr != nil {
		return emptySlice, xerr
	}

	var nets []*abstract.Network
	for _, v := range resp {
		nets = append(nets, toAbstractNetwork(v))
	}

	return nets, nil
}

//func (s stack) deleteSecurityGroup(networkID string) fail.Error {
//	if networkID == "" {
//		return fail.InvalidParameterError("networkID", "cannot be empty string")
//	}
//	resp, xerr := s.rpcReadSecurityGroups(networkID, nil)
//	if xerr != nil {
//		return xerr
//	}
//
//	if len(resp) == 0 {
//		logrus.Debugf("No Security Groups in Network with ID %s", networkID)
//		return nil
//	}
//
//	for _, sg := range resp {
//		if xerr = s.rpcDeleteSecurityGroup(sg.SecurityGroupId); xerr != nil {
//			return xerr
//		}
//	}
//	return nil
//}

// DeleteNetwork deletes the network identified by id
func (s stack) DeleteNetwork(id string) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	// Reads NICs that belong to the subnet
	resp, xerr := s.rpcReadNics(id, "")
	if xerr != nil {
		return xerr
	}

	// Remove should succeed only when something goes wrong when deleting VMs
	if len(resp) > 0 {
		if xerr = s.deleteNICs(resp); xerr == nil {
			return xerr
		}
	}

	// delete VPC
	return s.rpcDeleteNetwork(id)
}

// CreateSubnet creates a Subnet
func (s stack) CreateSubnet(req abstract.SubnetRequest) (as *abstract.Subnet, xerr fail.Error) {
	nullAS := abstract.NewSubnet()
	if s.IsNull() {
		return nullAS, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%v)", req).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	// Check if CIDR intersects with VPC cidr; if not, error
	vpc, xerr := s.InspectNetwork(req.NetworkID)
	if xerr != nil {
		return nullAS, xerr
	}

	ok, err := netutils.CIDRString(vpc.CIDR).Contains(netutils.CIDRString(req.CIDR))
	if err != nil {
		return nullAS, fail.Wrap(err, "failed to determine if network CIDR '%s' is inside Network/VPC CIDR ('%s')", req.CIDR, vpc.CIDR)
	}
	if !ok {
		return nullAS, fail.InvalidRequestError("subnet CIDR '%s' must be inside Network/VPC CIDR ('%s')", req.CIDR, vpc.CIDR)
	}
	if vpc.CIDR == req.CIDR {
		return nullAS, fail.InvalidRequestError("subnet CIDR '%s' cannot be equal to Network CIDR ('%s')", req.CIDR, vpc.CIDR)
	}

	// Create a subnet with the same IPRanges than the network
	resp, xerr := s.rpcCreateSubnet(req.Name, vpc.ID, req.CIDR)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			if derr := s.rpcDeleteSubnet(resp.SubnetId); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Subnet"))
			}
		}
	}()

	// Prevent automatic assignment of public ip to VM created in the subnet

	as = abstract.NewSubnet()
	as.ID = resp.SubnetId
	as.CIDR = resp.IpRange
	as.IPVersion = ipversion.IPv4
	as.Name = req.Name
	as.Network = resp.NetId

	return as, nil
}

// InspectSubnet returns the Subnet identified by id
func (s stack) InspectSubnet(id string) (_ *abstract.Subnet, xerr fail.Error) {
	nullAS := abstract.NewSubnet()
	if s.IsNull() {
		return nullAS, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAS, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	resp, xerr := s.rpcReadSubnetByID(id)
	if xerr != nil {
		return nil, xerr
	}

	return toAbstractSubnet(resp), nil
}

// InspectSubnetByName returns the Subnet identified by name
func (s stack) InspectSubnetByName(networkRef, subnetName string) (_ *abstract.Subnet, xerr fail.Error) {
	nullAS := abstract.NewSubnet()
	if s.IsNull() {
		return nullAS, fail.InvalidInstanceError()
	}
	if networkRef == "" {
		return nullAS, fail.InvalidParameterError("networkRef", "cannot be empty string")
	}
	if subnetName == "" {
		return nullAS, fail.InvalidParameterError("subnetName", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%s, %s)", networkRef, subnetName).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	var networkID string
	// If networkRef is not empty string, networkRef can be an ID or a Name; let's find out the ID of this network for sure
	an, xerr := s.InspectNetwork(networkRef)
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
	networkID = an.ID

	resp, xerr := s.rpcReadSubnets(networkID, nil)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nullAS, fail.NotFoundError("failed to find Subnet with name '%s' in Network %s", subnetName, an.Name)
		default:
			return nullAS, xerr
		}
	}
	var (
		found bool
		out   osc.Subnet
	)
	for _, v := range resp {
		for _, t := range v.Tags {
			if t.Key == tagNameLabel && t.Value == subnetName {
				out = v
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return nullAS, fail.NotFoundError("failed to find a Subnet named '%s'", subnetName)
	}
	return toAbstractSubnet(out), nil
}

func toAbstractSubnet(subnet osc.Subnet) *abstract.Subnet {
	out := abstract.NewSubnet()
	out.ID = subnet.SubnetId
	out.CIDR = subnet.IpRange
	out.IPVersion = ipversion.IPv4
	out.Network = subnet.NetId
	tags := unwrapTags(subnet.Tags)
	if name, ok := tags[tagNameLabel]; ok {
		out.Name = name
	}
	return out
}

// ListSubnets lists all subnets
func (s stack) ListSubnets(networkRef string) (_ []*abstract.Subnet, xerr fail.Error) {
	var emptySlice []*abstract.Subnet
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	if networkRef == "" {
		networkRef = s.Options.Network.DefaultNetworkName
	}
	if networkRef == "" {
		return nil, fail.InvalidParameterError("networkRef", "cannot be empty string if tenant does not set keyword 'VPCNAME' or 'DefaultNetworkName'")
	}

	an, xerr := s.InspectNetwork(networkRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			if an, xerr = s.InspectNetworkByName(networkRef); xerr != nil {
				return emptySlice, xerr
			}
		default:
			return emptySlice, xerr
		}
	}

	resp, xerr := s.rpcReadSubnets(an.ID, nil)
	if xerr != nil {
		return emptySlice, xerr
	}
	var subnets []*abstract.Subnet
	for _, v := range resp {
		subnets = append(subnets, toAbstractSubnet(v))
	}

	return subnets, nil
}

func (s stack) listSubnetsByHost(hostID string) ([]*abstract.Subnet, []osc.Nic, fail.Error) {
	var (
		emptySubnetSlice []*abstract.Subnet
		emptyNicSlice    []osc.Nic
	)

	resp, xerr := s.rpcReadNics("", hostID)
	if xerr != nil {
		return emptySubnetSlice, emptyNicSlice, xerr
	}

	var list []*abstract.Subnet
	for _, nic := range resp {
		item, xerr := s.InspectSubnet(nic.SubnetId)
		if xerr != nil {
			return emptySubnetSlice, emptyNicSlice, xerr
		}
		list = append(list, item)
	}
	return list, resp, nil
}

// DeleteSubnet deletes the subnet identified by id
func (s stack) DeleteSubnet(id string) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	// Reads NIS that belong to the subnet
	resp, xerr := s.rpcReadNics(id, "")
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// No nics, continue
		default:
			return xerr
		}
	}

	if len(resp) > 0 {
		// Remove should succeed only when something goes wrong when deleting VMs
		logrus.Warnf("found orphan Nics to delete, check if nothing goes wrong deleting Hosts...")
		if xerr = s.deleteNICs(resp); xerr != nil {
			return xerr
		}
	}

	return s.rpcDeleteSubnet(id)
}

// BindSecurityGroupToSubnet binds a Security Group to a Subnet
// Does nothing in outscale stack
func (s stack) BindSecurityGroupToSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if subnetID != "" {
		return fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg.ID)
		if xerr != nil {
			return xerr
		}
	}

	return nil
}

// UnbindSecurityGroupFromSubnet unbinds a security group from a subnet
// Does nothing in outscale stack
func (s stack) UnbindSecurityGroupFromSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if subnetID == "" {
		return fail.InvalidParameterError("subnetID", "cannot be empty string")
	}
	asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(asg.ID)
		if xerr != nil {
			return xerr
		}
	}

	return nil
}

func (s stack) updateDefaultSecurityRules(sg osc.SecurityGroup) fail.Error {
	rules := append(s.createTCPPermissions(), s.createUDPPermissions()...)
	rules = append(rules, s.createICMPPermissions()...)
	xerr := s.rpcCreateSecurityGroupRules(sg.SecurityGroupId, "Inbound", rules)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to add Network ingress rules to Security Group %s", sg.SecurityGroupId)
	}

	xerr = s.rpcCreateSecurityGroupRules(sg.SecurityGroupId, "Outbound", rules)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to add Network egress rules to Security Group %s", sg.SecurityGroupId)
	}
	return nil
}

// VPL: obsolete
//func (s stack) getNetworkSecurityGroup(netID string) (*osc.SecurityGroup, fail.Error) {
//	readSecurityGroupsRequest := osc.ReadSecurityGroupsRequest{
//		Filters: osc.FiltersSecurityGroup{
//			SecurityGroupNames: []string{"default"},
//		},
//	}
//	res, _, err := s.client.SecurityGroupApi.ReadSecurityGroups(s.auth, &osc.ReadSecurityGroupsOpts{
//		ReadSecurityGroupsRequest: optional.NewInterface(readSecurityGroupsRequest),
//	})
//	if err != nil {
//		return nil, normalizeError(err)
//	}
//
//	for _, sg := range res.SecurityGroups {
//		if sg.NetId == netID {
//			return &sg, nil
//		}
//	}
//	// should never go there, in case this means that the network do not have a default security group
//	return nil, fail.NotFoundError("failed to get security group of Networking '%s'", netID)
//}

// open all ports, ingress is controlled by the vm firewall
func (s stack) createTCPPermissions() []osc.SecurityGroupRule {
	rule := osc.SecurityGroupRule{
		FromPortRange: 1,
		ToPortRange:   65535,
		IpRanges:      []string{"0.0.0.0/0"},
		IpProtocol:    "tcp",
	}
	return []osc.SecurityGroupRule{rule}
}

// open all ports, ingress is controlled by the vm firewall
func (s stack) createUDPPermissions() []osc.SecurityGroupRule {
	rule := osc.SecurityGroupRule{
		FromPortRange: 1,
		ToPortRange:   65535,
		IpRanges:      []string{"0.0.0.0/0"},
		IpProtocol:    "udp",
	}
	return []osc.SecurityGroupRule{rule}
}

// ingress is controlled by the vm firewall
func (s stack) createICMPPermissions() []osc.SecurityGroupRule {
	var rules []osc.SecurityGroupRule
	// Echo reply
	rules = append(rules, osc.SecurityGroupRule{
		FromPortRange: -1,
		ToPortRange:   -1,
		IpRanges:      []string{"0.0.0.0/0"},
		IpProtocol:    "icmp",
	})
	return rules
}
