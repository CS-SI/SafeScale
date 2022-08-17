/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/v22/lib/utils/net"
)

const tagNameLabel = "name"

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (s stack) HasDefaultNetwork(ctx context.Context) (bool, fail.Error) {
	if valid.IsNil(s) {
		return false, fail.InvalidInstanceError()
	}
	return s.vpc != nil, nil
}

// GetDefaultNetwork returns the *abstract.Network corresponding to the default network
func (s stack) GetDefaultNetwork(ctx context.Context) (*abstract.Network, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if s.vpc == nil {
		return nil, fail.NotFoundError("no default Network in stack")
	}
	return s.vpc, nil
}

// CreateNetwork creates a network named name (in OutScale terminology, a Network corresponds to a VPC)
func (s stack) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (an *abstract.Network, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if req.CIDR == "" {
		req.CIDR = stacks.DefaultNetworkCIDR
	}
	tracer := debug.NewTracer(ctx, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%v)", req).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcCreateNetwork(ctx, req.Name, req.CIDR)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && !req.KeepOnFailure {
			if derr := s.DeleteNetwork(context.Background(), resp.NetId); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Network '%s'", req.Name))
			}
		}
	}()

	// update default security group to allow external traffic
	securityGroup, xerr := s.rpcReadSecurityGroupByName(ctx, resp.NetId, "default")
	if xerr != nil {
		return nil, xerr
	}

	xerr = s.updateDefaultSecurityRules(ctx, securityGroup)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to update default security group of Network/VPC")
	}

	if xerr = s.createDHCPOptionSet(ctx, req, resp); xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create DHCP options set of Network/VPC")
	}

	if xerr = s.createInternetService(ctx, req, resp); xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create Internet Service of Network/VPC")
	}

	return toAbstractNetwork(resp), nil
}

func (s stack) createDHCPOptionSet(ctx context.Context, req abstract.NetworkRequest, net osc.Net) (ferr fail.Error) {
	if len(req.DNSServers) == 0 {
		return nil
	}

	ntpServers, xerr := s.getDefaultDhcpNtpServers(ctx, net)
	if xerr != nil {
		return xerr
	}

	resp, xerr := s.rpcCreateDhcpOptions(ctx, req.Name, req.DNSServers, ntpServers)
	if xerr != nil {
		return xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := s.deleteDhcpOptions(context.Background(), net, false)
			_ = ferr.AddConsequence(derr)
		}
	}()

	return s.rpcUpdateNet(ctx, net.NetId, resp.DhcpOptionsSetId)
}

func (s stack) getDefaultDhcpNtpServers(ctx context.Context, net osc.Net) ([]string, fail.Error) {
	resp, xerr := s.rpcReadDhcpOptionsByID(ctx, net.DhcpOptionsSetId)
	if xerr != nil {
		return []string{}, xerr
	}
	if len(resp) != 1 {
		return []string{}, fail.InconsistentError("inconsistent provider response")
	}
	return resp[0].NtpServers, nil
}

func (s stack) deleteDhcpOptions(ctx context.Context, onet osc.Net, checkName bool) fail.Error {
	// Remove DHCP options
	namedDHCPOptions, xerr := s.checkDHCPOptionsName(ctx, onet)
	if xerr != nil {
		return xerr
	}

	// prevent deleting default dhcp options
	if checkName && !namedDHCPOptions {
		return nil
	}

	return s.rpcDeleteDhcpOptions(ctx, onet.DhcpOptionsSetId)
}

func (s stack) checkDHCPOptionsName(ctx context.Context, onet osc.Net) (bool, fail.Error) {
	tags, xerr := s.rpcReadTagsOfResource(ctx, onet.DhcpOptionsSetId)
	if xerr != nil {
		return false, xerr
	}
	_, ok := tags[tagNameLabel]
	return ok, nil
}

func (s stack) createInternetService(ctx context.Context, req abstract.NetworkRequest, onet osc.Net) fail.Error {
	// Create internet service to allow internet access from VMs attached to the network
	resp, xerr := s.rpcCreateInternetService(ctx, req.Name)
	if xerr != nil {
		return xerr
	}

	if xerr := s.rpcLinkInternetService(ctx, onet.NetId, resp.InternetServiceId); xerr != nil {
		return xerr
	}

	return s.updateRouteTable(ctx, onet, resp)
}

func (s stack) deleteInternetService(ctx context.Context, netID string) fail.Error {
	// Unlink and delete internet service
	resp, xerr := s.rpcReadInternetServices(ctx, nil)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// internet service not found
			logrus.WithContext(ctx).Warnf("no internet service linked to network '%s': %v", netID, xerr)
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

		if xerr := s.rpcUnlinkInternetService(ctx, netID, ois.InternetServiceId); xerr != nil {
			return fail.Wrap(xerr, "failed to unlink Internet Service %s from Network %s", ois.InternetServiceId, netID)
		}

		if xerr := s.rpcDeleteInternetService(ctx, ois.InternetServiceId); xerr != nil {
			return fail.Wrap(xerr, "failed to delete Internet Service %s", ois.InternetServiceId)
		}
		break
	}

	return nil
}

func (s stack) updateRouteTable(ctx context.Context, onet osc.Net, is osc.InternetService) fail.Error {
	table, xerr := s.getDefaultRouteTable(ctx, onet.NetId)
	if xerr != nil {
		return xerr
	}

	return s.rpcCreateRoute(ctx, is.InternetServiceId, table.RouteTableId, "0.0.0.0/0")
}

func (s stack) getDefaultRouteTable(ctx context.Context, id string) (osc.RouteTable, fail.Error) {
	if id == "" {
		return osc.RouteTable{}, fail.InvalidParameterError("id", "cannot be empty string")
	}

	resp, xerr := s.rpcReadRouteTableOfNetwork(ctx, id)
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
func (s stack) InspectNetwork(ctx context.Context, id string) (_ *abstract.Network, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcReadNetByID(ctx, id)
	if xerr != nil {
		return nil, xerr
	}

	return toAbstractNetwork(resp), nil
}

// InspectNetworkByName returns the network identified by 'name'
func (s stack) InspectNetworkByName(ctx context.Context, name string) (_ *abstract.Network, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcReadNetByName(ctx, name)
	if xerr != nil {
		return nil, xerr
	}

	return toAbstractNetwork(resp), nil
}

// ListNetworks lists all networks
func (s stack) ListNetworks(ctx context.Context) (_ []*abstract.Network, ferr fail.Error) {
	var emptySlice []*abstract.Network
	if valid.IsNil(s) {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcReadNets(ctx, nil)
	if xerr != nil {
		return emptySlice, xerr
	}

	var nets []*abstract.Network
	for _, v := range resp {
		nets = append(nets, toAbstractNetwork(v))
	}

	return nets, nil
}

// DeleteNetwork deletes the network identified by id
func (s stack) DeleteNetwork(ctx context.Context, id string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Reads NICs that belong to the subnet
	resp, xerr := s.rpcReadNics(ctx, id, "")
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// if no nics found, considered as a success and continue
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	} else if len(resp) > 0 { // Delete remaining nics (may happen when something goes wrong during VM deletions)
		if xerr = s.deleteNICs(ctx, resp); xerr != nil {
			return xerr
		}
	}

	// Delete Internet Gateway
	if xerr = s.deleteInternetService(ctx, id); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// no Internet Gateway, consider the deletion successful and continue
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}

	// delete VPC
	return s.rpcDeleteNetwork(ctx, id)
}

// CreateSubnet creates a Subnet
func (s stack) CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (as *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%v)", req).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Check if CIDR intersects with VPC cidr; if not, error
	vpc, xerr := s.InspectNetwork(ctx, req.NetworkID)
	if xerr != nil {
		return nil, xerr
	}

	ok, err := netutils.CIDRString(vpc.CIDR).Contains(netutils.CIDRString(req.CIDR))
	if err != nil {
		return nil, fail.Wrap(err, "failed to determine if network CIDR '%s' is inside Network/VPC CIDR ('%s')", req.CIDR, vpc.CIDR)
	}
	if !ok {
		return nil, fail.InvalidRequestError("subnet CIDR '%s' must be inside Network/VPC CIDR ('%s')", req.CIDR, vpc.CIDR)
	}

	// Create a subnet with the same Targets as the network
	resp, xerr := s.rpcCreateSubnet(ctx, req.Name, vpc.ID, req.CIDR)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && !req.KeepOnFailure {
			if derr := s.rpcDeleteSubnet(context.Background(), resp.SubnetId); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Subnet"))
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
func (s stack) InspectSubnet(ctx context.Context, id string) (_ *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcReadSubnetByID(ctx, id)
	if xerr != nil {
		return nil, xerr
	}

	return toAbstractSubnet(resp), nil
}

// InspectSubnetByName returns the Subnet identified by name
func (s stack) InspectSubnetByName(ctx context.Context, networkRef, subnetName string) (_ *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if networkRef == "" {
		return nil, fail.InvalidParameterError("networkRef", "cannot be empty string")
	}
	if subnetName == "" {
		return nil, fail.InvalidParameterError("subnetName", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%s, %s)", networkRef, subnetName).WithStopwatch().Entering()
	defer tracer.Exiting()

	var networkID string
	// If networkRef is not empty string, networkRef can be an ID or a Name; let's find out the ID of this network for sure
	an, xerr := s.InspectNetwork(ctx, networkRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			an, xerr = s.InspectNetworkByName(ctx, networkRef)
			if xerr != nil {
				return nil, xerr
			}
		default:
			return nil, xerr
		}
	}

	networkID = an.ID

	resp, xerr := s.rpcReadSubnets(ctx, networkID, nil)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nil, fail.NotFoundError("failed to find Subnet with name '%s' in Network %s", subnetName, an.Name)
		default:
			return nil, xerr
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
		return nil, fail.NotFoundError("failed to find a Subnet named '%s'", subnetName)
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
func (s stack) ListSubnets(ctx context.Context, networkRef string) (_ []*abstract.Subnet, ferr fail.Error) {
	var emptySlice []*abstract.Subnet
	if valid.IsNil(s) {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/).WithStopwatch().Entering()
	defer tracer.Exiting()

	if networkRef == "" {
		networkRef = s.Options.Network.DefaultNetworkName
		if networkRef == "" {
			return nil, fail.InvalidParameterError("networkRef", "cannot be empty string if tenant does not set keyword 'VPCNAME' or 'DefaultNetworkName'")
		}
	}

	an, xerr := s.InspectNetwork(ctx, networkRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			if an, xerr = s.InspectNetworkByName(ctx, networkRef); xerr != nil {
				return emptySlice, xerr
			}
		default:
			return emptySlice, xerr
		}
	}

	resp, xerr := s.rpcReadSubnets(ctx, an.ID, nil)
	if xerr != nil {
		return emptySlice, xerr
	}
	var subnets []*abstract.Subnet
	for _, v := range resp {
		subnets = append(subnets, toAbstractSubnet(v))
	}

	return subnets, nil
}

func (s stack) listSubnetsByHost(ctx context.Context, hostID string) ([]*abstract.Subnet, []osc.Nic, fail.Error) {
	var (
		emptySubnetSlice []*abstract.Subnet
		emptyNicSlice    []osc.Nic
	)

	resp, xerr := s.rpcReadNics(ctx, "", hostID)
	if xerr != nil {
		switch xerr.(type) { // nolint
		case *fail.ErrNotFound:
			// No nics found, considered as a success and returns empty slices
			debug.IgnoreError(xerr)
			return emptySubnetSlice, emptyNicSlice, nil
		}
		return emptySubnetSlice, emptyNicSlice, xerr
	}

	var list []*abstract.Subnet
	for _, nic := range resp {
		item, xerr := s.InspectSubnet(ctx, nic.SubnetId)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				continue
			default:
				return emptySubnetSlice, emptyNicSlice, xerr
			}
		}

		list = append(list, item)
	}
	return list, resp, nil
}

// DeleteSubnet deletes the subnet identified by id
func (s stack) DeleteSubnet(ctx context.Context, id string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Reads NIS that belong to the subnet
	resp, xerr := s.rpcReadNics(ctx, id, "")
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// No nics, continue
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}

	if len(resp) > 0 {
		for _, nic := range resp {
			if nic.LinkNic.LinkNicId != "" {
				xerr = s.rpcUnLinkNic(ctx, nic.LinkNic.LinkNicId)
				if xerr != nil {
					debug.IgnoreError(xerr)
				}
			}
		}

		// Remove should fail only if something goes wrong when deleting VMs
		logrus.WithContext(ctx).Warnf("found orphan Nics to delete (%s), check if nothing goes wrong deleting Hosts...", spew.Sdump(resp))
		if xerr = s.deleteNICs(ctx, resp); xerr != nil {
			return xerr
		}
	}

	return s.rpcDeleteSubnet(ctx, id)
}

// BindSecurityGroupToSubnet binds a Security Group to a Subnet
// Actually does nothing for outscale
func (s stack) BindSecurityGroupToSubnet(ctx context.Context, sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if subnetID != "" {
		return fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	return nil
}

// UnbindSecurityGroupFromSubnet unbinds a security group from a subnet
// Actually does nothing for outscale
func (s stack) UnbindSecurityGroupFromSubnet(ctx context.Context, sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if subnetID == "" {
		return fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	return nil
}

func (s stack) updateDefaultSecurityRules(ctx context.Context, sg osc.SecurityGroup) fail.Error {
	rules := append(s.createTCPPermissions(), s.createUDPPermissions()...)
	rules = append(rules, s.createICMPPermissions()...)
	xerr := s.rpcCreateSecurityGroupRules(ctx, sg.SecurityGroupId, "Inbound", rules)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to add Network ingress rules to Security Group %s", sg.SecurityGroupId)
	}

	xerr = s.rpcCreateSecurityGroupRules(ctx, sg.SecurityGroupId, "Outbound", rules)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to add Network egress rules to Security Group %s", sg.SecurityGroupId)
	}
	return nil
}

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
