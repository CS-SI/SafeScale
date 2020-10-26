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
	"github.com/sirupsen/logrus"

	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

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

	createNetRequest := osc.CreateNetRequest{
		IpRange: req.CIDR,
		Tenancy: s.Options.Compute.DefaultTenancy,
	}
	var respNet osc.CreateNetResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			respNet, _, innerErr = s.client.NetApi.CreateNet(s.auth, &osc.CreateNetOpts{
				CreateNetRequest: optional.NewInterface(createNetRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nullAN, xerr
	}
	onet := respNet.Net

	defer func() {
		if xerr != nil {
			if derr := s.DeleteNetwork(onet.NetId); derr != nil {
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	tags, xerr := s.setResourceTags(onet.NetId, map[string]string{
		"name": req.Name,
	})
	if xerr != nil {
		return nullAN, xerr
	}
	onet.Tags = tags

	// update default security group to allow external traffic
	securityGroup, xerr := s.getNetworkSecurityGroup(onet.NetId)
	if xerr != nil {
		return nullAN, xerr
	}

	xerr = s.updateDefaultSecurityRules(securityGroup)
	if xerr != nil {
		return nullAN, fail.Wrap(xerr, "failed to update default security group of Network/VPC")
	}

	xerr = s.createDHCPOptionSet(req, onet)
	if xerr != nil {
		return nullAN, fail.Wrap(xerr, "failed to create DHCP options set of Network/VPC")
	}

	xerr = s.createInternetService(req, onet)
	if xerr != nil {
		return nullAN, fail.Wrap(xerr, "failed to create Internet Service of Network/VPC")
	}

	return toNetwork(onet), nil
}

func (s stack) createDHCPOptionSet(req abstract.NetworkRequest, net osc.Net) fail.Error {
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
	var resp osc.CreateDhcpOptionsResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.DhcpOptionApi.CreateDhcpOptions(s.auth, &osc.CreateDhcpOptionsOpts{
				CreateDhcpOptionsRequest: optional.NewInterface(createDhcpOptionsRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return xerr
	}

	defer func() {
		if xerr != nil {
			derr := s.deleteDhcpOptions(net, false)
			_ = xerr.AddConsequence(derr)
		}
	}()

	dhcpOptionID := resp.DhcpOptionsSet.DhcpOptionsSetId
	_, xerr = s.setResourceTags(dhcpOptionID, map[string]string{
		"name": req.Name,
	})
	if xerr != nil {
		return xerr
	}

	updateNetRequest := osc.UpdateNetRequest{
		DhcpOptionsSetId: dhcpOptionID,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, _, innerErr := s.client.NetApi.ReadNets(s.auth, &osc.ReadNetsOpts{
				ReadNetsRequest: optional.NewInterface(updateNetRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

func (s stack) getDefaultDhcpNtpServers(net osc.Net) ([]string, fail.Error) {
	readDhcpOptionsRequest := osc.ReadDhcpOptionsRequest{
		Filters: osc.FiltersDhcpOptions{
			DhcpOptionsSetIds: []string{net.DhcpOptionsSetId},
		},
	}
	var resp osc.ReadDhcpOptionsResponse
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.DhcpOptionApi.ReadDhcpOptions(s.auth, &osc.ReadDhcpOptionsOpts{
				ReadDhcpOptionsRequest: optional.NewInterface(readDhcpOptionsRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return []string{}, xerr
	}
	if len(resp.DhcpOptionsSets) != 1 {
		return []string{}, fail.InconsistentError("inconsistent provider response")
	}
	return resp.DhcpOptionsSets[0].NtpServers, nil
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

	deleteDhcpOptionsRequest := osc.DeleteDhcpOptionsRequest{
		DhcpOptionsSetId: onet.DhcpOptionsSetId,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, _, innerErr := s.client.DhcpOptionApi.DeleteDhcpOptions(s.auth, &osc.DeleteDhcpOptionsOpts{
				DeleteDhcpOptionsRequest: optional.NewInterface(deleteDhcpOptionsRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

func (s stack) checkDHCPOptionsName(onet osc.Net) (bool, fail.Error) {
	tags, xerr := s.getResourceTags(onet.DhcpOptionsSetId)
	if xerr != nil {
		return false, xerr
	}
	_, ok := tags["name"]
	return ok, nil
}

func (s stack) createInternetService(req abstract.NetworkRequest, onet osc.Net) fail.Error {
	// Create internet service to allow internet access from VMs attached to the network
	var resp osc.CreateInternetServiceResponse
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.InternetServiceApi.CreateInternetService(s.auth, nil)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return xerr
	}

	_, xerr = s.setResourceTags(resp.InternetService.InternetServiceId, map[string]string{
		"name": req.Name,
	})
	if xerr != nil {
		return xerr
	}

	linkInternetServiceRequest := osc.LinkInternetServiceRequest{
		InternetServiceId: resp.InternetService.InternetServiceId,
		NetId:             onet.NetId,
	}
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, _, innerErr := s.client.InternetServiceApi.LinkInternetService(s.auth, &osc.LinkInternetServiceOpts{
				LinkInternetServiceRequest: optional.NewInterface(linkInternetServiceRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return xerr
	}
	return s.updateRouteTable(onet, resp.InternetService)
}

func (s stack) deleteInternetService(netID string) fail.Error {
	// Unlink and delete internet service
	var resp osc.ReadInternetServicesResponse
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.InternetServiceApi.ReadInternetServices(s.auth, nil)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil || len(resp.InternetServices) <= 0 {
		// internet service not found
		logrus.Warnf("no internet service linked to network '%s': %v", netID, xerr)
		return nil
	}

	// internet service found
	for _, ois := range resp.InternetServices {
		tags := unwrapTags(ois.Tags)
		if _, ok := tags["name"]; ois.NetId != netID || !ok {
			continue
		}
		unlinkInternetServiceOpts := osc.UnlinkInternetServiceOpts{
			UnlinkInternetServiceRequest: optional.NewInterface(osc.UnlinkInternetServiceRequest{
				InternetServiceId: ois.InternetServiceId,
				NetId:             netID,
			}),
		}
		xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
			func() error {
				_, _, innerErr := s.client.InternetServiceApi.UnlinkInternetService(s.auth, &unlinkInternetServiceOpts)
				return normalizeError(innerErr)
			},
			temporal.GetCommunicationTimeout(),
		)
		if xerr != nil {
			logrus.Errorf("cannot unlink internet service '%s' from network '%s': %v", ois.InternetServiceId, netID, xerr)
			return xerr
		}

		deleteInternetServiceOpts := osc.DeleteInternetServiceOpts{
			DeleteInternetServiceRequest: optional.NewInterface(osc.DeleteInternetServiceRequest{
				InternetServiceId: ois.InternetServiceId,
			}),
		}
		xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
			func() error {
				_, _, innerErr := s.client.InternetServiceApi.DeleteInternetService(s.auth, &deleteInternetServiceOpts)
				return normalizeError(innerErr)
			},
			temporal.GetCommunicationTimeout(),
		)
		if xerr != nil {
			logrus.Errorf("internet service '%s' linked to network '%s' cannot be deleted: %v", ois.InternetServiceId, netID, xerr)
			return normalizeError(xerr)
		}
		break
	}

	return nil
}

func (s stack) updateRouteTable(onet osc.Net, is osc.InternetService) fail.Error {
	table, xerr := s.getDefaultRouteTable(onet)
	if xerr != nil {
		return xerr
	}
	createRouteRequest := osc.CreateRouteRequest{
		DestinationIpRange: "0.0.0.0/0",
		GatewayId:          is.InternetServiceId,
		RouteTableId:       table.RouteTableId,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, _, innerErr := s.client.RouteApi.CreateRoute(s.auth, &osc.CreateRouteOpts{
				CreateRouteRequest: optional.NewInterface(createRouteRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

func (s stack) getDefaultRouteTable(onet osc.Net) (*osc.RouteTable, fail.Error) {
	readRouteTablesRequest := osc.ReadRouteTablesRequest{
		Filters: osc.FiltersRouteTable{
			NetIds: []string{onet.NetId},
		},
	}
	var resp osc.ReadRouteTablesResponse
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.RouteTableApi.ReadRouteTables(s.auth, &osc.ReadRouteTablesOpts{
				ReadRouteTablesRequest: optional.NewInterface(readRouteTablesRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}
	if len(resp.RouteTables) != 1 {
		return nil, fail.InconsistentError("inconsistent provider response when trying to default route table")
	}
	return &resp.RouteTables[0], nil
}

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
func (s stack) InspectNetwork(id string) (_ *abstract.Network, xerr fail.Error) {
	nullAN := abstract.NewNetwork()
	if s.IsNull() {
		return nullAN, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	readNetsRequest := osc.ReadNetsRequest{
		Filters: osc.FiltersNet{
			NetIds: []string{id},
		},
	}
	var resp osc.ReadNetsResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.NetApi.ReadNets(s.auth, &osc.ReadNetsOpts{
				ReadNetsRequest: optional.NewInterface(readNetsRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nullAN, xerr
	}
	if len(resp.Nets) == 0 {
		return nullAN, fail.NotFoundError("failed to find Network/VPC %s", id)
	}

	return toNetwork(resp.Nets[0]), nil
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

	readNetsRequest := osc.ReadNetsRequest{
		Filters: osc.FiltersNet{
			Tags: []string{fmt.Sprintf("%s=%s", "name", name)},
		},
	}
	var resp osc.ReadNetsResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.NetApi.ReadNets(s.auth, &osc.ReadNetsOpts{
				ReadNetsRequest: optional.NewInterface(readNetsRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nullAN, xerr
	}
	if len(resp.Nets) == 0 {
		return nullAN, fail.NotFoundError("failed to find a Network/VPC with name '%s'", name)
	}

	return toNetwork(resp.Nets[0]), nil
}

// ListNetworks lists all networks
func (s stack) ListNetworks() (_ []*abstract.Network, xerr fail.Error) {
	var emptySlice []*abstract.Network
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	readNetsOpts := osc.ReadNetsOpts{
		ReadNetsRequest: optional.NewInterface(osc.ReadNetsRequest{
			Filters: osc.FiltersNet{},
		}),
	}
	var resp osc.ReadNetsResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.NetApi.ReadNets(s.auth, &readNetsOpts)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return emptySlice, xerr
	}
	if len(resp.Nets) == 0 {
		return emptySlice, fail.NotFoundError("no Network/VPC found")
	}

	var nets []*abstract.Network
	for _, v := range resp.Nets {
		nets = append(nets, toNetwork(v))
	}

	return nets, nil
}

func (s stack) deleteSecurityGroup(onet *osc.Net) fail.Error {
	readSecurityGroupsRequest := osc.ReadSecurityGroupsRequest{
		DryRun:  false,
		Filters: osc.FiltersSecurityGroup{},
	}
	var resp osc.ReadSecurityGroupsResponse
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.SecurityGroupApi.ReadSecurityGroups(s.auth, &osc.ReadSecurityGroupsOpts{
				ReadSecurityGroupsRequest: optional.NewInterface(readSecurityGroupsRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return xerr
	}
	if len(resp.SecurityGroups) == 0 {
		logrus.Warnf("No security group in network %s", onet.NetId)
		return nil
	}

	for _, sg := range resp.SecurityGroups {
		if sg.NetId != onet.NetId {
			continue
		}
		deleteSecurityGroupRequest := osc.DeleteSecurityGroupRequest{
			SecurityGroupId: sg.SecurityGroupId,
		}
		xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
			func() error {
				_, _, innerErr := s.client.SecurityGroupApi.DeleteSecurityGroup(s.auth, &osc.DeleteSecurityGroupOpts{
					DeleteSecurityGroupRequest: optional.NewInterface(deleteSecurityGroupRequest),
				})
				return normalizeError(innerErr)
			},
			temporal.GetCommunicationTimeout(),
		)
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// DeleteNetwork deletes the network identified by id
func (s stack) DeleteNetwork(id string) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	// Reads NIS that belong to the subnet
	readNicsRequest := osc.ReadNicsRequest{
		Filters: osc.FiltersNic{
			SubnetIds: []string{id},
		},
	}
	var resp osc.ReadNicsResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.NicApi.ReadNics(s.auth, &osc.ReadNicsOpts{
				ReadNicsRequest: optional.NewInterface(readNicsRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to read nics")
	}

	// Remove should succeed only when something goes wrong when deleting VMs
	if len(resp.Nics) > 0 {
		if xerr = s.deleteNICs(resp.Nics); xerr == nil {
			return fail.Wrap(xerr, "failed to delete nic")
		}
	}

	// delete VPC
	deleteNetRequest := osc.DeleteNetRequest{
		NetId: id,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, _, innerErr := s.client.NetApi.DeleteNet(s.auth, &osc.DeleteNetOpts{
				DeleteNetRequest: optional.NewInterface(deleteNetRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

// CreateSubnet creates a Subnet
func (s stack) CreateSubnet(req abstract.SubnetRequest) (as *abstract.Subnet, xerr fail.Error) {
	nullAS := abstract.NewSubnet()
	if s.IsNull() {
		return nullAS, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%v)", req).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	// Check if CIDR intersects with VPC cidr; if not, error
	vpc, xerr := s.InspectNetwork(req.NetworkID)
	if xerr != nil {
		return nullAS, xerr
	}

	//	ok, xerr := netutils.DoCIDRsIntersect(vpc.IpRange), req.IPRanges)
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
	createSubnetRequest := osc.CreateSubnetRequest{
		IpRange:       req.CIDR,
		NetId:         vpc.ID,
		SubregionName: s.Options.Compute.Subregion,
	}
	var resp osc.CreateSubnetResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.SubnetApi.CreateSubnet(s.auth, &osc.CreateSubnetOpts{
				CreateSubnetRequest: optional.NewInterface(createSubnetRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil {
			deleteSubnetRequest := osc.DeleteSubnetRequest{
				SubnetId: resp.Subnet.SubnetId,
			}
			derr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
				func() error {
					_, _, innerErr := s.client.SubnetApi.CreateSubnet(s.auth, &osc.CreateSubnetOpts{
						CreateSubnetRequest: optional.NewInterface(deleteSubnetRequest),
					})
					return normalizeError(innerErr)
				},
				temporal.GetCommunicationTimeout(),
			)
			if derr != nil {
				_ = xerr.AddConsequence(normalizeError(derr))
			}
		}
	}()

	_, xerr = s.setResourceTags(resp.Subnet.SubnetId, map[string]string{
		"name": req.Name,
	})
	if xerr != nil {
		return nil, xerr
	}

	// Prevent automatic assignment of public ip to VM created in the subnet
	updateSubnetRequest := osc.UpdateSubnetRequest{
		MapPublicIpOnLaunch: false,
		SubnetId:            resp.Subnet.SubnetId,
	}
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, _, innerErr := s.client.SubnetApi.UpdateSubnet(s.auth, &osc.UpdateSubnetOpts{
				UpdateSubnetRequest: optional.NewInterface(updateSubnetRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}

	as = abstract.NewSubnet()
	as.ID = resp.Subnet.SubnetId
	as.CIDR = resp.Subnet.IpRange
	as.IPVersion = ipversion.IPv4
	as.Name = req.Name
	as.Network = resp.Subnet.NetId

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
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	readSubnetsRequest := osc.ReadSubnetsRequest{
		Filters: osc.FiltersSubnet{
			SubnetIds: []string{id},
		},
	}
	var resp osc.ReadSubnetsResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.SubnetApi.ReadSubnets(s.auth, &osc.ReadSubnetsOpts{
				ReadSubnetsRequest: optional.NewInterface(readSubnetsRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}
	if len(resp.Subnets) > 1 {
		return nil, fail.InconsistentError("inconsistent provider response")
	}
	if len(resp.Subnets) == 0 {
		return nil, fail.NotFoundError("failed to find subnet %s", id)
	}

	return toAbstractSubnet(resp.Subnets[0]), nil
}

// InspectSubnetByName returns the Subnet identified by id
func (s stack) InspectSubnetByName(networkRef, subnetName string) (_ *abstract.Subnet, xerr fail.Error) {
	nullAS := abstract.NewSubnet()
	if s.IsNull() {
		return nullAS, fail.InvalidInstanceError()
	}
	if subnetName == "" {
		return nullAS, fail.InvalidParameterError("subnetName", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%s, %s)", networkRef, subnetName).WithStopwatch().Entering()
	defer tracer.Exiting()
	//defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

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
	var resp osc.ReadSubnetsResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.SubnetApi.ReadSubnets(s.auth, &osc.ReadSubnetsOpts{
				ReadSubnetsRequest: optional.NewInterface(osc.ReadSubnetsRequest{Filters: filters}),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}
	if len(resp.Subnets) > 1 {
		return nil, fail.InconsistentError("inconsistent provider response, returned multiple Subnets")
	}
	if len(resp.Subnets) == 0 {
		if an != nil {
			return nil, fail.NotFoundError("failed to find subnet '%s' in Network/VPC '%s'", subnetName, an.Name)
		}
		return nil, fail.NotFoundError("failed to find subnet '%s'", subnetName)
	}
	//
	return toAbstractSubnet(resp.Subnets[0]), nil
}

func toAbstractSubnet(subnet osc.Subnet) *abstract.Subnet {
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
func (s stack) ListSubnets(networkRef string) (_ []*abstract.Subnet, xerr fail.Error) {
	var emptySlice []*abstract.Subnet
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

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

	readSubnetsRequest := osc.ReadSubnetsRequest{
		Filters: osc.FiltersSubnet{
			NetIds: []string{an.ID},
		},
	}
	var resp osc.ReadSubnetsResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.SubnetApi.ReadSubnets(s.auth, &osc.ReadSubnetsOpts{
				ReadSubnetsRequest: optional.NewInterface(readSubnetsRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return emptySlice, xerr
	}
	var subnets []*abstract.Subnet
	for _, v := range resp.Subnets {
		subnets = append(subnets, toAbstractSubnet(v))
	}

	return subnets, nil
}

func (s stack) listSubnetsByHost(hostID string) ([]*abstract.Subnet, []osc.Nic, fail.Error) {
	var (
		emptySubnetSlice []*abstract.Subnet
		emptyNicSlice    []osc.Nic
	)

	readNicsRequest := osc.ReadNicsRequest{
		Filters: osc.FiltersNic{
			LinkNicVmIds: []string{hostID},
		},
	}
	var resp osc.ReadNicsResponse
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.NicApi.ReadNics(s.auth, &osc.ReadNicsOpts{
				ReadNicsRequest: optional.NewInterface(readNicsRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return emptySubnetSlice, emptyNicSlice, xerr
	}

	var subnets []*abstract.Subnet
	for _, nic := range resp.Nics {
		subnet, xerr := s.InspectSubnet(nic.SubnetId)
		if xerr != nil {
			return emptySubnetSlice, emptyNicSlice, xerr
		}
		subnets = append(subnets, subnet)
	}
	return subnets, resp.Nics, nil
}

// DeleteSubnet deletes the subnet identified by id
func (s stack) DeleteSubnet(id string) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.outscale")*/, "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	// Reads NIS that belong to the subnet
	readNicsRequest := osc.ReadNicsRequest{
		Filters: osc.FiltersNic{
			SubnetIds: []string{id},
		},
	}
	var resp osc.ReadNicsResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.NicApi.ReadNics(s.auth, &osc.ReadNicsOpts{
				ReadNicsRequest: optional.NewInterface(readNicsRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to read nics")
	}

	if len(resp.Nics) > 0 {
		// Remove should succeed only when something goes wrong when deleting VMs
		if xerr = s.deleteNICs(resp.Nics); xerr == nil {
			logrus.Debugf("Check if nothing goes wrong deleting a VM")
		}
	}

	deleteSubnetRequest := osc.DeleteSubnetRequest{
		SubnetId: id,
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, _, innerErr := s.client.SubnetApi.DeleteSubnet(s.auth, &osc.DeleteSubnetOpts{
				DeleteSubnetRequest: optional.NewInterface(deleteSubnetRequest),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
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

func (s stack) updateDefaultSecurityRules(sg *osc.SecurityGroup) fail.Error {
	rules := append(s.createTCPPermissions(), s.createUDPPermissions()...)
	rules = append(rules, s.createICMPPermissions()...)
	createSecurityGroupRuleRequest := osc.CreateSecurityGroupRuleRequest{
		SecurityGroupId: sg.SecurityGroupId,
		Rules:           rules,
		Flow:            "Inbound",
	}
	_, _, err := s.client.SecurityGroupRuleApi.CreateSecurityGroupRule(s.auth, &osc.CreateSecurityGroupRuleOpts{
		CreateSecurityGroupRuleRequest: optional.NewInterface(createSecurityGroupRuleRequest),
	})
	if err != nil {
		return normalizeError(err)
	}
	createSecurityGroupRuleRequest = osc.CreateSecurityGroupRuleRequest{
		SecurityGroupId: sg.SecurityGroupId,
		Rules:           rules,
		Flow:            "Outbound",
	}
	_, _, err = s.client.SecurityGroupRuleApi.CreateSecurityGroupRule(s.auth, &osc.CreateSecurityGroupRuleOpts{
		CreateSecurityGroupRuleRequest: optional.NewInterface(createSecurityGroupRuleRequest),
	})
	return normalizeError(err)
}

func (s stack) getNetworkSecurityGroup(netID string) (*osc.SecurityGroup, fail.Error) {
	readSecurityGroupsRequest := osc.ReadSecurityGroupsRequest{
		Filters: osc.FiltersSecurityGroup{
			SecurityGroupNames: []string{"default"},
		},
	}
	res, _, err := s.client.SecurityGroupApi.ReadSecurityGroups(s.auth, &osc.ReadSecurityGroupsOpts{
		ReadSecurityGroupsRequest: optional.NewInterface(readSecurityGroupsRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}

	for _, sg := range res.SecurityGroups {
		if sg.NetId == netID {
			return &sg, nil
		}
	}
	// should never go there, in case this means that the network do not have a default security group
	return nil, fail.NotFoundError("failed to get security group of Networking '%s'", netID)
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
