/*
 * Copyright 2018, CS Systemes d'Information, http://csgroup.eu
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

package gcp

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"google.golang.org/api/compute/v1"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

const (
	natRouteNameFormat = "%s-%s-nat-allowed"
)

// ------ network methods ------

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (s stack) HasDefaultNetwork() bool {
	return false
}

// GetDefaultNetwork returns the *abstract.Network corresponding to the default network
func (s stack) GetDefaultNetwork() (*abstract.Network, fail.Error) {
	return nil, fail.NotFoundError("no default network in gcp driver")
}

// CreateNetwork creates a new network
func (s stack) CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	nullAN := abstract.NewNetwork()
	if s.IsNull() {
		return nullAN, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", req.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	if _, xerr := s.rpcGetNetworkByName(req.Name); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
		default:
			return nullAN, xerr
		}
	}

	// Checks if CIDR is valid...
	if req.CIDR == "" {
		tracer.Trace("CIDR is empty, choosing one...")
		req.CIDR = stacks.DefaultNetworkCIDR
		tracer.Trace("CIDR chosen for network is '%s'", req.CIDR)
	}

	// disable subnetwork auto-creation
	// ne := compute.Network{
	// 	Name:                  s.GcpConfig.NetworkName,
	// 	AutoCreateSubnetworks: false,
	// 	ForceSendFields:       []string{"AutoCreateSubnetworks"},
	// }
	//
	// compuService := s.ComputeService
	//
	// recreateSafescaleNetwork := true
	// recnet, err := compuService.Networks.Get(s.GcpConfig.ProjectID, ne.Name).Do()
	// if recnet != nil && err == nil {
	// 	recreateSafescaleNetwork = false
	// } else if err != nil {
	// 	xerr := normalizeError(err)
	// 	switch xerr.(type) {
	// 	case *fail.ErrNotFound:
	// 	default:
	// 		return nil, xerr
	// 	}
	// }
	// if recreateSafescaleNetwork {
	// 	opp, err := compuService.Networks.Insert(s.GcpConfig.ProjectID, &ne).Context(context.Background()).Do()
	// 	if err != nil {
	// 		return nil, fail.ToError(err)
	// 	}
	//
	// 	oco := opContext{
	// 		Operation:    opp,
	// 		ProjectID:    s.GcpConfig.ProjectID,
	// 		Service:      compuService,
	// 		DesiredState: "DONE",
	// 	}
	//
	// 	xerr := rpcWaitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
	// 	if err != nil {
	// 		return nil, xerr
	// 	}
	// }
	//
	// necreated, err := compuService.Networks.Get(s.GcpConfig.ProjectID, ne.Name).Do()
	// if err != nil {
	// 	return nil, normalizeError(err)
	// }
	//
	resp, xerr := s.rpcCreateNetwork(req.Name)
	if xerr != nil {
		return nullAN, xerr
	}

	net := abstract.NewNetwork()
	net.ID = strconv.FormatUint(resp.Id, 10)
	net.Name = req.Name
	net.CIDR = req.CIDR // Not enforced by GCP, but needed by SafeScale

	// // Create subnetwork
	//
	// theRegion := s.GcpConfig.Region
	//
	// subnetReq := compute.Subnetwork{
	//	IpCidrRange: req.CIDR,
	//	Name:        req.Name,
	//	Network:     fmt.Sprintf("%s/networks/%s", s.linksPrefix, s.GcpConfig.NetworkName),
	//	Region:      theRegion,
	// }
	//
	// opp, err := compuService.Subnetworks.Insert(s.GcpConfig.ProjectID, theRegion, &subnetReq).Context(context.Background()).Do()
	// if err != nil {
	//	return nil, normalizeError(err)
	// }
	//
	// oco := opContext{
	//	Operation:    opp,
	//	ProjectID:    s.GcpConfig.ProjectID,
	//	Service:      compuService,
	//	DesiredState: "DONE",
	// }
	//
	// err = rpcWaitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
	// if err != nil {
	//	return nil, fail.ToError(err)
	// }
	//
	// gcpSubNet, err := compuService.Subnetworks.Get(s.GcpConfig.ProjectID, theRegion, req.Name).Do()
	// if err != nil {
	//	return nil, normalizeError(err)
	// }
	//
	// // FIXME: Add properties and GatewayID
	// subnet := abstract.NewSubnetk()
	// subnet.ID = strconv.FormatUint(gcpSubNet.Id, 10)
	// subnet.Name = gcpSubNet.Name
	// subnet.CIDR = gcpSubNet.IpCidrRange
	// subnet.IPVersion = ipversion.IPv4
	//
	// buildNewRule := true
	// fws, err := s.ComputeService.Firewalls.Get(s.GcpConfig.ProjectID, firewallRuleName).Do()
	// if err != nil {
	// 	xerr := normalizeError(err)
	// 	switch xerr.(type) {
	// 	case *fail.ErrNotFound:
	// 	default:
	// 		return nil, xerr
	// 	}
	// }
	// if fws != nil {
	// 	buildNewRule = false
	// }
	// if buildNewRule {
	// fiw := compute.Firewall{
	// 	Allowed: []*compute.FirewallAllowed{
	// 		{
	// 			IPProtocol: "all",
	// 		},
	// 	},
	// 	Direction:    "INGRESS",
	// 	Disabled:     false,
	// 	Name:         firewallRuleName,
	// 	Network:      fmt.Sprintf("%s/networks/%s", s.linksPrefix, s.GcpConfig.NetworkName),
	// 	Priority:     999,
	// 	SourceRanges: []string{"0.0.0.0/0"},
	// }
	//
	// opp, err := s.ComputeService.Firewalls.Insert(s.GcpConfig.ProjectID, &fiw).Do()
	// if err != nil {
	// 	return nil, normalizeError(err)
	// }
	//
	// oco := opContext{
	// 	Operation:    opp,
	// 	ProjectID:    s.GcpConfig.ProjectID,
	// 	Service:      s.ComputeService,
	// 	DesiredState: "DONE",
	// }
	// xerr := rpcWaitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
	// if xerr != nil {
	// 	return nil, xerr
	// }
	// }

	_ = net.OK()

	return net, nil
}

// InspectNetwork returns the network identified by id (actually for gcp, id here is name)
func (s stack) InspectNetwork(id string) (*abstract.Network, fail.Error) {
	nullAN := abstract.NewNetwork()
	if s.IsNull() {
		return nullAN, fail.InvalidInstanceError()
	}
	if id = strings.TrimSpace(id); id == "" {
		return nullAN, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcGetNetworkByID(id)
	if xerr != nil {
		return nullAN, xerr
	}

	return toAbstractNetwork(*resp), nil
}

// InspectNetworkByName returns the network identified by ref (id or name)
func (s stack) InspectNetworkByName(name string) (*abstract.Network, fail.Error) {
	nullAN := abstract.NewNetwork()
	if s.IsNull() {
		return nullAN, fail.InvalidInstanceError()
	}
	if name = strings.TrimSpace(name); name == "" {
		return nullAN, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcGetNetworkByName(name)
	if xerr != nil {
		return nullAN, nil
	}
	return toAbstractNetwork(*resp), nil
	// nets, xerr := s.ListNetworks()
	// if xerr != nil {
	// 	return nil, xerr
	// }
	// for _, net := range nets {
	// 	if net.Name == name {
	// 		return net, nil
	// 	}
	// }
	//
	// return nil, abstract.ResourceNotFoundError("network", name)
}

func toAbstractNetwork(in compute.Network) *abstract.Network {
	out := abstract.NewNetwork()
	out.Name = in.Name
	out.ID = strconv.FormatUint(in.Id, 10)
	out.CIDR = in.IPv4Range
	return out
}

// ListNetworks lists available networks
func (s stack) ListNetworks() ([]*abstract.Network, fail.Error) {
	var emptySlice []*abstract.Network
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp")).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcListNetworks()
	if xerr != nil {
		return emptySlice, xerr
	}

	out := make([]*abstract.Network, 0, len(resp))
	for _, v := range resp {
		out = append(out, toAbstractNetwork(*v))
	}
	return out, nil
}

// DeleteNetwork deletes the network identified by id
func (s stack) DeleteNetwork(ref string) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()

	theNetwork, xerr := s.InspectNetwork(ref)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
		default:
			return xerr
		}
	}
	if !theNetwork.OK() {
		logrus.Warnf("Missing data in network: %s", spew.Sdump(theNetwork))
	}

	// Remove routes and firewall
	firewallRuleName := fmt.Sprintf("%s-all-in" /*"%s-%s-all-in"*/, s.GcpConfig.NetworkName /*, subnetwork.Name*/)
	fws, xerr := s.rpcGetFirewallRuleByName(firewallRuleName)
	if xerr != nil {
		return xerr
	}

	if fws != nil {
		if xerr = s.rpcDeleteFirewallRuleByID(fmt.Sprintf("%d", fws.Id)); xerr != nil {
			return xerr
		}
	}

	// natRuleName := fmt.Sprintf("%s-%s-nat-allowed", s.GcpConfig.NetworkName, subnetwork.Name)
	// nws, err := compuService.Routes.Get(s.GcpConfig.ProjectID, natRuleName).Do()
	// if err != nil {
	//	logrus.Warn(err)
	//	return fail.ToError(err)
	// }
	//
	// if nws != nil {
	//	opp, operr := compuService.Routes.Delete(s.GcpConfig.ProjectID, natRuleName).Do()
	//	if operr != nil {
	//		return normalizeError(err)
	//	}
	//
	//	oco := opContext{
	//		Operation:    opp,
	//		ProjectID:    s.GcpConfig.ProjectID,
	//		Service:      compuService,
	//		DesiredState: "DONE",
	//	}
	//	operr = rpcWaitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostCleanupTimeout())
	//	if operr != nil {
	//		logrus.Warn(operr)
	//		return fail.ToError(operr)
	//	}
	// }

	return s.rpcDeleteNetworkByID(theNetwork.ID)
}

// ------ VIP methods ------

// CreateVIP creates a private virtual IP
func (s stack) CreateVIP(networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if networkID == "" {
		return nil, fail.InvalidParameterError("networkID", "cannot be empty string")
	}
	if subnetID == "" {
		return nil, fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", networkID).WithStopwatch().Entering()
	defer tracer.Exiting()

	return nil, fail.NotImplementedError("CreateVIP() not implemented yet") // FIXME: Technical debt
}

// AddPublicIPToVIP adds a public IP to VIP
func (s stack) AddPublicIPToVIP(vip *abstract.VirtualIP) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%v)", vip).WithStopwatch().Entering()
	defer tracer.Exiting()

	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (s stack) BindHostToVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}
	if hostID == "" {
		return fail.InvalidParameterError("networkID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%v, %s)", vip, hostID).WithStopwatch().Entering()
	defer tracer.Exiting()

	return fail.NotImplementedError("BindHostToVIP() not implemented yet") // FIXME: Technical debt
}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (s stack) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}
	if hostID == "" {
		return fail.InvalidParameterError("networkID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%v, %s)", vip, hostID).WithStopwatch().Entering()
	defer tracer.Exiting()

	return fail.NotImplementedError("UnbindHostFromVIP() not implemented yet") // FIXME: Technical debt
}

// DeleteVIP deletes the VIP
func (s stack) DeleteVIP(vip *abstract.VirtualIP) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%v)", vip).WithStopwatch().Entering()
	defer tracer.Exiting()

	return fail.NotImplementedError("DeleteVIP() not implemented yet") // FIXME: Technical debt
}

// ------ SecurityGroup methods ------

// BindSecurityGroupToSubnet binds a security group to a subnet
// Does actually nothing for GCP
func (s stack) BindSecurityGroupToSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if subnetID == "" {
		return fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	// FIXME: add tracing
	// asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	// if xerr != nil {
	// 	return xerr
	// }
	// asg, xerr = s.InspectSecurityGroup(asg)
	// if xerr != nil {
	// 	return xerr
	// }

	return nil
}

// UnbindSecurityGroupFromSubnet unbinds a security group from a subnet
// Does actually nothing for GCP
func (s stack) UnbindSecurityGroupFromSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if subnetID == "" {
		return fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	// asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	// if xerr != nil {
	// 	return xerr
	// }
	// asg, xerr = s.InspectSecurityGroup(asg)
	// if xerr != nil {
	// 	return xerr
	// }

	return nil
}

// ------ Subnet methods ------

// CreateSubnet creates a new subnet
func (s stack) CreateSubnet(req abstract.SubnetRequest) (_ *abstract.Subnet, xerr fail.Error) {
	nullAS := abstract.NewSubnet()
	if s.IsNull() {
		return nullAS, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", req.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	// compuService := s.ComputeService

	// recreateSafescaleNetwork := true
	// recnet, err := compuService.Networks.Get(s.GcpConfig.ProjectID, ne.Name).Do()
	// if recnet != nil && err == nil {
	//    recreateSafescaleNetwork = false
	// } else if err != nil {
	//    xerr := normalizeError(err)
	//    switch xerr.(type) {
	//    case *fail.ErrNotFound:
	//    default:
	//        return nil, xerr
	//    }
	// }
	//
	// if recreateSafescaleNetwork {
	//    opp, err := compuService.Networks.Insert(s.GcpConfig.ProjectID, &ne).Context(context.Background()).Do()
	//    if err != nil {
	//        return nil, fail.ToError(err)
	//    }
	//
	//    oco := opContext{
	//        Operation:    opp,
	//        ProjectID:    s.GcpConfig.ProjectID,
	//        Service:      compuService,
	//        DesiredState: "DONE",
	//    }
	//
	//    xerr := rpcWaitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
	//    if err != nil {
	//        return nil, xerr
	//    }
	// }

	an, xerr := s.InspectNetwork(req.NetworkID)
	if xerr != nil {
		return nullAS, fail.Wrap(xerr, "failed to find Network identified by %s", req.NetworkID)
	}

	// // Checks if CIDR is valid...
	// if req.CIDR == "" {
	// 	tracer.Trace("CIDR is empty, choosing one...")
	// 	req.CIDR = "192.168.1.0/24"
	// 	tracer.Trace("CIDR chosen for Subnet is '%s'", req.CIDR)
	// }
	if xerr = s.validateCIDR(req, an); xerr != nil {
		return nil, xerr
	}

	// // Create as
	// theRegion := s.GcpConfig.Region
	//
	// subnetReq := compute.Subnetwork{
	// 	IpCidrRange: req.CIDR,
	// 	Name:        req.Name,
	// 	Network:     fmt.Sprintf("%s/networks/%s", s.linksPrefix, an.Name),
	// 	Region:      theRegion,
	// }
	// opp, err := compuService.Subnetworks.Insert(s.GcpConfig.ProjectID, theRegion, &subnetReq).Context(context.Background()).Do()
	// if err != nil {
	// 	return nil, normalizeError(err)
	// }
	//
	// defer func() {
	// 	if xerr != nil && !req.KeepOnFailure {
	// 		_, derr := compuService.Subnetworks.Delete(s.GcpConfig.ProjectID, theRegion, opp.Name).Do()
	// 		if derr != nil {
	// 			_ = xerr.AddConsequence(derr)
	// 		}
	// 	}
	// }()
	//
	// oco := opContext{
	// 	Operation:    opp,
	// 	ProjectID:    s.GcpConfig.ProjectID,
	// 	Service:      compuService,
	// 	DesiredState: "DONE",
	// }
	// err = rpcWaitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
	// if err != nil {
	// 	return nil, fail.ToError(err)
	// }
	//
	// gcpSubNet, err := compuService.Subnetworks.Get(s.GcpConfig.ProjectID, theRegion, req.Name).Do()
	// if err != nil {
	// 	return nil, normalizeError(err)
	// }

	resp, xerr := s.rpcCreateSubnet(req.Name, an.Name, req.CIDR)
	if xerr != nil {
		return nullAS, xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			if derr := s.rpcDeleteSubnetByName(req.Name); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Subnet '%s'", req.Name))
			}
		}
	}()

	as := abstract.NewSubnet()
	as.ID = strconv.FormatUint(resp.Id, 10)
	as.Name = req.Name
	as.CIDR = resp.IpCidrRange
	as.IPVersion = ipversion.IPv4
	as.Network = req.NetworkID

	var route *compute.Route
	if route, xerr = s.rpcCreateRoute(an.Name, as.Name); xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			if derr := s.rpcDeleteRoute(route.Name); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete route '%s'", route.Name))
			}
		}
	}()

	// firewallRuleName := fmt.Sprintf("%s-%s-all-in", an.Name, as.Name)
	// if _, xerr = s.rpcGetFirewallRuleByName(firewallRuleName); xerr != nil {
	// 	switch xerr.(type) {
	// 	case *fail.ErrNotFound:
	// 		// continue
	// 	default:
	// 		return nil, xerr
	// 	}
	// } else {
	// 	return nil, fail.DuplicateError("failed to create firewall rule named '%s', already exist", firewallRuleName)
	// }
	//
	// allowed := []*compute.FirewallAllowed{
	// 	{
	// 		IPProtocol: "all",
	// 	},
	// }
	// if _, xerr = s.rpcCreateFirewallRule(firewallRuleName, an.Name, "", "INGRESS", false, []string{"0.0.0.0/0"}, false, []string{req.CIDR}, allowed, nil); xerr != nil {
	// 	return nil, xerr
	// }

	_ = as.OK()

	return as, nil
}

func (s stack) validateCIDR(req abstract.SubnetRequest, network *abstract.Network) fail.Error {
	// _, networkDesc, _ := net.ParseCIDR(network.CIDR)
	_, _ /*subnetDesc*/, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return fail.Wrap(err, "failed to validate CIDR '%s' for Subnet '%s'", req.CIDR, req.Name)
	}
	// if networkDesc.IP.Equal(subnetDesc.IP) && networkDesc.Mask.String() == subnetDesc.Mask.String() {
	// 	return fail.InvalidRequestError("cannot create Subnet with CIDR '%s': equal to Network one", req.CIDR)
	// }
	return nil
}

// InspectSubnet returns the subnet identified by id
func (s stack) InspectSubnet(id string) (*abstract.Subnet, fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcGetSubnetByID(id)
	if xerr != nil {
		return nil, xerr
	}

	return toAbstractSubnet(*resp), nil
	// subnets, xerr := s.ListSubnets("")
	// for _, v := range subnets {
	// 	if v.ID == id {
	// 		return v, nil
	// 	}
	// }
	//
	// return nil, abstract.ResourceNotFoundError("network", id)
}

// InspectSubnetByName returns the subnet identified by name
func (s stack) InspectSubnetByName(networkRef, name string) (_ *abstract.Subnet, xerr fail.Error) {
	nullAS := abstract.NewSubnet()
	if s.IsNull() {
		return nullAS, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	// var region string
	// if networkRef != "" {
	// 	resp, xerr := s.rpcGetNetworkByID(networkRef)
	// 	if xerr != nil {
	// 		switch xerr.(type) {
	// 		case *fail.ErrNotFound:
	// 			resp, xerr = s.rpcGetNetworkByName(networkRef)
	// 		default:
	// 			return nullAS, xerr
	// 		}
	// 	}
	// 	if xerr != nil {
	// 		switch xerr.(type) {
	// 		case *fail.ErrNotFound:
	// 			return nullAS, fail.NotFoundError("failed to find Network %s", networkRef)
	// 		default:
	// 			return nullAS, xerr
	// 		}
	// 	}
	//
	// 	if region, xerr = getRegionFromSelfLink(genURL(resp.SelfLink)); xerr != nil {
	// 		return nullAS, xerr
	// 	}
	// }

	resp, xerr := s.rpcGetSubnetByName(name)
	if xerr != nil {
		return nil, xerr
	}

	var region string
	if region, xerr = getRegionFromSelfLink(genURL(resp.SelfLink)); xerr != nil {
		return nullAS, xerr
	}

	if region != s.GcpConfig.Region {
		return nil, fail.NotFoundError("failed to find a Subnet named '%s'", name)
	}

	return toAbstractSubnet(*resp), nil
}

// ListSubnets lists available subnets
func (s stack) ListSubnets(networkRef string) (_ []*abstract.Subnet, xerr fail.Error) {
	var emptySlice []*abstract.Subnet
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp")).WithStopwatch().Entering()
	defer tracer.Exiting()

	var (
		subnets []*abstract.Subnet
		filter  string
	)

	var an *abstract.Network
	if networkRef != "" {
		an, xerr = s.InspectNetwork(networkRef)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				an, xerr = s.InspectNetworkByName(networkRef)
			}
		}
		if xerr != nil {
			return emptySlice, fail.Wrap(xerr, "failed to find Network '%s'", networkRef)
		}
		filter = `selfLink eq "` + s.selfLinkPrefix + `/global/networks/` + an.Name + `"`
	}

	resp, xerr := s.rpcListSubnets(filter)
	if xerr != nil {
		return emptySlice, xerr
	}

	for _, v := range resp {
		subnets = append(subnets, toAbstractSubnet(*v))
	}

	return subnets, nil
}

func toAbstractSubnet(in compute.Subnetwork) *abstract.Subnet {
	item := abstract.NewSubnet()
	item.Name = in.Name
	item.ID = strconv.FormatUint(in.Id, 10)
	item.CIDR = in.IpCidrRange
	return item
}

// DeleteSubnet deletes the subnet identified by id
func (s stack) DeleteSubnet(id string) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	subn, xerr := s.rpcGetSubnetByID(id)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nil
		default:
			return xerr
		}
	}

	// Delete Subnet
	if xerr = s.rpcDeleteSubnetByName(subn.Name); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return fail.Wrap(xerr.Cause(), "Timeout waiting for Subnet deletion")
		default:
			return xerr
		}
	}

	// Delete NAT route
	tmp := strings.Split(subn.Network, "/")
	networkName := tmp[len(tmp)-1]
	natRuleName := fmt.Sprintf(natRouteNameFormat, networkName, subn.Name)
	if xerr = s.rpcDeleteRoute(natRuleName); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// consider missing route as a successful removal
		default:
			return xerr
		}
	}
	return nil
}
