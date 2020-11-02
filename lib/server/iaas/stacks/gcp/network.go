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
	"context"
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"strconv"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
	"google.golang.org/api/compute/v1"
)

// ------ network methods ------

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (s *stack) HasDefaultNetwork() bool {
	return false
}

// GetDefaultNetwork returns the *abstract.Network corresponding to the default network
func (s *stack) GetDefaultNetwork() (*abstract.Network, fail.Error) {
	return nil, fail.NotFoundError("no default network in stack")
}

// CreateNetwork creates a new network
func (s stack) CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	//if s == nil {
	//	return nil, fail.InvalidInstanceError()
	//}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", req.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	// disable subnetwork auto-creation
	ne := compute.Network{
		Name:                  s.GcpConfig.NetworkName,
		AutoCreateSubnetworks: false,
		ForceSendFields:       []string{"AutoCreateSubnetworks"},
	}

	compuService := s.ComputeService

	recreateSafescaleNetwork := true
	recnet, err := compuService.Networks.Get(s.GcpConfig.ProjectID, ne.Name).Do()
	if recnet != nil && err == nil {
		recreateSafescaleNetwork = false
	} else if err != nil {
		xerr := normalizeError(err)
		switch xerr.(type) {
		case *fail.ErrNotFound:
		default:
			return nil, xerr
		}
	}

	if recreateSafescaleNetwork {
		opp, err := compuService.Networks.Insert(s.GcpConfig.ProjectID, &ne).Context(context.Background()).Do()
		if err != nil {
			return nil, fail.ToError(err)
		}

		oco := OpContext{
			Operation:    opp,
			ProjectID:    s.GcpConfig.ProjectID,
			Service:      compuService,
			DesiredState: "DONE",
		}

		xerr := waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
		if err != nil {
			return nil, xerr
		}
	}

	necreated, err := compuService.Networks.Get(s.GcpConfig.ProjectID, ne.Name).Do()
	if err != nil {
		return nil, normalizeError(err)
	}

	net := abstract.NewNetwork()
	net.ID = strconv.FormatUint(necreated.Id, 10)
	net.Name = necreated.Name

	// Checks if IPRanges is valid...
	if req.CIDR == "" {
		tracer.Trace("IPRanges is empty, choosing one...")
		req.CIDR = "192.168.1.0/24"
		tracer.Trace("IPRanges chosen for network is '%s'", req.CIDR)
	}

	//// Create subnetwork
	//
	//theRegion := s.GcpConfig.Region
	//
	//subnetReq := compute.Subnetwork{
	//	IpCidrRange: req.IPRanges,
	//	Name:        req.Name,
	//	Network:     fmt.Sprintf("projects/%s/global/networks/%s", s.GcpConfig.ProjectID, s.GcpConfig.NetworkName),
	//	Region:      theRegion,
	//}
	//
	//opp, err := compuService.Subnetworks.Insert(s.GcpConfig.ProjectID, theRegion, &subnetReq).Context(context.Background()).Do()
	//if err != nil {
	//	return nil, normalizeError(err)
	//}
	//
	//oco := OpContext{
	//	Operation:    opp,
	//	ProjectID:    s.GcpConfig.ProjectID,
	//	Service:      compuService,
	//	DesiredState: "DONE",
	//}
	//
	//err = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
	//if err != nil {
	//	return nil, fail.ToError(err)
	//}
	//
	//gcpSubNet, err := compuService.Subnetworks.Get(s.GcpConfig.ProjectID, theRegion, req.Name).Do()
	//if err != nil {
	//	return nil, normalizeError(err)
	//}
	//
	//// FIXME: Add properties and GatewayID
	//subnet := abstract.NewSubnetk()
	//subnet.ID = strconv.FormatUint(gcpSubNet.Id, 10)
	//subnet.Name = gcpSubNet.Name
	//subnet.IPRanges = gcpSubNet.IpCidrRange
	//subnet.IPVersion = ipversion.IPv4
	//
	buildNewRule := true
	firewallRuleName := fmt.Sprintf("%s-all-in", s.GcpConfig.NetworkName /*, gcpSubNet.Name*/)

	fws, err := compuService.Firewalls.Get(s.GcpConfig.ProjectID, firewallRuleName).Do()
	if err != nil {
		xerr := normalizeError(err)
		switch xerr.(type) {
		case *fail.ErrNotFound:
		default:
			return nil, xerr
		}
	}
	if fws != nil {
		buildNewRule = false
	}

	if buildNewRule {
		fiw := compute.Firewall{
			Allowed: []*compute.FirewallAllowed{
				{
					IPProtocol: "all",
				},
			},
			Direction:    "INGRESS",
			Disabled:     false,
			Name:         firewallRuleName,
			Network:      fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/global/networks/%s", s.GcpConfig.ProjectID, s.GcpConfig.NetworkName),
			Priority:     999,
			SourceRanges: []string{"0.0.0.0/0"},
		}

		opp, err := compuService.Firewalls.Insert(s.GcpConfig.ProjectID, &fiw).Do()
		if err != nil {
			return nil, normalizeError(err)
		}

		oco := OpContext{
			Operation:    opp,
			ProjectID:    s.GcpConfig.ProjectID,
			Service:      compuService,
			DesiredState: "DONE",
		}
		xerr := waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
		if xerr != nil {
			return nil, xerr
		}
	}

	//buildNewNATRule := true
	//natRuleName := fmt.Sprintf("%s-%s-nat-allowed", s.GcpConfig.NetworkName, gcpSubNet.Name)
	//
	//rfs, err := compuService.Routes.Get(s.GcpConfig.ProjectID, natRuleName).Do()
	//if err != nil {
	//	xerr := normalizeError(err)
	//	switch xerr.(type) {
	//	case *fail.ErrNotFound:
	//	default:
	//		return nil, xerr
	//	}
	//}
	//if rfs != nil {
	//	buildNewNATRule = false
	//}
	//if buildNewNATRule {
	//	route := &compute.Route{
	//		DestRange:       "0.0.0.0/0",
	//		Name:            natRuleName,
	//		Network:         fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/global/networks/%s", s.GcpConfig.ProjectID, s.GcpConfig.NetworkName),
	//		NextHopInstance: fmt.Sprintf("projects/%s/zones/%s/instances/gw-%s", s.GcpConfig.ProjectID, s.GcpConfig.Zone, req.Name),
	//		Priority:        800,
	//		Tags:            []string{fmt.Sprintf("no-ip-%s", gcpSubNet.Name)},
	//	}
	//	opp, err := compuService.Routes.Insert(s.GcpConfig.ProjectID, route).Do()
	//	if err != nil {
	//		return nil, normalizeError(err)
	//	}
	//	oco = OpContext{
	//		Operation:    opp,
	//		ProjectID:    s.GcpConfig.ProjectID,
	//		Service:      compuService,
	//		DesiredState: "DONE",
	//	}
	//
	//	xerr := waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
	//	if xerr != nil {
	//		return nil, xerr
	//	}
	//}

	_ = net.OK()

	return net, nil
}

// InspectNetwork returns the network identified by id
func (s stack) InspectNetwork(id string) (*abstract.Network, fail.Error) {
	//if s == nil {
	//	return nil, fail.InvalidInstanceError()
	//}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	nets, xerr := s.ListNetworks()
	if xerr != nil {
		return nil, xerr
	}
	for _, net := range nets {
		if net.ID == id {
			return net, nil
		}
	}

	return nil, abstract.ResourceNotFoundError("network", id)
}

// InspectNetworkByName returns the network identified by ref (id or name)
func (s stack) InspectNetworkByName(name string) (*abstract.Network, fail.Error) {
	//if s == nil {
	//	return nil, fail.InvalidInstanceError()
	//}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	nets, xerr := s.ListNetworks()
	if xerr != nil {
		return nil, xerr
	}
	for _, net := range nets {
		if net.Name == name {
			return net, nil
		}
	}

	return nil, abstract.ResourceNotFoundError("network", name)
}

// ListNetworks lists available networks
func (s stack) ListNetworks() ([]*abstract.Network, fail.Error) {
	//if s == nil {
	//	return nil, fail.InvalidInstanceError()
	//}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp")).WithStopwatch().Entering()
	defer tracer.Exiting()

	var networks []*abstract.Network

	compuService := s.ComputeService

	token := ""
	for paginate := true; paginate; {
		resp, err := compuService.Networks.List(s.GcpConfig.ProjectID).PageToken(token).Do()
		if err != nil {
			return networks, fail.Wrap(err, "cannot list networks")
		}

		for _, nett := range resp.Items {
			newNet := abstract.NewNetwork()
			newNet.Name = nett.Name
			newNet.ID = strconv.FormatUint(nett.Id, 10)
			newNet.CIDR = nett.IPv4Range

			networks = append(networks, newNet)
		}
		token := resp.NextPageToken
		paginate = token != ""
	}

	return networks, nil
}

// DeleteNetwork deletes the network identified by id
func (s *stack) DeleteNetwork(ref string) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()

	theNetwork, xerr := s.InspectNetwork(ref)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return xerr
		}
	}
	if theNetwork == nil {
		return fail.NewError("delete network failed: unexpected nil network when looking for '%s'", ref)
	}
	if !theNetwork.OK() {
		logrus.Warnf("Missing data in network: %s", spew.Sdump(theNetwork))
	}

	compuService := s.ComputeService

	// Remove routes and firewall
	firewallRuleName := fmt.Sprintf("%s-all-in" /*"%s-%s-all-in"*/, s.GcpConfig.NetworkName /*, subnetwork.Name*/)
	fws, err := compuService.Firewalls.Get(s.GcpConfig.ProjectID, firewallRuleName).Do()
	if err != nil {
		logrus.Warn(err)
		return fail.ToError(err)
	}

	if fws != nil {
		opp, operr := compuService.Firewalls.Delete(s.GcpConfig.ProjectID, firewallRuleName).Do()
		if operr != nil {
			return normalizeError(operr)
		}

		oco := OpContext{
			Operation:    opp,
			ProjectID:    s.GcpConfig.ProjectID,
			Service:      compuService,
			DesiredState: "DONE",
		}
		operr = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostCleanupTimeout())
		if operr != nil {
			logrus.Warn(operr)
			return fail.ToError(operr)
		}
	}

	//natRuleName := fmt.Sprintf("%s-%s-nat-allowed", s.GcpConfig.NetworkName, subnetwork.Name)
	//nws, err := compuService.Routes.Get(s.GcpConfig.ProjectID, natRuleName).Do()
	//if err != nil {
	//	logrus.Warn(err)
	//	return fail.ToError(err)
	//}
	//
	//if nws != nil {
	//	opp, operr := compuService.Routes.Delete(s.GcpConfig.ProjectID, natRuleName).Do()
	//	if operr != nil {
	//		return normalizeError(err)
	//	}
	//
	//	oco := OpContext{
	//		Operation:    opp,
	//		ProjectID:    s.GcpConfig.ProjectID,
	//		Service:      compuService,
	//		DesiredState: "DONE",
	//	}
	//	operr = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostCleanupTimeout())
	//	if operr != nil {
	//		logrus.Warn(operr)
	//		return fail.ToError(operr)
	//	}
	//}

	return nil
}

// ------ VIP methods ------

// CreateVIP creates a private virtual IP
func (s *stack) CreateVIP(networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	if s == nil {
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
func (s *stack) AddPublicIPToVIP(vip *abstract.VirtualIP) fail.Error {
	if s == nil {
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
func (s *stack) BindHostToVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	if s == nil {
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
func (s *stack) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	if s == nil {
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
func (s *stack) DeleteVIP(vip *abstract.VirtualIP) fail.Error {
	if s == nil {
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
func (s *stack) BindSecurityGroupToSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	if s == nil {
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

	return fail.NotImplementedError()
}

// UnbindSecurityGroupFromSubnet unbinds a security group from a subnet
func (s *stack) UnbindSecurityGroupFromSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	if s == nil {
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

	return fail.NotImplementedError()
}

// ------ Subnet methods ------

// CreateSubnet creates a new subnet
func (s stack) CreateSubnet(req abstract.SubnetRequest) (*abstract.Subnet, fail.Error) {
	//if s == nil {
	//	return nil, fail.InvalidInstanceError()
	//}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", req.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	compuService := s.ComputeService

	//recreateSafescaleNetwork := true
	//recnet, err := compuService.Networks.Get(s.GcpConfig.ProjectID, ne.Name).Do()
	//if recnet != nil && err == nil {
	//    recreateSafescaleNetwork = false
	//} else if err != nil {
	//    xerr := normalizeError(err)
	//    switch xerr.(type) {
	//    case *fail.ErrNotFound:
	//    default:
	//        return nil, xerr
	//    }
	//}
	//
	//if recreateSafescaleNetwork {
	//    opp, err := compuService.Networks.Insert(s.GcpConfig.ProjectID, &ne).Context(context.Background()).Do()
	//    if err != nil {
	//        return nil, fail.ToError(err)
	//    }
	//
	//    oco := OpContext{
	//        Operation:    opp,
	//        ProjectID:    s.GcpConfig.ProjectID,
	//        Service:      compuService,
	//        DesiredState: "DONE",
	//    }
	//
	//    xerr := waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
	//    if err != nil {
	//        return nil, xerr
	//    }
	//}

	an, xerr := s.InspectNetwork(req.NetworkID)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			an, xerr = s.InspectNetworkByName(req.NetworkID)
		}
	}
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to find Network '%s'", req.NetworkID)
	}

	// Checks if IPRanges is valid...
	if req.CIDR == "" {
		tracer.Trace("CIDR is empty, choosing one...")
		req.CIDR = "192.168.1.0/24"
		tracer.Trace("CIDR chosen for Subnet is '%s'", req.CIDR)
	}

	// Create subnet
	theRegion := s.GcpConfig.Region

	subnetReq := compute.Subnetwork{
		IpCidrRange: req.CIDR,
		Name:        req.Name,
		Network:     fmt.Sprintf("projects/%s/global/networks/%s", s.GcpConfig.ProjectID, an.Name),
		Region:      theRegion,
	}

	opp, err := compuService.Subnetworks.Insert(s.GcpConfig.ProjectID, theRegion, &subnetReq).Context(context.Background()).Do()
	if err != nil {
		return nil, normalizeError(err)
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			_, derr := compuService.Subnetworks.Delete(s.GcpConfig.ProjectID, theRegion, opp.Name).Do()
			if derr != nil {
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	oco := OpContext{
		Operation:    opp,
		ProjectID:    s.GcpConfig.ProjectID,
		Service:      compuService,
		DesiredState: "DONE",
	}
	err = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
	if err != nil {
		return nil, fail.ToError(err)
	}

	gcpSubNet, err := compuService.Subnetworks.Get(s.GcpConfig.ProjectID, theRegion, req.Name).Do()
	if err != nil {
		return nil, normalizeError(err)
	}

	subnet := abstract.NewSubnet()
	subnet.ID = strconv.FormatUint(gcpSubNet.Id, 10)
	subnet.Name = gcpSubNet.Name
	subnet.CIDR = gcpSubNet.IpCidrRange
	subnet.IPVersion = ipversion.IPv4

	//buildNewRule := true
	//firewallRuleName := fmt.Sprintf("%s-%s-all-in", s.GcpConfig.NetworkName, an.Name /*gcpSubNet.Name*/)
	//
	//fws, err := compuService.Firewalls.Get(s.GcpConfig.ProjectID, firewallRuleName).Do()
	//if err != nil {
	//	xerr := normalizeError(err)
	//	switch xerr.(type) {
	//	case *fail.ErrNotFound:
	//	default:
	//		return nil, xerr
	//	}
	//}
	//if fws != nil {
	//	buildNewRule = false
	//}
	//
	//if buildNewRule {
	//	fiw := compute.Firewall{
	//		Allowed: []*compute.FirewallAllowed{
	//			{
	//				IPProtocol: "all",
	//			},
	//		},
	//		Direction:    "INGRESS",
	//		Disabled:     false,
	//		Name:         firewallRuleName,
	//		Network:      fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/global/networks/%s", s.GcpConfig.ProjectID, s.GcpConfig.NetworkName),
	//		Priority:     999,
	//		SourceRanges: []string{"0.0.0.0/0"},
	//	}
	//
	//	opp, err = compuService.Firewalls.Insert(s.GcpConfig.ProjectID, &fiw).Do()
	//	if err != nil {
	//		return nil, normalizeError(err)
	//	}
	//	oco = OpContext{
	//		Operation:    opp,
	//		ProjectID:    s.GcpConfig.ProjectID,
	//		Service:      compuService,
	//		DesiredState: "DONE",
	//	}
	//
	//	xerr := waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
	//	if xerr != nil {
	//		return nil, xerr
	//	}
	//}

	//buildNewNATRule := true
	//natRuleName := fmt.Sprintf("%s-%s-nat-allowed", s.GcpConfig.NetworkName, gcpSubNet.Name)
	//
	//rfs, err := compuService.Routes.Get(s.GcpConfig.ProjectID, natRuleName).Do()
	//if err != nil {
	//	xerr := normalizeError(err)
	//	switch xerr.(type) {
	//	case *fail.ErrNotFound:
	//	default:
	//		return nil, xerr
	//	}
	//}
	//if rfs != nil {
	//	buildNewNATRule = false
	//}
	//if buildNewNATRule {
	//	route := &compute.Route{
	//		DestRange:       "0.0.0.0/0",
	//		Name:            natRuleName,
	//		Network:         fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/global/networks/%s", s.GcpConfig.ProjectID, s.GcpConfig.NetworkName),
	//		NextHopInstance: fmt.Sprintf("projects/%s/zones/%s/instances/gw-%s", s.GcpConfig.ProjectID, s.GcpConfig.Zone, req.Name),
	//		Priority:        800,
	//		Tags:            []string{fmt.Sprintf("no-ip-%s", gcpSubNet.Name)},
	//	}
	//	opp, err := compuService.Routes.Insert(s.GcpConfig.ProjectID, route).Do()
	//	if err != nil {
	//		return nil, normalizeError(err)
	//	}
	//	oco = OpContext{
	//		Operation:    opp,
	//		ProjectID:    s.GcpConfig.ProjectID,
	//		Service:      compuService,
	//		DesiredState: "DONE",
	//	}
	//
	//	xerr := waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
	//	if xerr != nil {
	//		return nil, xerr
	//	}
	//}

	_ = subnet.OK()

	return subnet, nil
}

// InspectSubnet returns the subnet identified by id
func (s stack) InspectSubnet(id string) (*abstract.Subnet, fail.Error) {
	//if s == nil {
	//	return nil, fail.InvalidInstanceError()
	//}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	subnets, xerr := s.ListSubnets("")
	if xerr != nil {
		return nil, xerr
	}
	for _, v := range subnets {
		if v.ID == id {
			return v, nil
		}
	}

	return nil, abstract.ResourceNotFoundError("network", id)
}

// InspectSubnetByName returns the subnet identified by name
func (s stack) InspectSubnetByName(networkRef, name string) (*abstract.Subnet, fail.Error) {
	//if s == nil {
	//	return nil, fail.InvalidInstanceError()
	//}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	subnets, xerr := s.ListSubnets(networkRef)
	if xerr != nil {
		return nil, xerr
	}
	for _, v := range subnets {
		if v.Name == name {
			return v, nil
		}
	}

	return nil, abstract.ResourceNotFoundError("subnet", name)
}

// ListSubnets lists available subnets
func (s stack) ListSubnets(networkRef string) (_ []*abstract.Subnet, xerr fail.Error) {
	//if s == nil {
	//	return nil, fail.InvalidInstanceError()
	//}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp")).WithStopwatch().Entering()
	defer tracer.Exiting()

	var subnets []*abstract.Subnet

	compuService := s.ComputeService
	theRegion := s.GcpConfig.Region

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
			return nil, fail.Wrap(xerr, "failed to find Network '%s'", networkRef)
		}
	}

	token := ""
	for paginate := true; paginate; {
		// FIXME: insert a .Filter() between List() and .PageToken() to narrow list
		resp, err := compuService.Subnetworks.List(s.GcpConfig.ProjectID, theRegion).PageToken(token).Do()
		if err != nil {
			return subnets, fail.Wrap(normalizeError(err), "cannot list subnets")
		}

		for _, v := range resp.Items {
			if an != nil && an.ID == v.Network {
				item := abstract.NewSubnet()
				item.Name = v.Name
				item.ID = strconv.FormatUint(v.Id, 10)
				item.CIDR = v.IpCidrRange

				subnets = append(subnets, item)
			}
		}
		token := resp.NextPageToken
		paginate = token != ""
	}

	return subnets, nil
}

// DeleteSubnet deletes the subnet identified by id
func (s stack) DeleteSubnet(id string) (xerr fail.Error) {
	//if s == nil {
	//	return fail.InvalidInstanceError()
	//}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	compuService := s.ComputeService
	subnetwork, err := compuService.Subnetworks.Get(s.GcpConfig.ProjectID, s.GcpConfig.Region, id).Do()
	if err != nil {
		return fail.ToError(err)
	}

	opp, err := compuService.Subnetworks.Delete(s.GcpConfig.ProjectID, s.GcpConfig.Region, subnetwork.Name).Do()
	if err != nil {
		return fail.ToError(err)
	}

	oco := OpContext{
		Operation:    opp,
		ProjectID:    s.GcpConfig.ProjectID,
		Service:      compuService,
		DesiredState: "DONE",
	}
	xerr = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostCleanupTimeout())
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			logrus.Warnf("Timeout waiting for subnet deletion")
			return xerr
		default:
			return xerr
		}
	}

	//// Remove routes and firewall
	//firewallRuleName := fmt.Sprintf("%s-%s-all-in", s.GcpConfig.NetworkName, subnetwork.Name)
	//fws, err := compuService.Firewalls.Get(s.GcpConfig.ProjectID, firewallRuleName).Do()
	//if err != nil {
	//	logrus.Warn(err)
	//	return fail.ToError(err)
	//}
	//
	//if fws != nil {
	//	opp, operr := compuService.Firewalls.Delete(s.GcpConfig.ProjectID, firewallRuleName).Do()
	//	if operr == nil {
	//		oco := OpContext{
	//			Operation:    opp,
	//			ProjectID:    s.GcpConfig.ProjectID,
	//			Service:      compuService,
	//			DesiredState: "DONE",
	//		}
	//
	//		operr = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostCleanupTimeout())
	//		if operr != nil {
	//			logrus.Warn(operr)
	//			return fail.ToError(operr)
	//		}
	//	} else {
	//		return fail.ToError(operr)
	//	}
	//}
	//
	//natRuleName := fmt.Sprintf("%s-%s-nat-allowed", s.GcpConfig.NetworkName, subnetwork.Name)
	//nws, err := compuService.Routes.Get(s.GcpConfig.ProjectID, natRuleName).Do()
	//if err != nil {
	//	logrus.Warn(err)
	//	return fail.ToError(err)
	//}
	//
	//if nws != nil {
	//	opp, operr := compuService.Routes.Delete(s.GcpConfig.ProjectID, natRuleName).Do()
	//	if operr == nil {
	//		oco := OpContext{
	//			Operation:    opp,
	//			ProjectID:    s.GcpConfig.ProjectID,
	//			Service:      compuService,
	//			DesiredState: "DONE",
	//		}
	//
	//		operr = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostCleanupTimeout())
	//		if operr != nil {
	//			logrus.Warn(operr)
	//			return fail.ToError(operr)
	//		}
	//	} else {
	//		return fail.ToError(operr)
	//	}
	//}

	return nil
}
