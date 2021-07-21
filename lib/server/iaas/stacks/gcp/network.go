/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

	"google.golang.org/api/compute/v1"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

const (
	natRouteNameFormat = "sfsnet-%s-nat-allowed"
	natRouteTagFormat  = "sfsnet-%s-nat-needed"
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
			debug.IgnoreError(xerr)
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

	resp, xerr := s.rpcCreateNetwork(req.Name)
	if xerr != nil {
		return nullAN, xerr
	}

	anet := abstract.NewNetwork()
	anet.ID = strconv.FormatUint(resp.Id, 10)
	anet.Name = req.Name
	anet.CIDR = req.CIDR // Not enforced by GCP, but needed by SafeScale

	// _ = net.OK()

	return anet, nil
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
		return nullAN, xerr
	}
	return toAbstractNetwork(*resp), nil
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

	metadata := true
	theNetwork, xerr := s.InspectNetwork(ref)
	if xerr != nil {
		metadata = false
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}

	if metadata {
		if theNetwork != nil { // maybe nullAn
			if theNetwork.ID != "" {
				return s.rpcDeleteNetworkByID(theNetwork.ID)
			}
		}
	}

	xerr = s.rpcDeleteNetworkByID(ref)
	if _, ok := xerr.(*fail.ErrNotFound); ok {
		return nil
	}
	return xerr
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
		return fail.InvalidParameterCannotBeNilError("vip")
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
		return fail.InvalidParameterCannotBeNilError("vip")
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
		return fail.InvalidParameterCannotBeNilError("vip")
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
		return fail.InvalidParameterCannotBeNilError("vip")
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

	an, xerr := s.InspectNetwork(req.NetworkID)
	if xerr != nil {
		return nullAS, fail.Wrap(xerr, "failed to find Network identified by %s", req.NetworkID)
	}

	if xerr = s.validateCIDR(req, an); xerr != nil {
		return nil, xerr
	}

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
	if route, xerr = s.rpcCreateRoute(an.Name, as.ID, as.Name); xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			if derr := s.rpcDeleteRoute(route.Name); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete route '%s'", route.Name))
			}
		}
	}()

	_ = as.OK()

	return as, nil
}

func (s stack) validateCIDR(req abstract.SubnetRequest, network *abstract.Network) fail.Error {
	if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
		return fail.Wrap(err, "failed to validate CIDR '%s' for Subnet '%s'", req.CIDR, req.Name)
	}
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
}

// InspectSubnetByName returns the subnet identified by name
func (s stack) InspectSubnetByName(networkRef, name string) (_ *abstract.Subnet, xerr fail.Error) {
	nullAS := abstract.NewSubnet()
	if s.IsNull() {
		return nullAS, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

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
			switch xerr.(type) { //nolint
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

	// Delete NAT route
	natRuleName := fmt.Sprintf(natRouteNameFormat, id)
	if xerr = s.rpcDeleteRoute(natRuleName); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// consider missing route as a successful removal
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}

	subn, xerr := s.rpcGetSubnetByID(id)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// consider a missing Subnet as a successful removal
			debug.IgnoreError(xerr)
			return nil
		default:
			return xerr
		}
	}

	// Delete Subnet
	if xerr = s.rpcDeleteSubnetByName(subn.Name); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return fail.Wrap(xerr.Cause(), "timeout waiting for Subnet '%s' deletion", subn.Name)
		default:
			return xerr
		}
	}

	// Check Subnet no longer exists
	if _, xerr = s.rpcGetSubnetByName(subn.Name); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// consider missing network as a successful removal
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}

	return nil
}
