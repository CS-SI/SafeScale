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

package gcp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"google.golang.org/api/compute/v1"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	NATRouteNameFormat = "sfsnet-%s-nat-allowed"
	NATRouteTagFormat  = "sfsnet-%s-nat-needed"
)

// ------ network methods ------

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (s stack) HasDefaultNetwork() (bool, fail.Error) {
	return false, nil
}

// DefaultNetwork returns the *abstract.Network corresponding to the default network
func (s stack) DefaultNetwork(_ context.Context) (*abstract.Network, fail.Error) {
	return nil, fail.NotFoundError("this provider has no default network")
}

// CreateNetwork creates a new network
func (s stack) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", req.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	if _, xerr := s.rpcGetNetworkByName(ctx, req.Name); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError(xerr)
		default:
			return nil, xerr
		}
	}

	// Checks if CIDR is valid...
	if req.CIDR == "" {
		tracer.Trace("CIDR is empty, choosing one...")
		req.CIDR = stacks.DefaultNetworkCIDR
		tracer.Trace("CIDR chosen for network is '%s'", req.CIDR)
	}

	resp, xerr := s.rpcCreateNetwork(ctx, req.Name)
	if xerr != nil {
		return nil, xerr
	}

	anet, xerr := abstract.NewNetwork(abstract.WithName(req.Name))
	if xerr != nil {
		return nil, xerr
	}

	anet.ID = strconv.FormatUint(resp.Id, 10)
	anet.CIDR = req.CIDR // Not enforced by GCP, but needed by SafeScale

	// _ = net.OK()

	return anet, nil
}

// InspectNetwork returns the network identified by id (actually for gcp, id here is name)
func (s stack) InspectNetwork(ctx context.Context, id string) (*abstract.Network, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id = strings.TrimSpace(id); id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcGetNetworkByID(ctx, id)
	if xerr != nil {
		return nil, xerr
	}

	return toAbstractNetwork(*resp), nil
}

// InspectNetworkByName returns the network identified by ref (id or name)
func (s stack) InspectNetworkByName(ctx context.Context, name string) (*abstract.Network, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcGetNetworkByName(ctx, name)
	if xerr != nil {
		return nil, xerr
	}

	anet := toAbstractNetwork(*resp)
	return anet, nil
}

func toAbstractNetwork(in compute.Network) *abstract.Network {
	out, xerr := abstract.NewNetwork(abstract.WithName(in.Name))
	if xerr != nil {
		out, _ = abstract.NewNetwork()
	}
	out.ID = strconv.FormatUint(in.Id, 10)
	out.CIDR = in.IPv4Range
	return out
}

// ListNetworks lists available networks
func (s stack) ListNetworks(ctx context.Context) ([]*abstract.Network, fail.Error) {
	var emptySlice []*abstract.Network
	if valid.IsNil(s) {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp")).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcListNetworks(ctx)
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
func (s stack) DeleteNetwork(ctx context.Context, networkParam iaasapi.NetworkParameter) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	an, networkLabel, xerr := iaasapi.ValidateNetworkParameter(networkParam)
	if xerr != nil {
		return xerr
	}
	if an.ID == "" {
		return fail.InvalidParameterError("an", "invalid empty string in field 'ID'")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", networkLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	metadata := true
	theNetwork, xerr := s.InspectNetwork(ctx, an.ID)
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

	if metadata && theNetwork != nil && theNetwork.ID != "" {
		return s.rpcDeleteNetworkByID(ctx, theNetwork.ID)
	}

	xerr = s.rpcDeleteNetworkByID(ctx, an.ID)
	if _, ok := xerr.(*fail.ErrNotFound); ok {
		return nil
	}
	return xerr
}

// ------ VIP methods ------

// CreateVIP creates a private virtual IP
func (s stack) CreateVIP(ctx context.Context, networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if networkID == "" {
		return nil, fail.InvalidParameterError("networkID", "cannot be empty string")
	}
	if subnetID == "" {
		return nil, fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", networkID).WithStopwatch().Entering()
	defer tracer.Exiting()

	return nil, fail.NotImplementedError("CreateVIP() not implemented yet") // FIXME: Technical debt
}

// AddPublicIPToVIP adds a public IP to VIP
func (s stack) AddPublicIPToVIP(ctx context.Context, vip *abstract.VirtualIP) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%v)", vip).WithStopwatch().Entering()
	defer tracer.Exiting()

	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (s stack) BindHostToVIP(ctx context.Context, vip *abstract.VirtualIP, hostID string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}
	if hostID == "" {
		return fail.InvalidParameterError("networkID", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%v, %s)", vip, hostID).WithStopwatch().Entering()
	defer tracer.Exiting()

	return fail.NotImplementedError("BindHostToVIP() not implemented yet") // FIXME: Technical debt
}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (s stack) UnbindHostFromVIP(ctx context.Context, vip *abstract.VirtualIP, hostID string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}
	if hostID == "" {
		return fail.InvalidParameterError("networkID", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%v, %s)", vip, hostID).WithStopwatch().Entering()
	defer tracer.Exiting()

	return fail.NotImplementedError("UnbindHostFromVIP() not implemented yet") // FIXME: Technical debt
}

// DeleteVIP deletes the VIP
func (s stack) DeleteVIP(ctx context.Context, vip *abstract.VirtualIP) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%v)", vip).WithStopwatch().Entering()
	defer tracer.Exiting()

	return fail.NotImplementedError("DeleteVIP() not implemented yet") // FIXME: Technical debt
}

// ------ SecurityGroup methods ------

// ------ Subnet methods ------

// CreateSubnet creates a new subnet
func (s stack) CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (_ *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", req.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	an, xerr := s.InspectNetwork(ctx, req.NetworkID)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to find Network identified by %s", req.NetworkID)
	}

	if xerr = s.validateCIDR(req, an); xerr != nil {
		return nil, xerr
	}

	resp, xerr := s.rpcCreateSubnet(ctx, req.Name, an.Name, req.CIDR)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && req.CleanOnFailure() {
			if derr := s.rpcDeleteSubnetByName(context.Background(), req.Name); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Subnet '%s'", req.Name))
			}
		}
	}()

	as, xerr := abstract.NewSubnet(abstract.WithName(req.Name))
	if xerr != nil {
		return nil, xerr
	}

	as.ID = strconv.FormatUint(resp.Id, 10)
	as.CIDR = resp.IpCidrRange
	as.IPVersion = ipversion.IPv4
	as.Network = req.NetworkID

	var route *compute.Route
	if route, xerr = s.rpcCreateRoute(ctx, an.Name, as.ID, as.Name); xerr != nil {
		return nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && req.CleanOnFailure() {
			if derr := s.rpcDeleteRoute(context.Background(), route.Name); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete route '%s'", route.Name))
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
func (s stack) InspectSubnet(ctx context.Context, id string) (*abstract.Subnet, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcGetSubnetByID(ctx, id)
	if xerr != nil {
		return nil, xerr
	}

	return toAbstractSubnet(*resp), nil
}

// InspectSubnetByName returns the subnet identified by name
func (s stack) InspectSubnetByName(ctx context.Context, networkID string, name string) (_ *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcGetSubnetByName(ctx, name)
	if xerr != nil {
		return nil, xerr
	}

	var region string
	if region, xerr = getRegionFromSelfLink(genURL(resp.SelfLink)); xerr != nil {
		return nil, xerr
	}

	if region != s.GcpConfig.Region {
		return nil, fail.NotFoundError("failed to find a Subnet named '%s'", name)
	}

	return toAbstractSubnet(*resp), nil
}

// ListSubnets lists available subnets
func (s stack) ListSubnets(ctx context.Context, networkRef string) (_ []*abstract.Subnet, ferr fail.Error) {
	var emptySlice []*abstract.Subnet
	if valid.IsNil(s) {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp")).WithStopwatch().Entering()
	defer tracer.Exiting()

	var (
		subnets []*abstract.Subnet
		filter  string
	)

	var an *abstract.Network
	var xerr fail.Error
	if networkRef != "" {
		an, xerr = s.InspectNetwork(ctx, networkRef)
		if xerr != nil {
			switch xerr.(type) { // nolint
			case *fail.ErrNotFound:
				an, xerr = s.InspectNetworkByName(ctx, networkRef)
				if xerr != nil {
					return emptySlice, fail.Wrap(xerr, "failed to find Network '%s'", networkRef)
				}
			default:
				return emptySlice, fail.Wrap(xerr, "failed to find Network '%s'", networkRef)
			}
		}

		filter = `selfLink eq "` + s.selfLinkPrefix + `/global/networks/` + an.Name + `"`
	}

	resp, xerr := s.rpcListSubnets(ctx, filter)
	if xerr != nil {
		return emptySlice, xerr
	}

	for _, v := range resp {
		subnets = append(subnets, toAbstractSubnet(*v))
	}

	return subnets, nil
}

func toAbstractSubnet(in compute.Subnetwork) *abstract.Subnet {
	item, _ := abstract.NewSubnet() // note: not using WithName() here permits to have a Subnet with no name...
	item.Name = in.Name
	item.ID = strconv.FormatUint(in.Id, 10)
	item.CIDR = in.IpCidrRange
	parts := strings.Split(in.Network, "/")
	item.Network = parts[len(parts)-1]
	return item
}

// DeleteSubnet deletes the subnet identified by id
func (s stack) DeleteSubnet(ctx context.Context, id string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Delete NAT route
	natRouteName := fmt.Sprintf(NATRouteNameFormat, id)
	var xerr fail.Error
	if xerr = s.rpcDeleteRoute(ctx, natRouteName); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// consider missing route as a successful removal
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}

	subn, xerr := s.rpcGetSubnetByID(ctx, id)
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
	if xerr = s.rpcDeleteSubnetByName(ctx, subn.Name); xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(xerr), "error deleting Subnet '%s', stopping retries", subn.Name)
		case *fail.ErrTimeout:
			return fail.Wrap(fail.Cause(xerr), "timeout waiting for Subnet '%s' deletion", subn.Name)
		default:
			return xerr
		}
	}

	// Check Subnet no longer exists
	if _, xerr = s.rpcGetSubnetByName(ctx, subn.Name); xerr != nil {
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
