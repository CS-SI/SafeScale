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

package openstack

import (
	"context"
	"net"
	"strings"

	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/portsecurity"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

// RouterRequest represents a router request
type RouterRequest struct {
	Name string `json:"name,omitempty"`
	// NetworkID is the Network ID which the router gateway is connected to.
	NetworkID string `json:"network_id,omitempty"`
}

// Router represents a router
type Router struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	// NetworkID is the Network ID which the router gateway is connected to.
	NetworkID string `json:"network_id,omitempty"`
}

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (s *stack) HasDefaultNetwork() (bool, fail.Error) {
	return false, nil
}

// DefaultNetwork returns the *abstract.Network corresponding to the default network
func (s *stack) DefaultNetwork(context.Context) (*abstract.Network, fail.Error) {
	// FIXME: support default network
	return nil, fail.NotFoundError("no default network in stack")
}

// CreateNetwork creates a network named name
func (s stack) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (_ *abstract.Network, ferr fail.Error) {
	var xerr fail.Error
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", req.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Checks if CIDR is valid...
	if req.CIDR != "" {
		_, _, err := net.ParseCIDR(req.CIDR)
		if err != nil {
			return nil, fail.Wrap(err, "failed to create subnet '%s (%s)': %s", req.Name, req.CIDR)
		}
	} else { // CIDR is empty, choose the first Class C one possible
		tracer.Trace("CIDR is empty, choosing one...")
		req.CIDR = "192.168.1.0/24"
		tracer.Trace("CIDR chosen for network is '%s'", req.CIDR)
	}

	// We specify a name and that it should forward packets
	state := true
	basicOpts := networks.CreateOpts{
		Name:         req.Name,
		AdminStateUp: &state,
	}

	opts := portsecurity.NetworkCreateOptsExt{
		CreateOptsBuilder:   basicOpts,
		PortSecurityEnabled: gophercloud.Enabled,
	}

	// Creates the network
	var network *networks.Network
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			network, innerErr = networks.Create(s.NetworkClient, opts).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create network '%s'", req.Name)
	}

	// Starting from here, delete network if exit with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := stacks.RetryableRemoteCall(context.Background(),
				func() error {
					return networks.Delete(s.NetworkClient, network.ID).ExtractErr()
				},
				NormalizeError,
			)
			if derr != nil {
				logrus.WithContext(ctx).Errorf("failed to delete Network '%s': %v", req.Name, derr)
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

	newNet, xerr := abstract.NewNetwork(abstract.WithName(network.Name))
	if xerr != nil {
		return nil, xerr
	}

	newNet.ID = network.ID
	// newNet.Name = network.Name
	newNet.CIDR = req.CIDR
	return newNet, nil
}

// InspectNetworkByName ...
func (s stack) InspectNetworkByName(ctx context.Context, name string) (*abstract.Network, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", name).WithStopwatch().Entering().Exiting()

	// Gophercloud doesn't propose the way to get a host by name, but OpenStack knows how to do it...
	r := networks.GetResult{}
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			_, r.Err = s.ComputeClient.Get(s.NetworkClient.ServiceURL("networks?name="+name), &r.Body, &gophercloud.RequestOpts{
				OkCodes: []int{200, 203},
			})
			return r.Err
		},
		NormalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrForbidden:
			return nil, abstract.ResourceForbiddenError("network", name)
		default:
			return nil, fail.NewError("query for network '%s' failed: %v", name, r.Err)
		}
	}

	nets, found := r.Body.(map[string]interface{})["networks"].([]interface{})
	if found && len(nets) > 0 {
		entry, ok := nets[0].(map[string]interface{})
		if !ok {
			return nil, fail.InvalidParameterError("Body['networks']", "is not a map[string]")
		}
		id, ok := entry["id"].(string)
		if !ok {
			return nil, fail.InvalidParameterError("entry['id']", "is not a string")
		}
		return s.InspectNetwork(ctx, id)
	}
	return nil, abstract.ResourceNotFoundError("network", name)
}

// InspectNetwork returns the network identified by id
func (s stack) InspectNetwork(ctx context.Context, id string) (*abstract.Network, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	// If not found, we look for any network from provider
	// 1st try with id
	var network *networks.Network
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			network, innerErr = networks.Get(s.NetworkClient, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError(xerr)
		default:
			return nil, xerr
		}
	}
	if network != nil && network.ID != "" {
		newNet, xerr := abstract.NewNetwork(abstract.WithName(network.Name))
		if xerr != nil {
			return nil, xerr
		}

		newNet.ID = network.ID
		// newNet.Name = network.Name
		return newNet, nil
	}

	// At this point, no network has been found with given reference
	errNotFound := abstract.ResourceNotFoundError("network", id)
	// logrus.Debug(errNotFound)
	return nil, errNotFound
}

// ListNetworks lists available networks
func (s stack) ListNetworks(ctx context.Context) ([]*abstract.Network, fail.Error) {
	var emptySlice []*abstract.Network
	if valid.IsNil(s) {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "").WithStopwatch().Entering().Exiting()

	// Retrieve a pager (i.e. a paginated collection)
	var netList []*abstract.Network
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			innerErr := networks.List(s.NetworkClient, networks.ListOpts{}).EachPage(
				func(page pagination.Page) (bool, error) {
					networkList, err := networks.ExtractNetworks(page)
					if err != nil {
						return false, err
					}

					for _, n := range networkList {
						if n.ID == s.ProviderNetworkID {
							continue
						}

						newNet, xerr := abstract.NewNetwork(abstract.WithName(n.Name))
						if xerr != nil {
							return false, xerr
						}

						newNet.ID = n.ID
						// newNet.Name = n.Name

						netList = append(netList, newNet)
					}
					return true, nil
				},
			)
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return emptySlice, xerr
	}

	return netList, nil
}

// DeleteNetwork deletes the network identified by id
func (s stack) DeleteNetwork(ctx context.Context, networkParam iaasapi.NetworkParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	an, networkLabel, xerr := iaasapi.ValidateNetworkParameter(networkParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", networkLabel).WithStopwatch().Entering().Exiting()

	var network *networks.Network
	if an.ID == "" {
		return fail.InvalidParameterError("networkParam", "does not contain valid value for 'ID' field")
	}
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			network, innerErr = networks.Get(s.NetworkClient, an.ID).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		logrus.WithContext(ctx).Errorf("failed to get Network %s: %+v", networkLabel, xerr)
		return xerr
	}

	sns, xerr := s.ListSubnets(ctx, an.ID)
	if xerr != nil {
		xerr = fail.Wrap(xerr, "failed to list Subnets of Network %s", networkLabel)
		logrus.WithContext(ctx).Debugf(strprocess.Capitalize(xerr.Error()))
		return xerr
	}
	if len(sns) > 0 {
		return fail.InvalidRequestError("cannot delete a Network %s: there are Subnets in it", networkLabel)
	}

	xerr = stacks.RetryableRemoteCall(ctx,
		func() error {
			return networks.Delete(s.NetworkClient, an.ID).ExtractErr()
		},
		NormalizeError,
	)
	if xerr != nil {
		xerr = fail.Wrap(xerr, "failed to delete Network '%s'", network.Name)
		logrus.WithContext(ctx).Debugf(strprocess.Capitalize(xerr.Error()))
		return xerr
	}

	return nil
}

// ToGophercloudIPVersion converts ipversion.Enum (corresponding to SafeScale abstract) to gophercloud.IPVersion
// if v is invalid, returns gophercloud.IPv4
func ToGophercloudIPVersion(v ipversion.Enum) gophercloud.IPVersion {
	switch v {
	case ipversion.IPv6:
		return gophercloud.IPv6
	case ipversion.IPv4:
		fallthrough
	default:
		return gophercloud.IPv4
	}
}

// ToAbstractIPVersion converts an int representation of IPVersion to an ipversion.Enum
// if v is invalid, returns ipversion.sIPv4
func ToAbstractIPVersion(v int) ipversion.Enum {
	switch v {
	case 6:
		return ipversion.IPv6
	case 4:
		fallthrough
	default:
		return ipversion.IPv4
	}
}

// CreateSubnet creates a subnet
func (s stack) CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (newNet *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", req.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Checks if CIDR is valid...
	if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
		return nil, fail.ConvertError(err)
	}

	// If req.IPVersion contains invalid value, force to IPv4
	var ipVersion gophercloud.IPVersion
	switch ToGophercloudIPVersion(req.IPVersion) {
	case gophercloud.IPv6:
		ipVersion = gophercloud.IPv6
	case gophercloud.IPv4:
		fallthrough
	default:
		ipVersion = gophercloud.IPv4
	}

	// You must associate a new subnet with an existing network - to do this you
	// need its UUID. You must also provide a well-formed CIDR value.
	dhcp := true
	opts := subnets.CreateOpts{
		NetworkID:  req.NetworkID,
		CIDR:       req.CIDR,
		IPVersion:  ipVersion,
		Name:       req.Name,
		EnableDHCP: &dhcp,
	}
	if len(req.DNSServers) > 0 {
		opts.DNSNameservers = req.DNSServers
	}

	if !s.cfgOpts.UseLayer3Networking {
		noGateway := ""
		opts.GatewayIP = &noGateway
	}

	var subnet *subnets.Subnet
	// Execute the operation and get back a subnets.Subnet struct
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			subnet, innerErr = subnets.Create(s.NetworkClient, opts).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	// Starting from here, delete subnet if exit with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := s.DeleteSubnet(context.Background(), subnet.ID)
			if derr != nil {
				wrapErr := fail.Wrap(derr, "cleaning up on failure, failed to delete Subnet '%s'", subnet.Name)
				logrus.Error(wrapErr.Error())
				_ = ferr.AddConsequence(wrapErr)
			}
		}
	}()

	if s.cfgOpts.UseLayer3Networking {
		router, xerr := s.createRouter(ctx, RouterRequest{
			Name:      subnet.ID,
			NetworkID: s.ProviderNetworkID,
		})
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to create router '%s'", subnet.ID)
		}

		// Starting from here, delete router if exit with error
		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil {
				derr := s.deleteRouter(context.Background(), router.ID)
				if derr != nil {
					wrapErr := fail.Wrap(derr, "cleaning up on failure, failed to delete route '%s'", router.Name)
					_ = ferr.AddConsequence(wrapErr)
					logrus.Error(wrapErr.Error())
				}
			}
		}()

		xerr = s.addSubnetToRouter(ctx, router.ID, subnet.ID)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to add subnet '%s' to router '%s'", subnet.Name, router.Name)
		}
	}

	out, xerr := abstract.NewSubnet(abstract.WithName(subnet.Name))
	if xerr != nil {
		return nil, xerr
	}

	out.ID = subnet.ID
	// out.Name = subnet.Name
	out.IPVersion = ToAbstractIPVersion(subnet.IPVersion)
	out.CIDR = subnet.CIDR
	out.Network = subnet.NetworkID
	out.Domain = req.Domain
	return out, nil
}

func (s stack) validateCIDR(req abstract.SubnetRequest, network *abstract.Network) fail.Error {
	_, _ /*subnetDesc*/, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return fail.Wrap(err, "failed to validate CIDR '%s' for Subnet '%s'", req.CIDR, req.Name)
	}
	return nil
}

// InspectSubnet returns the subnet identified by id
func (s stack) InspectSubnet(ctx context.Context, id string) (_ *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	var sn *subnets.Subnet
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			sn, innerErr = subnets.Get(s.NetworkClient, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	as, xerr := abstract.NewSubnet(abstract.WithName(sn.Name))
	if xerr != nil {
		return nil, xerr
	}

	as.ID = sn.ID
	as.Network = sn.NetworkID
	as.IPVersion = ToAbstractIPVersion(sn.IPVersion)
	as.CIDR = sn.CIDR
	as.DNSServers = sn.DNSNameservers
	return as, nil
}

// InspectSubnetByName ...
func (s stack) InspectSubnetByName(ctx context.Context, networkRef, name string) (subnet *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", name).WithStopwatch().Entering().Exiting()

	listOpts := subnets.ListOpts{
		Name: name,
	}
	var an *abstract.Network
	if networkRef != "" {
		var xerr fail.Error
		an, xerr = s.InspectNetwork(ctx, networkRef)
		if xerr != nil {
			switch xerr.(type) { // nolint
			case *fail.ErrNotFound:
				an, xerr = s.InspectNetworkByName(ctx, networkRef)
				if xerr != nil {
					return nil, xerr
				}
			default:
				return nil, xerr
			}
		}

		listOpts.NetworkID = an.ID
	}

	var resp []subnets.Subnet
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			var allPages pagination.Page
			var innerErr error
			if allPages, innerErr = subnets.List(s.NetworkClient, listOpts).AllPages(); innerErr != nil {
				return innerErr
			}
			resp, innerErr = subnets.ExtractSubnets(allPages)
			if innerErr != nil {
				return innerErr
			}
			return nil
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	switch len(resp) {
	case 0:
		msg := "failed to find a Subnet named '%s'"
		if an != nil {
			msg += " in Network '%s'"
			return nil, fail.NotFoundError(msg, name, an.Name)
		}
		return nil, fail.NotFoundError(msg, name)

	case 1:
		var xerr fail.Error
		item := resp[0]
		subnet, xerr = abstract.NewSubnet(abstract.WithName(name))
		if xerr != nil {
			return nil, xerr
		}

		subnet.ID = item.ID
		subnet.Network = item.NetworkID
		// subnet.Name = name
		subnet.CIDR = item.CIDR
		subnet.DNSServers = item.DNSNameservers
		subnet.IPVersion = ToAbstractIPVersion(item.IPVersion)
		return subnet, nil

	default:
		msg := "more than one Subnet named '%s' found"
		if an != nil {
			msg += " in Network '%s'"
			return nil, fail.DuplicateError(msg, name, an.Name)
		}

		return nil, fail.DuplicateError(msg, name)
	}
}

// ListSubnets lists available subnets in a network
func (s stack) ListSubnets(ctx context.Context, networkID string) ([]*abstract.Subnet, fail.Error) {
	var emptySlice []*abstract.Subnet
	if valid.IsNil(s) {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "").WithStopwatch().Entering().Exiting()

	listOpts := subnets.ListOpts{}
	if networkID != "" {
		listOpts.NetworkID = networkID
	}
	var subnetList []*abstract.Subnet
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			return subnets.List(s.NetworkClient, listOpts).EachPage(func(page pagination.Page) (bool, error) {
				list, err := subnets.ExtractSubnets(page)
				if err != nil {
					return false, NormalizeError(err)
				}

				for _, subnet := range list {
					item, xerr := abstract.NewSubnet(abstract.WithName(subnet.Name))
					if xerr != nil {
						return false, xerr
					}

					item.ID = subnet.ID
					// item.Name = subnet.Name
					item.Network = subnet.ID
					item.IPVersion = ToAbstractIPVersion(subnet.IPVersion)
					subnetList = append(subnetList, item)
				}
				return true, nil
			})
		},
		NormalizeError,
	)
	if xerr != nil {
		return emptySlice, xerr
	}
	// VPL: empty subnet list is not an abnormal situation, do not log
	return subnetList, nil
}

// DeleteSubnet deletes the network identified by id
func (s stack) DeleteSubnet(ctx context.Context, id string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.openstack"), "(%s)", id).WithStopwatch().Entering().Exiting()

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	routerList, _ := s.ListRouters(ctx)
	var router *Router
	for _, r := range routerList {
		r := r
		if r.Name == id {
			router = &r
			break
		}
	}
	if router != nil {
		if xerr := s.removeSubnetFromRouter(ctx, router.ID, id); xerr != nil {
			return fail.Wrap(xerr, "failed to remove Subnet %s from its router %s", id, router.ID)
		}
		if xerr := s.deleteRouter(ctx, router.ID); xerr != nil {
			return fail.Wrap(xerr, "failed to delete router %s associated with Subnet %s", router.ID, id)
		}
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			innerXErr := stacks.RetryableRemoteCall(ctx,
				func() error {
					return subnets.Delete(s.NetworkClient, id).ExtractErr()
				},
				NormalizeError,
			)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrInvalidRequest, *fail.ErrDuplicate:
					msg := "hosts or services are still attached"
					return retry.StopRetryError(fail.Wrap(innerXErr, msg))
				case *fail.ErrNotFound:
					// consider a missing Subnet as a successful deletion
					debug.IgnoreError(innerXErr)
				default:
					return innerXErr
				}
			}
			return nil
		},
		timings.NormalDelay(),
		timings.ContextTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrTimeout:
			return fail.Wrap(fail.Cause(retryErr), "timeout")
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(retryErr), "stopping retries")
		default:
			return retryErr
		}
	}
	return nil
}

// createRouter creates a router satisfying req
func (s stack) createRouter(ctx context.Context, req RouterRequest) (*Router, fail.Error) {
	// Create a router to connect external Provider network
	gi := routers.GatewayInfo{
		NetworkID: req.NetworkID,
	}
	state := true
	opts := routers.CreateOpts{
		Name:         req.Name,
		AdminStateUp: &state,
		GatewayInfo:  &gi,
	}
	var router *routers.Router
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			router, innerErr = routers.Create(s.NetworkClient, opts).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	logrus.WithContext(ctx).Debugf("Openstack router '%s' (%s) successfully created", router.Name, router.ID)
	return &Router{
		ID:        router.ID,
		Name:      router.Name,
		NetworkID: router.GatewayInfo.NetworkID,
	}, nil
}

// ListRouters lists available routers
func (s stack) ListRouters(ctx context.Context) ([]Router, fail.Error) {
	var emptySlice []Router
	if valid.IsNil(s) {
		return emptySlice, fail.InvalidInstanceError()
	}

	var ns []Router
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			return routers.List(s.NetworkClient, routers.ListOpts{}).EachPage(
				func(page pagination.Page) (bool, error) {
					list, err := routers.ExtractRouters(page)
					if err != nil {
						return false, err
					}
					for _, r := range list {
						an := Router{
							ID:        r.ID,
							Name:      r.Name,
							NetworkID: r.GatewayInfo.NetworkID,
						}
						ns = append(ns, an)
					}
					return true, nil
				},
			)
		},
		NormalizeError,
	)
	return ns, xerr
}

// deleteRouter deletes the router identified by id
func (s stack) deleteRouter(ctx context.Context, id string) fail.Error {
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return routers.Delete(s.NetworkClient, id).ExtractErr()
		},
		NormalizeError,
	)
}

// addSubnetToRouter attaches subnet to router
func (s stack) addSubnetToRouter(ctx context.Context, routerID string, subnetID string) fail.Error {
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, innerErr := routers.AddInterface(s.NetworkClient, routerID, routers.AddInterfaceOpts{
				SubnetID: subnetID,
			}).Extract()
			return innerErr
		},
		NormalizeError,
	)
}

// removeSubnetFromRouter detaches a subnet from router interface
func (s stack) removeSubnetFromRouter(ctx context.Context, routerID string, subnetID string) fail.Error {
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, innerErr := routers.RemoveInterface(s.NetworkClient, routerID, routers.RemoveInterfaceOpts{
				SubnetID: subnetID,
			}).Extract()
			return innerErr
		},
		NormalizeError,
	)
}

// CreateVIP creates a private virtual IP
// If public is set to true,
func (s stack) CreateVIP(ctx context.Context, networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if networkID = strings.TrimSpace(networkID); networkID == "" {
		return nil, fail.InvalidParameterError("networkID", "cannot be empty string")
	}
	if subnetID = strings.TrimSpace(subnetID); subnetID == "" {
		return nil, fail.InvalidParameterError("subnetID", "cannot be empty string")
	}
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	var port *ports.Port
	asu := true
	options := ports.CreateOpts{
		NetworkID:      networkID,
		AdminStateUp:   &asu,
		Name:           name,
		SecurityGroups: &[]string{},
		FixedIPs:       []ports.IP{{SubnetID: subnetID}},
	}
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			var aport *ports.Port
			aport, innerErr = ports.Create(s.NetworkClient, options).Extract()
			if innerErr != nil {
				return innerErr
			}
			port = aport
			return nil
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	// FIXME: OPP Now, and only for OVH, disable port security
	// _, _ = s.rpcChangePortSecurity(ctx, port.ID, false)

	vip, xerr := abstract.NewVirtualIP(abstract.WithName(name))
	if xerr != nil {
		return nil, xerr
	}

	vip.ID = port.ID
	vip.PrivateIP = port.FixedIPs[0].IPAddress
	return vip, nil
}

// AddPublicIPToVIP adds a public IP to VIP
func (s stack) AddPublicIPToVIP(ctx context.Context, vip *abstract.VirtualIP) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}

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
	if hostID = strings.TrimSpace(hostID); hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	var vipPort *ports.Port
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			vipPort, innerErr = ports.Get(s.NetworkClient, vip.ID).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return xerr
	}
	hostPorts, xerr := s.rpcListPorts(ctx, ports.ListOpts{
		DeviceID:  hostID,
		NetworkID: vip.NetworkID,
	})
	if xerr != nil {
		return xerr
	}
	addressPair := ports.AddressPair{
		MACAddress: vipPort.MACAddress,
		IPAddress:  vip.PrivateIP,
	}
	for _, p := range hostPorts {
		p := p
		p.AllowedAddressPairs = append(p.AllowedAddressPairs, addressPair)
		xerr = stacks.RetryableRemoteCall(ctx,
			func() error {
				_, innerErr := ports.Update(s.NetworkClient, p.ID, ports.UpdateOpts{AllowedAddressPairs: &p.AllowedAddressPairs}).Extract()
				return innerErr
			},
			NormalizeError,
		)
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (s stack) UnbindHostFromVIP(ctx context.Context, vip *abstract.VirtualIP, hostID string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}
	if hostID = strings.TrimSpace(hostID); hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	var vipPort *ports.Port
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			vipPort, innerErr = ports.Get(s.NetworkClient, vip.ID).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return xerr
	}
	hostPorts, xerr := s.rpcListPorts(ctx, ports.ListOpts{
		DeviceID:  hostID,
		NetworkID: vip.NetworkID,
	})
	if xerr != nil {
		return xerr
	}
	for _, p := range hostPorts {
		var newAllowedAddressPairs []ports.AddressPair
		for _, a := range p.AllowedAddressPairs {
			if a.MACAddress != vipPort.MACAddress {
				newAllowedAddressPairs = append(newAllowedAddressPairs, a)
			}
		}
		xerr = stacks.RetryableRemoteCall(ctx,
			func() error {
				_, innerErr := ports.Update(s.NetworkClient, p.ID, ports.UpdateOpts{AllowedAddressPairs: &newAllowedAddressPairs}).Extract()
				return innerErr
			},
			NormalizeError,
		)
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// DeleteVIP deletes the port corresponding to the VIP
func (s stack) DeleteVIP(ctx context.Context, vip *abstract.VirtualIP) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}

	for _, v := range vip.Hosts {
		xerr := s.UnbindHostFromVIP(ctx, vip, v.ID)
		if xerr != nil {
			return xerr
		}
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return ports.Delete(s.NetworkClient, vip.ID).ExtractErr()
		},
		NormalizeError,
	)
}
