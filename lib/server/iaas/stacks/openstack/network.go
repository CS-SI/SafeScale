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

package openstack

import (
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
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

// HasDefaultNetwork returns true if the Stack as a default network set (coming from tenants file)
func (s Stack) HasDefaultNetwork() bool {
	return false
}

// GetDefaultNetwork returns the *abstract.Network corresponding to the default network
func (s Stack) GetDefaultNetwork() (*abstract.Network, fail.Error) {
	// FIXME: support default network
	return nil, fail.NotFoundError("no default network in Stack")
}

// CreateNetwork creates a network named name
func (s Stack) CreateNetwork(req abstract.NetworkRequest) (newNet *abstract.Network, xerr fail.Error) {
	nullAN := abstract.NewNetwork()
	if s.IsNull() {
		return nullAN, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("Stack.network"), "(%s)", req.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Checks if IPRanges is valid...
	if req.CIDR != "" {
		_, _, err := net.ParseCIDR(req.CIDR)
		if err != nil {
			return nullAN, fail.Wrap(err, "failed to create subnet '%s (%s)': %s", req.Name, req.CIDR)
		}
	} else { // IPRanges is empty, choose the first Class C one possible
		tracer.Trace("IPRanges is empty, choosing one...")
		req.CIDR = "192.168.1.0/24"
		tracer.Trace("IPRanges chosen for network is '%s'", req.CIDR)
	}

	// We specify a name and that it should forward packets
	state := true
	opts := networks.CreateOpts{
		Name:         req.Name,
		AdminStateUp: &state,
	}

	// Creates the network
	var network *networks.Network
	xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			network, innerErr = networks.Create(s.NetworkClient, opts).Extract()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nullAN, fail.Wrap(xerr, "failed to create network '%s'", req.Name)
	}

	// Starting from here, delete network if exit with error
	defer func() {
		if xerr != nil {
			derr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
				func() error {
					innerErr := networks.Delete(s.NetworkClient, network.ID).ExtractErr()
					return NormalizeError(innerErr)
				},
				temporal.GetCommunicationTimeout(),
			)
			if derr != nil {
				logrus.Errorf("failed to delete Network '%s': %v", req.Name, derr)
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	newNet = abstract.NewNetwork()
	newNet.ID = network.ID
	newNet.Name = network.Name
	newNet.CIDR = req.CIDR
	return newNet, nil
}

// InspectNetworkByName ...
func (s Stack) InspectNetworkByName(name string) (*abstract.Network, fail.Error) {
	nullAN := abstract.NewNetwork()
	if s.IsNull() {
		return nullAN, fail.InvalidInstanceError()
	}
	if name == "" {
		return nullAN, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("Stack.network"), "(%s)", name).WithStopwatch().Entering().Exiting()

	// Gophercloud doesn't propose the way to get a host by name, but OpenStack knows how to do it...
	r := networks.GetResult{}
	xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, r.Err = s.ComputeClient.Get(s.NetworkClient.ServiceURL("networks?name="+name), &r.Body, &gophercloud.RequestOpts{
				OkCodes: []int{200, 203},
			})
			return NormalizeError(r.Err)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrForbidden:
			return nullAN, abstract.ResourceForbiddenError("network", name)
		default:
			return nullAN, fail.NewError("query for network '%s' failed: %v", name, r.Err)
		}
	}

	nets, found := r.Body.(map[string]interface{})["networks"].([]interface{})
	if found && len(nets) > 0 {
		entry, ok := nets[0].(map[string]interface{})
		if !ok {
			return nullAN, fail.InvalidParameterError("Body['networks']", "is not a map[string]")
		}
		id, ok := entry["id"].(string)
		if !ok {
			return nullAN, fail.InvalidParameterError("entry['id']", "is not a string")
		}
		return s.InspectNetwork(id)
	}
	return nullAN, abstract.ResourceNotFoundError("network", name)
}

// InspectNetwork returns the network identified by id
func (s Stack) InspectNetwork(id string) (*abstract.Network, fail.Error) {
	nullAN := abstract.NewNetwork()
	if s.IsNull() {
		return nullAN, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAN, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("Stack.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	// If not found, we look for any network from provider
	// 1st try with id
	var network *networks.Network
	xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			network, innerErr = networks.Get(s.NetworkClient, id).Extract()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
		default:
			return nullAN, xerr
		}
	}
	if network != nil && network.ID != "" {
		newNet := abstract.NewNetwork()
		newNet.ID = network.ID
		newNet.Name = network.Name
		return newNet, nil
	}

	// At this point, no network has been found with given reference
	errNotFound := abstract.ResourceNotFoundError("network", id)
	logrus.Debug(errNotFound)
	return nullAN, errNotFound
}

// ListNetworks lists available networks
func (s Stack) ListNetworks() ([]*abstract.Network, fail.Error) {
	var emptySlice []*abstract.Network
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("Stack.network"), "").WithStopwatch().Entering().Exiting()

	// Retrieve a pager (i.e. a paginated collection)
	var netList []*abstract.Network
	xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
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

						newNet := abstract.NewNetwork()
						newNet.ID = n.ID
						newNet.Name = n.Name
						//newNet.Subnets = n.Subnets

						netList = append(netList, newNet)
					}
					return true, nil
				},
			)
			return innerErr
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return emptySlice, xerr
	}
	return netList, nil
}

// DeleteNetwork deletes the network identified by id
func (s Stack) DeleteNetwork(id string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("Stack.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	var network *networks.Network
	xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			network, innerErr = networks.Get(s.NetworkClient, id).Extract()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		logrus.Errorf("failed to get network '%s': %+v", id, xerr)
		return xerr
	}

	sns, xerr := s.ListSubnets(id)
	if xerr != nil {
		xerr = fail.Wrap(xerr, "failed to list subnets of network '%s'", network.Name)
		logrus.Debugf(strprocess.Capitalize(xerr.Error()))
		return xerr
	}
	if len(sns) > 0 {
		return fail.InvalidRequestError("cannot delete a Network with Subnets in it")
	}

	xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			innerErr := networks.Delete(s.NetworkClient, id).ExtractErr()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		xerr = fail.Wrap(xerr, "failed to delete network '%s'", network.Name)
		logrus.Debugf(strprocess.Capitalize(xerr.Error()))
		return xerr
	}

	return nil
}

// ToGophercloudIPVersion converts ipversion.Enum (corresponding to SafeScale abstract) to gophercloud.IPVersion
// if v is invalid, returns gophercloud.IPv4
func ToGophercloudIPVersion(v ipversion.Enum) gophercloud.IPVersion {
	//if v == ipversion.IPv4 {
	//	return gophercloud.IPv4
	//}
	//if v == ipversion.IPv6 {
	//	return gophercloud.IPv6
	//}
	//return -1
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
func (s Stack) CreateSubnet(req abstract.SubnetRequest) (newNet *abstract.Subnet, xerr fail.Error) {
	nullAS := abstract.NewSubnet()
	if s.IsNull() {
		return nullAS, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("Stack.network"), "(%s)", req.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Checks if IPRanges is valid...
	if req.CIDR != "" {
		_, _, err := net.ParseCIDR(req.CIDR)
		if err != nil {
			return nullAS, fail.Wrap(err, "failed to create subnet '%s (%s)': %s", req.Name, req.CIDR)
		}
	} else { // IPRanges is empty, choose the first Class C possible
		tracer.Trace("IPRanges is empty, choosing one...")
		req.CIDR = "192.168.1.0/24"
		tracer.Trace("IPRanges chosen for subnet is '%s'", req.CIDR)
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
	// need its UUID. You must also provide a well-formed IPRanges value.
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
	xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			subnet, innerErr = subnets.Create(s.NetworkClient, opts).Extract()
			innerErr = NormalizeError(innerErr)
			if innerErr != nil {
				switch innerErr.(type) { // nolint
				case *fail.ErrInvalidRequest:
					neutronError, innerXErr := ParseNeutronError(innerErr.Error())
					if innerXErr != nil {
						switch innerXErr.(type) {
						case *fail.ErrSyntax:
							return innerXErr
						default:
							return retry.StopRetryError(innerXErr)
						}
					}
					if neutronError != nil {
						return retry.StopRetryError(fail.NewError("bad request: %s", neutronError["message"]))
					}
				default:
					return retry.StopRetryError(innerErr)
				}
			}
			return nil
		},
		10*time.Second,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry:
			xerr = fail.ToError(xerr.Cause())
		}
		return nullAS, xerr
	}

	// Starting from here, delete subnet if exit with error
	defer func() {
		if xerr != nil {
			derr := s.DeleteSubnet(subnet.ID)
			if derr != nil {
				logrus.Warnf("Error deleting subnet: %v", derr)
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Subnet '%s'", subnet.Name))
			}
		}
	}()

	if s.cfgOpts.UseLayer3Networking {
		router, xerr := s.createRouter(RouterRequest{
			Name:      subnet.ID,
			NetworkID: s.ProviderNetworkID,
		})
		if xerr != nil {
			return nullAS, fail.Wrap(xerr, "failed to create router '%s'", subnet.ID)
		}

		// Starting from here, delete router if exit with error
		defer func() {
			if xerr != nil {
				derr := s.deleteRouter(router.ID)
				if derr != nil {
					logrus.Warnf("Error deleting router: %v", derr)
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete route '%s'", router.Name))
				}
			}
		}()

		xerr = s.addSubnetToRouter(router.ID, subnet.ID)
		if xerr != nil {
			return nullAS, fail.Wrap(xerr, "failed to add subnet '%s' to router '%s'", subnet.Name, router.Name)
		}
	}

	out := &abstract.Subnet{
		ID:        subnet.ID,
		Name:      subnet.Name,
		IPVersion: ToAbstractIPVersion(subnet.IPVersion),
		CIDR:      subnet.CIDR,
		Network:   subnet.NetworkID,
		Domain:    req.Domain,
	}
	return out, nil
}

// InspectSubnet returns the subnet identified by id
func (s Stack) InspectSubnet(id string) (_ *abstract.Subnet, xerr fail.Error) {
	nullAS := abstract.NewSubnet()
	if s.IsNull() {
		return nullAS, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAS, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("Stack.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	as := abstract.NewSubnet()
	xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			sn, innerErr := subnets.Get(s.NetworkClient, id).Extract()
			if innerErr != nil {
				return NormalizeError(innerErr)
			}
			as.ID = sn.ID
			as.Name = sn.Name
			as.Network = sn.NetworkID
			as.IPVersion = ToAbstractIPVersion(sn.IPVersion)
			as.CIDR = sn.CIDR
			as.DNSServers = sn.DNSNameservers
			return nil
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nullAS, xerr
	}
	return as, nil
}

// InspectSubnetByName ...
func (s Stack) InspectSubnetByName(networkRef, name string) (subnet *abstract.Subnet, xerr fail.Error) {
	nullAS := abstract.NewSubnet()
	if s.IsNull() {
		return nullAS, fail.InvalidInstanceError()
	}
	if name == "" {
		return nullAS, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("Stack.network"), "(%s)", name).WithStopwatch().Entering().Exiting()

	listOpts := subnets.ListOpts{
		Name: name,
	}
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
			return nullAS, xerr
		}
		listOpts.NetworkID = an.ID
	}

	var resp []subnets.Subnet
	xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			var allPages pagination.Page
			if allPages, innerErr = subnets.List(s.NetworkClient, listOpts).AllPages(); innerErr == nil {
				resp, innerErr = subnets.ExtractSubnets(allPages)
			}
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nullAS, xerr
	}

	switch len(resp) {
	case 0:
		msg := "failed to find a Subnet named '%s'"
		if an != nil {
			msg += " in Network '%s'"
			return nullAS, fail.NotFoundError(msg, name, an.Name)
		}
		return nullAS, fail.NotFoundError(msg, name)
	case 1:
		item := resp[0]
		subnet = abstract.NewSubnet()
		subnet.ID = item.ID
		subnet.Network = item.NetworkID
		subnet.Name = name
		subnet.CIDR = item.CIDR
		subnet.DNSServers = item.DNSNameservers
		subnet.IPVersion = ToAbstractIPVersion(item.IPVersion)
		return subnet, nil
	default:
		msg := "more than one Subnet named '%s' found"
		if an != nil {
			msg += " in Network '%s'"
			return nullAS, fail.NotFoundError(msg, name, an.Name)
		}
		return nullAS, fail.NotFoundError(msg, name)
	}
}

// ListSubnets lists available subnets in a network
func (s Stack) ListSubnets(networkID string) ([]*abstract.Subnet, fail.Error) {
	var emptySlice []*abstract.Subnet
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("Stack.network"), "").WithStopwatch().Entering().Exiting()

	listOpts := subnets.ListOpts{}
	if networkID != "" {
		listOpts.NetworkID = networkID
	}
	var subnetList []*abstract.Subnet
	xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			innerErr := subnets.List(s.NetworkClient, listOpts).EachPage(func(page pagination.Page) (bool, error) {
				list, err := subnets.ExtractSubnets(page)
				if err != nil {
					return false, NormalizeError(err)
				}

				for _, subnet := range list {
					item := abstract.NewSubnet()
					item.ID = subnet.ID
					item.Name = subnet.Name
					item.Network = subnet.ID
					item.IPVersion = ToAbstractIPVersion(subnet.IPVersion)
					subnetList = append(subnetList, item)
				}
				return true, nil
			})
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return emptySlice, xerr
	}
	// VPL: empty subnet list is not an abnormal situation, do not log
	return subnetList, nil
}

// DeleteSubnet deletes the network identified by id
func (s Stack) DeleteSubnet(id string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("Stack.openstack"), "(%s)", id).WithStopwatch().Entering().Exiting()
	routerList, _ := s.ListRouters()
	var router *Router
	for _, r := range routerList {
		if r.Name == id {
			router = &r
			break
		}
	}
	if router != nil {
		if xerr := s.removeSubnetFromRouter(router.ID, id); xerr != nil {
			return fail.Wrap(xerr, "failed to remove Subnet %s from its router %s", id, router.ID)
		}
		if xerr := s.deleteRouter(router.ID); xerr != nil {
			return fail.Wrap(xerr, "failed to delete router %s associated with Subnet %s", router.ID, id)
		}
	}

	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			innerXErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
				func() error {
					err := subnets.Delete(s.NetworkClient, id).ExtractErr()
					return NormalizeError(err)
				},
				temporal.GetCommunicationTimeout(),
			)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrInvalidRequest:
					msg := "hosts or services are still attached"
					logrus.Warnf(strprocess.Capitalize(msg))
					return retry.StopRetryError(abstract.ResourceNotAvailableError("subnet", id), msg)
				default: // case gophercloud.ErrUnexpectedResponseCode:
					neutronError, innerErr := ParseNeutronError(innerXErr.Error())
					if innerErr != nil {
						switch innerErr.(type) {
						case *fail.ErrSyntax:
						default:
							return retry.StopRetryError(innerXErr)
						}
					}

					switch neutronError["type"] {
					case "SubnetInUse":
						msg := "hosts or services are still attached"
						logrus.Warnf(strprocess.Capitalize(msg))
						return retry.StopRetryError(abstract.ResourceNotAvailableError("subnet", id), msg)
					default:
						logrus.Debugf("NeutronError: type = %s", neutronError["type"])
					}
				}
			}
			return innerXErr
		},
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrTimeout:
			return abstract.ResourceTimeoutError("network", id, temporal.GetContextTimeout())
		case *retry.ErrStopRetry:
			return fail.Wrap(retryErr.Cause(), "failed to delete subnet after %v", temporal.GetContextTimeout())
		default:
			return retryErr
		}
	}
	return nil
}

// createRouter creates a router satisfying req
func (s Stack) createRouter(req RouterRequest) (*Router, fail.Error) {
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
	xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			router, innerErr = routers.Create(s.NetworkClient, opts).Extract()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}
	logrus.Debugf("Router '%s' (%s) successfully created", router.Name, router.ID)
	return &Router{
		ID:        router.ID,
		Name:      router.Name,
		NetworkID: router.GatewayInfo.NetworkID,
	}, nil
}

// ListRouters lists available routers
func (s Stack) ListRouters() ([]Router, fail.Error) {
	var emptySlice []Router
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	var ns []Router
	xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			innerErr := routers.List(s.NetworkClient, routers.ListOpts{}).EachPage(
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
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	return ns, xerr
}

// deleteRouter deletes the router identified by id
func (s Stack) deleteRouter(id string) fail.Error {
	return netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			innerErr := routers.Delete(s.NetworkClient, id).ExtractErr()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

// addSubnetToRouter attaches subnet to router
func (s Stack) addSubnetToRouter(routerID string, subnetID string) fail.Error {
	return netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := routers.AddInterface(s.NetworkClient, routerID, routers.AddInterfaceOpts{
				SubnetID: subnetID,
			}).Extract()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

// removeSubnetFromRouter detaches a subnet from router interface
func (s Stack) removeSubnetFromRouter(routerID string, subnetID string) fail.Error {
	return netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := routers.RemoveInterface(s.NetworkClient, routerID, routers.RemoveInterfaceOpts{
				SubnetID: subnetID,
			}).Extract()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

// BindSecurityGroupToSubnet binds a security group to a subnet
func (s Stack) BindSecurityGroupToSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
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

	return netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			var innerErr error
			// FIXME: bind security group to port associated to subnet
			//innerErr = secgroups.AddServer(s.ComputeClient, ahf.Core.ID, asg.ID).ExtractErr()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

// UnbindSecurityGroupFromSubnet unbinds a security group from a subnet
func (s Stack) UnbindSecurityGroupFromSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
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

	return netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			var innerErr error
			// FIXME: unbind security group from port associated to subnet
			//innerErr := secgroups.RemoveServer(s.ComputeClient, ahf.Core.ID, asg.ID).ExtractErr()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

// BindSecurityGroupToSubnet binds a security group to a subnet
func (s Stack) BindSecurityGroupToSubnet(subnetID string, sgParam stacks.SecurityGroupParameter) fail.Error {
	//if s == nil {
	//	return fail.InvalidInstanceError()
	//}
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

	return netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			var innerErr error
			// FIXME: bind security group to port associated to subnet
			//innerErr = secgroups.AddServer(s.ComputeClient, ahf.Core.ID, asg.ID).ExtractErr()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

// UnbindSecurityGroupFromSubnet unbinds a security group from a subnet
func (s Stack) UnbindSecurityGroupFromSubnet(subnetID string, sgParam stacks.SecurityGroupParameter) fail.Error {
	//if s == nil {
	//	return fail.InvalidInstanceError()
	//}
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

	return netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			var innerErr error
			// FIXME: unbind security group from port associated to subnet
			//innerErr := secgroups.RemoveServer(s.ComputeClient, ahf.Core.ID, asg.ID).ExtractErr()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

// CreateVIP creates a private virtual IP
// If public is set to true,
func (s Stack) CreateVIP(networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	nullAVIP := abstract.NewVirtualIP()
	if s.IsNull() {
		return nullAVIP, fail.InvalidInstanceError()
	}
	if networkID = strings.TrimSpace(networkID); networkID == "" {
		return nullAVIP, fail.InvalidParameterError("networkID", "cannot be empty string")
	}
	if subnetID = strings.TrimSpace(subnetID); subnetID == "" {
		return nullAVIP, fail.InvalidParameterError("subnetID", "cannot be empty string")
	}
	if name = strings.TrimSpace(name); name == "" {
		return nullAVIP, fail.InvalidParameterError("name", "cannot be empty string")
	}

	var port *ports.Port
	xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			asu := true
			options := ports.CreateOpts{
				NetworkID:      networkID,
				AdminStateUp:   &asu,
				Name:           name,
				SecurityGroups: &securityGroups,
				FixedIPs:       []ports.IP{{SubnetID: subnetID}},
			}
			port, innerErr = ports.Create(s.NetworkClient, options).Extract()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nullAVIP, xerr
	}
	vip := abstract.NewVirtualIP()
	vip.ID = port.ID
	vip.PrivateIP = port.FixedIPs[0].IPAddress
	return vip, nil
}

// AddPublicIPToVIP adds a public IP to VIP
func (s Stack) AddPublicIPToVIP(vip *abstract.VirtualIP) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}

	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (s Stack) BindHostToVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}
	if hostID = strings.TrimSpace(hostID); hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	var vipPort *ports.Port
	xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			vipPort, innerErr = ports.Get(s.NetworkClient, vip.ID).Extract()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return xerr
	}
	hostPorts, xerr := s.listPorts(ports.ListOpts{
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
		p.AllowedAddressPairs = append(p.AllowedAddressPairs, addressPair)
		xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
			func() error {
				_, innerErr := ports.Update(s.NetworkClient, p.ID, ports.UpdateOpts{AllowedAddressPairs: &p.AllowedAddressPairs}).Extract()
				return NormalizeError(innerErr)
			},
			temporal.GetCommunicationTimeout(),
		)
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (s Stack) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}
	if hostID = strings.TrimSpace(hostID); hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	var vipPort *ports.Port
	xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			vipPort, innerErr = ports.Get(s.NetworkClient, vip.ID).Extract()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return xerr
	}
	hostPorts, xerr := s.listPorts(ports.ListOpts{
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
		xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
			func() error {
				_, innerErr := ports.Update(s.NetworkClient, p.ID, ports.UpdateOpts{AllowedAddressPairs: &newAllowedAddressPairs}).Extract()
				return NormalizeError(innerErr)
			},
			temporal.GetCommunicationTimeout(),
		)
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// DeleteVIP deletes the port corresponding to the VIP
func (s Stack) DeleteVIP(vip *abstract.VirtualIP) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}

	for _, v := range vip.Hosts {
		xerr := s.UnbindHostFromVIP(vip, v.ID)
		if xerr != nil {
			return xerr
		}
	}
	return netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			innerErr := ports.Delete(s.NetworkClient, vip.ID).ExtractErr()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

// createPort creates a port
func (s Stack) createPort(req ports.CreateOpts) (port *ports.Port, xerr fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			port, innerErr = ports.Create(s.NetworkClient, req).Extract()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}

	return port, nil
}

func (s Stack) deletePort(id string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if id = strings.TrimSpace(id); id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	if _, xerr := s.inspectPort(id); xerr != nil {
		return fail.NotFoundError("failed to query port %s", id)
	}

	xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			innerErr = ports.Delete(s.NetworkClient, id).ExtractErr()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return xerr
	}

	return nil
}

// listPorts lists all ports available
func (s Stack) listPorts(options ports.ListOpts) ([]ports.Port, fail.Error) {
	var allPages pagination.Page
	xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			allPages, innerErr = ports.List(s.NetworkClient, options).AllPages()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}
	r, err := ports.ExtractPorts(allPages)
	return r, NormalizeError(err)
}

// updatePort updates the settings of a port
func (s Stack) updatePort(id string, options ports.UpdateOpts) fail.Error {
	return netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			resp, innerErr := ports.Update(s.NetworkClient, id, options).Extract()
			_ = resp
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

// inspectPort returns port from its ID
func (s Stack) inspectPort(id string) (port *ports.Port, xerr fail.Error) {
	xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			port, innerErr = ports.Get(s.NetworkClient, id).Extract()
			return NormalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}
	return port, nil
}
