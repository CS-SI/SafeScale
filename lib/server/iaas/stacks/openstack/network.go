/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
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

// Subnet define a sub network
type Subnet struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	// IPVersion is IPv4 or IPv6 (see IPVersion)
	IPVersion ipversion.Enum `json:"ip_version,omitempty"`
	// Mask mask in CIDR notation
	Mask string `json:"mask,omitempty"`
	// NetworkID id of the parent network
	NetworkID string `json:"network_id,omitempty"`
}

// CreateNetwork creates a network named name
func (s *Stack) CreateNetwork(req abstract.NetworkRequest) (newNet *abstract.Network, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stack.network"), "(%s)", req.Name).WithStopwatch().Entering()
	defer tracer.OnExitTrace()

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
	opts := networks.CreateOpts{
		Name:         req.Name,
		AdminStateUp: &state,
	}

	// Execute the operation and get back a networks.NetworkClient struct
	network, err := networks.Create(s.NetworkClient, opts).Extract()
	if err != nil {
		return nil, fail.NewError("error creating network '%s': %s", req.Name, ProviderErrorToString(err))
	}

	// Starting from here, delete network if exit with error
	defer func() {
		if xerr != nil {
			derr := networks.Delete(s.NetworkClient, network.ID).ExtractErr()
			if derr != nil {
				logrus.Errorf("failed to delete network '%s': %v", req.Name, derr)
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	subnet, xerr := s.createSubnet(req.Name, network.ID, req.CIDR, req.IPVersion, req.DNSServers)
	if xerr != nil {
		return nil, fail.NewError("error creating network '%s': %s", req.Name, ProviderErrorToString(xerr))
	}

	// Starting from here, delete subnet if exit with error
	defer func() {
		if xerr != nil {
			derr := s.deleteSubnet(subnet.ID)
			if derr != nil {
				logrus.Errorf("failed to delete subnet '%s': %+v", subnet.ID, derr)
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	newNet = abstract.NewNetwork()
	newNet.ID = network.ID
	newNet.Name = network.Name
	newNet.CIDR = subnet.Mask
	newNet.IPVersion = subnet.IPVersion
	return newNet, nil
}

// GetNetworkByName ...
func (s *Stack) GetNetworkByName(name string) (*abstract.Network, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("stack.network"), "(%s)", name).WithStopwatch().Entering().OnExitTrace()

	// Gophercloud doesn't propose the way to get a host by name, but OpenStack knows how to do it...
	r := networks.GetResult{}
	_, r.Err = s.ComputeClient.Get(s.NetworkClient.ServiceURL("networks?name="+name), &r.Body, &gophercloud.RequestOpts{
		OkCodes: []int{200, 203},
	})
	if r.Err != nil {
		if _, ok := r.Err.(gophercloud.ErrDefault403); ok {
			return nil, abstract.ResourceForbiddenError("network", name)
		}
		return nil, fail.NewError("query for network '%s' failed: %v", name, r.Err)
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
		return s.GetNetwork(id)
	}
	return nil, abstract.ResourceNotFoundError("network", name)
}

// GetNetwork returns the network identified by id
func (s *Stack) GetNetwork(id string) (*abstract.Network, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("stack.network"), "(%s)", id).WithStopwatch().Entering().OnExitTrace()

	// If not found, we look for any network from provider
	// 1st try with id
	network, err := networks.Get(s.NetworkClient, id).Extract()
	if err != nil {
		if _, ok := err.(gophercloud.ErrDefault404); !ok {
			return nil, fail.Wrap(err, fmt.Sprintf("error getting network '%s': %s", id, ProviderErrorToString(err)))
		}
	}
	if network != nil && network.ID != "" {
		sns, xerr := s.listSubnets(id)
		if xerr != nil {
			return nil, fail.Wrap(xerr, fmt.Sprintf("error getting network: %s", ProviderErrorToString(err)))
		}
		if len(sns) != 1 {
			return nil, fail.InconsistentError("bad configuration, each network should have exactly one subnet")
		}
		sn := sns[0]
		// gwID, _ := client.getGateway(id)
		// if err != nil {
		// 	return nil, fail.InconsistentError("bad configuration, no gateway associated to this network")
		// }
		newNet := abstract.NewNetwork()
		newNet.ID = network.ID
		newNet.Name = network.Name
		newNet.CIDR = sn.Mask
		newNet.IPVersion = sn.IPVersion
		// net.GatewayID = network.GatewayId
		return newNet, nil
	}

	// At this point, no network has been found with given reference
	errNotFound := abstract.ResourceNotFoundError("network(GetNetwork)", id)
	logrus.Debug(errNotFound)
	return nil, errNotFound
}

// ListNetworks lists available networks
func (s *Stack) ListNetworks() ([]*abstract.Network, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("stack.network"), "").WithStopwatch().Entering().OnExitTrace()

	// Retrieve a pager (i.e. a paginated collection)
	var netList []*abstract.Network
	pager := networks.List(s.NetworkClient, networks.ListOpts{})
	err := pager.EachPage(
		func(page pagination.Page) (bool, error) {
			networkList, err := networks.ExtractNetworks(page)
			if err != nil {
				return false, err
			}

			for _, n := range networkList {
				sns, xerr := s.listSubnets(n.ID)
				if xerr != nil {
					return false, fail.NewError("error getting network: %s", ProviderErrorToString(xerr))
				}
				if len(sns) != 1 {
					continue
				}
				if n.ID == s.ProviderNetworkID {
					continue
				}
				sn := sns[0]

				newNet := abstract.NewNetwork()
				newNet.ID = n.ID
				newNet.Name = n.Name
				newNet.CIDR = sn.Mask
				newNet.IPVersion = sn.IPVersion
				// GatewayID: gwID,
				netList = append(netList, newNet)
			}
			return true, nil
		},
	)
	if len(netList) == 0 || err != nil {
		if err != nil {
			return nil, fail.Wrap(err, fmt.Sprintf("error listing networks: %s", ProviderErrorToString(err)))
		}
		logrus.Debugf("Listing all networks: Empty network list !")
	}
	return netList, nil
}

// DeleteNetwork deletes the network identified by id
func (s *Stack) DeleteNetwork(id string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("stack.network"), "(%s)", id).WithStopwatch().Entering().OnExitTrace()

	network, err := networks.Get(s.NetworkClient, id).Extract()
	if err != nil {
		xerr := TranslateProviderError(err)
		logrus.Errorf("failed to delete network: %+v", xerr)
		return xerr
	}

	sns, xerr := s.listSubnets(id)
	if xerr != nil {
		xerr = fail.Wrap(xerr, "failed to delete network '%s'", network.Name)
		logrus.Debugf(strprocess.Capitalize(xerr.Error()))
		return xerr
	}
	for _, sn := range sns {
		xerr := s.deleteSubnet(sn.ID)
		if xerr != nil {
			xerr = fail.Wrap(xerr, "failed to delete network '%s'", network.Name)
			logrus.Debugf(strprocess.Capitalize(xerr.Error()))
			return xerr
		}
	}
	err = networks.Delete(s.NetworkClient, id).ExtractErr()
	if err != nil {
		xerr = fail.NewError("failed to delete network '%s': %s", network.Name, ProviderErrorToString(err))
		logrus.Debugf(strprocess.Capitalize(err.Error()))
		return xerr
	}

	return nil
}

// ToGopherIPversion ...
func ToGopherIPversion(v ipversion.Enum) gophercloud.IPVersion {
	if v == ipversion.IPv4 {
		return gophercloud.IPv4
	}
	if v == ipversion.IPv6 {
		return gophercloud.IPv6
	}
	return -1
}

// FromIntIPversion ...
func FromIntIPversion(v int) ipversion.Enum {
	if v == 4 {
		return ipversion.IPv4
	}
	if v == 6 {
		return ipversion.IPv6
	}
	return -1
}

// createSubnet creates a sub network
// - networkID is the ID of the parent network
// - name is the name of the sub network
// - cidr is a network in CIDR notation
func (s *Stack) createSubnet(name string, networkID string, cidr string, ipVersion ipversion.Enum, dnsServers []string) (subn *Subnet, xerr fail.Error) {
	// You must associate a new subnet with an existing network - to do this you
	// need its UUID. You must also provide a well-formed CIDR value.
	dhcp := true
	opts := subnets.CreateOpts{
		NetworkID:  networkID,
		CIDR:       cidr,
		IPVersion:  ToGopherIPversion(ipVersion),
		Name:       name,
		EnableDHCP: &dhcp,
	}

	if len(dnsServers) > 0 {
		opts.DNSNameservers = dnsServers
	}

	if !s.cfgOpts.UseLayer3Networking {
		noGateway := ""
		opts.GatewayIP = &noGateway
	}

	var subnet *subnets.Subnet
	// Execute the operation and get back a subnets.Subnet struct
	xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			var innerErr error
			r := subnets.Create(s.NetworkClient, opts)
			subnet, innerErr = r.Extract()
			if innerErr != nil {
				switch r.Err.(type) { // nolint
				case gophercloud.ErrDefault400:
					neutronError, innerXErr := ParseNeutronError(r.Err.Error())
					if innerXErr != nil {
						switch innerXErr.(type) {
						case *fail.ErrSyntax:
							return innerXErr
						default:
							return retry.StopRetryError(innerXErr)
						}
					}
					if neutronError != nil {
						return retry.StopRetryError(fail.NewError("bad request: %s", neutronError["message"]), "error creating subnet:")
					}
				default:
					return retry.StopRetryError(innerErr, "error creating subnet: %s", ProviderErrorToString(innerErr))
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
		return nil, xerr
	}

	// Starting from here, delete subnet if exit with error
	defer func() {
		if xerr != nil {
			derr := s.deleteSubnet(subnet.ID)
			if derr != nil {
				logrus.Warnf("Error deleting subnet: %v", derr)
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	if s.cfgOpts.UseLayer3Networking {
		router, xerr := s.createRouter(RouterRequest{
			Name:      subnet.ID,
			NetworkID: s.ProviderNetworkID,
		})
		if xerr != nil {
			return nil, fail.Wrap(xerr, "error creating subnet")
		}

		// Starting from here, delete router if exit with error
		defer func() {
			if xerr != nil {
				derr := s.deleteRouter(router.ID)
				if derr != nil {
					logrus.Warnf("Error deleting router: %v", derr)
					_ = xerr.AddConsequence(derr)
				}
			}
		}()

		xerr = s.addSubnetToRouter(router.ID, subnet.ID)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "error creating subnet")
		}
	}

	return &Subnet{
		ID:        subnet.ID,
		Name:      subnet.Name,
		IPVersion: FromIntIPversion(subnet.IPVersion),
		Mask:      subnet.CIDR,
		NetworkID: subnet.NetworkID,
	}, nil
}

// listSubnets lists available sub networks of network net
func (s *Stack) listSubnets(netID string) ([]Subnet, fail.Error) {
	pager := subnets.List(s.NetworkClient, subnets.ListOpts{
		NetworkID: netID,
	})
	var subnetList []Subnet
	paginationErr := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := subnets.ExtractSubnets(page)
		if err != nil {
			return false, fail.NewError("error listing subnets: %s", ProviderErrorToString(err))
		}

		for _, subnet := range list {
			subnetList = append(subnetList, Subnet{
				ID:        subnet.ID,
				Name:      subnet.Name,
				IPVersion: FromIntIPversion(subnet.IPVersion),
				Mask:      subnet.CIDR,
				NetworkID: subnet.NetworkID,
			})
		}
		return true, nil
	})

	if (paginationErr != nil) || (len(subnetList) == 0) {
		if paginationErr != nil {
			return nil, fail.Wrap(paginationErr, fmt.Sprintf("we have a pagination error !: %v", paginationErr))
		}
	}

	return subnetList, nil
}

// deleteSubnet deletes the sub network identified by id
func (s *Stack) deleteSubnet(id string) (xerr fail.Error) {
	tracer := concurrency.NewTracer(nil, debug.ShouldTrace("stack.network"), "").Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)

	routerList, _ := s.ListRouters()
	var router *Router
	for _, r := range routerList {
		if r.Name == id {
			router = &r
			break
		}
	}
	if router != nil {
		if xerr = s.removeSubnetFromRouter(router.ID, id); xerr != nil {
			return fail.NewError("failed to delete subnet '%s': %s", id, ProviderErrorToString(xerr))
		}
		if xerr = s.deleteRouter(router.ID); xerr != nil {
			return fail.NewError("failed to delete subnet '%s': %s", id, ProviderErrorToString(xerr))
		}
	}

	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			r := subnets.Delete(s.NetworkClient, id)
			err := r.ExtractErr()
			switch err.(type) {
			case gophercloud.ErrDefault409:
				msg := "hosts or services are still attached"
				logrus.Warnf(strprocess.Capitalize(msg))
				return retry.StopRetryError(abstract.ResourceNotAvailableError("subnet", id), msg)
			case gophercloud.ErrUnexpectedResponseCode:
				neutronError, innerXErr := ParseNeutronError(err.Error())
				if innerXErr != nil {
					switch innerXErr.(type) {
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
			if err != nil {
				return fail.NewError("failed to delete subnet '%s': %s", id, ProviderErrorToString(err))
			}
			return nil
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
func (s *Stack) createRouter(req RouterRequest) (*Router, fail.Error) {
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
	router, err := routers.Create(s.NetworkClient, opts).Extract()
	if err != nil {
		return nil, fail.Wrap(err, fmt.Sprintf("failed to create router '%s': %s", req.Name, ProviderErrorToString(err)))
	}
	logrus.Debugf("Router '%s' (%s) successfully created", router.Name, router.ID)
	return &Router{
		ID:        router.ID,
		Name:      router.Name,
		NetworkID: router.GatewayInfo.NetworkID,
	}, nil
}

// ListRouters lists available routers
func (s *Stack) ListRouters() ([]Router, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	var ns []Router
	err := routers.List(s.NetworkClient, routers.ListOpts{}).EachPage(
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
	if err != nil {
		return nil, fail.Wrap(err, "error listing volume types: %s", ProviderErrorToString(err))
	}
	return ns, nil
}

// deleteRouter deletes the router identified by id
func (s *Stack) deleteRouter(id string) fail.Error {
	err := routers.Delete(s.NetworkClient, id).ExtractErr()
	if err != nil {
		return fail.Wrap(err, "failed to delete router: %s", ProviderErrorToString(err))
	}
	return nil
}

// addSubnetToRouter attaches subnet to router
func (s *Stack) addSubnetToRouter(routerID string, subnetID string) fail.Error {
	_, err := routers.AddInterface(s.NetworkClient, routerID, routers.AddInterfaceOpts{
		SubnetID: subnetID,
	}).Extract()
	if err != nil {
		return fail.Wrap(err, "failed to add subnet to router: %s", ProviderErrorToString(err))
	}
	return nil
}

// removeSubnetFromRouter detaches a subnet from router interface
func (s *Stack) removeSubnetFromRouter(routerID string, subnetID string) fail.Error {
	r := routers.RemoveInterface(s.NetworkClient, routerID, routers.RemoveInterfaceOpts{
		SubnetID: subnetID,
	})
	_, err := r.Extract()
	if err != nil {
		return fail.Wrap(err, "failed to remove subnet '%s' from router '%s': %s", subnetID, routerID, ProviderErrorToString(err))
	}
	return nil
}

// listPorts lists all ports available
func (s *Stack) listPorts(options ports.ListOpts) ([]ports.Port, fail.Error) {
	allPages, err := ports.List(s.NetworkClient, options).AllPages()
	if err != nil {
		return nil, fail.ToError(err)
	}
	r, err := ports.ExtractPorts(allPages)
	return r, fail.ToError(err)
}

// CreateVIP creates a private virtual IP
// If public is set to true,
func (s *Stack) CreateVIP(networkID string, name string) (*abstract.VirtualIP, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	asu := true
	sg := []string{s.SecurityGroup.ID}
	options := ports.CreateOpts{
		NetworkID:      networkID,
		AdminStateUp:   &asu,
		Name:           name,
		SecurityGroups: &sg,
	}
	port, err := ports.Create(s.NetworkClient, options).Extract()
	if err != nil {
		return nil, fail.ToError(err)
	}
	vip := abstract.VirtualIP{
		ID:        port.ID,
		PrivateIP: port.FixedIPs[0].IPAddress,
	}
	return &vip, nil
}

// AddPublicIPToVIP adds a public IP to VIP
func (s *Stack) AddPublicIPToVIP(vip *abstract.VirtualIP) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME Technical debt
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (s *Stack) BindHostToVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}
	if hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	vipPort, err := ports.Get(s.NetworkClient, vip.ID).Extract()
	if err != nil {
		return fail.ToError(err)
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
		_, err = ports.Update(s.NetworkClient, p.ID, ports.UpdateOpts{AllowedAddressPairs: &p.AllowedAddressPairs}).Extract()
		if err != nil {
			return fail.ToError(err)
		}
	}
	return nil
}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (s *Stack) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}
	if hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	vipPort, err := ports.Get(s.NetworkClient, vip.ID).Extract()
	if err != nil {
		return fail.ToError(err)
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
		_, err = ports.Update(s.NetworkClient, p.ID, ports.UpdateOpts{AllowedAddressPairs: &newAllowedAddressPairs}).Extract()
		if err != nil {
			return fail.ToError(err)
		}
	}
	return nil
}

// DeleteVIP deletes the port corresponding to the VIP
func (s *Stack) DeleteVIP(vip *abstract.VirtualIP) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}

	for _, v := range vip.Hosts {
		rerr := s.UnbindHostFromVIP(vip, v.ID)
		if rerr != nil {
			return rerr
		}
	}
	err := ports.Delete(s.NetworkClient, vip.ID).ExtractErr()
	return fail.ToError(err)
}
