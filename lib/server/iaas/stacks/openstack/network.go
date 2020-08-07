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

    tracer := debug.NewTracer(nil, tracing.ShouldTrace("stack.network"), "(%s)", req.Name).WithStopwatch().Entering()
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
        return nil, fail.Prepend(xerr, "failed to create network '%s'", req.Name)
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
                logrus.Errorf("failed to delete network '%s': %v", req.Name, derr)
                _ = xerr.AddConsequence(derr)
            }
        }
    }()

    // creates the subnet
    subnet, xerr := s.createSubnet(req.Name, network.ID, req.CIDR, req.IPVersion, req.DNSServers)
    if xerr != nil {
        return nil, fail.Prepend(xerr, "failed to create subnet '%s'", req.Name)
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

    defer debug.NewTracer(nil, tracing.ShouldTrace("stack.network"), "(%s)", name).WithStopwatch().Entering().Exiting()

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

    defer debug.NewTracer(nil, tracing.ShouldTrace("stack.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

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
            return nil, xerr
        }
    }
    if network != nil && network.ID != "" {
        sns, xerr := s.listSubnets(id)
        if xerr != nil {
            return nil, xerr
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

    defer debug.NewTracer(nil, tracing.ShouldTrace("stack.network"), "").WithStopwatch().Entering().Exiting()

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
                        sns, xerr := s.listSubnets(n.ID)
                        if xerr != nil {
                            return false, fail.Wrap(xerr, "error getting list of subnets")
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
            return innerErr
        },
        temporal.GetCommunicationTimeout(),
    )
    if xerr != nil {
        return nil, xerr
    }
    // VPL: empty list is not an abnormal situation; do not log
    // if len(netList) == 0
    //     logrus.Debugf("Listing all networks: Empty network list !")
    // }
    return netList, nil
}

// DeleteNetwork deletes the network identified by id
func (s *Stack) DeleteNetwork(id string) fail.Error {
    if s == nil {
        return fail.InvalidInstanceError()
    }
    if id == "" {
        return fail.InvalidParameterError("id", "cannot be empty string")
    }

    defer debug.NewTracer(nil, tracing.ShouldTrace("stack.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

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

    sns, xerr := s.listSubnets(id)
    if xerr != nil {
        xerr = fail.Prepend(xerr, "failed to list subnets of network '%s'", network.Name)
        logrus.Debugf(strprocess.Capitalize(xerr.Error()))
        return xerr
    }
    for _, sn := range sns {
        xerr := s.deleteSubnet(sn.ID)
        if xerr != nil {
            xerr = fail.Prepend(xerr, "failed to delete subnet '%s' of network '%s'", sn.Name, network.Name)
            logrus.Debugf(strprocess.Capitalize(xerr.Error()))
            return xerr
        }
    }

    xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            innerErr := networks.Delete(s.NetworkClient, id).ExtractErr()
            return NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
    if xerr != nil {
        xerr = fail.Prepend(xerr, "failed to delete network '%s'", network.Name)
        logrus.Debugf(strprocess.Capitalize(xerr.Error()))
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
        return nil, xerr
    }

    // Starting from here, delete subnet if exit with error
    defer func() {
        if xerr != nil {
            derr := s.deleteSubnet(subnet.ID)
            if derr != nil {
                logrus.Warnf("Error deleting subnet: %v", derr)
                _ = xerr.AddConsequence(fail.Prepend(derr, "failed to delete subnet '%s'", subnet.Name))
            }
        }
    }()

    if s.cfgOpts.UseLayer3Networking {
        router, xerr := s.createRouter(RouterRequest{
            Name:      subnet.ID,
            NetworkID: s.ProviderNetworkID,
        })
        if xerr != nil {
            return nil, fail.Prepend(xerr, "failed to create router '%s'", subnet.ID)
        }

        // Starting from here, delete router if exit with error
        defer func() {
            if xerr != nil {
                derr := s.deleteRouter(router.ID)
                if derr != nil {
                    logrus.Warnf("Error deleting router: %v", derr)
                    _ = xerr.AddConsequence(fail.Prepend(derr, "failed to delete route '%s'", router.Name))
                }
            }
        }()

        xerr = s.addSubnetToRouter(router.ID, subnet.ID)
        if xerr != nil {
            return nil, fail.Prepend(xerr, "failed to add subnet '%s' to router '%s'", subnet.Name, router.Name)
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
func (s *Stack) listSubnets(netID string) (_ []Subnet, xerr fail.Error) {
    listOpts := subnets.ListOpts{
        NetworkID: netID,
    }
    var subnetList []Subnet
    xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            innerErr := subnets.List(s.NetworkClient, listOpts).EachPage(func(page pagination.Page) (bool, error) {
                list, err := subnets.ExtractSubnets(page)
                if err != nil {
                    return false, NormalizeError(err)
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
            return NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
    if xerr != nil {
        return []Subnet{}, xerr
    }

    // VPL: empty subnet list is not an abnormal situation, do not log
    return subnetList, nil
}

// deleteSubnet deletes the sub network identified by id
func (s *Stack) deleteSubnet(id string) (xerr fail.Error) {
    tracer := debug.NewTracer(nil, tracing.ShouldTrace("stack.network"), "").Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

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
            return fail.Prepend(xerr,"failed to delete subnet '%s'", id)
        }
        if xerr = s.deleteRouter(router.ID); xerr != nil {
            return fail.Prepend(xerr, "failed to delete subnet '%s'", id)
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
            switch innerXErr.(type) {
            case *fail.ErrInvalidRequest:
                msg := "hosts or services are still attached"
                logrus.Warnf(strprocess.Capitalize(msg))
                return retry.StopRetryError(abstract.ResourceNotAvailableError("subnet", id), msg)
            default: //case gophercloud.ErrUnexpectedResponseCode:
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
func (s *Stack) ListRouters() ([]Router, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
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
func (s *Stack) deleteRouter(id string) fail.Error {
    return netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            innerErr := routers.Delete(s.NetworkClient, id).ExtractErr()
            return NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
}

// addSubnetToRouter attaches subnet to router
func (s *Stack) addSubnetToRouter(routerID string, subnetID string) fail.Error {
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
func (s *Stack) removeSubnetFromRouter(routerID string, subnetID string) fail.Error {
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

// listPorts lists all ports available
func (s *Stack) listPorts(options ports.ListOpts) ([]ports.Port, fail.Error) {
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

// CreateVIP creates a private virtual IP
// If public is set to true,
func (s *Stack) CreateVIP(networkID string, name string) (*abstract.VirtualIP, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }
    if networkID = strings.TrimSpace(networkID); networkID == "" {
        return nil, fail.InvalidParameterError("networkID", "cannot be empty string")
    }
    if name = strings.TrimSpace(name); name == "" {
        return nil, fail.InvalidParameterError("name", "cannot be empty string")
    }

    var port *ports.Port
    xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() (innerErr error) {
            asu := true
            sg := []string{s.SecurityGroup.ID}
            options := ports.CreateOpts{
                NetworkID:      networkID,
                AdminStateUp:   &asu,
                Name:           name,
                SecurityGroups: &sg,
            }
            port, innerErr = ports.Create(s.NetworkClient, options).Extract()
            return NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
    if xerr != nil {
        return nil, xerr
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
func (s *Stack) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
    if s == nil {
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
func (s *Stack) DeleteVIP(vip *abstract.VirtualIP) fail.Error {
    if s == nil {
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
