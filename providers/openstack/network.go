/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"log"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/enums/IPVersion"
	"github.com/CS-SI/SafeScale/providers/metadata"

	gc "github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/gophercloud/gophercloud/pagination"
)

//RouterRequest represents a router request
type RouterRequest struct {
	Name string `json:"name,omitempty"`
	//NetworkID is the Network ID which the router gateway is connected to.
	NetworkID string `json:"network_id,omitempty"`
}

//Router represents a router
type Router struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	//NetworkID is the Network ID which the router gateway is connected to.
	NetworkID string `json:"network_id,omitempty"`
}

//Subnet define a sub network
type Subnet struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	//IPVersion is IPv4 or IPv6 (see IPVersion)
	IPVersion IPVersion.Enum `json:"ip_version,omitempty"`
	//Mask mask in CIDR notation
	Mask string `json:"mask,omitempty"`
	//NetworkID id of the parent network
	NetworkID string `json:"network_id,omitempty"`
}

//CreateNetwork creates a network named name
func (client *Client) CreateNetwork(req api.NetworkRequest) (*api.Network, error) {
	// We 1st check if name is not aleready used
	_net, err := metadata.LoadNetwork(providers.FromClient(client), req.Name)
	if err != nil {
		return nil, err
	}
	if _net != nil {
		return nil, fmt.Errorf("A network already exist with name '%s'", req.Name)
	}

	// We specify a name and that it should forward packets
	state := true
	opts := networks.CreateOpts{
		Name:         req.Name,
		AdminStateUp: &state,
	}

	// Execute the operation and get back a networks.Network struct
	network, err := networks.Create(client.Network, opts).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating network %s: %s", req.Name, ProviderErrorToString(err))
	}

	sn, err := client.CreateSubnet(req.Name, network.ID, req.CIDR, req.IPVersion)
	if err != nil {
		client.DeleteNetwork(network.ID)
		return nil, fmt.Errorf("Error creating network %s: %s", req.Name, ProviderErrorToString(err))
	}

	net := &api.Network{
		ID:        network.ID,
		Name:      network.Name,
		CIDR:      sn.Mask,
		IPVersion: sn.IPVersion,
	}
	err = metadata.SaveNetwork(providers.FromClient(client), net)
	if err != nil {
		client.DeleteNetwork(network.ID)
		return nil, err
	}
	return net, nil
}

//GetNetwork returns the network identified by ref (id or name)
func (client *Client) GetNetwork(ref string) (*api.Network, error) {
	// We first try looking for network from metadata
	m, err := metadata.LoadNetwork(providers.FromClient(client), ref)
	if err != nil {
		return nil, err
	}
	if m != nil {
		return m.Get(), nil
	}

	// If not found, we look for any network from provider
	// 1st try with id
	network, err := networks.Get(client.Network, ref).Extract()
	if err != nil {
		if _, ok := err.(gc.ErrDefault404); !ok {
			return nil, fmt.Errorf("Error getting network: %s", ProviderErrorToString(err))
		}
	}
	if network != nil && network.ID != "" {

		sns, err := client.ListSubnets(ref)
		if err != nil {
			return nil, fmt.Errorf("Error getting network: %s", ProviderErrorToString(err))
		}
		if len(sns) != 1 {
			return nil, fmt.Errorf("Bad configuration, each network should have exactly one subnet")
		}
		sn := sns[0]
		// gwID, _ := client.getGateway(id)
		// if err != nil {
		// 	return nil, fmt.Errorf("Bad configuration, no gateway associated to this network")
		// }
		return &api.Network{
			ID:        network.ID,
			Name:      network.Name,
			CIDR:      sn.Mask,
			IPVersion: sn.IPVersion,
			// GatewayID: network.GatewayId,
		}, nil
	}

	// Last chance, we look at all network
	nets, err := client.listAllNetworks()
	if err != nil {
		return nil, err
	}
	for _, n := range nets {
		if n.ID == ref || n.Name == ref {
			return &n, err
		}
	}

	// At this point, no network has been found with given reference
	return nil, nil
}

//ListNetworks lists available networks
func (client *Client) ListNetworks(all bool) ([]api.Network, error) {
	if all {
		return client.listAllNetworks()
	}
	return client.listMonitoredNetworks()
}

//listAllNetworks lists available networks
func (client *Client) listAllNetworks() ([]api.Network, error) {
	// We have the option of filtering the network list. If we want the full
	// collection, leave it as an empty struct
	opts := networks.ListOpts{}

	// Retrieve a pager (i.e. a paginated collection)
	pager := networks.List(client.Network, opts)
	var netList []api.Network
	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		networkList, err := networks.ExtractNetworks(page)
		if err != nil {
			return false, err
		}

		for _, n := range networkList {

			sns, err := client.ListSubnets(n.ID)
			if err != nil {
				return false, fmt.Errorf("Error getting network: %s", ProviderErrorToString(err))
			}
			if len(sns) != 1 {
				continue
			}
			if n.ID == client.ProviderNetworkID {
				continue
			}
			sn := sns[0]
			// gwID, err := client.getGateway(n.ID)
			// if err != nil {
			// 	return false, fmt.Errorf("Error getting network: %s", ProviderErrorToString(err))
			// }
			netList = append(netList, api.Network{
				ID:        n.ID,
				Name:      n.Name,
				CIDR:      sn.Mask,
				IPVersion: sn.IPVersion,
				// GatewayID: gwID,
			})
		}
		return true, nil
	})
	if len(netList) == 0 && err != nil {
		return nil, fmt.Errorf("Error listing networks: %s", ProviderErrorToString(err))
	}
	return netList, nil
}

//listMonitoredNetworks lists available networks created by SafeScale (ie those registered in object storage)
func (client *Client) listMonitoredNetworks() ([]api.Network, error) {
	var netList []api.Network

	m := metadata.NewNetwork(providers.FromClient(client))
	err := m.Browse(func(net *api.Network) error {
		// Get info about the gateway associated to this network
		mgw, err := metadata.NewGateway(providers.FromClient(client), net.ID)
		if err != nil {
			log.Print(err.Error())
			return nil
		}
		ok, err := mgw.Read()
		if err != nil {
			log.Print(err.Error())
			return fmt.Errorf("failed to read gateway metadata for network '%s': %s", net.ID, err.Error())
		}
		if !ok {
			log.Print("gateway metadata not found")
			return fmt.Errorf("failed to find gateway metadata for network '%s'", net.ID)
		}
		gwhost := mgw.Get()

		// Update GatewayId field
		net.GatewayID = gwhost.ID

		netList = append(netList, *net)
		return nil
	})
	return netList, err
}

// DeleteNetwork deletes the network identified by id
func (client *Client) DeleteNetwork(networkRef string) error {
	m, err := metadata.LoadNetwork(providers.FromClient(client), networkRef)
	if err != nil {
		return err
	}
	if m == nil {
		return fmt.Errorf("Failed to find network '%s' in metadata", networkRef)
	}
	networkID := m.Get().ID
	hosts, err := m.ListHosts()
	if err != nil {
		return err
	}
	gwID := m.Get().GatewayID
	if len(hosts) > 0 {
		var allhosts []string
		for _, i := range hosts {
			if gwID != i.ID {
				allhosts = append(allhosts, i.Name)
			}
		}
		if len(allhosts) > 0 {
			var lenS string
			if len(allhosts) > 1 {
				lenS = "s"
			}
			return fmt.Errorf("network '%s' has %d host%s attached (%s)", networkRef, len(allhosts), lenS, strings.Join(allhosts, ","))
		}
	}

	client.DeleteGateway(networkID)

	sns, err := client.ListSubnets(networkID)
	if err != nil {
		return fmt.Errorf("error deleting network: %s", ProviderErrorToString(err))
	}
	for _, sn := range sns {
		err := client.DeleteSubnet(sn.ID)
		if err != nil {
			return fmt.Errorf("error deleting network: %s", ProviderErrorToString(err))
		}
	}
	err = networks.Delete(client.Network, networkID).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting network: %s", ProviderErrorToString(err))
	}
	err = m.Delete()
	if err != nil {
		return fmt.Errorf("Error deleting network: %s", ProviderErrorToString(err))
	}

	return nil
}

// CreateGateway creates a public Gateway for a private network
func (client *Client) CreateGateway(req api.GWRequest) (*api.Host, error) {
	// Ensure network exists
	net, err := client.GetNetwork(req.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("Network %s not found %s", req.NetworkID, ProviderErrorToString(err))
	}
	if net == nil {
		return nil, fmt.Errorf("Network %s not found", req.NetworkID)
	}
	gwname := req.GWName
	if gwname == "" {
		gwname = "gw-" + net.Name
	}
	hostReq := api.HostRequest{
		ImageID:    req.ImageID,
		KeyPair:    req.KeyPair,
		Name:       gwname,
		TemplateID: req.TemplateID,
		NetworkIDs: []string{req.NetworkID},
		PublicIP:   true,
	}
	host, err := client.createHost(hostReq, true)
	if err != nil {
		return nil, fmt.Errorf("error creating gateway : %s", ProviderErrorToString(err))
	}
	err = metadata.SaveGateway(providers.FromClient(client), host, req.NetworkID)
	return host, err
}

// DeleteGateway delete the public gateway of a private network
func (client *Client) DeleteGateway(networkID string) error {
	m, err := metadata.LoadGateway(providers.FromClient(client), networkID)
	if err != nil {
		return err
	}
	if m == nil {
		return nil
	}

	host := m.Get()
	client.DeleteHost(host.ID)
	// Loop waiting for effective deletion of the host
	for err = nil; err != nil; _, err = client.GetHost(host.ID) {
		time.Sleep(100 * time.Millisecond)
	}
	return m.Delete()
}

// ToGopherIPversion ...
func ToGopherIPversion(v IPVersion.Enum) gc.IPVersion {
	if v == IPVersion.IPv4 {
		return gc.IPv4
	} else if v == IPVersion.IPv6 {
		return gc.IPv6
	}
	return -1
}

func fromGopherIPversion(v gc.IPVersion) IPVersion.Enum {
	if v == gc.IPv4 {
		return IPVersion.IPv4
	} else if v == gc.IPv6 {
		return IPVersion.IPv6
	}
	return -1
}

// FromIntIPversion ...
func FromIntIPversion(v int) IPVersion.Enum {
	if v == 4 {
		return IPVersion.IPv4
	} else if v == 6 {
		return IPVersion.IPv6
	}
	return -1
}

// CreateSubnet creates a sub network
// - netID ID of the parent network
// - name is the name of the sub network
// - mask is a network mask defined in CIDR notation
func (client *Client) CreateSubnet(name string, networkID string, cidr string, ipVersion IPVersion.Enum) (*Subnet, error) {
	// You must associate a new subnet with an existing network - to do this you
	// need its UUID. You must also provide a well-formed CIDR value.
	//addr, _, err := net.ParseCIDR(mask)
	dhcp := true
	opts := subnets.CreateOpts{
		NetworkID:  networkID,
		CIDR:       cidr,
		IPVersion:  ToGopherIPversion(ipVersion),
		Name:       name,
		EnableDHCP: &dhcp,
	}

	if !client.Cfg.UseLayer3Networking {
		noGateway := ""
		opts.GatewayIP = &noGateway
	}

	// Execute the operation and get back a subnets.Subnet struct
	subnet, err := subnets.Create(client.Network, opts).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating subnet: %s", ProviderErrorToString(err))
	}

	if client.Cfg.UseLayer3Networking {
		router, err := client.CreateRouter(RouterRequest{
			Name:      subnet.ID,
			NetworkID: client.ProviderNetworkID,
		})
		if err != nil {
			client.DeleteSubnet(subnet.ID)
			return nil, fmt.Errorf("Error creating subnet: %s", ProviderErrorToString(err))
		}
		err = client.AddSubnetToRouter(router.ID, subnet.ID)
		if err != nil {
			client.DeleteSubnet(subnet.ID)
			client.DeleteRouter(router.ID)
			return nil, fmt.Errorf("Error creating subnet: %s", ProviderErrorToString(err))
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

// GetSubnet returns the sub network identified by id
func (client *Client) GetSubnet(id string) (*Subnet, error) {
	// Execute the operation and get back a subnets.Subnet struct
	subnet, err := subnets.Get(client.Network, id).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting subnet: %s", ProviderErrorToString(err))
	}
	return &Subnet{
		ID:        subnet.ID,
		Name:      subnet.Name,
		IPVersion: FromIntIPversion(subnet.IPVersion),
		Mask:      subnet.CIDR,
		NetworkID: subnet.NetworkID,
	}, nil
}

// ListSubnets lists available sub networks of network net
func (client *Client) ListSubnets(netID string) ([]Subnet, error) {
	pager := subnets.List(client.Network, subnets.ListOpts{
		NetworkID: netID,
	})
	var subnetList []Subnet
	pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := subnets.ExtractSubnets(page)
		if err != nil {
			return false, fmt.Errorf("Error listing subnets: %s", ProviderErrorToString(err))
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
	return subnetList, nil
}

// DeleteSubnet deletes the sub network identified by id
func (client *Client) DeleteSubnet(id string) error {
	routerList, _ := client.ListRouters()
	var router *Router
	for _, r := range routerList {
		if r.Name == id {
			router = &r
			break
		}
	}
	if router != nil {
		if err := client.RemoveSubnetFromRouter(router.ID, id); err != nil {
			return fmt.Errorf("Error deleting subnets: %s", ProviderErrorToString(err))
		}
		if err := client.DeleteRouter(router.ID); err != nil {
			return fmt.Errorf("Error deleting subnets: %s", ProviderErrorToString(err))
		}
	}
	var err error
	for i := 0; i < 10; i++ {
		if err = subnets.Delete(client.Network, id).ExtractErr(); err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		return fmt.Errorf("Error deleting subnets: %s", ProviderErrorToString(err))
	}

	return nil
}

// CreateRouter creates a router satisfying req
func (client *Client) CreateRouter(req RouterRequest) (*Router, error) {
	//Create a router to connect external Provider network
	gi := routers.GatewayInfo{
		NetworkID: req.NetworkID,
	}
	state := true
	opts := routers.CreateOpts{
		Name:         req.Name,
		AdminStateUp: &state,
		GatewayInfo:  &gi,
	}
	router, err := routers.Create(client.Network, opts).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating Router: %s", ProviderErrorToString(err))
	}
	return &Router{
		ID:        router.ID,
		Name:      router.Name,
		NetworkID: router.GatewayInfo.NetworkID,
	}, nil

}

// GetRouter returns the router identified by id
func (client *Client) GetRouter(id string) (*Router, error) {

	r, err := routers.Get(client.Network, id).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting Router: %s", ProviderErrorToString(err))
	}
	return &Router{
		ID:        r.ID,
		Name:      r.Name,
		NetworkID: r.GatewayInfo.NetworkID,
	}, nil

}

// ListRouters lists available routers
func (client *Client) ListRouters() ([]Router, error) {

	var ns []Router
	err := routers.List(client.Network, routers.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
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
	})
	if err != nil {
		return nil, fmt.Errorf("Error listing volume types: %s", ProviderErrorToString(err))
	}
	return ns, nil
}

// DeleteRouter deletes the router identified by id
func (client *Client) DeleteRouter(id string) error {
	err := routers.Delete(client.Network, id).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting Router: %s", ProviderErrorToString(err))
	}
	return nil
}

// AddSubnetToRouter attaches subnet to router
func (client *Client) AddSubnetToRouter(routerID string, subnetID string) error {
	_, err := routers.AddInterface(client.Network, routerID, routers.AddInterfaceOpts{
		SubnetID: subnetID,
	}).Extract()
	if err != nil {
		return fmt.Errorf("Error addinter subnet: %s", ProviderErrorToString(err))
	}
	return nil
}

// RemoveSubnetFromRouter detachesa subnet from router interface
func (client *Client) RemoveSubnetFromRouter(routerID string, subnetID string) error {
	_, err := routers.RemoveInterface(client.Network, routerID, routers.RemoveInterfaceOpts{
		SubnetID: subnetID,
	}).Extract()
	if err != nil {
		return fmt.Errorf("Error addinter subnet: %s", ProviderErrorToString(err))
	}
	return nil
}
