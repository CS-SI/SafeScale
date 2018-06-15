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
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/api/IPVersion"
	metadata "github.com/CS-SI/SafeScale/providers/metadata"
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

func (client *Client) saveGateway(netID string, vmID string) error {
	m, err := metadata.NewGateway(netID)
	if err != nil {
		return err
	}
	return m.Carry(vmID).Write()
}

func (client *Client) saveNetwork(network api.Network) error {
	m, err := metadata.NewNetwork()
	if err != nil {
		return err
	}
	return m.Carry(&network).Write()
}

//CreateNetwork creates a network named name
func (client *Client) CreateNetwork(req api.NetworkRequest) (*api.Network, error) {
	// We specify a name and that it should forward packets
	state := true
	opts := networks.CreateOpts{
		Name:         req.Name,
		AdminStateUp: &state,
	}

	// Execute the operation and get back a networks.Network struct
	network, err := networks.Create(client.Network, opts).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating network %s: %s", req.Name, errorString(err))
	}

	sn, err := client.createSubnet(req.Name, network.ID, req.CIDR, req.IPVersion)
	if err != nil {
		client.DeleteNetwork(network.ID)
		return nil, fmt.Errorf("Error creating network %s: %s", req.Name, errorString(err))
	}

	apiNetwork := &api.Network{
		ID:        network.ID,
		Name:      network.Name,
		CIDR:      sn.Mask,
		IPVersion: sn.IPVersion,
	}

	err = client.saveNetwork(*apiNetwork)
	if err != nil {
		client.DeleteNetwork(network.ID)
		return nil, fmt.Errorf("Error creating network : %s", errorString(err))
	}
	return apiNetwork, nil

}

//GetNetwork returns the network identified by id
func (client *Client) GetNetwork(id string) (*api.Network, error) {
	network, err := networks.Get(client.Network, id).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting network: %s", errorString(err))
	}
	sns, err := client.listSubnets(id)
	if err != nil {
		return nil, fmt.Errorf("Error getting network: %s", errorString(err))
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
		// GatewayID: gwID,
	}, nil
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

			sns, err := client.listSubnets(n.ID)
			if err != nil {
				return false, fmt.Errorf("Error getting network: %s", errorString(err))
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
			// 	return false, fmt.Errorf("Error getting network: %s", errorString(err))
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
		return nil, fmt.Errorf("Error listing networks: %s", errorString(err))
	}
	return netList, nil
}

//listMonitoredNetworks lists available networks created by SaeScale (ie those registered in object storage)
func (client *Client) listMonitoredNetworks() ([]api.Network, error) {
	var netList []api.Network

	m, err := metadata.NewNetwork()
	if err != nil {
		return netList, err
	}
	err = m.Browse(func(net *api.Network) error {
		netList = append(netList, *net)
		return nil
	})
	return netList, err
}

//DeleteNetwork deletes the network identified by id
func (client *Client) DeleteNetwork(networkID string) error {
	net, err := client.GetNetwork(networkID)
	if err != nil {
		return fmt.Errorf("error deleting networks: %s", errorString(err))
	}

	m, err := metadata.NewNetwork()
	if err != nil {
		return err
	}
	// Look for VMs attached on this network
	vmids, err := m.Carry(net).ListHosts()
	if err != nil {
		return err
	}
	if len(vmids) > 1 {
		return fmt.Errorf("Network '%s' has hosts attached: %s", networkID, strings.Join(vmids, " "))
	}

	client.DeleteGateway(net.ID)
	sns, err := client.listSubnets(networkID)
	if err != nil {
		return fmt.Errorf("error deleting network: %s", errorString(err))
	}
	for _, sn := range sns {
		err := client.deleteSubnet(sn.ID)
		if err != nil {
			return fmt.Errorf("error deleting network: %s", errorString(err))
		}
	}
	err = networks.Delete(client.Network, networkID).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting network: %s", errorString(err))
	}
	err = m.Delete()
	if err != nil {
		return fmt.Errorf("Error deleting network: %s", errorString(err))
	}

	return nil
}

//CreateGateway creates a public Gateway for a private network
func (client *Client) CreateGateway(req api.GWRequest) error {
	net, err := client.GetNetwork(req.NetworkID)
	if err != nil {
		return fmt.Errorf("Network %s not found %s", req.NetworkID, errorString(err))
	}
	gwname := req.GWName
	if gwname == "" {
		gwname = "gw-" + net.Name
	}
	vmReq := api.VMRequest{
		ImageID:    req.ImageID,
		KeyPair:    req.KeyPair,
		Name:       gwname,
		TemplateID: req.TemplateID,
		NetworkIDs: []string{req.NetworkID},
		PublicIP:   true,
	}
	vm, err := client.createVM(vmReq, true)
	if err != nil {
		return fmt.Errorf("Error creating gateway : %s", errorString(err))
	}
	err = client.saveGateway(req.NetworkID, vm.ID)
	if err != nil {
		client.DeleteVM(vm.ID)
		return fmt.Errorf("Error creating gateway : %s", errorString(err))
	}
	return nil
}

//DeleteGateway delete the public gateway of a private network
func (client *Client) DeleteGateway(networkID string) error {
	m, err := metadata.NewGateway(networkID)
	if err != nil {
		return err
	}
	found, err := m.Read()
	if err != nil {
		return err
	}
	if found {
		vmID := m.Get()
		client.DeleteVM(vmID)
		// Loop waiting for effective deletion of the VM
		for err = nil; err != nil; _, err = client.GetVM(vmID) {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return m.Delete()
}

func toGopherIPversion(v IPVersion.Enum) gc.IPVersion {
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
func fromIntIPversion(v int) IPVersion.Enum {
	if v == 4 {
		return IPVersion.IPv4
	} else if v == 6 {
		return IPVersion.IPv6
	}
	return -1
}

//createSubnet creates a sub network
//- netID ID of the parent network
//- name is the name of the sub network
//- mask is a network mask defined in CIDR notation
func (client *Client) createSubnet(name string, networkID string, cidr string, ipVersion IPVersion.Enum) (*Subnet, error) {
	// You must associate a new subnet with an existing network - to do this you
	// need its UUID. You must also provide a well-formed CIDR value.
	//addr, _, err := net.ParseCIDR(mask)
	dhcp := true
	opts := subnets.CreateOpts{
		NetworkID:  networkID,
		CIDR:       cidr,
		IPVersion:  toGopherIPversion(ipVersion),
		Name:       name,
		EnableDHCP: &dhcp,
	}

	// Execute the operation and get back a subnets.Subnet struct
	subnet, err := subnets.Create(client.Network, opts).Extract()
	if client.Cfg.UseLayer3Networking {
		if err != nil {
			return nil, fmt.Errorf("Error creating subnet: %s", errorString(err))
		}

		router, err := client.createRouter(RouterRequest{
			Name:      subnet.ID,
			NetworkID: client.ProviderNetworkID,
		})
		if err != nil {
			client.deleteSubnet(subnet.ID)
			return nil, fmt.Errorf("Error creating subnet: %s", errorString(err))
		}
		err = client.addSubnetToRouter(router.ID, subnet.ID)
		if err != nil {
			client.deleteSubnet(subnet.ID)
			client.deleteRouter(router.ID)
			return nil, fmt.Errorf("Error creating subnet: %s", errorString(err))
		}
	}

	return &Subnet{
		ID:        subnet.ID,
		Name:      subnet.Name,
		IPVersion: fromIntIPversion(subnet.IPVersion),
		Mask:      subnet.CIDR,
		NetworkID: subnet.NetworkID,
	}, nil
}

//getSubnet returns the sub network identified by id
func (client *Client) getSubnet(id string) (*Subnet, error) {
	// Execute the operation and get back a subnets.Subnet struct
	subnet, err := subnets.Get(client.Network, id).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting subnet: %s", errorString(err))
	}
	return &Subnet{
		ID:        subnet.ID,
		Name:      subnet.Name,
		IPVersion: fromIntIPversion(subnet.IPVersion),
		Mask:      subnet.CIDR,
		NetworkID: subnet.NetworkID,
	}, nil
}

//listSubnets lists available sub networks of network net
func (client *Client) listSubnets(netID string) ([]Subnet, error) {
	pager := subnets.List(client.Network, subnets.ListOpts{
		NetworkID: netID,
	})
	var subnetList []Subnet
	pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := subnets.ExtractSubnets(page)
		if err != nil {
			return false, fmt.Errorf("Error listing subnets: %s", errorString(err))
		}

		for _, subnet := range list {
			subnetList = append(subnetList, Subnet{
				ID:        subnet.ID,
				Name:      subnet.Name,
				IPVersion: fromIntIPversion(subnet.IPVersion),
				Mask:      subnet.CIDR,
				NetworkID: subnet.NetworkID,
			})
		}
		return true, nil
	})
	return subnetList, nil
}

//deleteSubnet deletes the sub network identified by id
func (client *Client) deleteSubnet(id string) error {
	routerList, _ := client.ListRouter()
	var router *Router
	for _, r := range routerList {
		if r.Name == id {
			router = &r
			break
		}
	}
	if router != nil {
		if err := client.removeSubnetFromRouter(router.ID, id); err != nil {
			return fmt.Errorf("Error deleting subnets: %s", errorString(err))
		}
		if err := client.deleteRouter(router.ID); err != nil {
			return fmt.Errorf("Error deleting subnets: %s", errorString(err))
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
		return fmt.Errorf("Error deleting subnets: %s", errorString(err))
	}

	return nil
}

//createRouter creates a router satisfying req
func (client *Client) createRouter(req RouterRequest) (*Router, error) {
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
		return nil, fmt.Errorf("Error creating Router: %s", errorString(err))
	}
	return &Router{
		ID:        router.ID,
		Name:      router.Name,
		NetworkID: router.GatewayInfo.NetworkID,
	}, nil

}

//getRouter returns the router identified by id
func (client *Client) getRouter(id string) (*Router, error) {

	r, err := routers.Get(client.Network, id).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting Router: %s", errorString(err))
	}
	return &Router{
		ID:        r.ID,
		Name:      r.Name,
		NetworkID: r.GatewayInfo.NetworkID,
	}, nil

}

//ListRouter lists available routers
func (client *Client) ListRouter() ([]Router, error) {

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
		return nil, fmt.Errorf("Error listing volume types: %s", errorString(err))
	}
	return ns, nil
}

//deleteRouter deletes the router identified by id
func (client *Client) deleteRouter(id string) error {
	err := routers.Delete(client.Network, id).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting Router: %s", errorString(err))
	}
	return nil
}

//addSubnetToRouter attaches subnet to router
func (client *Client) addSubnetToRouter(routerID string, subnetID string) error {
	_, err := routers.AddInterface(client.Network, routerID, routers.AddInterfaceOpts{
		SubnetID: subnetID,
	}).Extract()
	if err != nil {
		return fmt.Errorf("Error addinter subnet: %s", errorString(err))
	}
	return nil
}

//removeSubnetFromRouter detachesa subnet from router interface
func (client *Client) removeSubnetFromRouter(routerID string, subnetID string) error {
	_, err := routers.RemoveInterface(client.Network, routerID, routers.RemoveInterfaceOpts{
		SubnetID: subnetID,
	}).Extract()
	if err != nil {
		return fmt.Errorf("Error addinter subnet: %s", errorString(err))
	}
	return nil
}
