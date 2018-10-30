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

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/providers/enums/IPVersion"

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

// CreateNetwork creates a network named name
func (s *Stack) CreateNetwork(req model.NetworkRequest) (*model.Network, error) {
	// We specify a name and that it should forward packets
	state := true
	opts := networks.CreateOpts{
		Name:         req.Name,
		AdminStateUp: &state,
	}

	// Execute the operation and get back a networks.Network struct
	network, err := networks.Create(s.Network, opts).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating network %s: %s", req.Name, ErrorToString(err))
	}

	sn, err := s.CreateSubnet(req.Name, network.ID, req.CIDR, req.IPVersion)
	if err != nil {
		nerr := s.DeleteNetwork(network.ID)
		if nerr != nil {
			log.Warnf("Error deleting network: %v", nerr)
		}
		return nil, fmt.Errorf("Error creating network %s: %s", req.Name, ErrorToString(err))
	}

	net := &model.Network{
		ID:        network.ID,
		Name:      network.Name,
		CIDR:      sn.Mask,
		IPVersion: sn.IPVersion,
	}
	return net, nil
}

// GetNetwork returns the network identified by id
func (s *Stack) GetNetwork(ref string) (*model.Network, error) {
	// 1st try with id
	network, err := networks.Get(s.Network, ref).Extract()
	if err != nil {
		if _, ok := err.(gc.ErrDefault404); !ok {
			return nil, fmt.Errorf("Error getting network: %s", ErrorToString(err))
		}
	}
	if network != nil && network.ID != "" {
		sns, err := s.ListSubnets(ref)
		if err != nil {
			return nil, fmt.Errorf("Error getting network: %s", ErrorToString(err))
		}
		if len(sns) != 1 {
			return nil, fmt.Errorf("Bad configuration, each network should have exactly one subnet")
		}
		sn := sns[0]
		// gwID, _ := client.getGateway(id)
		// if err != nil {
		// 	return nil, fmt.Errorf("Bad configuration, no gateway associated to this network")
		// }
		return &model.Network{
			ID:        network.ID,
			Name:      network.Name,
			CIDR:      sn.Mask,
			IPVersion: sn.IPVersion,
			// GatewayID: network.GatewayId,
		}, nil
	}

	// Last chance, we look at all network
	nets, err := s.ListNetworks()
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

// ListNetworks lists available networks
func (s *Stack) ListNetworks() ([]model.Network, error) {
	// We have the option of filtering the network list. If we want the full
	// collection, leave it as an empty struct
	opts := networks.ListOpts{}

	// Retrieve a pager (i.e. a paginated collection)
	pager := networks.List(s.Network, opts)
	var netList []model.Network
	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		networkList, err := networks.ExtractNetworks(page)
		if err != nil {
			return false, err
		}

		for _, n := range networkList {
			sns, err := s.ListSubnets(n.ID)
			if err != nil {
				return false, fmt.Errorf("Error getting network: %s", ErrorToString(err))
			}
			if len(sns) != 1 {
				continue
			}
			if n.ID == s.ProviderNetworkID {
				continue
			}
			sn := sns[0]
			// gwID, err := client.getGateway(n.ID)
			// if err != nil {
			// 	return false, fmt.Errorf("Error getting network: %s", ProviderErrorToString(err))
			// }
			netList = append(netList, model.Network{
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
		return nil, fmt.Errorf("Error listing networks: %s", ErrorToString(err))
	}
	return netList, nil
}

// DeleteNetwork deletes the network identified by id
func (s *Stack) DeleteNetwork(networkID string) error {
	err := networks.Get(s.Network, networkID).Err
	if err != nil {
		if strings.Contains(err.Error(), "Resource not found") {
			log.Warnf("Inconsistent network data !!")
		}
	}

	err = s.DeleteGateway(networkID)
	if err != nil {
		log.Warnf("Error deleting gateway: %s", ErrorToString(err))
	}

	if gwID != "" {
		err = networks.Get(s.Network, gwID).Err
		if err != nil {
			if strings.Contains(err.Error(), "Resource not found") {
				log.Warnf("Inconsistent gateway data !!")
			}
		}
	}

	sns, err := s.ListSubnets(networkID)
	if err != nil {
		return fmt.Errorf("Error deleting network, listing subnets: %s", ErrorToString(err))
	}
	for _, sn := range sns {
		err := s.DeleteSubnet(sn.ID)
		if err != nil {
			return fmt.Errorf("Error deleting network, deleting subnets: %s", ErrorToString(err))
		}
	}
	err = networks.Delete(s.Network, networkID).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting network: %s", ErrorToString(err))
	}

	return nil
}

// CreateGateway creates a public Gateway for a private network
func (s *Stack) CreateGateway(req model.GatewayRequest) (*model.Host, error) {
	// Ensure network exists
	net, err := s.GetNetwork(req.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("Network %s not found %s", req.NetworkID, ErrorToString(err))
	}
	if net == nil {
		return nil, fmt.Errorf("Network %s not found", req.NetworkID)
	}
	gwname := req.GatewayName
	if gwname == "" {
		gwname = "gw-" + net.Name
	}
	hostReq := model.HostRequest{
		ImageID:    req.ImageID,
		KeyPair:    req.KeyPair,
		Name:       gwname,
		TemplateID: req.TemplateID,
		NetworkIDs: []string{req.NetworkID},
		PublicIP:   true,
	}
	host, err := s.createHost(hostReq, true)
	if err != nil {
		return nil, fmt.Errorf("Error creating gateway : %s", ErrorToString(err))
	}
	return host, err
}

// DeleteGateway delete the public gateway of a private network
func (s *Stack) DeleteGateway(hostID string) error {
	nerr := s.DeleteHost(hostID)
	if nerr != nil {
		log.Warnf("Error deleting host: %v", nerr)
	}
	// Loop waiting for effective deletion of the host
	var err error
	for err = nil; err != nil; _, err = s.GetHost(hostID) {
		time.Sleep(100 * time.Millisecond)
	}
	return err
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
	}
	if v == gc.IPv6 {
		return IPVersion.IPv6
	}
	return -1
}

// FromIntIPversion ...
func FromIntIPversion(v int) IPVersion.Enum {
	if v == 4 {
		return IPVersion.IPv4
	}
	if v == 6 {
		return IPVersion.IPv6
	}
	return -1
}

// CreateSubnet creates a sub network
// - netID ID of the parent network
// - name is the name of the sub network
// - mask is a network mask defined in CIDR notation
func (s *Stack) CreateSubnet(name string, networkID string, cidr string, ipVersion IPVersion.Enum) (*Subnet, error) {
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

	if !s.CfgOpts.UseLayer3Networking {
		noGateway := ""
		opts.GatewayIP = &noGateway
	}

	// Execute the operation and get back a subnets.Subnet struct
	subnet, err := subnets.Create(s.Network, opts).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating subnet: %s", ErrorToString(err))
	}

	if s.CfgOpts.UseLayer3Networking {
		router, err := s.CreateRouter(
			RouterRequest{
				Name:      subnet.ID,
				NetworkID: s.ProviderNetworkID,
			},
		)
		if err != nil {
			nerr := s.DeleteSubnet(subnet.ID)
			if nerr != nil {
				log.Warnf("Error deleting subnet: %v", nerr)
			}
			return nil, fmt.Errorf("Error creating subnet: %s", ErrorToString(err))
		}
		err = s.AddSubnetToRouter(router.ID, subnet.ID)
		if err != nil {
			nerr := s.DeleteSubnet(subnet.ID)
			if nerr != nil {
				log.Warnf("Error deleting subnet: %v", nerr)
			}
			nerr = s.DeleteRouter(router.ID)
			if nerr != nil {
				log.Warnf("Error deleting router: %v", nerr)
			}
			return nil, fmt.Errorf("Error creating subnet: %s", ErrorToString(err))
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
func (s *Stack) GetSubnet(id string) (*Subnet, error) {
	// Execute the operation and get back a subnets.Subnet struct
	subnet, err := subnets.Get(s.Network, id).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting subnet: %s", ErrorToString(err))
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
func (s *Stack) ListSubnets(netID string) ([]Subnet, error) {
	pager := subnets.List(s.Network, subnets.ListOpts{
		NetworkID: netID,
	})
	var subnetList []Subnet
	paginationErr := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := subnets.ExtractSubnets(page)
		if err != nil {
			return false, fmt.Errorf("Error listing subnets: %s", ErrorToString(err))
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

	// TODO previously we ignored the error here, consider returning nil, paginationErr
	if paginationErr != nil {
		log.Warnf("We have a pagination error !: %v", paginationErr)
	}

	return subnetList, nil
}

// DeleteSubnet deletes the sub network identified by id
func (s *Stack) DeleteSubnet(id string) error {
	routerList, _ := s.ListRouters()
	var router *Router
	for _, r := range routerList {
		if r.Name == id {
			router = &r
			break
		}
	}
	if router != nil {
		if err := s.RemoveSubnetFromRouter(router.ID, id); err != nil {
			return fmt.Errorf("Error deleting subnets: %s", ErrorToString(err))
		}
		if err := s.DeleteRouter(router.ID); err != nil {
			return fmt.Errorf("Error deleting subnets: %s", ErrorToString(err))
		}
	}
	var err error
	for i := 0; i < 10; i++ {
		if err = subnets.Delete(s.Network, id).ExtractErr(); err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		return fmt.Errorf("Error deleting subnets: %s", ErrorToString(err))
	}

	return nil
}

// CreateRouter creates a router satisfying req
func (s *Stack) CreateRouter(req RouterRequest) (*Router, error) {
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
	router, err := routers.Create(s.Network, opts).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating Router: %s", ErrorToString(err))
	}
	return &Router{
		ID:        router.ID,
		Name:      router.Name,
		NetworkID: router.GatewayInfo.NetworkID,
	}, nil

}

// GetRouter returns the router identified by id
func (s *Stack) GetRouter(id string) (*Router, error) {
	r, err := routers.Get(s.Network, id).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting Router: %s", ErrorToString(err))
	}
	return &Router{
		ID:        r.ID,
		Name:      r.Name,
		NetworkID: r.GatewayInfo.NetworkID,
	}, nil
}

// ListRouters lists available routers
func (s *Stack) ListRouters() ([]Router, error) {

	var ns []Router
	err := routers.List(s.Network, routers.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
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
		return nil, fmt.Errorf("Error listing volume types: %s", ErrorToString(err))
	}
	return ns, nil
}

// DeleteRouter deletes the router identified by id
func (s *Stack) DeleteRouter(id string) error {
	err := routers.Delete(s.Network, id).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting Router: %s", ErrorToString(err))
	}
	return nil
}

// AddSubnetToRouter attaches subnet to router
func (s *Stack) AddSubnetToRouter(routerID string, subnetID string) error {
	_, err := routers.AddInterface(s.Network, routerID, routers.AddInterfaceOpts{
		SubnetID: subnetID,
	}).Extract()
	if err != nil {
		return fmt.Errorf("Error addinter subnet: %s", ErrorToString(err))
	}
	return nil
}

// RemoveSubnetFromRouter detachesa subnet from router interface
func (s *Stack) RemoveSubnetFromRouter(routerID string, subnetID string) error {
	_, err := routers.RemoveInterface(s.Network, routerID, routers.RemoveInterfaceOpts{
		SubnetID: subnetID,
	}).Extract()
	if err != nil {
		return fmt.Errorf("Error addinter subnet: %s", ErrorToString(err))
	}
	return nil
}
