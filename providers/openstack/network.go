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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	gc "github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	"github.com/CS-SI/SafeScale/providers/model/enums/IPVersion"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
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
func (client *Client) CreateNetwork(req model.NetworkRequest) (*model.Network, error) {
	log.Debugf("providers.openstack.CreateNetwork(%s) called", req.Name)

	// We 1st check if name is not already used
	_net, err := metadata.LoadNetwork(client, req.Name)
	if err != nil {
		msg := fmt.Sprintf("Error creating network '%s': failed to access metadata: %v", req.Name, err)
		// log.Errorf(msg)
		return nil, fmt.Errorf(msg)
	}
	if _net != nil {
		return nil, fmt.Errorf("Error creating network '%s': a network already exists with that name", req.Name)
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
		msg := fmt.Sprintf("Error creating network '%s': %s", req.Name, ProviderErrorToString(err))
		// log.Errorf(msg)
		return nil, fmt.Errorf(msg)
	}

	// Starting from here, delete network if exit with error
	defer func() {
		if err != nil {
			derr := networks.Delete(client.Network, network.ID).ExtractErr()
			if derr != nil {
				log.Errorf("failed to delete network '%s': %v", req.Name, derr)
			}
		}
	}()

	subnet, err := client.createSubnet(req.Name, network.ID, req.CIDR, req.IPVersion, req.DNSServers)
	if err != nil {
		return nil, fmt.Errorf("Error creating network '%s': %s", req.Name, ProviderErrorToString(err))
	}

	// Starting from here, delete subnet if exit with error
	defer func() {
		if err != nil {
			derr := client.deleteSubnet(subnet.ID)
			if derr != nil {
				log.Errorf("failed to delete subnet '%s': %+v", subnet.ID, derr)
			}
		}
	}()

	net := model.NewNetwork()
	net.ID = network.ID
	net.Name = network.Name
	net.CIDR = subnet.Mask
	net.IPVersion = subnet.IPVersion
	err = metadata.SaveNetwork(client, net)
	if err != nil {
		return nil, err
	}
	return net, nil
}

// GetNetwork returns the network identified by ref (id or name)
func (client *Client) GetNetwork(ref string) (*model.Network, error) {
	// If not found, we look for any network from provider
	// 1st try with id
	network, err := networks.Get(client.Network, ref).Extract()
	if err != nil {
		if _, ok := err.(gc.ErrDefault404); !ok {
			// log.Errorf("Error getting network: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error getting network '%s': %s", ref, ProviderErrorToString(err)))
		}
	}
	if network != nil && network.ID != "" {
		sns, err := client.listSubnets(ref)
		if err != nil {
			// log.Errorf("Error getting network: listing subnet: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error getting network: %s", ProviderErrorToString(err)))
		}
		if len(sns) != 1 {
			return nil, fmt.Errorf("Bad configuration, each network should have exactly one subnet")
		}
		sn := sns[0]
		// gwID, _ := client.getGateway(id)
		// if err != nil {
		// 	return nil, fmt.Errorf("Bad configuration, no gateway associated to this network")
		// }
		net := model.NewNetwork()
		net.ID = network.ID
		net.Name = network.Name
		net.CIDR = sn.Mask
		net.IPVersion = sn.IPVersion
		//net.GatewayID = network.GatewayId
		return net, nil
	}

	// Last chance, we look at all network
	nets, err := client.listAllNetworks()
	if err != nil {
		// log.Debugf("Error getting network: listing all networks: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting network: listing all networks"))
	}
	for _, n := range nets {
		if n.ID == ref || n.Name == ref {
			return n, err
		}
	}

	// At this point, no network has been found with given reference
	return nil, nil
}

// ListNetworks lists available networks
func (client *Client) ListNetworks(all bool) ([]*model.Network, error) {
	if all {
		return client.listAllNetworks()
	}
	return client.listMonitoredNetworks()
}

// listAllNetworks lists available networks
func (client *Client) listAllNetworks() ([]*model.Network, error) {
	// We have the option of filtering the network list. If we want the full
	// collection, leave it as an empty struct
	opts := networks.ListOpts{}

	// Retrieve a pager (i.e. a paginated collection)
	pager := networks.List(client.Network, opts)
	var netList []*model.Network
	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		networkList, err := networks.ExtractNetworks(page)
		if err != nil {
			return false, err
		}

		for _, n := range networkList {
			sns, err := client.listSubnets(n.ID)
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
			net := model.NewNetwork()
			net.ID = n.ID
			net.Name = n.Name
			net.CIDR = sn.Mask
			net.IPVersion = sn.IPVersion
			// GatewayID: gwID,
			netList = append(netList, net)
		}
		return true, nil
	})
	if len(netList) == 0 || err != nil {
		if err != nil {
			log.Debugf("Error listing networks: pagination error: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error listing networks: %s", ProviderErrorToString(err)))
		}
		log.Debugf("Listing all networks: Empty network list !")
	}
	return netList, nil
}

// listMonitoredNetworks lists available networks created by SafeScale (ie those registered in object storage)
func (client *Client) listMonitoredNetworks() ([]*model.Network, error) {
	var netList []*model.Network

	m := metadata.NewNetwork(client)
	err := m.Browse(func(net *model.Network) error {
		// // Get info about the gateway associated to this network
		// mgw, err := metadata.NewGateway(client, net.ID)
		// if err != nil {
		// 	log.Print(err.Error())
		// 	return nil
		// }
		// ok, err := mgw.Read()

		// if ok && (err == nil) {
		// 	gwhost := mgw.Get()
		// 	// Update GatewayId field
		// 	net.GatewayID = gwhost.ID
		// }

		netList = append(netList, net)
		return nil
	})

	if len(netList) == 0 || err != nil {
		if err != nil {
			log.Debugf("Error listing monitored networks: pagination error: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error listing monitored networks: %s", ProviderErrorToString(err)))
		}
		log.Debugf("Listing monitored networks: Empty network list !")
	}

	return netList, err
}

// DeleteNetwork deletes the network identified by id
func (client *Client) DeleteNetwork(networkRef string) error {
	log.Infof("providers.openstack.DeleteNetwork(%s) called", networkRef)

	// TODO Add more detailed exceptions here
	mn, err := metadata.LoadNetwork(client, networkRef)
	if err != nil {
		msg := fmt.Sprintf("Error deleting network '%s': %+v", networkRef, err)
		log.Debugf(msg)
		return fmt.Errorf(msg)
	}
	if mn == nil {
		return fmt.Errorf("Failed to find network '%s' in metadata", networkRef)
	}
	network := mn.Get()
	networkID := network.ID

	err = networks.Get(client.Network, networkID).Err
	if err != nil {
		log.Errorf("Error deleting network: %+v", err)
		if strings.Contains(err.Error(), "Resource not found") {
			log.Errorf("Inconsistent network data !!")
		}
	}

	gwID := network.GatewayID

	hosts, err := mn.ListHosts()
	if err != nil {
		return err
	}
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

	if gwID != "" {
		err = client.DeleteGateway(networkID)
		if err != nil {
			log.Warnf("Error deleting gateway: %s", ProviderErrorToString(err))
		}
		err = networks.Get(client.Network, gwID).Err
		if err != nil {
			if strings.Contains(err.Error(), "Resource not found") {
				log.Warnf("Inconsistent gateway data !!")
			}
		}
	}

	sns, err := client.listSubnets(networkID)
	if err != nil {
		msg := fmt.Sprintf("Error deleting network '%s': %s", networkID, ProviderErrorToString(err))
		log.Debugf(msg)
		return fmt.Errorf(msg)
	}
	for _, sn := range sns {
		err := client.deleteSubnet(sn.ID)
		if err != nil {
			log.Errorf("Error deleting network: deleting subnets: %+v", err)
			return errors.Wrap(err, fmt.Sprintf("Error deleting network, deleting subnets: %s", ProviderErrorToString(err)))
		}
	}
	err = networks.Delete(client.Network, networkID).ExtractErr()
	if err != nil {
		log.Errorf("Error deleting network: extracting errors: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting network: %s", ProviderErrorToString(err)))
	}
	err = mn.Delete()
	if err != nil {
		log.Errorf("Error deleting network: deletion: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting network: %s", ProviderErrorToString(err)))
	}

	return nil
}

// CreateGateway creates a public Gateway for a private network
func (client *Client) CreateGateway(req model.GWRequest) (*model.Host, error) {
	// Ensure network exists
	net, err := client.GetNetwork(req.NetworkID)
	if err != nil {
		log.Errorf("Error creating gateway: getting network: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating gateway, getting network by id, Network '%s' not found '%s'", req.NetworkID, ProviderErrorToString(err)))
	}
	if net == nil {
		return nil, fmt.Errorf("Error creating gateway, Network %s not found", req.NetworkID)
	}
	gwname := req.GWName
	if gwname == "" {
		gwname = "gw-" + net.Name
	}
	hostReq := model.HostRequest{
		ImageID:      req.ImageID,
		KeyPair:      req.KeyPair,
		ResourceName: gwname,
		TemplateID:   req.TemplateID,
		NetworkIDs:   []string{req.NetworkID},
		PublicIP:     true,
	}
	host, err := client.createHost(hostReq, true)
	if err != nil {
		log.Errorf("Error creating gateway: creating host: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating gateway : %s", ProviderErrorToString(err)))
	}

	// delete the host when found problem starting from here
	defer func() {
		if err != nil {
			nerr := client.DeleteHost(host.ID)
			if nerr != nil {
				log.Warnf("Problem cleaning up after failure saving metadata : trying to delete host: %v", nerr)
			}
		}
	}()

	// Updates Host Property propsv1.HostSizing
	hpSizingV1 := propsv1.BlankHostSizing
	err = host.Properties.Get(HostProperty.SizingV1, &hpSizingV1)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating gateway : %s", ProviderErrorToString(err)))
	}
	hpSizingV1.Template = req.TemplateID
	err = host.Properties.Set(HostProperty.SizingV1, &hpSizingV1)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating gateway : %s", ProviderErrorToString(err)))
	}

	// Writes Gateway metadata
	err = metadata.SaveGateway(client, host, req.NetworkID)
	if err != nil {
		log.Debugf("Error creating gateway: saving network metadata: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating gateway: Error saving gateway metadata: %s", ProviderErrorToString(err)))
	}

	return host, nil
}

// DeleteGateway delete the public gateway of a private network
func (client *Client) DeleteGateway(networkID string) error {
	m, err := metadata.LoadGateway(client, networkID)
	if err != nil {
		// log.Errorf("Error deleting gateway: failure loading gateway metadata: %+v", err)
		return errors.Wrap(err, "Error deleting gateway: failure loading gateway metadata")
	}
	if m == nil {
		return nil
	}

	host := m.Get()
	nerr := client.DeleteHost(host.ID)
	if nerr != nil {
		return errors.Wrapf(nerr, "Error deleting gateway: error deleting host '%s'", host.ID)
	} else {
		// TODO Handle edge cases, and don't wait forever

		// Loop waiting for effective deletion of the host
		for err = nil; err != nil; _, err = client.GetHost(host.ID) {
			time.Sleep(100 * time.Millisecond)
		}
	}
	// Loop waiting for effective deletion of the host
	for err = nil; err != nil; err = client.UpdateHost(host) {
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

// createSubnet creates a sub network
// - netID ID of the parent network
// - name is the name of the sub network
// - mask is a network mask defined in CIDR notation
func (client *Client) createSubnet(name string, networkID string, cidr string, ipVersion IPVersion.Enum, dnsServers []string) (*Subnet, error) {
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

	if !client.Cfg.UseLayer3Networking {
		noGateway := ""
		opts.GatewayIP = &noGateway
	}

	// Execute the operation and get back a subnets.Subnet struct
	r := subnets.Create(client.Network, opts)
	subnet, err := r.Extract()
	if err != nil {
		switch r.Err.(type) {
		case gc.ErrDefault400:
			msg := extractMessageFromNeutronError(r.Err.Error())
			if msg != "" {
				msg = fmt.Sprintf("Error creating subnet: bad request: %s\n", msg)
				log.Debugf(msg)
				return nil, fmt.Errorf(msg)
			}
		}
		log.Debugf("Error creating subnet: %+v\n", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating subnet: %s", ProviderErrorToString(err)))
	}

	// Starting from here, delete subnet if exit with error
	defer func() {
		if err != nil {
			derr := client.deleteSubnet(subnet.ID)
			if derr != nil {
				log.Warnf("Error deleting subnet: %v", derr)
			}
		}
	}()

	if client.Cfg.UseLayer3Networking {
		router, err := client.createRouter(RouterRequest{
			Name:      subnet.ID,
			NetworkID: client.ProviderNetworkID,
		})
		if err != nil {
			log.Debugf("Error creating subnet: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error creating subnet: %s", ProviderErrorToString(err)))
		}

		// Starting from here, delete router if exit with error
		defer func() {
			if err != nil {
				derr := client.deleteRouter(router.ID)
				if derr != nil {
					log.Warnf("Error deleting router: %v", derr)
				}
			}
		}()

		err = client.addSubnetToRouter(router.ID, subnet.ID)
		if err != nil {
			log.Debugf("Error creating subnet: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error creating subnet: %s", ProviderErrorToString(err)))
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

func extractMessageFromNeutronError(neutronError string) string {
	startIdx := strings.Index(neutronError, "{\"NeutronError\":")
	//startIdx += len("\"NeutronError\":")
	jsonError := strings.Trim(neutronError[startIdx:], " ")
	unjsoned := map[string]map[string]string{}
	json.Unmarshal([]byte(jsonError), &unjsoned)
	if msg, ok := unjsoned["NeutronError"]["message"]; ok {
		return msg
	}
	return ""
}

// getSubnet returns the sub network identified by id
func (client *Client) getSubnet(id string) (*Subnet, error) {
	// Execute the operation and get back a subnets.Subnet struct
	subnet, err := subnets.Get(client.Network, id).Extract()
	if err != nil {
		log.Debugf("Error getting subnet: getting subnet: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting subnet: %s", ProviderErrorToString(err)))
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
func (client *Client) listSubnets(netID string) ([]Subnet, error) {
	pager := subnets.List(client.Network, subnets.ListOpts{
		NetworkID: netID,
	})
	var subnetList []Subnet
	paginationErr := pager.EachPage(func(page pagination.Page) (bool, error) {
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

	if (paginationErr != nil) || (len(subnetList) == 0) {
		if paginationErr != nil {
			log.Debugf("Error listing subnets: pagination error: %+v", paginationErr)
			return nil, errors.Wrap(paginationErr, fmt.Sprintf("We have a pagination error !: %v", paginationErr))
		}
		log.Debugf("Listing subnets: Empty subnet list !")
	}

	return subnetList, nil
}

// deleteSubnet deletes the sub network identified by id
func (client *Client) deleteSubnet(id string) error {
	routerList, _ := client.ListRouters()
	var router *Router
	for _, r := range routerList {
		if r.Name == id {
			router = &r
			break
		}
	}
	if router != nil {
		if err := client.removeSubnetFromRouter(router.ID, id); err != nil {
			msg := fmt.Sprintf("Error deleting subnet: %s", ProviderErrorToString(err))
			log.Errorf(msg)
			return fmt.Errorf(msg)
		}
		if err := client.deleteRouter(router.ID); err != nil {
			msg := fmt.Sprintf("Error deleting subnet: %s", ProviderErrorToString(err))
			log.Errorf(msg)
			return fmt.Errorf(msg)
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
		msg := fmt.Sprintf("Error deleting subnet: %s", ProviderErrorToString(err))
		log.Errorf(msg)
		return fmt.Errorf(msg)
	}

	return nil
}

// createRouter creates a router satisfying req
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
		log.Debugf("Error deleting subnet: deleting subnet: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating Router: %s", ProviderErrorToString(err)))
	}
	return &Router{
		ID:        router.ID,
		Name:      router.Name,
		NetworkID: router.GatewayInfo.NetworkID,
	}, nil

}

// getRouter returns the router identified by id
func (client *Client) getRouter(id string) (*Router, error) {

	r, err := routers.Get(client.Network, id).Extract()
	if err != nil {
		log.Debugf("Error getting router: get router: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting Router: %s", ProviderErrorToString(err)))
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
	if (err != nil) || (len(ns) == 0) {
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("Error listing volume types: %s", ProviderErrorToString(err)))
		}
		// log.Debugf("Router list empty !")
	}
	return ns, nil
}

// deleteRouter deletes the router identified by id
func (client *Client) deleteRouter(id string) error {
	err := routers.Delete(client.Network, id).ExtractErr()
	if err != nil {
		log.Debugf("Error deleting router: delete: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting Router: %s", ProviderErrorToString(err)))
	}
	return nil
}

// addSubnetToRouter attaches subnet to router
func (client *Client) addSubnetToRouter(routerID string, subnetID string) error {
	_, err := routers.AddInterface(client.Network, routerID, routers.AddInterfaceOpts{
		SubnetID: subnetID,
	}).Extract()
	if err != nil {
		log.Debugf("Error adding subnet to router: adding interface: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error addinter subnet: %s", ProviderErrorToString(err)))
	}
	return nil
}

// removeSubnetFromRouter detachesa subnet from router interface
func (client *Client) removeSubnetFromRouter(routerID string, subnetID string) error {
	_, err := routers.RemoveInterface(client.Network, routerID, routers.RemoveInterfaceOpts{
		SubnetID: subnetID,
	}).Extract()
	if err != nil {
		log.Debugf("Error removing subnet from router: removing interface: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error addinter subnet: %s", ProviderErrorToString(err)))
	}
	return nil
}
