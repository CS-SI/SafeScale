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
	"net"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	gc "github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	"github.com/CS-SI/SafeScale/providers/model/enums/IPVersion"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/retry"
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
	log.Debugf("providers.openstack.Client.CreateNetwork(%s) called", req.Name)
	defer log.Debugf("providers.openstack.Client.CreateNetwork(%s) called", req.Name)

	// // We 1st check if name is not already used
	// _net, err := metadata.LoadNetwork(client, req.Name)
	// if err != nil {
	// 	msg := fmt.Sprintf("Error creating network '%s': failed to access metadata: %v", req.Name, err)
	// 	// log.Errorf(msg)
	// 	return nil, fmt.Errorf(msg)
	// }
	// if _net != nil {
	// 	return nil, fmt.Errorf("Error creating network '%s': a network already exists with that name", req.Name)
	// }

	// Checks if CIDR is valid...
	_, _, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to create subnet '%s (%s)': %s", req.Name, req.CIDR, err.Error())
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
	return net, nil
}

// GetNetworkByName ...
func (client *Client) GetNetworkByName(name string) (*model.Network, error) {
	if name == "" {
		panic("name is empty!")
	}

	// Gophercloud doesn't propose the way to get a host by name, but OpenStack knows how to do it...
	r := networks.GetResult{}
	_, r.Err = client.Compute.Get(client.Network.ServiceURL("networks?name="+name), &r.Body, &gc.RequestOpts{
		OkCodes: []int{200, 203},
	})
	if r.Err != nil {
		return nil, fmt.Errorf("query for network '%s' failed: %v", name, r.Err)
	}
	nets, found := r.Body.(map[string]interface{})["networks"].([]interface{})
	if found && len(nets) > 0 {
		entry := nets[0].(map[string]interface{})
		id := entry["id"].(string)
		return client.GetNetwork(id)
	}
	return nil, model.ResourceNotFoundError("network", name)
}

// GetNetwork returns the network identified by id
func (client *Client) GetNetwork(id string) (*model.Network, error) {
	// If not found, we look for any network from provider
	// 1st try with id
	network, err := networks.Get(client.Network, id).Extract()
	if err != nil {
		if _, ok := err.(gc.ErrDefault404); !ok {
			// log.Errorf("Error getting network: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error getting network '%s': %s", id, ProviderErrorToString(err)))
		}
	}
	if network != nil && network.ID != "" {
		sns, err := client.listSubnets(id)
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

	// // Last chance, we look at all network
	// nets, err := client.ListNetworks()
	// if err != nil {
	// 	// log.Debugf("Error getting network: listing all networks: %+v", err)
	// 	return nil, errors.Wrap(err, fmt.Sprintf("Error getting network: listing all networks"))
	// }
	// for _, n := range nets {
	// 	if n.ID == ref || n.Name == ref {
	// 		return n, err
	// 	}
	// }

	// At this point, no network has been found with given reference
	log.Debugf(model.ResourceNotFoundError("network(GetNetwork)", id).Error())
	return nil, errors.Wrap(model.ResourceNotFoundError("network(GetNetwork)", id), "")
}

// ListNetworks lists available networks
func (client *Client) ListNetworks() ([]*model.Network, error) {
	// Retrieve a pager (i.e. a paginated collection)
	var netList []*model.Network
	pager := networks.List(client.Network, networks.ListOpts{})
	err := pager.EachPage(
		func(page pagination.Page) (bool, error) {
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

				net := model.NewNetwork()
				net.ID = n.ID
				net.Name = n.Name
				net.CIDR = sn.Mask
				net.IPVersion = sn.IPVersion
				// GatewayID: gwID,
				netList = append(netList, net)
			}
			return true, nil
		},
	)
	if len(netList) == 0 || err != nil {
		if err != nil {
			log.Debugf("Error listing networks: pagination error: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error listing networks: %s", ProviderErrorToString(err)))
		}
		log.Debugf("Listing all networks: Empty network list !")
	}
	return netList, nil
}

// DeleteNetwork deletes the network identified by id
func (client *Client) DeleteNetwork(id string) error {
	log.Debugf("providers.openstack.Client.DeleteNetwork(%s) called", id)
	defer log.Debugf("providers.openstack.Client.DeleteNetwork(%s) done", id)

	network, err := networks.Get(client.Network, id).Extract()
	if err != nil {
		log.Errorf("Failed to delete network: %+v", err)
		if strings.Contains(err.Error(), "Resource not found") {
			log.Errorf("Inconsistent network data !!")
		}
	}

	sns, err := client.listSubnets(id)
	if err != nil {
		msg := fmt.Sprintf("failed to delete network '%s': %s", network.Name, ProviderErrorToString(err))
		log.Debugf(utils.TitleFirst(msg))
		return fmt.Errorf(msg)
	}
	for _, sn := range sns {
		err := client.deleteSubnet(sn.ID)
		if err != nil {
			switch err.(type) {
			case model.ErrResourceNotAvailable:
				return err
			default:
				msg := fmt.Sprintf("failed to delete network '%s': %s", network.Name, ProviderErrorToString(err))
				log.Debugf(utils.TitleFirst(msg))
				return fmt.Errorf(msg)
			}
		}
	}
	err = networks.Delete(client.Network, id).ExtractErr()
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotAvailable:
			return err
		default:
			msg := fmt.Sprintf("failed to delete network '%s': %s", network.Name, ProviderErrorToString(err))
			log.Debugf(utils.TitleFirst(msg))
			return fmt.Errorf(msg)
		}
	}

	return nil
}

// CreateGateway creates a public Gateway for a private network
func (client *Client) CreateGateway(req model.GatewayRequest) (*model.Host, error) {
	// Ensure network exists
	if req.Network == nil {
		panic("req.Network is nil!")
	}
	gwname := req.Name
	if gwname == "" {
		gwname = "gw-" + req.Network.Name
	}
	hostReq := model.HostRequest{
		ImageID:      req.ImageID,
		KeyPair:      req.KeyPair,
		ResourceName: gwname,
		TemplateID:   req.TemplateID,
		Networks:     []*model.Network{req.Network},
		PublicIP:     true,
	}
	host, err := client.CreateHost(hostReq)
	if err != nil {
		log.Errorf("Error creating gateway: creating host: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating gateway : %s", ProviderErrorToString(err)))
	}

	// delete the host when found problem starting from here
	defer func() {
		if err != nil {
			derr := client.DeleteHost(host.ID)
			if derr != nil {
				log.Errorf("failed to delete host '%s': %v", host.Name, derr)
			}
		}
	}()

	// Updates Host Property propsv1.HostSizing
	hostSizingV1 := propsv1.NewHostSizing()
	err = host.Properties.Get(HostProperty.SizingV1, hostSizingV1)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating gateway : %s", ProviderErrorToString(err)))
	}
	hostSizingV1.Template = req.TemplateID
	err = host.Properties.Set(HostProperty.SizingV1, hostSizingV1)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating gateway : %s", ProviderErrorToString(err)))
	}
	return host, nil
}

// DeleteGateway delete the public gateway of a private network
func (client *Client) DeleteGateway(id string) error {
	return client.DeleteHost(id)
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
			neutronError := ParseNeutronError(r.Err.Error())
			if neutronError != nil {
				msg := fmt.Sprintf("Error creating subnet: bad request: %s\n", neutronError["message"])
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
			return nil, errors.Wrap(paginationErr, fmt.Sprintf("we have a pagination error !: %v", paginationErr))
		}
	}

	return subnetList, nil
}

// deleteSubnet deletes the sub network identified by id
func (client *Client) deleteSubnet(id string) error {
	log.Debugf("providers.openstack.deleteSubnet(%s) called", id)
	defer log.Debugf("providers.openstack.deleteSubnet(%s) done", id)

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
			msg := fmt.Sprintf("failed to delete subnet '%s': %s", id, ProviderErrorToString(err))
			log.Debug(utils.TitleFirst(msg))
			return fmt.Errorf(msg)
		}
		if err := client.deleteRouter(router.ID); err != nil {
			msg := fmt.Sprintf("failed to delete subnet '%s': %s", id, ProviderErrorToString(err))
			log.Debug(utils.TitleFirst(msg))
			return fmt.Errorf(msg)
		}
	}

	var err error
	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			r := subnets.Delete(client.Network, id)
			err = r.ExtractErr()
			if err != nil {
				switch err.(type) {
				case gc.ErrUnexpectedResponseCode:
					neutronError := ParseNeutronError(err.Error())
					switch neutronError["type"] {
					case "SubnetInUse":
						msg := fmt.Sprintf("hosts or services are still attached")
						log.Warnf(utils.TitleFirst(msg))
						return model.ResourceNotAvailableError("subnet", id)
					default:
						log.Debugf("NeutronError: type = %s", neutronError["type"])
					}
				default:
					msg := fmt.Sprintf("failed to delete subnet '%s': %s", id, ProviderErrorToString(err))
					log.Errorf(utils.TitleFirst(msg))
					return fmt.Errorf(msg)
				}
			}
			return nil
		},
		1*time.Minute,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			// If we have the last error of the delete try, returns this error
			if err != nil {
				return fmt.Errorf("failed to delete subnet after %v: %v", 1*time.Minute, err)
			}
		default:
			return fmt.Errorf("failed to delete subnet after %v", 1*time.Minute)
		}
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
		log.Debugf("failed to create router '%s': %+v", req.Name, err)
		return nil, errors.Wrap(err, fmt.Sprintf("failed to create router '%s': %s", req.Name, ProviderErrorToString(err)))
	}
	log.Debugf("Router '%s' (%s) successfully created", router.Name, router.ID)
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
		log.Debugf("Error getting router '%s': %+v", id, err)
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
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error listing volume types: %s", ProviderErrorToString(err)))
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
	r := routers.RemoveInterface(client.Network, routerID, routers.RemoveInterfaceOpts{
		SubnetID: subnetID,
	})
	_, err := r.Extract()
	if err != nil {
		spew.Dump(r)
		msg := fmt.Sprintf("failed to remove subnet '%s' from router '%s': %s", subnetID, routerID, ProviderErrorToString(err))
		log.Debug(msg)
		return errors.Wrap(err, msg)
	}
	return nil
}
