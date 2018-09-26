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

package ovh

import (
	"fmt"

	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/enums/IPVersion"
	"github.com/CS-SI/SafeScale/providers/openstack"

	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
)

// CreateNetwork creates a network named name
func (client *Client) CreateNetwork(req api.NetworkRequest) (*api.Network, error) {
	return client.osclt.CreateNetwork(req)
}

// GetNetwork returns the network identified by ref (id or name)
func (client *Client) GetNetwork(ref string) (*api.Network, error) {
	return client.osclt.GetNetwork(ref)
}

// ListNetworks lists available networks
func (client *Client) ListNetworks(all bool) ([]api.Network, error) {
	return client.osclt.ListNetworks(all)
}

// DeleteNetwork deletes the network identified by id
func (client *Client) DeleteNetwork(networkRef string) error {
	return client.osclt.DeleteNetwork(networkRef)
}

// CreateGateway creates a public Gateway for a private network
func (client *Client) CreateGateway(req api.GWRequest) (*api.Host, error) {
	return client.osclt.CreateGateway(req)
}

// DeleteGateway delete the public gateway of a private network
func (client *Client) DeleteGateway(networkID string) error {
	return client.osclt.DeleteGateway(networkID)
}

// CreateSubnet creates a sub network
//- netID ID of the parent network
//- name is the name of the sub network
//- mask is a network mask defined in CIDR notation
func (client *Client) CreateSubnet(name string, networkID string, cidr string, ipVersion IPVersion.Enum) (*openstack.Subnet, error) {
	// You must associate a new subnet with an existing network - to do this you
	// need its UUID. You must also provide a well-formed CIDR value.
	//addr, _, err := net.ParseCIDR(mask)
	dhcp := true
	opts := subnets.CreateOpts{
		NetworkID:      networkID,
		CIDR:           cidr,
		IPVersion:      openstack.ToGopherIPversion(ipVersion),
		Name:           name,
		EnableDHCP:     &dhcp,
		DNSNameservers: []string{"0.0.0.0"},
	}

	if !client.osclt.Cfg.UseLayer3Networking {
		noGateway := ""
		opts.GatewayIP = &noGateway
	}

	// Execute the operation and get back a subnets.Subnet struct
	subnet, err := subnets.Create(client.osclt.Network, opts).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating subnet: %s", openstack.ProviderErrorToString(err))
	}

	if client.osclt.Cfg.UseLayer3Networking {
		router, err := client.CreateRouter(openstack.RouterRequest{
			Name:      subnet.ID,
			NetworkID: client.osclt.ProviderNetworkID,
		})
		if err != nil {
			client.DeleteSubnet(subnet.ID)
			return nil, fmt.Errorf("Error creating subnet: %s", openstack.ProviderErrorToString(err))
		}
		err = client.AddSubnetToRouter(router.ID, subnet.ID)
		if err != nil {
			client.DeleteSubnet(subnet.ID)
			client.DeleteRouter(router.ID)
			return nil, fmt.Errorf("Error creating subnet: %s", openstack.ProviderErrorToString(err))
		}
	}

	return &openstack.Subnet{
		ID:        subnet.ID,
		Name:      subnet.Name,
		IPVersion: openstack.FromIntIPversion(subnet.IPVersion),
		Mask:      subnet.CIDR,
		NetworkID: subnet.NetworkID,
	}, nil
}

// GetSubnet returns the sub network identified by id
func (client *Client) GetSubnet(id string) (*openstack.Subnet, error) {
	return client.osclt.GetSubnet(id)
}

// ListSubnets lists available sub networks of network net
func (client *Client) ListSubnets(netID string) ([]openstack.Subnet, error) {
	return client.osclt.ListSubnets(netID)
}

// DeleteSubnet deletes the sub network identified by id
func (client *Client) DeleteSubnet(id string) error {
	return client.osclt.DeleteSubnet(id)
}

// CreateRouter creates a router satisfying req
func (client *Client) CreateRouter(req openstack.RouterRequest) (*openstack.Router, error) {
	return client.osclt.CreateRouter(req)
}

// GetRouter returns the router identified by id
func (client *Client) GetRouter(id string) (*openstack.Router, error) {
	return client.osclt.GetRouter(id)
}

// ListRouters lists available routers
func (client *Client) ListRouters() ([]openstack.Router, error) {
	return client.osclt.ListRouters()
}

// DeleteRouter deletes the router identified by id
func (client *Client) DeleteRouter(id string) error {
	return client.osclt.DeleteRouter(id)
}

// AddSubnetToRouter attaches subnet to router
func (client *Client) AddSubnetToRouter(routerID string, subnetID string) error {
	return client.osclt.AddSubnetToRouter(routerID, subnetID)
}

// RemoveSubnetFromRouter detachesa subnet from router interface
func (client *Client) RemoveSubnetFromRouter(routerID string, subnetID string) error {
	return client.osclt.RemoveSubnetFromRouter(routerID, subnetID)
}
