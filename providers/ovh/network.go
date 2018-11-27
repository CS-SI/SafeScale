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
	"github.com/CS-SI/SafeScale/providers/model"
)

// CreateNetwork creates a network named name
func (client *Client) CreateNetwork(req model.NetworkRequest) (*model.Network, error) {
	// Special treatment for OVH : no dnsServers means __NO__ DNS servers, not default ones
	// The way to do so, accordingly to OVH support, is to set DNS servers to 0.0.0.0
	if len(req.DNSServers) == 0 {
		req.DNSServers = []string{"0.0.0.0"}
	}
	return client.osclt.CreateNetwork(req)
}

// GetNetworkByName returns the network identified name
func (client *Client) GetNetworkByName(name string) (*model.Network, error) {
	return client.osclt.GetNetworkByName(name)
}

// GetNetwork returns the network identified by ref (id or name)
func (client *Client) GetNetwork(ref string) (*model.Network, error) {
	return client.osclt.GetNetwork(ref)
}

// ListNetworks lists networks
func (client *Client) ListNetworks() ([]*model.Network, error) {
	return client.osclt.ListNetworks()
}

// DeleteNetwork deletes the network identified by id
func (client *Client) DeleteNetwork(networkRef string) error {
	return client.osclt.DeleteNetwork(networkRef)
}

// CreateGateway creates a public Gateway for a private network
func (client *Client) CreateGateway(req model.GatewayRequest) (*model.Host, error) {
	return client.osclt.CreateGateway(req)
}

// DeleteGateway delete the public gateway of a private network
func (client *Client) DeleteGateway(networkID string) error {
	return client.osclt.DeleteGateway(networkID)
}
