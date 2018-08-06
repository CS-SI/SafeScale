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

package opentelekom

import (
	"github.com/CS-SI/SafeScale/providers/api"
)

// CreateNetwork creates a network (ie a subnet in the network associated to VPC in FlexibleEngine
func (client *Client) CreateNetwork(req api.NetworkRequest) (*api.Network, error) {
	return client.feclt.CreateNetwork(req)
}

// GetNetwork returns the network identified by id
func (client *Client) GetNetwork(id string) (*api.Network, error) {
	return client.feclt.GetNetwork(id)
}

// ListNetworks lists available networks
func (client *Client) ListNetworks(all bool) ([]api.Network, error) {
	return client.feclt.ListNetworks(all)
}

// DeleteNetwork consists to delete subnet in FlexibleEngine VPC
func (client *Client) DeleteNetwork(id string) error {
	return client.feclt.DeleteNetwork(id)
}

// CreateGateway creates a gateway for a network.
// By current implementation, only one gateway can exist by Network because the object is intended
// to contain only one hostID
func (client *Client) CreateGateway(req api.GWRequest) error {
	return client.feclt.CreateGateway(req)
}

// GetGateway returns the name of the gateway of a network
func (client *Client) GetGateway(networkID string) (*api.Host, error) {
	return client.feclt.GetGateway(networkID)
}

// DeleteGateway deletes the gateway associated with network identified by ID
func (client *Client) DeleteGateway(networkID string) error {
	return client.feclt.DeleteGateway(networkID)
}
