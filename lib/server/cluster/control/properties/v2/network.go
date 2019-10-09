/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package propertiesv2

import (
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Property"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/NetworkState"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// Network ...
// NOT FROZEN YET
type Network struct {
	NetworkID          string            `json:"network_id"`           // contains the ID of the network
	CIDR               string            `json:"cidr"`                 // the network CIDR
	GatewayID          string            `json:"gateway_id"`           // contains the ID of the primary gateway
	GatewayIP          string            `json:"gateway_ip"`           // contains the private IP address of the primary gateway
	SecondaryGatewayID string            `json:"secondary_gateway_id"` // contains the ID of the secondary gateway
	SecondaryGatewayIP string            `json:"secondary_gateway_ip"` // contains the private IP of the secondary gateway
	DefaultRouteIP     string            `json:"default_route_ip"`     // contains the IP of the default route
	PrimaryPublicIP    string            `json:"primary_public_ip"`    // contains the public IP of the primary gateway
	SecondaryPublicIP  string            `json:"secondary_public_ip"`  // contains the public IP of the secondary gateway
	EndpointIP         string            `json:"endpoint_ip"`          // contains the IP of the external Endpoint
	NetworkState       NetworkState.Enum `json:"status"`
}

func newNetwork() *Network {
	return &Network{
		NetworkState: NetworkState.UNKNOWNSTATE,
	}
}

// Content ... (serialize.Property interface)
func (n *Network) Content() interface{} {
	return n
}

// Clone ... (serialize.Property interface)
func (n *Network) Clone() serialize.Property {
	return newNetwork().Replace(n)
}

// Replace ... (serialize.Property interface)
func (n *Network) Replace(p serialize.Property) serialize.Property {
	*n = *p.(*Network)
	return n
}

func init() {
	serialize.PropertyTypeRegistry.Register("clusters", Property.NetworkV2, &Network{})
}
