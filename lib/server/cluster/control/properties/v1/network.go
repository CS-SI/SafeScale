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

package propertiesv1

import (
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Property"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// Network ...
type Network struct {
	NetworkID string `json:"network_id"` // contains the ID of the network
	GatewayID string `json:"gateway_id"`
	GatewayIP string `json:"gateway_ip"` // contains the private IP address of the gateway
	PublicIP  string `json:"public_ip"`  // contains the IP address to reach the cluster (== PublicIP of gateway)
	CIDR      string `json:"cidr"`       // the network CIDR
}

func newNetwork() *Network {
	return &Network{}
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
	serialize.PropertyTypeRegistry.Register("clusters", Property.NetworkV1, &Network{})
}
