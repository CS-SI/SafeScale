/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/property"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// Network ...
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with updated/additional fields
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

// Content ...
// satisfies interface data.Clonable
func (n *Network) Content() data.Clonable {
	return n
}

// Clone ...
// satisfies interface data.Clonable
func (n *Network) Clone() data.Clonable {
	return newNetwork().Replace(n)
}

// Replace ...
// satisfies interface data.Clonable
func (n *Network) Replace(p data.Clonable) data.Clonable {
	*n = *p.(*Network)
	return n
}

func init() {
	serialize.PropertyTypeRegistry.Register("clusters", property.NetworkV1, &Network{})
}
