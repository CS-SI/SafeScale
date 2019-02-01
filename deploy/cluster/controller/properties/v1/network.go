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

package propertiesv1

import (
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Property"
	"github.com/CS-SI/SafeScale/utils/serialize"
)

// Network ...
type Network struct {
	NetworkID string `json:"network_id"` // contains the ID of the network
	GatewayID string `json:"gateway_id"`
	GatewayIP string `json:"gateway_ip"` // contains the private IP address of the gateway
	PublicIP  string `json:"public_ip"`  // contains the IP address to reach the cluster (== PublicIP of gateway)
	CIDR      string `json:"cidr"`       // the network CIDR
}

// Content ... (serialize.Property interface)
func (s *Network) Content() interface{} {
	return s
}

// Clone ... (serialize.Property interface)
func (s *Network) Clone() serialize.Property {
	ns := &Network{}
	*ns = *s
	return ns
}

// Replace ... (serialize.Property interface)
func (s *Network) Replace(v interface{}) {
	*s = *(v.(*Network))
}

func init() {
	serialize.PropertyTypeRegistry.Register("clusters", Property.NetworkV1, &Network{})
}
