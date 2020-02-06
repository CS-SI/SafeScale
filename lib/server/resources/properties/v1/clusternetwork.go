/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// Network ...
// !!! FROZEN !!!
type ClusterNetwork struct {
	NetworkID string `json:"network_id"` // contains the ID of the network
	GatewayID string `json:"gateway_id"` // DEPRECATED
	GatewayIP string `json:"gateway_ip"` // DEPRECATED
	PublicIP  string `json:"public_ip"`  // DEPRECATED
	CIDR      string `json:"cidr"`       // the network CIDR
}

func newNetwork() *ClusterNetwork {
	return &ClusterNetwork{}
}

// Content ... (data.Clonable interface)
func (n *ClusterNetwork) Content() interface{} {
	return n
}

// Clone ... (data.Clonable interface)
func (n *ClusterNetwork) Clone() data.Clonable {
	return newNetwork().Replace(n)
}

// Replace ... (data.Clonable interface)
func (n *ClusterNetwork) Replace(p data.Clonable) data.Clonable {
	*n = *p.(*ClusterNetwork)
	return n
}

func init() {
	serialize.PropertyTypeRegistry.Register("clusters", clusterproperty.NetworkV1, &ClusterNetwork{})
}
