/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/serialize"
)

// NetworkSubnets contains additional information describing the subnets in a network, in V1
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type NetworkSubnets struct {
	ByID   map[string]string `json:"by_id,omitempty"`   // contains a list of subnet names indexed by id
	ByName map[string]string `json:"by_name,omitempty"` // contains a list of subnet ids index by name
}

// NewNetworkSubnets ...
func NewNetworkSubnets() *NetworkSubnets {
	return &NetworkSubnets{
		ByID:   map[string]string{},
		ByName: map[string]string{},
	}
}

// IsNull
// ... (data.Clonable interface)
func (nd *NetworkSubnets) IsNull() bool {
	return nd == nil || len(nd.ByID) == 0
}

// Clone ... (data.Clonable interface)
func (nd NetworkSubnets) Clone() data.Clonable {
	return NewNetworkSubnets().Replace(&nd)
}

// Replace ... (data.Clonable interface)
func (nd *NetworkSubnets) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value...
	if nd == nil || p == nil {
		return nd
	}

	src := p.(*NetworkSubnets)
	nd.ByID = make(map[string]string, len(src.ByID))
	for k, v := range src.ByID {
		nd.ByID[k] = v
	}
	nd.ByName = make(map[string]string, len(src.ByName))
	for k, v := range src.ByName {
		nd.ByName[k] = v
	}
	return nd
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.network", string(networkproperty.SubnetsV1), NewNetworkSubnets())
}
