/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"fmt"

	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

// ClusterNetwork contains network information relative to cluster
// !!! FROZEN !!!
// !!! DEPRECATED !!! superseded by propertiesv2.ClusterNetwork
type ClusterNetwork struct {
	NetworkID string `json:"network_id,omitempty"` // contains the ID of the network
	GatewayID string `json:"gateway_id,omitempty"` // DEPRECATED
	GatewayIP string `json:"gateway_ip,omitempty"` // DEPRECATED
	PublicIP  string `json:"public_ip,omitempty"`  // DEPRECATED
	CIDR      string `json:"cidr,omitempty"`       // the network CIDR
}

func newClusterNetwork() *ClusterNetwork {
	return &ClusterNetwork{}
}

// IsNull ...
// satisfies interface data.Clonable
func (n *ClusterNetwork) IsNull() bool {
	return n == nil || (n.NetworkID == "" && n.GatewayID == "")
}

// Clone ...
// satisfies interface data.Clonable
func (n ClusterNetwork) Clone() (data.Clonable, error) {
	return newClusterNetwork().Replace(&n)
}

// Replace ...
// satisfies interface data.Clonable
func (n *ClusterNetwork) Replace(p data.Clonable) (data.Clonable, error) {
	if n == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	casted, ok := p.(*ClusterNetwork)
	if !ok {
		return nil, fmt.Errorf("p is not a *ClusterNetwork")
	}

	*n = *casted
	return n, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.NetworkV1, &ClusterNetwork{})
}
