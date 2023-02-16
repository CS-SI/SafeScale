/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

// ClusterNetwork contains network information relative to cluster
// !!! FROZEN !!!
// !!! DEPRECATED !!! superseded by propertiesv2.ClusterNetwork
type ClusterNetwork struct {
	NetworkID string `json:"network_id,omitempty"` // contains the ID of the network
	GatewayID string `json:"gateway_id,omitempty"` // DEPRECATED: deprecated
	GatewayIP string `json:"gateway_ip,omitempty"` // DEPRECATED: deprecated
	PublicIP  string `json:"public_ip,omitempty"`  // DEPRECATED: deprecated
	CIDR      string `json:"cidr,omitempty"`       // the network CIDR
}

func newClusterNetwork() *ClusterNetwork {
	return &ClusterNetwork{}
}

// IsNull ...
// satisfies interface clonable.Clonable
func (n *ClusterNetwork) IsNull() bool {
	return n == nil || (n.NetworkID == "" && n.GatewayID == "")
}

// Clone ...
// satisfies interface clonable.Clonable
func (n *ClusterNetwork) Clone() (clonable.Clonable, error) {
	if n == nil {
		return nil, fail.InvalidInstanceError()
	}

	ncn := newClusterNetwork()
	return ncn, ncn.Replace(n)
}

// Replace ...
// satisfies interface clonable.Clonable
func (n *ClusterNetwork) Replace(p clonable.Clonable) error {
	if n == nil {
		return fail.InvalidInstanceError()
	}

	casted, err := lang.Cast[*ClusterNetwork](p)
	if err != nil {
		return err
	}

	*n = *casted
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.NetworkV1, newClusterNetwork())
}
