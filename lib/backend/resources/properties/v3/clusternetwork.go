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

package propertiesv3

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

// ClusterNetwork contains network information relative to cluster
// not FROZEN yet
type ClusterNetwork struct {
	NetworkID          string           `json:"network_id,omitempty"`           // contains the ID of the network
	CreatedNetwork     bool             `json:"created_network,omitempty"`      // tells if the network had been created with the cluster
	SubnetID           string           `json:"subnet_id,omitempty"`            // contains the ID of the subnet
	CIDR               string           `json:"cidr,omitempty"`                 // the network CIDR
	GatewayID          string           `json:"gateway_id,omitempty"`           // contains the ID of the primary gateway
	GatewayIP          string           `json:"gateway_ip,omitempty"`           // contains the private IP address of the primary gateway
	SecondaryGatewayID string           `json:"secondary_gateway_id,omitempty"` // contains the ID of the secondary gateway
	SecondaryGatewayIP string           `json:"secondary_gateway_ip,omitempty"` // contains the private IP of the secondary gateway
	DefaultRouteIP     string           `json:"default_route_ip,omitempty"`     // contains the IP of the default route
	PrimaryPublicIP    string           `json:"primary_public_ip,omitempty"`    // contains the public IP of the primary gateway
	SecondaryPublicIP  string           `json:"secondary_public_ip,omitempty"`  // contains the public IP of the secondary gateway
	EndpointIP         string           `json:"endpoint_ip,omitempty"`          // contains the IP of the external Endpoint
	SubnetState        subnetstate.Enum `json:"status,omitempty"`               // contains the network state
	Domain             string           `json:"domain,omitempty"`               // contains the domain used to define the FQDN of hosts created (taken from network)X
}

func newClusterNetwork() *ClusterNetwork {
	return &ClusterNetwork{
		SubnetState: subnetstate.Unknown,
	}
}

// IsNull ...
// satisfies interface clonable.Clonable
func (n *ClusterNetwork) IsNull() bool {
	return n == nil || (n.NetworkID == "" && n.SubnetID == "" && n.CIDR == "" && n.GatewayID == "")
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
		return fail.Wrap(err)
	}

	*n = *casted
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.NetworkV3, newClusterNetwork())
}
