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

package propertiesv2

import (
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/networkstate"
    "github.com/CS-SI/SafeScale/lib/utils/data"
    "github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// ClusterNetwork contains network information relative to cluster
// !!! FROZEN !!!
type ClusterNetwork struct {
    NetworkID          string            `json:"network_id"`           // contains the GetID of the network
    CIDR               string            `json:"cidr"`                 // the network CIDR
    GatewayID          string            `json:"gateway_id"`           // contains the GetID of the primary gateway
    GatewayIP          string            `json:"gateway_ip"`           // contains the private IP address of the primary gateway
    SecondaryGatewayID string            `json:"secondary_gateway_id"` // contains the GetID of the secondary gateway
    SecondaryGatewayIP string            `json:"secondary_gateway_ip"` // contains the private IP of the secondary gateway
    DefaultRouteIP     string            `json:"default_route_ip"`     // contains the IP of the default route
    PrimaryPublicIP    string            `json:"primary_public_ip"`    // contains the public IP of the primary gateway
    SecondaryPublicIP  string            `json:"secondary_public_ip"`  // contains the public IP of the secondary gateway
    EndpointIP         string            `json:"endpoint_ip"`          // contains the IP of the external Endpoint
    NetworkState       networkstate.Enum `json:"status"`               // contains the network state
    Domain             string            `json:"domain,omitempty"`     // Contains the domain used to define the FQDN of hosts created (taken from network)
}

func newClusterNetwork() *ClusterNetwork {
    return &ClusterNetwork{
        NetworkState: networkstate.UNKNOWNSTATE,
    }
}

// Clone ...
// satisfies interface data.Clonable
func (n *ClusterNetwork) Clone() data.Clonable {
    return newClusterNetwork().Replace(n)
}

// Replace ...
// satisfies interface data.Clonable
func (n *ClusterNetwork) Replace(p data.Clonable) data.Clonable {
    *n = *p.(*ClusterNetwork)
    return n
}

func init() {
    serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.NetworkV2, newClusterNetwork())
}
