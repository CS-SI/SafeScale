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
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

// HostNetwork contains network information related to Host
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
type HostNetwork struct {
	IsGateway               bool              `json:"is_gateway,omitempty"`                 // Tells if host is a gateway of a network
	DefaultGatewayID        string            `json:"default_gateway_id,omitempty"`         // DEPRECATED: contains the ID of the Default getGateway
	DefaultGatewayPrivateIP string            `json:"default_gateway_private_ip,omitempty"` // DEPRECATED: contains the private IP of the default gateway
	DefaultNetworkID        string            `json:"default_network_id,omitempty"`         // contains the ID of the default Networking
	NetworksByID            map[string]string `json:"networks_by_id,omitempty"`             // contains the name of each network bound to the host (indexed by ID)
	NetworksByName          map[string]string `json:"networks_by_name,omitempty"`           // contains the ID of each network bound to the host (indexed by GetName)
	PublicIPv4              string            `json:"public_ip_v4,omitempty"`               // contains the public IPv4 address of the host
	PublicIPv6              string            `json:"public_ip_v6,omitempty"`               // contains the public IPv6 address of the host
	IPv4Addresses           map[string]string `json:"ipv4_addresses,omitempty"`             // contains ipv4 (indexed by Networking ID) allocated to the host
	IPv6Addresses           map[string]string `json:"ipv6_addresses,omitempty"`             // contains ipv6 (indexed by Networking ID) allocated to the host
}

// NewHostNetwork ...
func NewHostNetwork() *HostNetwork {
	return &HostNetwork{
		NetworksByID:   map[string]string{},
		NetworksByName: map[string]string{},
		IPv4Addresses:  map[string]string{},
		IPv6Addresses:  map[string]string{},
	}
}

// IsNull tells if the HostNetwork corresponds to a null value
func (hn *HostNetwork) IsNull() bool {
	return hn == nil || hn.DefaultNetworkID == "" || (len(hn.IPv4Addresses) == 0 && len(hn.IPv6Addresses) == 0)
}

// Reset resets the content of the property
func (hn *HostNetwork) Reset() {
	*hn = HostNetwork{
		NetworksByID:   map[string]string{},
		NetworksByName: map[string]string{},
		IPv4Addresses:  map[string]string{},
		IPv6Addresses:  map[string]string{},
	}
}

// Clone ...
// satisfies interface clonable.Clonable
func (hn *HostNetwork) Clone() (clonable.Clonable, error) {
	if hn == nil {
		return nil, fail.InvalidInstanceError()
	}

	nhn := NewHostNetwork()
	return nhn, nhn.Replace(hn)
}

// Replace ...
// satisfies interface clonable.Clonable
func (hn *HostNetwork) Replace(p clonable.Clonable) error {
	if hn == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*HostNetwork](p)
	if err != nil {
		return err
	}

	*hn = *src
	hn.NetworksByID = make(map[string]string, len(src.NetworksByID))
	for k, v := range src.NetworksByID {
		hn.NetworksByID[k] = v
	}
	hn.NetworksByName = make(map[string]string, len(src.NetworksByName))
	for k, v := range src.NetworksByName {
		hn.NetworksByName[k] = v
	}
	hn.IPv4Addresses = make(map[string]string, len(src.IPv4Addresses))
	for k, v := range src.IPv4Addresses {
		hn.IPv4Addresses[k] = v
	}
	hn.IPv6Addresses = make(map[string]string, len(src.IPv6Addresses))
	for k, v := range src.IPv6Addresses {
		hn.IPv6Addresses[k] = v
	}
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.NetworkV1, NewHostNetwork())
}
