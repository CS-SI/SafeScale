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

package propertiesv2

import (
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// HostNetworking contains network information related to Host
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
type HostNetworking struct {
	DefaultSubnetID string            `json:"default_subnet_id,omitempty"` // contains the ID of the default subnet
	PublicIPv4      string            `json:"public_ip_v4,omitempty"`
	PublicIPv6      string            `json:"public_ip_v6,omitempty"`
	SubnetsByID     map[string]string `json:"subnet_by_id,omitempty"`   // contains the name of each subnet bound to the host (indexed by ID)
	SubnetsByName   map[string]string `json:"subnet_by_name,omitempty"` // contains the ID of each subnet bound to the host (indexed by Name)
	IPv4Addresses   map[string]string `json:"ipv4_addresses,omitempty"` // contains ipv4 (indexed by network ID) allocated to the host
	IPv6Addresses   map[string]string `json:"ipv6_addresses,omitempty"` // contains ipv6 (indexed by Networking ID) allocated to the host
	IsGateway       bool              `json:"is_gateway,omitempty"`     // Tells if host is a gateway of a Subnet
	Single          bool              `json:"single,omitempty"`         // Tells if the Host is single
}

// NewHostNetworking ...
func NewHostNetworking() *HostNetworking {
	return &HostNetworking{
		SubnetsByID:   map[string]string{},
		SubnetsByName: map[string]string{},
		IPv4Addresses: map[string]string{},
		IPv6Addresses: map[string]string{},
	}
}

func NewHostNetworkingFromProperty(propos *serialize.JSONProperties) (*HostNetworking, fail.Error) {
	var netInfo *HostNetworking
	xerr := propos.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
		clod, ok := clonable.(*HostNetworking)
		if !ok {
			return fail.InconsistentError("Bad cast")
		}

		*netInfo = *clod
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	return netInfo, nil
}

// IsNull tells if the HostNetworking corresponds to a null value
func (hn *HostNetworking) IsNull() bool {
	return hn == nil || hn.DefaultSubnetID == "" || (len(hn.IPv4Addresses) == 0 && len(hn.IPv6Addresses) == 0)
}

// Reset resets the content of the property
func (hn *HostNetworking) Reset() {
	*hn = HostNetworking{
		SubnetsByID:   map[string]string{},
		SubnetsByName: map[string]string{},
		IPv4Addresses: map[string]string{},
		IPv6Addresses: map[string]string{},
	}
}

// Clone ...
// satisfies interface data.Clonable
func (hn HostNetworking) Clone() (data.Clonable, error) {
	return NewHostNetworking().Replace(&hn)
}

// Replace ...
// satisfies interface data.Clonable
func (hn *HostNetworking) Replace(p data.Clonable) (data.Clonable, error) {
	if hn == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*HostNetworking)
	if !ok {
		return nil, fmt.Errorf("p is not a *HostNetworking")
	}

	*hn = *src
	hn.SubnetsByID = make(map[string]string, len(src.SubnetsByID))
	for k, v := range src.SubnetsByID {
		hn.SubnetsByID[k] = v
	}
	hn.SubnetsByName = make(map[string]string, len(src.SubnetsByName))
	for k, v := range src.SubnetsByName {
		hn.SubnetsByName[k] = v
	}
	hn.IPv4Addresses = make(map[string]string, len(src.IPv4Addresses))
	for k, v := range src.IPv4Addresses {
		hn.IPv4Addresses[k] = v
	}
	hn.IPv6Addresses = make(map[string]string, len(src.IPv6Addresses))
	for k, v := range src.IPv6Addresses {
		hn.IPv6Addresses[k] = v
	}
	return hn, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.NetworkV2, NewHostNetworking())
}
