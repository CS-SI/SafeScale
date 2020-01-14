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
	"time"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// NetworkDescription contains additional information describing the network, in V1
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type NetworkDescription struct {
	Purpose string    `json:"purpose,omitempty"` // contains the purpose of this network
	Created time.Time `json:"created,omitempty"` // Contains the date of creation if the network
}

// NewNetworkDescription ...
func NewNetworkDescription() *NetworkDescription {
	return &NetworkDescription{}
}

// Content ...
// satisfies interface data.Clonable
func (nd *NetworkDescription) Content() data.Clonable {
	return nd
}

// Clone ...
// satisfies interface data.Clonable
func (nd *NetworkDescription) Clone() data.Clonable {
	return NewNetworkDescription().Replace(nd)
}

// Replace ...
// satisfies interface data.Clonable
func (nd *NetworkDescription) Replace(p data.Clonable) data.Clonable {
	*nd = *p.(*NetworkDescription)
	return nd
}

// NetworkHosts contains information about hosts connected to the network
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type NetworkHosts struct {
	ByID   map[string]string `json:"by_id"`   // list of host names, indexed by host id
	ByName map[string]string `json:"by_name"` // list of host IDs, indexed by host name
}

// NewNetworkHosts ...
func NewNetworkHosts() *NetworkHosts {
	return &NetworkHosts{
		ByID:   map[string]string{},
		ByName: map[string]string{},
	}
}

// Reset resets the content of the property
func (nh *NetworkHosts) Reset() {
	*nh = NetworkHosts{
		ByID:   map[string]string{},
		ByName: map[string]string{},
	}
}

// Content ...
// satisfies interface data.Clonable
func (nh *NetworkHosts) Content() data.Clonable {
	return nh
}

// Clone ...
// satisfies interface data.Clonable
func (nh *NetworkHosts) Clone() data.Clonable {
	return NewNetworkHosts().Replace(nh)
}

// Replace ...
// satisfies interface data.Clonable
func (nh *NetworkHosts) Replace(p data.Clonable) data.Clonable {
	src := p.(*NetworkHosts)
	nh.ByID = make(map[string]string, len(src.ByID))
	for k, v := range src.ByID {
		nh.ByID[k] = v
	}
	nh.ByName = make(map[string]string, len(src.ByName))
	for k, v := range src.ByName {
		nh.ByName[k] = v
	}
	return nh
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.network", networkproperty.HostsV1, NewNetworkHosts())
	serialize.PropertyTypeRegistry.Register("resources.network", networkproperty.DescriptionV1, NewNetworkDescription())
}
