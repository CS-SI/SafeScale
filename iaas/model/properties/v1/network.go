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
	"time"

	"github.com/CS-SI/SafeScale/providers/model/enums/NetworkProperty"
	"github.com/CS-SI/SafeScale/utils/serialize"
)

// NetworkDescription contains additional information describing the network, in V1
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type NetworkDescription struct {
	Purpose string    `json:"purpose,omitempty"` // contains the purpose of this network
	Created time.Time `json:"created,omitempty"` // Contains the date of creation if the network
}

// NewNetworkDescription ...
func NewNetworkDescription() *NetworkDescription {
	return &NetworkDescription{}
}

// Content ... (serialize.Property interface)
func (nd *NetworkDescription) Content() interface{} {
	return nd
}

// Clone ... (serialize.Property interface)
func (nd *NetworkDescription) Clone() serialize.Property {
	return NewNetworkDescription().Replace(nd)
}

// Replace ... (serialize.Property interface)
func (nd *NetworkDescription) Replace(p serialize.Property) serialize.Property {
	*nd = *p.(*NetworkDescription)
	return nd
}

// NetworkHosts contains information about hosts connected to the network
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

// Content ... (serialize.Property interface)
func (nh *NetworkHosts) Content() interface{} {
	return nh
}

// Clone ... (serialize.Property interface)
func (nh *NetworkHosts) Clone() serialize.Property {
	return NewNetworkHosts().Replace(nh)
}

// Replace ... (serialize.Property interface)
func (nh *NetworkHosts) Replace(p serialize.Property) serialize.Property {
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
	serialize.PropertyTypeRegistry.Register("resources.network", NetworkProperty.HostsV1, NewNetworkHosts())
	serialize.PropertyTypeRegistry.Register("resources.network", NetworkProperty.DescriptionV1, NewNetworkDescription())
}
