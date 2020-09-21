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
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// NetworkSecurityGroups contains a list of security groups bound to the network, applied to each host created in it
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type NetworkSecurityGroups struct {
	ByID   map[string]*SecurityGroupBond `json:"by_id,omitempty"`   // map of security groups by IDs; if value is true, security group is currently applied
	ByName map[string]*SecurityGroupBond `json:"by_name,omitempty"` // map of security groups by Names; if value is true, security group is currently applied
}

// NewNetworkSecurityGroups ...
func NewNetworkSecurityGroups() *NetworkSecurityGroups {
	return &NetworkSecurityGroups{
		ByID:   map[string]*SecurityGroupBond{},
		ByName: map[string]*SecurityGroupBond{},
	}
}

// Reset ...
func (hsg *NetworkSecurityGroups) Reset() {
	*hsg = NetworkSecurityGroups{
		ByID:   map[string]*SecurityGroupBond{},
		ByName: map[string]*SecurityGroupBond{},
	}
}

// Clone ...
func (hsg *NetworkSecurityGroups) Clone() data.Clonable {
	return NewNetworkSecurityGroups().Replace(hsg)
}

// Replace ...
func (hsg *NetworkSecurityGroups) Replace(p data.Clonable) data.Clonable {
	src := p.(*NetworkSecurityGroups)
	hsg.ByID = make(map[string]*SecurityGroupBond, len(src.ByID))
	for k, v := range src.ByID {
		hsg.ByID[k] = v.Clone().(*SecurityGroupBond)
	}
	hsg.ByName = make(map[string]*SecurityGroupBond, len(src.ByName))
	for k, v := range src.ByName {
		hsg.ByName[k] = v.Clone().(*SecurityGroupBond)
	}
	return hsg
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.network", networkproperty.SecurityGroupsV1, NewNetworkSecurityGroups())
}
