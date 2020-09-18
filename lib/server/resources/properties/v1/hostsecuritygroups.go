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
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// HostSecurityGroups contains a list of security groups binded to the host
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostSecurityGroups struct {
	ByID   map[string]*SecurityGroupBond `json:"by_id,omitempty"`   // map of security groups by IDs; if value is true, security group is currently applied
	ByName map[string]*SecurityGroupBond `json:"by_name,omitempty"` // map of security groups by Names; if value is true, security group is currently applied
}

// NewHostSecurityGroups ...
func NewHostSecurityGroups() *HostSecurityGroups {
	return &HostSecurityGroups{
		ByID:   map[string]*SecurityGroupBond{},
		ByName: map[string]*SecurityGroupBond{},
	}
}

// Reset ...
func (hsg *HostSecurityGroups) Reset() {
	*hsg = HostSecurityGroups{
		ByID:   map[string]*SecurityGroupBond{},
		ByName: map[string]*SecurityGroupBond{},
	}
}

// Clone ...
func (hsg *HostSecurityGroups) Clone() data.Clonable {
	return NewHostSecurityGroups().Replace(hsg)
}

// Replace ...
func (hsg *HostSecurityGroups) Replace(p data.Clonable) data.Clonable {
	src := p.(*HostSecurityGroups)
	hsg.ByID = make(map[string]*SecurityGroupBond, len(src.ByID))
	for k, v := range src.ByID {
		hsg.ByID[k] = v.Clone().(*SecurityGroupBond)
	}
	hsg.ByName = make(map[string]*SecurityGroupBond, len(src.ByName))
	for k, v := range src.ByName {
		hsg.ByName[k] = v
	}
	return hsg
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.SecurityGroupsV1, NewHostSecurityGroups())
}
