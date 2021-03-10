/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// SubnetSecurityGroups contains a list of security groups bound to the network, applied to each host created in it
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type SubnetSecurityGroups struct {
	DefaultID string                        `json:"default_id,omitempty"` // Contains the ID of the default security group
	ByID      map[string]*SecurityGroupBond `json:"by_id,omitempty"`      // map of security groups by IDs; if value is true, security group is currently applied
	ByName    map[string]string             `json:"by_name,omitempty"`    // map of security group IDs by Names
}

// NewSubnetSecurityGroups ...
func NewSubnetSecurityGroups() *SubnetSecurityGroups {
	return &SubnetSecurityGroups{
		ByID:   map[string]*SecurityGroupBond{},
		ByName: map[string]string{},
	}
}

// Reset ...
func (ssg *SubnetSecurityGroups) Reset() {
	*ssg = SubnetSecurityGroups{
		ByID:   map[string]*SecurityGroupBond{},
		ByName: map[string]string{},
	}
}

// Clone ...
func (ssg SubnetSecurityGroups) Clone() data.Clonable {
	return NewSubnetSecurityGroups().Replace(&ssg)
}

// Replace ...
func (ssg *SubnetSecurityGroups) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value...
	if ssg == nil || p == nil {
		return ssg
	}

	src := p.(*SubnetSecurityGroups)
	*ssg = *src
	ssg.ByID = make(map[string]*SecurityGroupBond, len(src.ByID))
	for k, v := range src.ByID {
		ssg.ByID[k] = v.Clone().(*SecurityGroupBond)
	}
	ssg.ByName = make(map[string]string, len(src.ByName))
	for k, v := range src.ByName {
		ssg.ByName[k] = v
	}
	return ssg
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.subnet", subnetproperty.SecurityGroupsV1, NewSubnetSecurityGroups())
}
