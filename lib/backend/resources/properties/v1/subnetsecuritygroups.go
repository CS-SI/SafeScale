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
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// SubnetSecurityGroups contains a list of security groups bound to the network, applied to each host created in it
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
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

// IsNull ...
func (ssg *SubnetSecurityGroups) IsNull() bool {
	return ssg == nil || len(ssg.ByID) == 0
}

// Clone ...
func (ssg SubnetSecurityGroups) Clone() (data.Clonable, error) {
	return NewSubnetSecurityGroups().Replace(&ssg)
}

// Replace ...
func (ssg *SubnetSecurityGroups) Replace(p data.Clonable) (data.Clonable, error) {
	if ssg == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*SubnetSecurityGroups)
	if !ok {
		return nil, fmt.Errorf("p is not a *SubnetDescription")
	}

	*ssg = *src
	ssg.ByID = make(map[string]*SecurityGroupBond, len(src.ByID))
	for k, v := range src.ByID {
		cloned, err := v.Clone()
		if err != nil {
			return nil, err
		}
		ssg.ByID[k], ok = cloned.(*SecurityGroupBond)
		if !ok {
			return nil, fmt.Errorf("cloned is not a *SecurityGroupBond")
		}
	}
	ssg.ByName = make(map[string]string, len(src.ByName))
	for k, v := range src.ByName {
		ssg.ByName[k] = v
	}
	return ssg, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.subnet", subnetproperty.SecurityGroupsV1, NewSubnetSecurityGroups())
}
