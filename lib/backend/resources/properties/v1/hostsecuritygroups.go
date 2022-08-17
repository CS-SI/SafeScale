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
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// HostSecurityGroups contains a list of security groups bound to the host
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
type HostSecurityGroups struct {
	// DefaultID string                        `json:"default_id,omitempty"` // contains the ID of the Security Group considered as default
	ByID   map[string]*SecurityGroupBond `json:"by_id,omitempty"`   // map of security groups by IDs
	ByName map[string]string             `json:"by_name,omitempty"` // map of security group IDs by Names
}

// NewHostSecurityGroups ...
func NewHostSecurityGroups() *HostSecurityGroups {
	return &HostSecurityGroups{
		ByID:   map[string]*SecurityGroupBond{},
		ByName: map[string]string{},
	}
}

// IsNull ...
func (hsg *HostSecurityGroups) IsNull() bool {
	return hsg == nil || len(hsg.ByID) == 0
}

// Clone ...
func (hsg HostSecurityGroups) Clone() (data.Clonable, error) {
	return NewHostSecurityGroups().Replace(&hsg)
}

// Replace ...
func (hsg *HostSecurityGroups) Replace(p data.Clonable) (data.Clonable, error) {
	if hsg == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*HostSecurityGroups)
	if !ok {
		return nil, fmt.Errorf("p is not a *HostSecurityGroups")
	}

	*hsg = *src
	hsg.ByID = make(map[string]*SecurityGroupBond, len(src.ByID))
	for k, v := range src.ByID {
		cloned, err := v.Clone()
		if err != nil {
			return nil, err
		}
		hsg.ByID[k], ok = cloned.(*SecurityGroupBond)
		if !ok {
			return nil, fmt.Errorf("cloned is not a *SecurityGroupBond")
		}
	}
	hsg.ByName = make(map[string]string, len(src.ByName))
	for k, v := range src.ByName {
		hsg.ByName[k] = v
	}
	return hsg, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.SecurityGroupsV1, NewHostSecurityGroups())
}
