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
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

// NetworkSecurityGroups contains a list of security groups owned by the Network
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
type NetworkSecurityGroups struct {
	ByID   map[string]string `json:"by_id,omitempty"`   // map of security group names indexed by IDs
	ByName map[string]string `json:"by_name,omitempty"` // map of security group IDs indexed by names
}

// NewNetworkSecurityGroups ...
func NewNetworkSecurityGroups() *NetworkSecurityGroups {
	return &NetworkSecurityGroups{
		ByID:   map[string]string{},
		ByName: map[string]string{},
	}
}

// IsNull ...
func (nsg *NetworkSecurityGroups) IsNull() bool {
	return nsg == nil || len(nsg.ByID) == 0
}

// Clone ...
func (nsg *NetworkSecurityGroups) Clone() (clonable.Clonable, error) {
	if nsg == nil {
		return nil, fail.InvalidInstanceError()
	}

	nnsg := NewNetworkSecurityGroups()
	return nnsg, nnsg.Replace(nsg)
}

// Replace ...
func (nsg *NetworkSecurityGroups) Replace(p clonable.Clonable) error {
	if nsg == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*NetworkSecurityGroups](p)
	if err != nil {
		return err
	}

	*nsg = *src
	nsg.ByID = make(map[string]string, len(src.ByID))
	for k, v := range src.ByID {
		nsg.ByID[k] = v
	}
	nsg.ByName = make(map[string]string, len(src.ByName))
	for k, v := range src.ByName {
		nsg.ByName[k] = v
	}
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.network", networkproperty.SecurityGroupsV1, NewNetworkSecurityGroups())
}
