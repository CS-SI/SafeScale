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
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

// SubnetDescription contains additional information describing the subnet, in V1
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
type SubnetDescription struct {
	Purpose string    `json:"purpose,omitempty"` // contains the purpose of this network
	Created time.Time `json:"created,omitempty"` // Contains the date of creation if the network
	Domain  string    `json:"domain,omitempty"`  // Defines the domain to use for host FQDN in this network
}

// NewSubnetDescription ...
func NewSubnetDescription() *SubnetDescription {
	return &SubnetDescription{}
}

// IsNull ...
// (clonable.Clonable interface)
func (sd *SubnetDescription) IsNull() bool {
	return sd == nil || (sd.Created.IsZero() && sd.Purpose == "")
}

// Clone ... (clonable.Clonable interface)
func (sd *SubnetDescription) Clone() (clonable.Clonable, error) {
	if sd == nil {
		return nil, fail.InvalidInstanceError()
	}

	ssd := NewSubnetDescription()
	return ssd, ssd.Replace(sd)
}

// Replace ... (clonable.Clonable interface)
func (sd *SubnetDescription) Replace(p clonable.Clonable) error {
	if sd == nil {
		return fail.InvalidInstanceError()
	}

	casted, err := lang.Cast[*SubnetDescription](p)
	if err != nil {
		return err
	}

	*sd = *casted
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.subnet", subnetproperty.DescriptionV1, NewSubnetDescription())
}
