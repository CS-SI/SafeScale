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
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

// SubnetDescription contains additional information describing the subnet, in V1
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
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
// (data.Clonable interface)
func (sd *SubnetDescription) IsNull() bool {
	return sd == nil || (sd.Created.IsZero() && sd.Purpose == "")
}

// Clone ... (data.Clonable interface)
func (sd SubnetDescription) Clone() (data.Clonable, error) {
	return NewSubnetDescription().Replace(&sd)
}

// Replace ... (data.Clonable interface)
func (sd *SubnetDescription) Replace(p data.Clonable) (data.Clonable, error) {
	if sd == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	casted, ok := p.(*SubnetDescription)
	if !ok {
		return nil, fmt.Errorf("p is not a *SubnetDescription")
	}

	*sd = *casted
	return sd, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.subnet", subnetproperty.DescriptionV1, NewSubnetDescription())
}
