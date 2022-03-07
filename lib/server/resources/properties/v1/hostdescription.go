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

	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

// HostDescription contains description information for the host
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostDescription struct {
	Created time.Time `json:"created,omitempty"`  // tells when the host has been created
	Creator string    `json:"creator,omitempty"`  // contains information (forged) about the creator of the host
	Updated time.Time `json:"modified,omitempty"` // tells the last time the host has been modified (by SafeScale)
	Purpose string    `json:"purpose,omitempty"`  // contains a description of the use of a host (not set for now)
	Tenant  string    `json:"tenant,omitempty"`   // contains the tenant name used to create the host
	Domain  string    `json:"domain,omitempty"`   // Contains the domain used to define the FQDN of the host at creation (taken from first network attached to the host)
}

// NewHostDescription ...
func NewHostDescription() *HostDescription {
	return &HostDescription{}
}

// IsNull ...
// satisfies interface data.Clonable
func (hd *HostDescription) IsNull() bool {
	return hd == nil || (hd.Created.IsZero() && hd.Tenant == "")
}

// Clone ... (data.Clonable interface)
func (hd HostDescription) Clone() (data.Clonable, error) {
	return NewHostDescription().Replace(&hd)
}

// Replace ... (data.Clonable interface)
func (hd *HostDescription) Replace(p data.Clonable) (data.Clonable, error) {
	if hd == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	casted, ok := p.(*HostDescription)
	if !ok {
		return nil, fmt.Errorf("p is not a *HostDescription")
	}

	*hd = *casted
	return hd, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.DescriptionV1, NewHostDescription())
}
