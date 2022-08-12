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

// HostSystem contains information about the operating system
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostSystem struct {
	Type     string `json:"type,omitempty"`     // Type of operating system (ie linux, windows, ... Not normalized yet...)
	Flavor   string `json:"flavor,omitempty"`   // Flavor of operating system (ie 'ubuntu server', 'windows server 2016', ... Not normalized yet...)
	Image    string `json:"image,omitempty"`    // name of the provider's image used
	HostName string `json:"hostname,omitempty"` // Hostname on the system
}

// NewHostSystem ...
func NewHostSystem() *HostSystem {
	return &HostSystem{}
}

// IsNull ...
func (hs *HostSystem) IsNull() bool {
	return hs == nil || (hs.Type == "" && hs.Flavor == "" && hs.Image == "" && hs.HostName == "")
}

// Clone ...
func (hs HostSystem) Clone() (data.Clonable, error) {
	return NewHostSystem().Replace(&hs)
}

// Replace ...
func (hs *HostSystem) Replace(p data.Clonable) (data.Clonable, error) {
	if hs == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*HostSystem)
	if !ok {
		return nil, fmt.Errorf("p is not a *HostSystem")
	}

	*hs = *src
	return hs, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.SystemV1, NewHostSystem())
}
