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

package propertiesv2

import (
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// HostSizing contains sizing information about the host
// not frozen yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostSizing struct {
	RequestedSize *abstracts.SizingRequirements `json:"requested_size,omitempty"`
	Template      string                        `json:"template,omitempty"`
	AllocatedSize *propertiesv1.HostSize        `json:"allocated_size,omitempty"`
}

// NewHostSizing ...
func NewHostSizing() *HostSizing {
	return &HostSizing{
		RequestedSize: &abstracts.SizingRequirements{},
		AllocatedSize: propertiesv1.NewHostSize(),
	}
}

// Reset ...
func (hs *HostSizing) Reset() {
	*hs = HostSizing{
		RequestedSize: &abstracts.SizingRequirements{},
		Template:      "",
		AllocatedSize: propertiesv1.NewHostSize(),
	}
}

// Content ... (data.Clonable interface)
func (hs *HostSizing) Content() interface{} {
	return hs
}

// Clone ... (data.Clonable interface)
func (hs *HostSizing) Clone() data.Clonable {
	return NewHostSizing().Replace(hs)
}

// Replace ...
func (hs *HostSizing) Replace(p data.Clonable) data.Clonable {
	src := p.(*HostSizing)
	hs.AllocatedSize = propertiesv1.NewHostSize()
	*hs.AllocatedSize = *src.AllocatedSize
	return hs
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", string(hostproperty.SizingV2), NewHostSizing())
}
