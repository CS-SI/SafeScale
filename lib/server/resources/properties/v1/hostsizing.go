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
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/serialize"
)

// HostSizingRequirements describes host sizing requirements to fulfill
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostSizingRequirements struct {
	Cores     int     `json:"cores,omitempty"`
	RAMSize   float32 `json:"ram_size,omitempty"`
	DiskSize  int     `json:"disk_size,omitempty"`
	GPUNumber int     `json:"gpu_number,omitempty"`
	GPUType   string  `json:"gpu_type,omitempty"`
	CPUFreq   float32 `json:"cpu_freq,omitempty"`
}

// NewHostSizingRequirements ...
func NewHostSizingRequirements() *HostSizingRequirements {
	return &HostSizingRequirements{}
}

// IsNull ...
func (hsr *HostSizingRequirements) IsNull() bool {
	return hsr == nil || hsr.Cores == 0
}

// HostEffectiveSizing represent sizing elements of a host
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostEffectiveSizing struct {
	Cores     int     `json:"cores,omitempty"`
	RAMSize   float32 `json:"ram_size,omitempty"`
	DiskSize  int     `json:"disk_size,omitempty"`
	GPUNumber int     `json:"gpu_number,omitempty"`
	GPUType   string  `json:"gpu_type,omitempty"`
	CPUFreq   float32 `json:"cpu_freq,omitempty"`
}

// NewHostEffectiveSizing ...
func NewHostEffectiveSizing() *HostEffectiveSizing {
	return &HostEffectiveSizing{}
}

// IsNull ...
func (hes *HostEffectiveSizing) IsNull() bool {
	return hes == nil || hes.Cores == 0
}

// HostSizing contains sizing information about the host
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostSizing struct {
	RequestedSize *HostSizingRequirements `json:"requested_size,omitempty"`
	Template      string                  `json:"template,omitempty"`
	AllocatedSize *HostEffectiveSizing    `json:"allocated_size,omitempty"`
}

// NewHostSizing ...
func NewHostSizing() *HostSizing {
	return &HostSizing{
		RequestedSize: NewHostSizingRequirements(),
		AllocatedSize: NewHostEffectiveSizing(),
	}
}

// IsNull ...
// (data.Clonable interface)
func (hs *HostSizing) IsNull() bool {
	return hs == nil || (hs.RequestedSize.IsNull() && hs.AllocatedSize.IsNull())
}

// Clone ... (data.Clonable interface)
func (hs HostSizing) Clone() data.Clonable {
	return NewHostSizing().Replace(&hs)
}

// Replace ...
func (hs *HostSizing) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value...
	if hs == nil || p == nil {
		return hs
	}

	// FIXME: Replace should also return an error
	src, _ := p.(*HostSizing) // nolint
	hs.RequestedSize = NewHostSizingRequirements()
	if src.RequestedSize != nil {
		*hs.RequestedSize = *src.RequestedSize
	}
	hs.AllocatedSize = NewHostEffectiveSizing()
	if src.AllocatedSize != nil {
		*hs.AllocatedSize = *src.AllocatedSize
	}
	hs.Template = src.Template
	return hs
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.SizingV1, NewHostSizing())
}
