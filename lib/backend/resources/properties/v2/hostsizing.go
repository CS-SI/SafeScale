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

package propertiesv2

import (
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// HostSizingRequirements describes host sizing requirements to fulfill
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
type HostSizingRequirements struct {
	MinCores    int     `json:"min_cores,omitempty"`
	MaxCores    int     `json:"max_cores,omitempty"`
	MinRAMSize  float32 `json:"min_ram_size,omitempty"`
	MaxRAMSize  float32 `json:"max_ram_size,omitempty"`
	MinDiskSize int     `json:"min_disk_size,omitempty"`
	MinGPU      int     `json:"min_gpu,omitempty"`
	MinCPUFreq  float32 `json:"min_freq,omitempty"`
	Replaceable bool    `json:"replaceable,omitempty"` // Tells if we accept host that could be removed without notice (AWS proposes such kind of server known as SPOT)
}

// NewHostSizingRequirements ...
func NewHostSizingRequirements() *HostSizingRequirements {
	return &HostSizingRequirements{}
}

// IsNull tells if the struct is a null value
func (hsr *HostSizingRequirements) IsNull() bool {
	return hsr == nil || (hsr.MinCores == 0 && hsr.MaxCores == 0)
}

// HostEffectiveSizing represent sizing elements of a host
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
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

// IsNull tells if the struct is a null value
func (hes *HostEffectiveSizing) IsNull() bool {
	return hes == nil || hes.Cores == 0
}

// HostSizing contains sizing information about the host
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
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
// satisfies interface data.Clonable
func (hs *HostSizing) IsNull() bool {
	return hs == nil || (valid.IsNil(hs.RequestedSize) && hs.Template == "" && valid.IsNil(hs.AllocatedSize))
}

// Clone ... (data.Clonable interface)
func (hs HostSizing) Clone() (data.Clonable, error) {
	return NewHostSizing().Replace(&hs)
}

// Replace ...
func (hs *HostSizing) Replace(p data.Clonable) (data.Clonable, error) {
	if hs == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*HostSizing)
	if !ok {
		return nil, fmt.Errorf("p is not a *HostSizing")
	}

	hs.RequestedSize = NewHostSizingRequirements()
	*hs.RequestedSize = *src.RequestedSize
	hs.AllocatedSize = NewHostEffectiveSizing()
	*hs.AllocatedSize = *src.AllocatedSize
	hs.Template = src.Template
	return hs, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.SizingV2, NewHostSizing())
}
