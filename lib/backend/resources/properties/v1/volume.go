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

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumeproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

// VolumeDescription contains additional information describing the volume, in V1
// !!!FROZEN!!!
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
type VolumeDescription struct {
	// Purpose contains the reason of the existence of the volume
	Purpose string `json:"purpose,omitempty"`
	// Created contains the time of creation of the volume
	Created time.Time `json:"created,omitempty"`
}

// NewVolumeDescription ...
func NewVolumeDescription() *VolumeDescription {
	return &VolumeDescription{}
}

// IsNull ...
func (vd *VolumeDescription) IsNull() bool {
	return vd == nil || (vd.Created.IsZero() && vd.Purpose == "")
}

// Clone ...
func (vd *VolumeDescription) Clone() (clonable.Clonable, error) {
	if vd == nil {
		return nil, fail.InvalidInstanceError()
	}

	nvd := NewVolumeDescription()
	return nvd, nvd.Replace(vd)
}

// Replace ...
func (vd *VolumeDescription) Replace(p clonable.Clonable) error {
	if vd == nil {
		return fail.InvalidInstanceError()
	}

	cloned, err := lang.Cast[*VolumeDescription](p)
	if err != nil {
		return err
	}

	*vd = *cloned
	return nil
}

// VolumeAttachments contains host ids where the volume is attached
// !!!FROZEN!!!
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
type VolumeAttachments struct {
	Shareable bool              `json:"shareable,omitempty"` // Tells if the volume can be shared with multiple host
	Hosts     map[string]string `json:"hosts,omitempty"`     // Contains the name of the hosts mounting the volume, indexed by host ID
}

// NewVolumeAttachments ...
func NewVolumeAttachments() *VolumeAttachments {
	return &VolumeAttachments{
		Hosts: map[string]string{},
	}
}

// IsNull ...
// (clonable.Clonable interface)
func (va *VolumeAttachments) IsNull() bool {
	return va == nil || len(va.Hosts) == 0
}

// Clone ... (clonable.Clonable interface)
func (va *VolumeAttachments) Clone() (clonable.Clonable, error) {
	if va == nil {
		return nil, fail.InvalidInstanceError()
	}

	nva := NewVolumeAttachments()
	return nva, nva.Replace(va)
}

// Replace ... (clonable.Clonable interface)
func (va *VolumeAttachments) Replace(p clonable.Clonable) error {
	if va == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*VolumeAttachments](p)
	if err != nil {
		return err
	}

	*va = *src
	va.Hosts = make(map[string]string, len(src.Hosts))
	for k, v := range src.Hosts {
		va.Hosts[k] = v
	}
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.volume", volumeproperty.DescriptionV1, NewVolumeDescription())
	serialize.PropertyTypeRegistry.Register("resources.volume", volumeproperty.AttachedV1, NewVolumeAttachments())
}
