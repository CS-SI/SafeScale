/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/volumeproperty"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// VolumeDescription contains additional information describing the volume, in V1
// !!!FROZEN!!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type VolumeDescription struct {
	// Purpose contains the reason of the existence of the volume
	Purpose string
	// Created contains the time of creation of the volume
	Created time.Time
}

// NewVolumeDescription ...
func NewVolumeDescription() *VolumeDescription {
	return &VolumeDescription{}
}

// Content ... (serialize.Property interface)
func (vd *VolumeDescription) Content() interface{} {
	return vd
}

// Clone ... (serialize.Property interface)
func (vd *VolumeDescription) Clone() serialize.Property {
	return NewVolumeDescription().Replace(vd)
}

// Replace ... (serialize.Property interface)
func (vd *VolumeDescription) Replace(p serialize.Property) serialize.Property {
	*vd = *p.(*VolumeDescription)
	return vd
}

// VolumeAttachments contains host ids where the volume is attached
// !!!FROZEN!!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type VolumeAttachments struct {
	Shareable bool              `json:"shareable,omitempty"` // Tells if the volume can be shared with multiple host
	Hosts     map[string]string `json:"hosts,omitempty"`     // Contains the name of the hosts mounting the volume, indexed by ID
}

// NewVolumeAttachments ...
func NewVolumeAttachments() *VolumeAttachments {
	return &VolumeAttachments{
		Hosts: map[string]string{},
	}
}

// Reset resets the content of the property
func (va *VolumeAttachments) Reset() {
	*va = VolumeAttachments{
		Hosts: map[string]string{},
	}
}

// Content ... (serialize.Property interface)
func (va *VolumeAttachments) Content() interface{} {
	return va
}

// Clone ... (serialize.Property interface)
func (va *VolumeAttachments) Clone() serialize.Property {
	return NewVolumeAttachments().Replace(va)
}

// Replace ... (serialize.Property interface)
func (va *VolumeAttachments) Replace(p serialize.Property) serialize.Property {
	src := p.(*VolumeAttachments)
	*va = *src
	va.Hosts = make(map[string]string, len(src.Hosts))
	for k, v := range src.Hosts {
		va.Hosts[k] = v
	}
	return va
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.volume", volumeproperty.DescriptionV1, NewVolumeDescription())
	serialize.PropertyTypeRegistry.Register("resources.volume", volumeproperty.AttachedV1, NewVolumeAttachments())
}
