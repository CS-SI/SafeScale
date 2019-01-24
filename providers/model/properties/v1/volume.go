/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeProperty"
	"github.com/CS-SI/SafeScale/utils/serialize"
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
func (p *VolumeDescription) Content() interface{} {
	return p
}

// Clone ... (serialize.Property interface)
func (p *VolumeDescription) Clone() serialize.Property {
	n := NewVolumeDescription()
	*n = *p
	return n
}

// Replace replaces content of property (serialize.Property interface)
func (p *VolumeDescription) Replace(v interface{}) {
	*p = *v.(*VolumeDescription)
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
func (p *VolumeAttachments) Reset() {
	*p = VolumeAttachments{
		Hosts: map[string]string{},
	}
}

// Content ... (serialize.Property interface)
func (p *VolumeAttachments) Content() interface{} {
	return p
}

// Clone ... (serialize.Property interface)
func (p *VolumeAttachments) Clone() serialize.Property {
	n := NewVolumeAttachments()
	*n = *p
	return n
}

// Replace replaces content of property (serialize.Property interface)
func (p *VolumeAttachments) Replace(v interface{}) {
	*p = *v.(*VolumeAttachments)
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.volume", VolumeProperty.DescriptionV1, NewVolumeDescription())
	serialize.PropertyTypeRegistry.Register("resources.volume", VolumeProperty.AttachedV1, NewVolumeAttachments())
}
