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

package model

import (
	"time"

	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeState"
)

// VolumeRequest represents a volume request
type VolumeRequest struct {
	Name  string           `json:"name,omitempty"`
	Size  int              `json:"size,omitempty"`
	Speed VolumeSpeed.Enum `json:"speed,omitempty"`
}

// VolumeExtensionDescriptionV1 contains additional information describing the volume, in V1
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type VolumeExtensionDescriptionV1 struct {
	Purpose  string
	Creation time.Time
}

// Volume represents a block volume
type Volume struct {
	ID    string           `json:"id,omitempty"`
	Name  string           `json:"name,omitempty"`
	Size  int              `json:"size,omitempty"`
	Speed VolumeSpeed.Enum `json:"speed,omitempty"`
	State VolumeState.Enum `json:"state,omitempty"`
	// Extensions contains optional supplemental information (cf. metadata.Extensions)
	Extensions *Extensions `json:"extensions,omitempty"`
}

// NewVolume ...
func NewVolume() *Volume {
	return &Volume{
		Extensions: NewExtensions(),
	}
}

// Serialize serializes Host instance into bytes (output json code)
func (v *Volume) Serialize() ([]byte, error) {
	return SerializeToJSON(v)
}

// Deserialize reads json code and restores an Host
func (v *Volume) Deserialize(buf []byte) error {
	return DeserializeFromJSON(buf, v)
}

// VolumeAttachmentRequest represents a volume attachment request
type VolumeAttachmentRequest struct {
	Name     string `json:"name,omitempty"`
	VolumeID string `json:"volume,omitempty"`
	ServerID string `json:"host,omitempty"`
}

// VolumeAttachment represents a volume attachment
type VolumeAttachment struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	VolumeID   string `json:"volume,omitempty"`
	ServerID   string `json:"host,omitempty"`
	Device     string `json:"device,omitempty"`
	MountPoint string `json:"mountpoint,omitempty"`
	Format     string `json:"format,omitempty"`
}

// Serialize serializes Host instance into bytes (output json code)
func (va *VolumeAttachment) Serialize() ([]byte, error) {
	return SerializeToJSON(va)
}

// Deserialize reads json code and restores a VolumeAttachment
func (va *VolumeAttachment) Deserialize(buf []byte) error {
	return DeserializeFromJSON(buf, va)
}
