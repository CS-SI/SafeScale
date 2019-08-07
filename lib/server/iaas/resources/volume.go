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

package resources

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeState"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// VolumeRequest represents a volume request
type VolumeRequest struct {
	Name  string           `json:"name,omitempty"`
	Size  int              `json:"size,omitempty"`
	Speed VolumeSpeed.Enum `json:"speed,omitempty"`
}

// Volume represents a block volume
type Volume struct {
	ID         string                    `json:"id,omitempty"`
	Name       string                    `json:"name,omitempty"`
	Size       int                       `json:"size,omitempty"`
	Speed      VolumeSpeed.Enum          `json:"speed,omitempty"`
	State      VolumeState.Enum          `json:"state,omitempty"`
	Properties *serialize.JSONProperties `json:"properties,omitempty"`
}

// NewVolume ...
func NewVolume() *Volume {
	return &Volume{
		Properties: serialize.NewJSONProperties("resources.volume"),
	}
}

// OK ...
func (v *Volume) OK() bool {
	result := true
	result = result && v.ID != ""
	result = result && v.Name != ""
	result = result && v.Size != 0
	result = result && v.Properties != nil
	return result
}

// Serialize serializes Host instance into bytes (output json code)
func (v *Volume) Serialize() ([]byte, error) {
	return serialize.ToJSON(v)
}

// Deserialize reads json code and restores an Host
func (v *Volume) Deserialize(buf []byte) error {
	if v.Properties == nil {
		v.Properties = serialize.NewJSONProperties("resources.volume")
	} else {
		v.Properties.SetModule("resources.volume")
	}
	err := serialize.FromJSON(buf, v)
	if err != nil {
		return err
	}

	return nil
}

// VolumeAttachmentRequest represents a volume attachment request
type VolumeAttachmentRequest struct {
	Name     string `json:"name,omitempty"`
	VolumeID string `json:"volume_id,omitempty"`
	HostID   string `json:"host_id,omitempty"`
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
