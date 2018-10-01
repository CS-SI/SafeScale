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

package core

import (

	// "github.com/CS-SI/SafeScale/system"

	"github.com/CS-SI/SafeScale/providers/api/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/api/enums/VolumeState"
)

// Volume represents a block volume
type Volume struct {
	ID    string           `json:"id,omitempty"`
	Name  string           `json:"name,omitempty"`
	Size  int              `json:"size,omitempty"`
	Speed VolumeSpeed.Enum `json:"speed,omitempty"`
	State VolumeState.Enum `json:"state,omitempty"`
}

// VolumeRequest represents a volume request
type VolumeRequest struct {
	Name  string           `json:"name,omitempty"`
	Size  int              `json:"size,omitempty"`
	Speed VolumeSpeed.Enum `json:"speed,omitempty"`
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

// VolumeAttachmentRequest represents a volume attachment request
type VolumeAttachmentRequest struct {
	Name     string `json:"name,omitempty"`
	VolumeID string `json:"volume,omitempty"`
	ServerID string `json:"host,omitempty"`
}
