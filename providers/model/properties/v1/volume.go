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
)

// VolumeDescription contains additional information describing the volume, in V1
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type VolumeDescription struct {
	// Purpose contains the reason of the existence of the volume
	Purpose string
	// Created contains the time of creation of the volume
	Created time.Time
}

// BlankVolumeDescription ...
var BlankVolumeDescription = VolumeDescription{}

// VolumeAttachments contains host ids where the volume is attached
type VolumeAttachments struct {
	HostIDs []string `json:"host_ids,omitempty"`
}

// BlankVolumeAttachments ...
var BlankVolumeAttachments = VolumeAttachments{HostIDs: []string{}}
