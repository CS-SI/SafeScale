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
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// HostVolume contains information about attached volume
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
type HostVolume struct {
	AttachID string `json:"attach_id"` // contains the ID of the volume attachment
	Device   string `json:"device"`    // contains the device on the host
}

// NewHostVolume ...
func NewHostVolume() *HostVolume {
	return &HostVolume{}
}

// HostVolumes contains information about attached volumes
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
type HostVolumes struct {
	VolumesByID     map[string]*HostVolume `json:"volumes_by_id,omitempty"`     // contains the information of the attached volume, indexed by volume ID
	VolumesByName   map[string]string      `json:"volumes_by_name,omitempty"`   // contains the ID of attached volume, indexed by volume name
	VolumesByDevice map[string]string      `json:"volumes_by_device,omitempty"` // contains the ID of attached volume, indexed by device
	DevicesByID     map[string]string      `json:"devices_by_id,omitempty"`     // contains the device of attached volume, indexed by ID
}

// NewHostVolumes ...
func NewHostVolumes() *HostVolumes {
	return &HostVolumes{
		VolumesByID:     map[string]*HostVolume{},
		VolumesByName:   map[string]string{},
		VolumesByDevice: map[string]string{},
		DevicesByID:     map[string]string{},
	}
}

// IsNull ...
func (hv *HostVolumes) IsNull() bool {
	return hv == nil || len(hv.VolumesByID) == 0
}

// Clone ...
func (hv HostVolumes) Clone() (data.Clonable, error) {
	return NewHostVolumes().Replace(&hv)
}

// Replace ...
func (hv *HostVolumes) Replace(p data.Clonable) (data.Clonable, error) {
	if hv == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*HostVolumes)
	if !ok {
		return nil, fmt.Errorf("p is not a *HostVolumes")
	}

	hv.VolumesByID = make(map[string]*HostVolume, len(src.VolumesByID))
	for k, v := range src.VolumesByID {
		hv.VolumesByID[k] = v
	}
	hv.VolumesByName = make(map[string]string, len(src.VolumesByName))
	for k, v := range src.VolumesByName {
		hv.VolumesByName[k] = v
	}
	hv.VolumesByDevice = make(map[string]string, len(src.VolumesByDevice))
	for k, v := range src.VolumesByDevice {
		hv.VolumesByDevice[k] = v
	}
	hv.DevicesByID = make(map[string]string, len(src.DevicesByID))
	for k, v := range src.DevicesByID {
		hv.DevicesByID[k] = v
	}
	return hv, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.VolumesV1, NewHostVolumes())
}
