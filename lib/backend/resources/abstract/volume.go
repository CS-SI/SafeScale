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

package abstract

import (
	"fmt"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

const VolumeKind = "volume"

// VolumeRequest represents a volume request
type VolumeRequest struct {
	Name          string           `json:"name,omitempty"`
	Size          int              `json:"size,omitempty"`
	Speed         volumespeed.Enum `json:"speed"`
	KeepOnFailure bool
}

// CleanOnFailure tells if request asks for cleaning created ressource on failure
func (vr VolumeRequest) CleanOnFailure() bool {
	return !vr.KeepOnFailure
}

// Volume represents a block volume
type Volume struct {
	*core
	ID    string           `json:"id,omitempty"`
	Size  int              `json:"size,omitempty"`
	Speed volumespeed.Enum `json:"speed"`
	State volumestate.Enum `json:"state"`
}

// NewVolume ...
func NewVolume(opts ...Option) (*Volume, fail.Error) {
	opts = append(opts, withKind(VolumeKind))
	c, xerr := newCore(opts...)
	if xerr != nil {
		return nil, xerr
	}

	nv := &Volume{
		core: c,
	}
	nv.Tags["CreationDate"] = time.Now().Format(time.RFC3339)
	nv.Tags["ManagedBy"] = "safescale"
	return nv, nil
}

// NewEmptyVolume returns a empty, unnamed Volume instance
func NewEmptyVolume() *Volume {
	out, _ := NewVolume()
	return out
}

// IsNull ...
// satisfies interface clonable.Clonable
func (v *Volume) IsNull() bool {
	return v == nil || (v.ID == "" && (v.Name == "" || v.Name == Unnamed))
}

// Clone ...
// satisfies interface clonable.Clonable
func (v *Volume) Clone() (clonable.Clonable, error) {
	if v == nil {
		return nil, fail.InvalidInstanceError()
	}

	nv, _ := NewVolume()
	return nv, nv.Replace(v)
}

// Replace ...
//
// satisfies interface clonable.Clonable
func (v *Volume) Replace(p clonable.Clonable) error {
	if v == nil {
		return fail.InvalidInstanceError()
	}

	src, err := clonable.Cast[*Volume](p)
	if err != nil {
		return err
	}

	*v = *src
	v.core, err = clonable.CastedClone[*core](src.core)
	if err != nil {
		return err
	}

	return nil
}

// OK ...
func (v *Volume) OK() bool {
	result := true
	result = result && v != nil
	result = result && v.ID != ""
	result = result && v.Name != ""
	result = result && v.Size != 0
	// result = result && v.properties != nil
	return result
}

// Serialize serializes instance into bytes (output json code)
func (v *Volume) Serialize() ([]byte, fail.Error) {
	if v == nil {
		return nil, fail.InvalidInstanceError()
	}
	r, err := json.Marshal(v)
	return r, fail.Wrap(err)
}

// Deserialize reads json code and restores a Volume
func (v *Volume) Deserialize(buf []byte) (ferr fail.Error) {
	if v == nil {
		return fail.InvalidInstanceError()
	}

	defer fail.OnPanic(&ferr) // json.Unmarshal may panic
	return fail.Wrap(json.Unmarshal(buf, v))
}

// // GetName returns the name of the volume
// // Satisfies interface data.Identifiable
// func (v *Volume) GetName() string {
// 	return v.Name
// }

// GetID returns the ID of the volume
// Satisfies interface data.Identifiable
func (v *Volume) GetID() (string, error) {
	if v == nil {
		return "", fmt.Errorf("invalid instance")
	}

	return v.ID, nil
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

func NewVolumeAttachment() *VolumeAttachment {
	return &VolumeAttachment{}
}

func (va *VolumeAttachment) IsNull() bool {
	return va == nil || (va.ID == "" && va.Name == "")
}

// OK ...
func (va *VolumeAttachment) OK() bool {
	if va == nil {
		return false
	}
	result := true
	result = result && va.ID != ""
	result = result && va.Name != ""
	result = result && va.VolumeID != ""
	result = result && va.ServerID != ""
	result = result && va.Device != ""
	result = result && va.MountPoint != ""
	result = result && va.Format != ""
	return result
}
