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

	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
)

// HostLocalMount stores information about a device (as an attached volume) mount
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type HostLocalMount struct {
	Device     string `json:"device"`            // Device is the name of the device (/dev/... for local mount, host:/path for remote mount)
	Path       string `json:"mountpoint"`        // Path is the mount point of the device
	FileSystem string `json:"file_system"`       // FileSystem tells the filesystem used
	Options    string `json:"options,omitempty"` // Options contains the mount options
}

// NewHostLocalMount ...
func NewHostLocalMount() *HostLocalMount {
	return &HostLocalMount{}
}

// IsNull ...
// satisfies interface data.Clonable
func (hlm *HostLocalMount) IsNull() bool {
	return hlm == nil || (hlm.Device == "" && hlm.Path == "" && hlm.FileSystem == "")
}

// Clone ...
// satisfies interface data.Clonable
func (hlm HostLocalMount) Clone() (data.Clonable, error) {
	return NewHostLocalMount().Replace(&hlm)
}

// Replace ...
func (hlm *HostLocalMount) Replace(p data.Clonable) (data.Clonable, error) {
	// Do not test with isNull(), it's allowed to clone a null value...
	if hlm == nil || p == nil {
		return hlm, nil
	}

	src, ok := p.(*HostLocalMount)
	if !ok {
		return nil, fmt.Errorf("p is not a *HostLocalMount")
	}

	*hlm = *src
	return hlm, nil
}

// HostRemoteMount stores information about a remote filesystem mount
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type HostRemoteMount struct {
	ShareID    string `json:"share_id"`          // contains the ID of the share mounted
	Export     string `json:"export"`            // contains the path of the export (ie: <host>:/data/shared)
	Path       string `json:"mountpoint"`        // Path is the mount point of the device
	FileSystem string `json:"file_system"`       // FileSystem tells the filesystem used
	Options    string `json:"options,omitempty"` // Options contains the mount options
}

// NewHostRemoteMount ...
func NewHostRemoteMount() *HostRemoteMount {
	return &HostRemoteMount{}
}

// IsNull ...
func (hrm *HostRemoteMount) IsNull() bool {
	return hrm == nil || (hrm.ShareID == "" && hrm.Export == "" && hrm.Path == "")
}

// Clone ...
func (hrm *HostRemoteMount) Clone() (data.Clonable, error) {
	return NewHostRemoteMount().Replace(hrm)
}

// Replace ...
func (hrm *HostRemoteMount) Replace(p data.Clonable) (data.Clonable, error) {
	// Do not test with isNull(), it's allowed to clone a null value...
	if hrm == nil || p == nil {
		return hrm, nil
	}

	// FIXME: Replace should also return an error
	src, _ := p.(*HostRemoteMount) // nolint
	*hrm = *src
	return hrm, nil
}

// HostMounts contains information about mounts on the host
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type HostMounts struct {
	LocalMountsByDevice   map[string]string           `json:"local_mounts_by_device,omitempty"`  // contains local mount path, indexed by devices
	LocalMountsByPath     map[string]*HostLocalMount  `json:"local_mounts_by_path,omitempty"`    // contains HostLocalMount structs, indexed by path
	RemoteMountsByShareID map[string]string           `json:"remote_mounts_by_device,omitempty"` // contains local mount path, indexed by Share ID
	RemoteMountsByExport  map[string]string           `json:"remote_mounts_by_export,omitempty"` // contains local mount path, indexed by export
	RemoteMountsByPath    map[string]*HostRemoteMount `json:"remote_mounts_by_path,omitempty"`   // contains HostRemoteMount, indexed by path
	BucketMounts          map[string]string           `json:"bucket_mounts,omitempty"`           // contains the path where the index (corresponding to Bucket name) is mounted
}

// NewHostMounts ...
func NewHostMounts() *HostMounts {
	return &HostMounts{
		LocalMountsByDevice:   map[string]string{},
		LocalMountsByPath:     map[string]*HostLocalMount{},
		RemoteMountsByShareID: map[string]string{},
		RemoteMountsByExport:  map[string]string{},
		RemoteMountsByPath:    map[string]*HostRemoteMount{},
		BucketMounts:          map[string]string{},
	}
}

// IsNull ...
// (data.Clonable interface)
func (hm *HostMounts) IsNull() bool {
	return hm == nil || (len(hm.LocalMountsByPath) == 0 && len(hm.RemoteMountsByPath) == 0)
}

// Clone ...  (data.Clonable interface)
func (hm *HostMounts) Clone() (data.Clonable, error) {
	return NewHostMounts().Replace(hm)
}

// Replace ...  (data.Clonable interface)
func (hm *HostMounts) Replace(p data.Clonable) (data.Clonable, error) {
	// Note: do not validate with isNull(), it's allowed to replace a null value...
	if hm == nil || p == nil {
		return hm, nil
	}

	src, ok := p.(*HostMounts)
	if !ok {
		return nil, fmt.Errorf("p is not a *HostMounts")
	}

	hm.LocalMountsByDevice = make(map[string]string, len(src.LocalMountsByDevice))
	for k, v := range src.LocalMountsByDevice {
		hm.LocalMountsByDevice[k] = v
	}
	hm.LocalMountsByPath = make(map[string]*HostLocalMount, len(src.LocalMountsByPath))
	for k, v := range src.LocalMountsByPath {
		cloned, err := v.Clone()
		if err != nil {
			return nil, err
		}
		hm.LocalMountsByPath[k], ok = cloned.(*HostLocalMount)
		if !ok {
			return nil, fmt.Errorf("cloned is not a *HostLocalMount")
		}
	}
	hm.RemoteMountsByShareID = make(map[string]string, len(src.RemoteMountsByShareID))
	for k, v := range src.RemoteMountsByShareID {
		hm.RemoteMountsByShareID[k] = v
	}
	hm.RemoteMountsByExport = make(map[string]string, len(src.RemoteMountsByExport))
	for k, v := range src.RemoteMountsByExport {
		hm.RemoteMountsByExport[k] = v
	}
	hm.RemoteMountsByPath = make(map[string]*HostRemoteMount, len(src.RemoteMountsByPath))
	for k, v := range src.RemoteMountsByPath {
		cloned, err := v.Clone()
		if err != nil {
			return nil, err
		}
		hm.RemoteMountsByPath[k], ok = cloned.(*HostRemoteMount)
		if !ok {
			return nil, fmt.Errorf("p is not a *HostRemoteMount")
		}
	}
	hm.BucketMounts = make(map[string]string, len(src.BucketMounts))
	for k, v := range src.BucketMounts {
		hm.BucketMounts[k] = v
	}
	return hm, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.MountsV1, NewHostMounts())
}
