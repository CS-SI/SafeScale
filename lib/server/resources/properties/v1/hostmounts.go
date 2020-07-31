/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
    "github.com/CS-SI/SafeScale/lib/utils/data"
    "github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// HostLocalMount stores information about a device (as an attached volume) mount
// not FROZEN yet
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

// Reset ...
func (hlm *HostLocalMount) Reset() {
    *hlm = HostLocalMount{}
}

// Clone ...
func (hlm *HostLocalMount) Clone() data.Clonable {
    return NewHostLocalMount().Replace(hlm)
}

// Replace ...
func (hlm *HostLocalMount) Replace(p data.Clonable) data.Clonable {
    src := p.(*HostLocalMount)
    *hlm = *src
    return hlm
}

// HostRemoteMount stores information about a remote filesystem mount
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type HostRemoteMount struct {
    ShareID    string `json:"share_id"`          // contains the GetID of the share mounted
    Export     string `json:"export"`            // contains the path of the export (ie: <host>:/data/shared)
    Path       string `json:"mountpoint"`        // Path is the mount point of the device
    FileSystem string `json:"file_system"`       // FileSystem tells the filesystem used
    Options    string `json:"options,omitempty"` // Options contains the mount options
}

// NewHostRemoteMount ...
func NewHostRemoteMount() *HostRemoteMount {
    return &HostRemoteMount{}
}

// Reset ...
func (hrm *HostRemoteMount) Reset() {
    *hrm = HostRemoteMount{}
}

// Clone ...
func (hrm *HostRemoteMount) Clone() data.Clonable {
    return NewHostRemoteMount().Replace(hrm)
}

// Replace ...
func (hrm *HostRemoteMount) Replace(p data.Clonable) data.Clonable {
    src := p.(*HostRemoteMount)
    *hrm = *src
    return hrm
}

// HostMounts contains information about mounts on the host
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type HostMounts struct {
    LocalMountsByDevice   map[string]string           `json:"local_mounts_by_device"`  // contains local mount path, indexed by devices
    LocalMountsByPath     map[string]*HostLocalMount  `json:"local_mounts_by_path"`    // contains HostLocalMount structs, indexed by path
    RemoteMountsByShareID map[string]string           `json:"remote_mounts_by_device"` // contains local mount path, indexed by Share GetID
    RemoteMountsByExport  map[string]string           `json:"remote_mounts_by_export"` // contains local mount path, indexed by export
    RemoteMountsByPath    map[string]*HostRemoteMount `json:"remote_mounts_by_path"`   // contains HostRemoteMount, indexed by path
}

// NewHostMounts ...
func NewHostMounts() *HostMounts {
    return &HostMounts{
        LocalMountsByDevice:   map[string]string{},
        LocalMountsByPath:     map[string]*HostLocalMount{},
        RemoteMountsByShareID: map[string]string{},
        RemoteMountsByExport:  map[string]string{},
        RemoteMountsByPath:    map[string]*HostRemoteMount{},
    }
}

// Reset ...
func (hm *HostMounts) Reset() {
    *hm = HostMounts{
        LocalMountsByDevice:   map[string]string{},
        LocalMountsByPath:     map[string]*HostLocalMount{},
        RemoteMountsByShareID: map[string]string{},
        RemoteMountsByExport:  map[string]string{},
        RemoteMountsByPath:    map[string]*HostRemoteMount{},
    }
}

// Content ...  (data.Clonable interface)
func (hm *HostMounts) Content() interface{} {
    return hm
}

// Clone ...  (data.Clonable interface)
func (hm *HostMounts) Clone() data.Clonable {
    return NewHostMounts().Replace(hm)
}

// Replace ...  (data.Clonable interface)
func (hm *HostMounts) Replace(p data.Clonable) data.Clonable {
    src := p.(*HostMounts)
    hm.LocalMountsByDevice = make(map[string]string, len(src.LocalMountsByDevice))
    for k, v := range src.LocalMountsByDevice {
        hm.LocalMountsByDevice[k] = v
    }
    hm.LocalMountsByPath = make(map[string]*HostLocalMount, len(src.LocalMountsByPath))
    for k, v := range src.LocalMountsByPath {
        hm.LocalMountsByPath[k] = v
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
        hm.RemoteMountsByPath[k] = v
    }
    return hm
}

func init() {
    serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.MountsV1, NewHostMounts())
}
