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

// HostDescription contains description information for the host
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostDescription struct {
	Created time.Time `json:"created,omitempty"`  // tells when the host has been created
	Creator string    `json:"creator,omitempty"`  // contains information (forged) about the creator of a host
	Updated time.Time `json:"modified,omitempty"` // tells the last time the host has been modified
	Purpose string    `json:"purpose,omitempty"`  // contains a description of the use of a host
}

// NewHostDescription returns a blank HostDescription
func NewHostDescription() *HostDescription {
	return &HostDescription{}
}

// HostNetwork contains network information related to Host
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostNetwork struct {
	IsGateway               bool              `json:"is_gateway,omitempty"`                 // Tells if host is a gateway of a network
	DefaultGatewayID        string            `json:"default_gateway_id,omitempty"`         // contains the ID of the Default Gateway
	DefaultGatewayPrivateIP string            `json:"default_gateway_private_ip,omitempty"` // contains the private IP of the default gateway
	DefaultNetworkID        string            `json:"default_network_id,omitempty"`         // contains the ID of the default Network
	NetworksByID            map[string]string `json:"networks_by_id,omitempty"`             // contains the name of each network binded to the host (indexed by ID)
	NetworksByName          map[string]string `json:"networks_by_name,omitempty"`           // contains the ID of each network binded to the host (indexed by Name)
	PublicIPv4              string            `json:"public_ip_v4,omitempty"`
	PublicIPv6              string            `json:"public_ip_v6,omitempty"`
	IPv4Addresses           map[string]string `json:"ipv4_addresses,omitempty"` // contains ipv4 (indexed by network ID) allocated to the host
	IPv6Addresses           map[string]string `json:"ipv6_addresses,omitempty"` // contains ipv6 (indexed by Network ID) allocated to the host
}

// NewHostNetwork retuns a blank HostNetwork
func NewHostNetwork() *HostNetwork {
	return &HostNetwork{
		NetworksByID:   map[string]string{},
		NetworksByName: map[string]string{},
		IPv4Addresses:  map[string]string{},
		IPv6Addresses:  map[string]string{},
	}
}

// HostSize represent sizing elements of an host
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostSize struct {
	Cores     int     `json:"cores,omitempty"`
	RAMSize   float32 `json:"ram_size,omitempty"`
	DiskSize  int     `json:"disk_size,omitempty"`
	GPUNumber int     `json:"gpu_number,omitempty"`
	GPUType   string  `json:"gpu_type,omitempty"`
	CPUFreq   float32 `json:"cpu_freq,omitempty"`
}

// NewHostSize ...
func NewHostSize() *HostSize {
	return &HostSize{}
}

// HostTemplate represents an host template
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostTemplate struct {
	*HostSize `json:"host_size,omitempty"`
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
}

// NewHostTemplate ...
func NewHostTemplate() *HostTemplate {
	return &HostTemplate{
		HostSize: NewHostSize(),
	}
}

// HostSizing contains sizing information about the host
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostSizing struct {
	RequestedSize *HostSize `json:"requested_size,omitempty"`
	Template      string    `json:"template,omitempty"`
	AllocatedSize *HostSize `json:"allocated_size,omitempty"`
}

// NewHostSizing ...
func NewHostSizing() *HostSizing {
	return &HostSizing{
		RequestedSize: NewHostSize(),
		AllocatedSize: NewHostSize(),
	}
}

// HostSystem contains information about the operating system
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostSystem struct {
	Type     string `json:"type,omitempty"`     // Type of operating system (ie linux, windows, ... Not normalized yet...)
	Flavor   string `json:"flavor,omitempty"`   // Flavor of operating system (ie 'ubuntu server', 'windows server 2016', ... Not normalized yet...)
	Image    string `json:"image,omitempty"`    // Name of the provider's image used
	HostName string `json:"hostname,omitempty"` // Hostname on the system
}

// NewHostSystem ...
func NewHostSystem() *HostSystem {
	return &HostSystem{}
}

// HostVolume contains information about attached volume
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
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
//       Create a new version instead with needed supplemental fields
type HostVolumes struct {
	VolumesByID     map[string]*HostVolume `json:"volumes_by_id"`     // contains the volume name of the attached volume, indexed by ID
	VolumesByName   map[string]string      `json:"volumes_by_name"`   // contains the ID of attached volume, indexed by volume name
	VolumesByDevice map[string]string      `json:"volumes_by_device"` // contains the ID of attached volume, indexed by device
	DevicesByID     map[string]string      `json:"devices_by_id"`     // contains the device of attached volume, indexed by ID
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

// HostRemoteMount stores information about a remote filesystem mount
// not FROZEN yet
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

// HostMounts contains information about mounts on the host
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type HostMounts struct {
	LocalMountsByDevice   map[string]string           `json:"local_mounts_by_device"`  // contains local mount path, indexed by devices
	LocalMountsByPath     map[string]*HostLocalMount  `json:"local_mounts_by_path"`    // contains HostLocalMount structs, indexed by path
	RemoteMountsByShareID map[string]string           `json:"remote_mounts_by_device"` // contains local mount path, indexed by Share ID
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

// HostShare describes a filesystem exported from the host
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type HostShare struct {
	ID            string            `json:"id"`                         // ID ...
	Name          string            `json:"name"`                       // the name of the share
	Path          string            `json:"path"`                       // the path on the host filesystem that is shared
	PathAcls      string            `json:"path_acls,omitempty"`        // filesystem acls to set on the exported folder
	Type          string            `json:"type,omitempty"`             // export type is lowercase (ie. nfs, glusterfs, ...)
	ShareAcls     string            `json:"share_acls,omitempty"`       // the acls to set on the share
	ShareOptions  string            `json:"share_options,omitempty"`    // the options (other than acls) to set on the share
	ClientsByID   map[string]string `json:"clients_by_id,omit_empty"`   // contains the name of the hosts mounting the export, indexed by ID
	ClientsByName map[string]string `json:"clients_by_name,omit_empty"` // contains the ID of the hosts mounting the export, indexed by Name
}

// NewHostShare ...
func NewHostShare() *HostShare {
	return &HostShare{
		ClientsByID:   map[string]string{},
		ClientsByName: map[string]string{},
	}
}

// HostShares contains information about the shares of the host
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type HostShares struct {
	ByID   map[string]*HostShare `json:"by_id"`
	ByName map[string]string     `json:"by_name"`
}

// NewHostShares ...
func NewHostShares() *HostShares {
	return &HostShares{
		ByID:   map[string]*HostShare{},
		ByName: map[string]string{},
	}
}

// HostInstalledFeature ...
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type HostInstalledFeature struct {
	HostContext bool     `json:"host_context,omitempty"` // tells if the feature has been explicitly installed for host (opposed to for cluster)
	RequiredBy  []string `json:"required_by,omitempty"`  // tells what feature(s) needs this one
	Requires    []string `json:"requires,omitempty"`
}

// NewHostInstalledFeature ...
func NewHostInstalledFeature() *HostInstalledFeature {
	return &HostInstalledFeature{
		RequiredBy: []string{},
		Requires:   []string{},
	}
}

// HostFeatures ...
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostFeatures struct {
	Installed map[string]*HostInstalledFeature `json:"installed,omitempty"` // list of installed features, indexed on feature name
}

// NewHostFeatures ...
func NewHostFeatures() *HostFeatures {
	return &HostFeatures{
		Installed: map[string]*HostInstalledFeature{},
	}
}
