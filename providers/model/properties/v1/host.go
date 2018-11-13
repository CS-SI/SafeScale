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

// BlankHostDescription is a pristine HostDescription
var BlankHostDescription = HostDescription{}

// HostNetwork contains network information related to Host
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostNetwork struct {
	IsGateway              bool              `json:"is_gateway,omitempty"`                // Tells if host is a gateway of a network
	DefaultGatewayID       string            `json:"default_gateway_id,omitempty"`        // contains the ID of the Default Gateway
	DefaultGatewayAccessIP string            `json:"default_gateway_access_ip,omitempty"` // contains the access IP of the default gateway
	DefaultNetworkID       string            `json:"default_network_id,omitempty"`        // contains the ID of the default Network
	NetworksByID           map[string]string `json:"networks_by_id,omitempty"`            // contains the name of each network binded to the host (indexed by ID)
	NetworksByName         map[string]string `json:"networks_by_name,omitempty"`          // contains the ID of each network binded to the host (indexed by Name)
	PublicIPv4             string            `json:"public_ip_v4,omitempty"`
	PublicIPv6             string            `json:"public_ip_v6,omitempty"`
	IPv4Addresses          map[string]string `json:"ipv4_addresses,omitempty"` // contains ipv4 (indexed by network ID) allocated to the host
	IPv6Addresses          map[string]string `json:"ipv6_addresses,omitempty"` // contains ipv6 (indexed by Network ID) allocated to the host
}

// BlankHostNetwork is a HostNetwork structure pristine
var BlankHostNetwork = HostNetwork{
	NetworksByID:   map[string]string{},
	NetworksByName: map[string]string{},
	IPv4Addresses:  map[string]string{},
	IPv6Addresses:  map[string]string{},
}

// HostSize represent sizing elements of an host
// FROZEN
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostSize struct {
	Cores     int     `json:"cores,omitempty"`
	RAMSize   float32 `json:"ram_size,omitempty"`
	DiskSize  int     `json:"disk_size,omitempty"`
	GPUNumber int     `json:"gpu_number,omitempty"`
	GPUType   string  `json:"gpu_type,omitempty"`
}

// BlankHostSize ...
var BlankHostSize = HostSize{}

// HostTemplate represents an host template
// FROZEN
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostTemplate struct {
	HostSize `json:"host_size,omitempty"`
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
}

// BlankHostTemplate ...
var BlankHostTemplate = HostTemplate{
	HostSize: BlankHostSize,
}

// HostSizing contains sizing information about the host
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostSizing struct {
	RequestedSize HostSize `json:"requested_size,omitempty"`
	Template      string   `json:"template,omitempty"`
	AllocatedSize HostSize `json:"allocated_size,omitempty"`
}

// BlankHostSizing ...
var BlankHostSizing = HostSizing{
	RequestedSize: BlankHostSize,
	AllocatedSize: BlankHostSize,
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

// BlankHostSystem ...
var BlankHostSystem = HostSystem{}

// HostVolume contains information about attached volume
type HostVolume struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Device string `json:"device"`
}

// BlankHostVolume ...
var BlankHostVolume = HostVolume{}

// HostVolumes contains information about attached volumes
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostVolumes struct {
	VolumeByID     map[string]HostVolume // contains the volume name of the attached volume, indexed by ID
	VolumeByName   map[string]string     // contains the ID of attached volume, indexed by volume name
	VolumeByDevice map[string]string     // contains the ID of attached volume, indexed by device
	DeviceByID     map[string]string     // contains the device of attached volume, indexed by ID
}

// BlankHostVolumes ...
var BlankHostVolumes = HostVolumes{
	VolumeByID:     map[string]HostVolume{},
	VolumeByName:   map[string]string{},
	VolumeByDevice: map[string]string{},
	DeviceByID:     map[string]string{},
}

// HostMount stores information about a device mount (being local or remote)
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type HostMount struct {
	// Local tells if the mount is local
	Local bool `json:"local"`
	// Device is the name of the device (/dev/... for local mount, host:/path for remote mount)
	Device string `json:"device,omitempty"`
	// Path is the mount point of the device
	Path string `json:"mountpoint,omitempty"`
	// FileSystem tells the filesystem used
	FileSystem string `json:"file_system,omitempty"`
	// Options contains the mount options
	Options string `json:"options,omitempty"`
}

// BlankHostMount ...
var BlankHostMount = HostMount{}

// HostMounts contains information about mounts on the host
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type HostMounts struct {
	MountsByDevice map[string]string    `json:"mounts_by_device"` // contains mount path, indexed by devices
	MountsByPath   map[string]HostMount `json:"mounts_by_path"`   // contains HostMount indexed by path
}

// BlankHostMounts ...
var BlankHostMounts = HostMounts{
	MountsByDevice: map[string]string{},
	MountsByPath:   map[string]HostMount{},
}

// HostExport describes an export by remote filesystem from the host
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type HostExport struct {
	// ID ...
	ID string `json:"uid"`
	// Name is the name of the export
	Name string `json:"name"`
	// Path is the path on the host filesystem exported
	Path string `json:"path"`
	// FsAcls are the filesystem acls to set on the exported folder
	PathAcls string `json:"path_acls,omitempty"`
	// Type is the export type (NFS, GlusterFS, ...)
	Type string `json:"type,omitempty"`
	// Acls are the acls to set on the export
	ExportAcls string `json:"export_acls,omitempty"`
	// ExportOptions are the options (other than acls) to set on the export
	ExportOptions string `json:"export_options,omitempty"`
	// ClientsByID contains the name of the hosts mounting the export, indexed by ID
	ClientsByID map[string]string `json:"clients_by_id,omit_empty"`
	// ClientsByName contains the ID of the hosts mounting the export, indexed by Name
	ClientsByName map[string]string `json:"clients_by_name,omit_empty"`
}

// BlankHostExport ...
var BlankHostExport = HostExport{
	ClientsByID:   map[string]string{},
	ClientsByName: map[string]string{},
}

// HostNas contains information about the Nas role of the host
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type HostNas struct {
	ExportsByID   map[string]HostExport `json:"exports_by_id"`
	ExportsByName map[string]string     `json:"exports_by_name"`
}

// BlankHostNas ...
var BlankHostNas = HostNas{
	ExportsByID:   map[string]HostExport{},
	ExportsByName: map[string]string{},
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

// BlankHostInstalledFeature ...
var BlankHostInstalledFeature = HostInstalledFeature{
	RequiredBy: []string{},
	Requires:   []string{},
}

// HostFeatures ...
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostFeatures struct {
	Installed map[string]HostInstalledFeature `json:"installed,omitempty"` // list of installed features, indexed on feature name
}

// BlankHostFeatures ...
var BlankHostFeatures = HostFeatures{
	Installed: map[string]HostInstalledFeature{},
}
