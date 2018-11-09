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

	"github.com/CS-SI/SafeScale/providers/model/enums/HostExtension"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostState"
)

// KeyPair represents a SSH key pair
type KeyPair struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
}

// HostSize represent Sizing elements of an host
type HostSize struct {
	Cores     int     `json:"cores,omitempty"`
	RAMSize   float32 `json:"ram_size,omitempty"`
	DiskSize  int     `json:"disk_size,omitempty"`
	GPUNumber int     `json:"gpu_number,omitempty"`
	GPUType   string  `json:"gpu_type,omitempty"`
}

// HostTemplate represents an host template
type HostTemplate struct {
	HostSize `json:"host_size,omitempty"`
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
}

// SizingRequirements represents host sizing requirements to fulfil
type SizingRequirements struct {
	MinCores    int     `json:"min_cores,omitempty"`
	MinRAMSize  float32 `json:"min_ram_size,omitempty"`
	MinDiskSize int     `json:"min_disk_size,omitempty"`
}

// Image representes an OS image
type Image struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// HostRequest represents requirements to create virtual machine properties
type HostRequest struct {
	// ResourceName contains the name of the compute resource
	ResourceName string `json:"resource_name,omitempty"`
	// HostName contains the hostname on the system (if empty, will use ResourceName)
	HostName string `json:"host_name,omitempty"`
	//NetworksIDs list of the network IDs the host must be connected
	NetworkIDs []string `json:"network_ids,omitempty"`
	//PublicIP a flg telling if the host must have a public IP is
	PublicIP bool `json:"public_ip,omitempty"`
	//TemplateID the UUID of the template used to size the host (see SelectTemplates)
	TemplateID string `json:"template_id,omitempty"`
	//ImageID  is the UUID of the image that contains the server's OS and initial state.
	ImageID string   `json:"image_id,omitempty"`
	KeyPair *KeyPair `json:"key_pair,omitempty"`
}

// HostExtensionDescriptionV1 contains description information for the host
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostExtensionDescriptionV1 struct {
	Created time.Time `json:"created,omitempty"`  // tells when the host has been created
	Creator string    `json:"creator,omitempty"`  // contains information (forged) about the creator of a host
	Updated time.Time `json:"modified,omitempty"` // tells the last time the host has been modified
	Purpose string    `json:"purpose,omitempty"`  // contains a description of the use of a host
}

// HostExtensionNetworkV1 contains network information related to Host
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostExtensionNetworkV1 struct {
	IsGateway              bool              `json:"is_gateway,omitempty"`                // Tells if host is a gateway of a network
	DefaultGatewayID       string            `json:"default_gateway_id,omitempty"`        // contains the ID of the Default Gateway
	DefaultGatewayAccessIP string            `json:"default_gateway_access_ip,omitempty"` // contains the access IP of the default gateway
	DefaultNetworkID       string            `json:"default_network_id,omitempty"`        // contains the ID of the default Network
	NetworksByID           map[string]string `json:"networks_by_id,omitempty"`            // contains the name of each network binded to the host (indexed by ID)
	NetworksByName         map[string]string `json:"networks_by_name,omitempty"`          // contains the ID of each network binded to the host (indexed by Name)
	IPv4Addresses          map[string]string `json:"ipv4_addresses,omitempty"`            // contains ipv4 (indexed by network ID) allocated to the host
	IPv6Addresses          map[string]string `json:"ipv6_addresses,omitempty"`            // contains ipv6 (indexed by Network ID) allocated to the host
}

// HostExtensionSizingV1 contains sizing information about the host
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostExtensionSizingV1 struct {
	RequestedSize HostSize `json:"requested_size,omitempty"`
	Template      string   `json:"template,omitempty"`
	AllocatedSize HostSize `json:"allocated_size,omitempty"`
}

// HostExtensionSystemV1 ...
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostExtensionSystemV1 struct {
	Type     string `json:"type,omitempty"`     // Type of operating system (ie linux, windows, ... Not normalized yet...)
	Flavor   string `json:"flavor,omitempty"`   // Flavor of operating system (ie 'ubuntu server', 'windows server 2016', ... Not normalized yet...)
	Image    string `json:"image,omitempty"`    // Name of the provider's image used
	HostName string `json:"hostname,omitempty"` // Hostname on the system
}

// HostExtensionVolumeV1 ...
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostExtensionVolumeV1 struct {
	AttachedByID []string `json:"attached_by_id,omitempty"`
}

// HostExtensionFeatureV1Installed ...
type HostExtensionFeatureV1Installed struct {
	HostContext bool     `json:"host_context,omitempty"` // tells if the feature has been explicitly installed for host (opposed to for cluster)
	RequiredBy  []string `json:"required_by,omitempty"`  // tells what feature(s) needs this one
	Requires    []string `json:"requires,omitempty"`
}

// HostExtensionFeatureV1 ...
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostExtensionFeatureV1 struct {
	Installed map[string]HostExtensionFeatureV1Installed `json:"installed,omitempty"` // list of installed features, indexed on feature name
}

// Host represents a virtual machine properties
type Host struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	// Moved to HostExtensionNetworkV1
	//PrivateIPsV4 []string `json:"private_ips_v4,omitempty"`
	// Moved to HostExtensionNetworkV1
	//PrivateIPsV6 []string `json:"private_ips_v6,omitempty"`
	PublicIPv4 string `json:"public_ip_v4,omitempty"`
	PublicIPv6 string `json:"public_ip_v6,omitempty"`
	// Moved to HostExtensionSizingV1
	//Size       HostSize `json:"size,omitempty"`
	LastState  HostState.Enum `json:"state,omitempty"`
	PrivateKey string         `json:"private_key,omitempty"`
	//Move to HostExtensionNtworkV1
	//GatewayID  string `json:"gateway_id,omitempty"`
	// Extensions contains optional supplemental information (cf. metadata.Extensions)
	Extensions *Extensions `json:"extensions,omitempty"`
}

// NewHost ...
func NewHost() *Host {
	return &Host{
		Extensions: NewExtensions(),
	}
}

// GetAccessIP returns the IP to reach the host
func (h *Host) GetAccessIP() string {
	ip := h.GetPublicIP()
	if ip == "" {
		ip = h.GetPrivateIP()
	}
	return ip
}

// GetPublicIP computes public IP of the host
func (h *Host) GetPublicIP() string {
	ip := h.PublicIPv4
	if ip == "" {
		ip = h.PublicIPv6
	}
	return ip
}

// GetPrivateIP ...
func (h *Host) GetPrivateIP() string {
	heNetworkV1 := HostExtensionNetworkV1{}
	err := h.Extensions.Get(HostExtension.NetworkV1, &heNetworkV1)
	if err != nil {
		return ""
	}
	ip := ""
	if len(heNetworkV1.IPv4Addresses) > 0 {
		ip = heNetworkV1.IPv4Addresses[heNetworkV1.DefaultNetworkID]
		if ip == "" {
			ip = heNetworkV1.IPv6Addresses[heNetworkV1.DefaultNetworkID]
		}
	}
	return ip
}

// Serialize serializes Host instance into bytes (output json code)
func (h *Host) Serialize() ([]byte, error) {
	return SerializeToJSON(h)
}

// Deserialize reads json code and reinstanciates an Host
func (h *Host) Deserialize(buf []byte) error {
	return DeserializeFromJSON(buf, h)
}
