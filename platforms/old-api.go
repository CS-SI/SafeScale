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

package api

import (
	"fmt"
	"io"
	"time"

	// "github.com/CS-SI/SafeScale/system"

	"github.com/CS-SI/SafeScale/providers/api/enums/HostExtension"
	"github.com/CS-SI/SafeScale/providers/api/enums/HostState"
	"github.com/CS-SI/SafeScale/providers/api/enums/IPVersion"
	"github.com/CS-SI/SafeScale/providers/api/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/api/enums/VolumeState"
)

const (
	// DefaultUser Default Host user
	DefaultUser = "gpac"

	// DefaultVolumeMountPoint Default mount point for volumes
	DefaultVolumeMountPoint = "/shared/"

	// DefaultContainerMountPoint Default mount point for containers
	DefaultContainerMountPoint = "/containers/"

	// DefaultNasExposedPath Default path to be exported by nfs server
	DefaultNasExposedPath = "/shared/data"

	// DefaultNasMountPath Default path to be mounted to access a nfs directory
	DefaultNasMountPath = "/data"
)

//ErrTimeout defines a Timeout error
type ErrTimeout struct {
	Message string
}

func (e *ErrTimeout) Error() string {
	return e.Message
}

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

// HostExtensionType ...
type HostExtensionType map[HostExtension.Enum]interface{}

// Host represents a virtual machine properties
type Host struct {
	ID           string         `json:"id,omitempty"`
	Name         string         `json:"name,omitempty"`
	PrivateIPsV4 []string       `json:"private_ips_v4,omitempty"`
	PrivateIPsV6 []string       `json:"private_ips_v6,omitempty"`
	AccessIPv4   string         `json:"access_ip_v4,omitempty"`
	AccessIPv6   string         `json:"access_ip_v6,omitempty"`
	Size         HostSize       `json:"size,omitempty"`
	State        HostState.Enum `json:"state,omitempty"`
	PrivateKey   string         `json:"private_key,omitempty"`
	GatewayID    string         `json:"gateway_id,omitempty"`
	// This field can contain any kind of supplemental information that will be stored as-is
	// functions using
	Extension HostExtensionType `json:"additional_info,omitempty"`
}

// GetAccessIP computes access IP of the host
func (host *Host) GetAccessIP() string {
	ip := host.AccessIPv4
	if ip == "" {
		ip = host.AccessIPv6
	}
	if ip == "" {
		if len(host.PrivateIPsV4) > 0 {
			ip = host.PrivateIPsV4[0]
		} else {
			ip = host.PrivateIPsV6[0]
		}
	}
	return ip
}

// GetPublicIP computes public IP of the host
func (host *Host) GetPublicIP() string {
	ip := host.AccessIPv4
	if ip == "" {
		ip = host.AccessIPv6
	}
	return ip
}

// GetPrivateIP computes private IP of the host
func (host *Host) GetPrivateIP() string {
	ip := ""
	if len(host.PrivateIPsV4) > 0 {
		ip = host.PrivateIPsV4[0]
	} else {
		if len(host.PrivateIPsV6) > 0 {
			ip = host.PrivateIPsV6[0]
		}
	}
	return ip
}

// HostRequest represents requirements to create virtual machine properties
type HostRequest struct {
	Name string `json:"name,omitempty"`
	//NetworksIDs list of the network IDs the host must be connected
	NetworkIDs []string `json:"network_i_ds,omitempty"`
	//PublicIP a flg telling if the host must have a public IP is
	PublicIP bool `json:"public_ip,omitempty"`
	//TemplateID the UUID of the template used to size the host (see SelectTemplates)
	TemplateID string `json:"template_id,omitempty"`
	//ImageID  is the UUID of the image that contains the server's OS and initial state.
	ImageID string   `json:"image_id,omitempty"`
	KeyPair *KeyPair `json:"key_pair,omitempty"`
}

// GWRequest to create a Gateway into a network
type GWRequest struct {
	NetworkID string `json:"network_id,omitempty"`
	//TemplateID the UUID of the template used to size the host (see SelectTemplates)
	TemplateID string `json:"template_id,omitempty"`
	//ImageID is the UUID of the image that contains the server's OS and initial state.
	ImageID string   `json:"image_id,omitempty"`
	KeyPair *KeyPair `json:"key_pair,omitempty"`
	//GWName is the name to give to the gateway
	GWName string `json:"gw_name,omitempty"`
}

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

//VolumeAttachment represents a volume attachment
type VolumeAttachment struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	VolumeID   string `json:"volume,omitempty"`
	ServerID   string `json:"host,omitempty"`
	Device     string `json:"device,omitempty"`
	MountPoint string `json:"mountpoint,omitempty"`
	Format     string `json:"format,omitempty"`
}

//VolumeAttachmentRequest represents a volume attachment request
type VolumeAttachmentRequest struct {
	Name     string `json:"name,omitempty"`
	VolumeID string `json:"volume,omitempty"`
	ServerID string `json:"host,omitempty"`
}

// Nas represents a nas definition
type Nas struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Host     string `json:"host,omitempty"`
	Path     string `json:"path,omitempty"`
	IsServer bool   `json:"isServer,omitempty"`
}

//Image representes an OS image
type Image struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

//ContainerInfo represents a container description
type ContainerInfo struct {
	Name       string `json:"name,omitempty"`
	Host       string `json:"host,omitempty"`
	MountPoint string `json:"mountPoint,omitempty"`
	NbItems    int    `json:"nbitems,omitempty"`
}

/*
// RouterRequest represents a router request
type RouterRequest struct {
	Name string `json:"name,omitempty"`
	//NetworkID is the Network ID which the router gateway is connected to.
	NetworkID string `json:"network_id,omitempty"`
}

// Router represents a router
type Router struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	//NetworkID is the Network ID which the router gateway is connected to.
	NetworkID string `json:"network_id,omitempty"`
}
*/

// Network representes a virtual network
type Network struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	//IPVersion is IPv4 or IPv6 (see IPVersion)
	IPVersion IPVersion.Enum `json:"ip_version,omitempty"`
	//Mask mask in CIDR notation
	CIDR string `json:"mask,omitempty"`
	// //Gateway network gateway
	GatewayID string `json:"gwid,omitempty"`
}

/*
// Subnet represents a sub network where Mask is defined in CIDR notation
// like "192.0.2.0/24" or "2001:db8::/32", as defined in RFC 4632 and RFC 4291.
type Subnet struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	//IPVersion is IPv4 or IPv6 (see IPVersion)
	IPVersion IPVersion.Enum `json:"ip_version,omitempty"`
	//Mask mask in CIDR notation
	Mask string `json:"mask,omitempty"`
	//NetworkID id of the parent network
	NetworkID string `json:"network_id,omitempty"`
}
*/

// NetworkRequest represents network requirements to create a subnet where Mask is defined in CIDR notation
// like "192.0.2.0/24" or "2001:db8::/32", as defined in RFC 4632 and RFC 4291.
type NetworkRequest struct {
	Name string `json:"name,omitempty"`
	//IPVersion must be IPv4 or IPv6 (see IPVersion)
	IPVersion IPVersion.Enum `json:"ip_version,omitempty"`
	//CIDR mask
	CIDR string `json:"cidr,omitempty"`
}

// Object object to put in a container
type Object struct {
	Name          string            `json:"name,omitempty"`
	Content       io.ReadSeeker     `json:"content,omitempty"`
	DeleteAt      time.Time         `json:"delete_at,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Date          time.Time         `json:"date,omitempty"`
	LastModified  time.Time         `json:"last_modified,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	ContentLength int64             `json:"content_length,omitempty"`
}

// ObjectFilter filter object
type ObjectFilter struct {
	Prefix string `json:"prefix,omitempty"`
	Path   string `json:"path,omitempty"`
}

// Range Defines a range of bytes
type Range struct {
	From *int `json:"from,omitempty"`
	To   *int `json:"to,omitempty"`
}

// NewRange creates a range
func NewRange(from, to int) Range {
	return Range{&from, &to}
}

func (r Range) String() string {
	if r.From != nil && r.To != nil {
		return fmt.Sprintf("%d-%d", *r.From, *r.To)
	}
	if r.From != nil {
		return fmt.Sprintf("%d-", *r.From)
	}
	if r.To != nil {
		return fmt.Sprintf("%d", *r.To)
	}
	return ""
}

// ConfigMap is a map[string]string that implements
// the Config method.
type ConfigMap map[string]interface{}

// Config gets a string configuration value and a
// bool indicating whether the value was present or not.
func (c ConfigMap) Config(name string) (interface{}, bool) {
	val, ok := c[name]
	return val, ok
}

// Get is an alias to Config()
func (c ConfigMap) Get(name string) (interface{}, bool) {
	return c.Config(name)
}

// GetString returns a string corresponding to the key, empty string if it doesn't exist
func (c ConfigMap) GetString(name string) string {
	val, ok := c.Get(name)
	if ok {
		return val.(string)
	}
	return ""
}

// GetSliceOfStrings returns a string slice corresponding to the key, empty string slice if it doesn't exist
func (c ConfigMap) GetSliceOfStrings(name string) []string {
	val, ok := c.Get(name)
	if ok {
		return val.([]string)
	}
	return []string{}
}

// GetMapOfStrings returns a string map of strings correspondong to the key, empty map if it doesn't exist
func (c ConfigMap) GetMapOfStrings(name string) map[string]string {
	val, ok := c.Get(name)
	if ok {
		return val.(map[string]string)
	}
	return map[string]string{}
}

// GetInteger returns an integer corresponding to the key, 0 if it doesn't exist
func (c ConfigMap) GetInteger(name string) int {
	val, ok := c.Get(name)
	if ok {
		return val.(int)
	}
	return 0
}

// Set sets name configuration to value
func (c ConfigMap) Set(name string, value interface{}) {
	c[name] = value
}
