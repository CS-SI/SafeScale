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

package abstract

import (
	"encoding/json"
	"time"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// KeyPair represents a SSH key pair
type KeyPair struct {
	ID         string
	Name       string
	PrivateKey string
	PublicKey  string
}

// HostSizingRequirements represents host sizing requirements to fulfil
type HostSizingRequirements struct {
	MinCores    int
	MaxCores    int
	MinRAMSize  float32
	MaxRAMSize  float32
	MinDiskSize int
	MinGPU      int
	MinCPUFreq  float32
	Replaceable bool // Tells if we accept server that could be removed without notice (AWS proposes such kind of server with SPOT
	Image       string
}

// StoredCPUInfo ...
type StoredCPUInfo struct {
	ID           string `bow:"key"`
	TenantName   string `json:"tenant_name,omitempty"`
	TemplateID   string `json:"template_id,omitempty"`
	TemplateName string `json:"template_name,omitempty"`
	ImageID      string `json:"image_id,omitempty"`
	ImageName    string `json:"image_name,omitempty"`
	LastUpdated  string `json:"last_updated,omitempty"`

	NumberOfCPU    int     `json:"number_of_cpu,omitempty"`
	NumberOfCore   int     `json:"number_of_core,omitempty"`
	NumberOfSocket int     `json:"number_of_socket,omitempty"`
	CPUFrequency   float64 `json:"cpu_frequency_Ghz,omitempty"`
	CPUArch        string  `json:"cpu_arch,omitempty"`
	Hypervisor     string  `json:"hypervisor,omitempty"`
	CPUModel       string  `json:"cpu_model,omitempty"`
	RAMSize        float64 `json:"ram_size_Gb,omitempty"`
	RAMFreq        float64 `json:"ram_freq,omitempty"`
	GPU            int     `json:"gpu,omitempty"`
	GPUModel       string  `json:"gpu_model,omitempty"`
	DiskSize       int64   `json:"disk_size_Gb,omitempty"`
	MainDiskType   string  `json:"main_disk_type"`
	MainDiskSpeed  float64 `json:"main_disk_speed_MBps"`
	SampleNetSpeed float64 `json:"sample_net_speed_KBps"`
	EphDiskSize    int64   `json:"eph_disk_size_Gb"`
	PricePerHour   float64 `json:"price_in_dollars_hour"`
}

// Image represents an OS image
type Image struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	URL  string
}

// OK ...
func (i Image) OK() bool {
	result := true
	result = result && i.ID != ""
	result = result && i.Name != ""
	result = result && i.URL != ""
	return result
}

// HostRequest represents requirements to create host
type HostRequest struct {
	// ResourceName contains the name of the compute resource
	ResourceName string
	// HostName contains the hostname on the system (if empty, will use ResourceName)
	HostName string
	// Networks lists the networks the host must be connected to
	Networks []*Network
	// DefaultRouteIP is the IP used as default route
	DefaultRouteIP string
	// // DefaultGateway is the host used as default gateway
	// DefaultGateway *HostCore
	// PublicIP a flag telling if the host must have a public IP
	PublicIP bool
	// TemplateID is the UUID of the template used to size the host (see SelectTemplates)
	TemplateID string
	// ImageID is the UUID of the image that contains the server's OS and initial state.
	ImageID string
	// KeyPair is the (optional) specific KeyPair to use (if not provided, a new KeyPair will be generated)
	KeyPair *KeyPair
	// Password contains the safescale password usable on host console only
	Password string
	// DiskSize allows to ask for a specific size for system disk (in GB)
	DiskSize int
	// IsGateway tells if the host will act as a gateway
	IsGateway bool
	// KeepOnFailure tells if resource must be kept on failure
	KeepOnFailure bool
}

// HostEffectiveSizing ...
type HostEffectiveSizing struct {
	Cores     int     `json:"cores,omitempty"`
	RAMSize   float32 `json:"ram_size,omitempty"`
	DiskSize  int     `json:"disk_size,omitempty"`
	GPUNumber int     `json:"gpu_number,omitempty"`
	GPUType   string  `json:"gpu_type,omitempty"`
	CPUFreq   float32 `json:"cpu_freq,omitempty"`
	ImageID   string  `json:"image_id,omitempty"`
	// TODO: implement the handling of this field (will need to introduce provider capabilities to know if a specific provider allows this kind of host)
	Replaceable bool `json:"replaceable,omitempty"` // Tells if we accept server that could be removed without notice (AWS proposes such kind of server with SPOT
}

// NewHostEffectiveSizing ...
func NewHostEffectiveSizing() *HostEffectiveSizing {
	return &HostEffectiveSizing{}
}

// HostTemplate ...
type HostTemplate struct {
	Cores     int     `json:"cores,omitempty"`
	RAMSize   float32 `json:"ram_size,omitempty"`
	DiskSize  int     `json:"disk_size,omitempty"`
	GPUNumber int     `json:"gpu_number,omitempty"`
	GPUType   string  `json:"gpu_type,omitempty"`
	CPUFreq   float32 `json:"cpu_freq,omitempty"`
	ID        string  `json:"id,omitempty"`
	Name      string  `json:"name,omitempty"`
}

// OK ...
func (ht HostTemplate) OK() bool {
	result := true
	result = result && ht.ID != ""
	result = result && ht.Name != ""
	return result
}

// HostCore contains the core information about a host
type HostCore struct {
	ID         string         `json:"id,omitempty"`
	Name       string         `json:"name,omitempty"`
	LastState  hoststate.Enum `json:"state,omitempty"`
	PrivateKey string         `json:"private_key,omitempty"`
	Password   string         `json:"password,omitempty"`
}

// NewHostCore ...
func NewHostCore() *HostCore {
	return &HostCore{
		LastState: hoststate.UNKNOWN,
	}
}

// IsConsistent tells if host struct is consistent
func (hc *HostCore) IsConsistent() bool {
	result := true
	result = result && hc.ID != ""
	result = result && hc.Name != ""
	// result = result && h.PrivateKey != ""
	// result = result && h.Password != ""
	// result = result && h.properties != nil
	return result
}

// OK ...
func (hc *HostCore) OK() bool {
	return hc.IsConsistent()
}

// Clone does a deep-copy of the Host
//
// satisfies interface data.Clonable
func (hc *HostCore) Clone() data.Clonable {
	return NewHostCore().Replace(hc)
}

// Replace ...
//
// satisfies interface data.Clonable
func (hc *HostCore) Replace(p data.Clonable) data.Clonable {
	*hc = *p.(*HostCore)
	return hc
}

// Serialize serializes Host instance into bytes (output json code)
func (hc *HostCore) Serialize() ([]byte, fail.Report) {
	if hc == nil {
		return nil, fail.InvalidInstanceReport()
	}

	r, jserr := json.Marshal(hc)
	if jserr != nil {
		return nil, fail.NewReport(jserr.Error())
	}
	return r, nil
}

// Deserialize reads json code and reinstantiates an Host
func (hc *HostCore) Deserialize(buf []byte) (oerr fail.Report) {
	if hc == nil {
		return fail.InvalidInstanceReport()
	}

	var panicErr error
	defer func() {
		if panicErr != nil {
			oerr = fail.ErrorToReport(panicErr) // If panic occured, transforms err to a fail.Report if needed
		}
	}()
	defer fail.OnPanic(&panicErr) // json.Unmarshal may panic

	jserr := json.Unmarshal(buf, hc)
	if jserr != nil {
		return fail.NewReport(jserr.Error())
	}
	return nil
}

// SafeGetName returns the name of the host
// Satisfies interface data.Identifyable
func (hc *HostCore) SafeGetName() string {
	if hc == nil {
		return ""
	}
	return hc.Name
}

// SafeGetID returns the ID of the host
// Satisfies interface data.Identifyable
func (hc *HostCore) SafeGetID() string {
	if hc == nil {
		return ""
	}
	return hc.ID
}

// HostNetwork contains network information related to Host
type HostNetwork struct {
	IsGateway               bool              `json:"is_gateway,omitempty"`                 // Tells if host is a gateway of a network
	DefaultGatewayID        string            `json:"default_gateway_id,omitempty"`         // DEPRECATED: contains the ID of the Default Gateway
	DefaultGatewayPrivateIP string            `json:"default_gateway_private_ip,omitempty"` // DEPRECATED: contains the private IP of the default gateway
	DefaultNetworkID        string            `json:"default_network_id,omitempty"`         // contains the ID of the default Network
	NetworksByID            map[string]string `json:"networks_by_id,omitempty"`             // contains the name of each network binded to the host (indexed by ID)
	NetworksByName          map[string]string `json:"networks_by_name,omitempty"`           // contains the ID of each network binded to the host (indexed by Name)
	PublicIPv4              string            `json:"public_ip_v4,omitempty"`
	PublicIPv6              string            `json:"public_ip_v6,omitempty"`
	IPv4Addresses           map[string]string `json:"ipv4_addresses,omitempty"` // contains ipv4 (indexed by network ID) allocated to the host
	IPv6Addresses           map[string]string `json:"ipv6_addresses,omitempty"` // contains ipv6 (indexed by Network ID) allocated to the host
}

// NewHostNetwork creates a new instance of HostNetwork
func NewHostNetwork() *HostNetwork {
	return &HostNetwork{
		NetworksByID:   map[string]string{},
		NetworksByName: map[string]string{},
		IPv4Addresses:  map[string]string{},
		IPv6Addresses:  map[string]string{},
	}
}

// HostDescription contains description information for the host
type HostDescription struct {
	Created time.Time `json:"created,omitempty"`  // tells when the host has been created
	Creator string    `json:"creator,omitempty"`  // contains information (forged) about the creator of a host
	Updated time.Time `json:"modified,omitempty"` // tells the last time the host has been modified
	Purpose string    `json:"purpose,omitempty"`  // contains a description of the use of a host
	Tenant  string    `json:"tenant"`             // contains the tenant name used to create the host
}

// HostFull groups information about host coming from provider
type HostFull struct {
	Core        *HostCore
	Sizing      *HostEffectiveSizing
	Network     *HostNetwork
	Description *HostDescription
}

// NewHostFull ...
func NewHostFull() *HostFull {
	return &HostFull{
		Core:        NewHostCore(),
		Sizing:      NewHostEffectiveSizing(),
		Network:     NewHostNetwork(),
		Description: &HostDescription{},
	}
}

// IsConsistent returns true if the struct is consistent
func (hc *HostFull) IsConsistent() bool {
	return hc != nil && hc.Core.OK() // && hc.Description.OK() && hc.Sizing.OK() && hc.Network.OK()
}

// OK is a synonym to IsConsistent
func (hc *HostFull) OK() bool {
	if hc == nil {
		return false
	}
	return hc.IsConsistent()
}

// HostList contains a list of HostFull
type HostList []*HostFull
