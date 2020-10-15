/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"fmt"
	"time"

	uuid "github.com/satori/go.uuid"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

const (
	HostDefaultSecurityGroupNameSuffix = "-host-default-sg"
)

// KeyPair represents a SSH key pair
type KeyPair struct {
	ID         string
	Name       string
	PrivateKey string
	PublicKey  string
}

// IsNull tells if the keypair is a null value
func (kp *KeyPair) IsNull() bool {
	return kp == nil || kp.Name == "" || kp.PublicKey == "" || kp.PrivateKey == ""
}

// NewKeyPair creates a *resources.KeyPair
func NewKeyPair(prefix string) (*KeyPair, fail.Error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, fail.Wrap(err, "failed to create host UUID")
	}

	if prefix == "" {
		prefix = "kp"
	}
	name := fmt.Sprintf("%s_%s", prefix, id)

	privKey, pubKey, xerr := crypt.GenerateRSAKeyPair(name)
	if err != nil {
		return nil, xerr
	}
	return &KeyPair{
		ID:         name,
		Name:       name,
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
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
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	URL         string `json:"url,omitempty"`
	Description string `json:"description,omitempty"`
	StorageType string `json:"storage_type,omitempty"`
	DiskSize    int64  `json:"disk_size_Gb,omitempty"`
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
	Subnets []*Subnet
	// defaultRouteIP is the IP used as default route
	DefaultRouteIP string
	// // DefaultGateway is the host used as default gateway
	// DefaultGateway *HostCore
	// getPublicIP a flag telling if the host must have a public IP
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
	// Use spot-like instance
	Disposable bool
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
// These information should not change over time
// TODO: profit of immutability status of HostCore to optimize some use (like SSHConfig), avoiding provider calls
type HostCore struct {
	ID         string         `json:"id,omitempty"`
	Name       string         `json:"name,omitempty"`
	PrivateKey string         `json:"private_key,omitempty"`
	Password   string         `json:"password,omitempty"`
	LastState  hoststate.Enum `json:"last_state,omitempty"`
}

// NewHostCore ...
func NewHostCore() *HostCore {
	return &HostCore{}
}

// IsNull tells if the instance is a null value
// satisfies interface data.NullValue
func (hc *HostCore) IsNull() bool {
	return hc == nil || (hc.ID == "" && hc.Name == "")
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
func (hc *HostCore) Serialize() ([]byte, fail.Error) {
	if hc == nil {
		return nil, fail.InvalidInstanceError()
	}

	r, jserr := json.Marshal(hc)
	if jserr != nil {
		return nil, fail.NewError(jserr.Error())
	}
	return r, nil
}

// Deserialize reads json code and reinstantiates an Host
func (hc *HostCore) Deserialize(buf []byte) (xerr fail.Error) {
	if hc == nil {
		return fail.InvalidInstanceError()
	}

	var panicErr error
	defer func() {
		if panicErr != nil {
			xerr = fail.ToError(panicErr) // If panic occured, transforms err to a fail.Error if needed
		}
	}()
	defer fail.OnPanic(&panicErr) // json.Unmarshal may panic

	jserr := json.Unmarshal(buf, hc)
	if jserr != nil {
		switch jserr.(type) {
		case *json.SyntaxError:
			return fail.SyntaxError(jserr.Error())
		default:
			return fail.NewError(jserr.Error())
		}
	}
	return nil
}

// GetName returns the name of the host
// Satisfies interface data.Identifiable
func (hc *HostCore) GetName() string {
	if hc == nil {
		return ""
	}
	return hc.Name
}

// GetID returns the ID of the host
// Satisfies interface data.Identifiable
func (hc *HostCore) GetID() string {
	if hc == nil {
		return ""
	}
	return hc.ID
}

// HostSubnet contains subnet information related to Host
type HostSubnet struct {
	IsGateway               bool              `json:"is_gateway,omitempty"`                 // Tells if host is a gateway of a network
	DefaultGatewayID        string            `json:"default_gateway_id,omitempty"`         // DEPRECATED: contains the ID of the default gateway
	DefaultGatewayPrivateIP string            `json:"default_gateway_private_ip,omitempty"` // DEPRECATED: contains the private IP of the default gateway
	DefaultSubnetID         string            `json:"default_network_id,omitempty"`         // contains the ID of the default subnet
	SubnetsByID             map[string]string `json:"networks_by_id,omitempty"`             // contains the name of each subnet bound to the host (indexed by ID)
	SubnetsByName           map[string]string `json:"networks_by_name,omitempty"`           // contains the ID of each subnet bound to the host (indexed by name)
	PublicIPv4              string            `json:"public_ip_v4,omitempty"`
	PublicIPv6              string            `json:"public_ip_v6,omitempty"`
	IPv4Addresses           map[string]string `json:"ipv4_addresses,omitempty"` // contains ipv4 (indexed by subnet ID) allocated to the host
	IPv6Addresses           map[string]string `json:"ipv6_addresses,omitempty"` // contains ipv6 (indexed by subnet ID) allocated to the host
}

// NewHostSubnet creates a new instance of HostSubnet
func NewHostSubnet() *HostSubnet {
	return &HostSubnet{
		SubnetsByID:   map[string]string{},
		SubnetsByName: map[string]string{},
		IPv4Addresses: map[string]string{},
		IPv6Addresses: map[string]string{},
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
	Core         *HostCore
	Sizing       *HostEffectiveSizing
	Subnet       *HostSubnet
	Description  *HostDescription
	CurrentState hoststate.Enum `json:"current_state,omitempty"`
}

// NewHostFull creates an instance of HostFull
func NewHostFull() *HostFull {
	return &HostFull{
		Core:         NewHostCore(),
		Sizing:       NewHostEffectiveSizing(),
		Subnet:       NewHostSubnet(),
		Description:  &HostDescription{},
		CurrentState: hoststate.UNKNOWN,
	}
}

// IsNull tells of the instance is a null value
// satisfies interface data.NullValue
func (hf *HostFull) IsNull() bool {
	return hf == nil || hf.Core.IsNull()
}

// IsConsistent returns true if the struct is consistent
func (hf *HostFull) IsConsistent() bool {
	return hf != nil && hf.Core.OK() // && hc.Description.OK() && hc.Sizing.OK() && hc.Network.OK()
}

// OK is a synonym to IsConsistent
func (hf *HostFull) OK() bool {
	if hf == nil {
		return false
	}
	return hf.IsConsistent()
}

// GetID returns the ID of the host
// satisfies interface data.Identifiable
func (hf *HostFull) GetID() string {
	return hf.Core.ID
}

// GetName returns the name of the host
// satisfies interface data.Identifiable
func (hf *HostFull) GetName() string {
	return hf.Core.Name
}

// HostList contains a list of HostFull
type HostList []*HostFull
