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

package abstract

import (
	stdjson "encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/gofrs/uuid"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// KeyPair represents a SSH key pair
type KeyPair struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// IsNull tells if the keypair is a null value
func (kp *KeyPair) IsNull() bool {
	return kp == nil || kp.Name == "" || kp.PublicKey == "" || kp.PrivateKey == ""
}

// NewKeyPair creates a *resources.KeyPair
func NewKeyPair(name string) (*KeyPair, fail.Error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, fail.Wrap(err, "failed to create host UUID")
	}

	if name == "" {
		name = fmt.Sprintf("kp_%s", id)
	}

	privKey, pubKey, xerr := crypt.GenerateRSAKeyPair(name)
	if xerr != nil {
		return nil, xerr
	}
	return &KeyPair{
		ID:         name,
		Name:       name,
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

// HostSizingRequirements represents host sizing requirements to fulfill
type HostSizingRequirements struct {
	MinCores    int
	MaxCores    int
	MinRAMSize  float32
	MaxRAMSize  float32
	MinDiskSize int
	MaxDiskSize int
	MinGPU      int
	MinCPUFreq  float32
	Replaceable bool // Tells if we accept server that could be removed without notice (AWS proposes such kind of server with SPOT
	Image       string
	Template    string // if != "", describes the template to use and disables the use of other fields
}

func almostEqual(a, b float32) bool {
	return math.Abs(float64(a-b)) <= 1e-6
}

func almostEqual64(a, b float64) bool { // nolint
	return math.Abs(a-b) <= 1e-6
}

func (hsr HostSizingRequirements) Equals(in HostSizingRequirements) bool {
	if hsr.MinCores != in.MinCores {
		return false
	}
	if hsr.MaxCores != in.MaxCores {
		return false
	}
	if !almostEqual(hsr.MinRAMSize, in.MinRAMSize) {
		return false
	}
	if !almostEqual(hsr.MaxRAMSize, in.MaxRAMSize) {
		return false
	}
	if hsr.MinDiskSize != in.MinDiskSize {
		return false
	}
	if hsr.MinGPU != in.MinGPU {
		return false
	}
	if !almostEqual(hsr.MinCPUFreq, in.MinCPUFreq) {
		return false
	}
	return true
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
	ResourceName     string              // ResourceName contains the name of the compute resource
	HostName         string              // HostName contains the hostname on the system (if empty, will use ResourceName)
	Subnets          []*Subnet           // lists the Subnets the host must be connected to
	DefaultRouteIP   string              // DefaultRouteIP is the IP used as default route
	TemplateID       string              // TemplateID is ID of the template used to size the host (see SelectTemplates)
	TemplateRef      string              // TemplateRef is the name or ID of the template used to size the host (see SelectTemplates)
	ImageID          string              // ImageID is the ID of the image that contains the server's OS and initial state.
	ImageRef         string              // ImageRef is the original reference of the image requested
	KeyPair          *KeyPair            // KeyPair is the (optional) specific KeyPair to use (if not provided, a new KeyPair will be generated)
	SSHPort          uint32              // contains the port to use for SSH
	Password         string              // Password contains the password of OperatorUsername account, usable on host console only
	DiskSize         int                 // DiskSize allows asking for a specific size for system disk (in GB)
	Single           bool                // Single tells if the Host is single
	PublicIP         bool                // PublicIP a flag telling if the host must have a public IP
	IsGateway        bool                // IsGateway tells if the host will act as a gateway
	KeepOnFailure    bool                // KeepOnFailure tells if resource must be kept on failure
	Preemptible      bool                // Use spot-like instance
	SecurityGroupIDs map[string]struct{} // List of Security Groups to attach to Host (using map as dict)
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

func (hse *HostEffectiveSizing) IsNull() bool {
	return hse == nil || hse.Cores == 0
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
// This information should not change over time, but IT ACTUALLY happens
type HostCore struct {
	ID                string            `json:"id,omitempty"`
	Name              string            `json:"name,omitempty"`
	PrivateKey        string            `json:"private_key,omitempty"`
	SSHPort           uint32            `json:"ssh_port,omitempty"`
	Password          string            `json:"password,omitempty"`
	LastState         hoststate.Enum    `json:"last_state"`         // Do not enable "omitempty", if state is "stopped", int value is 0, recognize as "not set" value during Serialize
	ProvisioningState hoststate.Enum    `json:"provisioning_state"` // Do not enable "omitempty", if state is "stopped", int value is 0, recognize as "not set" value during Serialize
	Tags              map[string]string `json:"tags,omitempty"`
}

// NewHostCore ...
func NewHostCore() *HostCore {
	hc := &HostCore{
		SSHPort: 22,
		Tags:    make(map[string]string),
	}

	hc.LastState = hoststate.Unknown
	hc.ProvisioningState = hoststate.Unknown
	hc.Tags["CreationDate"] = time.Now().Format(time.RFC3339)
	hc.Tags["ManagedBy"] = "safescale"
	return hc
}

// IsNull tells if the instance should be considered as a null value
func (hc *HostCore) IsNull() bool {
	return hc == nil || (hc.ID == "" && hc.Name == "")
}

// IsConsistent tells if host struct is consistent
func (hc *HostCore) IsConsistent() bool {
	return hc.ID != ""
}

// SetID is used to set ID field
func (hc *HostCore) SetID(id string) *HostCore {
	hc.ID = id
	return hc
}

// SetName is used to set Name field
func (hc *HostCore) SetName(name string) *HostCore {
	hc.Name = name
	return hc
}

// OK ...
func (hc *HostCore) OK() bool {
	return hc.IsConsistent()
}

// Clone does a deep-copy of the Host
// satisfies interface data.Clonable
func (hc HostCore) Clone() (data.Clonable, error) {
	return NewHostCore().Replace(&hc)
}

// Replace ...
// satisfies interface data.Clonable
func (hc *HostCore) Replace(p data.Clonable) (data.Clonable, error) {
	if hc == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	cloned, ok := p.(*HostCore)
	if !ok || cloned == nil {
		return nil, fmt.Errorf("p is not a *HostCore")
	}
	*hc = *cloned
	return hc, nil
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

// Deserialize reads json code and instantiates an Host
func (hc *HostCore) Deserialize(buf []byte) (ferr fail.Error) {
	if hc == nil {
		return fail.InvalidInstanceError()
	}

	var panicErr error
	defer func() {
		if panicErr != nil {
			ferr = fail.ConvertError(panicErr) // If panic occurred, transforms err to a fail.Error if needed
		}
	}()
	defer fail.OnPanic(&panicErr) // json.Unmarshal may panic

	jserr := json.Unmarshal(buf, hc)
	if jserr != nil {
		switch jserr.(type) {
		case *stdjson.SyntaxError:
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
	return hc.Name
}

// GetID returns the ID of the host
// Satisfies interface data.Identifiable
func (hc *HostCore) GetID() (string, error) {
	if hc == nil {
		return "", fmt.Errorf("invalid instance")
	}
	return hc.ID, nil
}

// HostNetworking contains subnets information related to Host
type HostNetworking struct {
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

// NewHostNetworking creates a new instance of HostNetworking
func NewHostNetworking() *HostNetworking {
	return &HostNetworking{
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
	Networking   *HostNetworking
	Description  *HostDescription
	CurrentState hoststate.Enum `json:"current_state"`
}

// NewHostFull creates an instance of HostFull
func NewHostFull() *HostFull {
	return &HostFull{
		Core:         NewHostCore(),
		Sizing:       NewHostEffectiveSizing(),
		Networking:   NewHostNetworking(),
		Description:  &HostDescription{},
		CurrentState: hoststate.Unknown,
	}
}

// IsNull tells if the instance should be considered as a null value
func (hf *HostFull) IsNull() bool {
	return hf == nil || valid.IsNil(hf.Core)
}

// IsConsistent returns true if the struct is consistent
func (hf *HostFull) IsConsistent() bool {
	return hf != nil && hf.Core.IsConsistent() // && hc.Description.OK() && hc.Sizing.OK() && hc.Networking.OK()
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
func (hf *HostFull) GetID() (string, error) {
	if hf == nil {
		return "", fmt.Errorf("invalid instance")
	}
	return hf.Core.ID, nil
}

// GetName returns the name of the host
// satisfies interface data.Identifiable
func (hf *HostFull) GetName() string {
	return hf.Core.Name
}

// SetName is a setter to initialize field 'Name'
func (hf *HostFull) SetName(name string) *HostFull {
	if hf != nil && hf.Core != nil {
		hf.Core.SetName(name)
	}
	return hf
}

// HostList contains a list of HostFull
type HostList []*HostFull

// LowerThan compares host sizing requirements, returns true if hsr requirements are lower than y
func (hsr *HostSizingRequirements) LowerThan(y *HostSizingRequirements) (bool, error) {
	if hsr == nil {
		return false, fail.InvalidInstanceError()
	}

	if y == nil {
		return false, fail.InvalidParameterError("y", "cannot be nil")
	}

	less := true

	if hsr.MinCores >= y.MinCores {
		if y.MinCores != 0 {
			less = false
		}
	}
	if hsr.MaxCores >= y.MaxCores {
		less = false
	}
	if hsr.MinRAMSize >= y.MinRAMSize {
		if y.MinRAMSize != 0 {
			less = false
		}
	}
	if hsr.MaxRAMSize >= y.MaxRAMSize {
		less = false
	}
	if hsr.MinDiskSize >= y.MinDiskSize {
		if y.MinDiskSize != 0 {
			less = false
		}
	}
	if hsr.MinGPU >= 0 && y.MinGPU >= 0 {
		if hsr.MinGPU >= y.MinGPU {
			less = false
		}
	}
	if hsr.MinCPUFreq >= y.MinCPUFreq {
		if y.MinCPUFreq != 0 {
			less = false
		}
	}

	return less, nil
}

// LowerOrEqualThan compares host sizing requirements, returns true if hsr requirements are lower or equal than y
func (hsr *HostSizingRequirements) LowerOrEqualThan(y *HostSizingRequirements) (bool, error) {
	if hsr == nil {
		return false, fail.InvalidInstanceError()
	}

	if y == nil {
		return false, fail.InvalidParameterError("y", "cannot be nil")
	}

	less := true

	if hsr.MinCores > y.MinCores {
		less = false
	}
	if hsr.MaxCores > y.MaxCores {
		less = false
	}
	if hsr.MinRAMSize > y.MinRAMSize {
		less = false
	}
	if hsr.MaxRAMSize > y.MaxRAMSize {
		less = false
	}
	if hsr.MinDiskSize > y.MinDiskSize {
		less = false
	}
	if hsr.MinGPU >= 0 && y.MinGPU >= 0 {
		if hsr.MinGPU > y.MinGPU {
			less = false
		}
	}
	if hsr.MinCPUFreq > y.MinCPUFreq {
		less = false
	}

	return less, nil
}
