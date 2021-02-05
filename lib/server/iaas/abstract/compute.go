/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

	uuid "github.com/satori/go.uuid"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hoststate"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/abstract/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// KeyPair represents a SSH key pair
type KeyPair struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
}

// IsNull tells if the keypair is a null value
func (kp *KeyPair) IsNull() bool {
	return kp == nil || kp.Name == "" || kp.PublicKey == "" || kp.PrivateKey == ""
}

// NewKeyPair creates a *abstract.KeyPair
func NewKeyPair(prefix string) (*KeyPair, error) {
	id, err := uuid.NewV4()
	if err != nil {
		msg := fmt.Sprintf("failed to create host UUID: %+v", err)
		return nil, fail.Errorf(msg, err)
	}

	if prefix == "" {
		prefix = "kp"
	}
	name := fmt.Sprintf("%s_%s", prefix, id)

	privKey, pubKey, err := crypt.GenerateRSAKeyPair(name)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		ID:         name,
		Name:       name,
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

// SizingRequirements represents host sizing requirements to fulfil
type SizingRequirements struct {
	MinCores    int     `json:"min_cores,omitempty"`
	MaxCores    int     `json:"max_cores,omitempty"`
	MinRAMSize  float32 `json:"min_ram_size,omitempty"`
	MaxRAMSize  float32 `json:"max_ram_size,omitempty"`
	MinDiskSize int     `json:"min_disk_size,omitempty"`
	MinGPU      int     `json:"min_gpu,omitempty"`
	MinFreq     float32 `json:"min_freq,omitempty"`
	Replaceable bool    `json:"replaceable,omitempty"` // Tells if we accept server that could be removed without notice (AWS proposes such kind of server with SPOT
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
	StorageType string `json:"storagetype,omitempty"`
	DiskSize    int64  `json:"disk_size_Gb,omitempty"`
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
	// DefaultGateway is the host used as default gateway
	DefaultGateway *Host
	// PublicIP a flag telling if the host must have a public IP
	PublicIP bool
	// TemplateID is the UUID of the template used to size the host (see SelectTemplates)
	TemplateID string
	// ImageID is the UUID of the image that contains the server's OS and initial state.
	ImageID string
	// KeyPair is the (mandatory) specific KeyPair to use (if not provided, a new KeyPair will be generated) // FIXME: Add govalidator here
	KeyPair *KeyPair
	// Password contains the safescale password usable on host console only
	Password string
	// DiskSize allows to ask for a specific size for system disk (in GB)
	DiskSize int
	// Use spot instance
	Spot bool
}

// HostDefinition ...
type HostDefinition struct {
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

// Host contains the information about a host
type Host struct {
	ID         string                    `json:"id,omitempty"`
	Name       string                    `json:"name,omitempty"`
	LastState  hoststate.Enum            `json:"state,omitempty"`
	PrivateKey string                    `json:"private_key,omitempty"`
	Password   string                    `json:"password,omitempty"`
	Properties *serialize.JSONProperties `json:"properties,omitempty"`
	Tags       map[string]string         `json:"tags,omitempty"`
}

// NewHost ...
func NewHost() *Host {
	return &Host{
		Properties: serialize.NewJSONProperties("abstract.host"),
	}
}

// IsConsistent tells if host struct is consistent
func (h *Host) IsConsistent() bool {
	result := true
	result = result && h.ID != ""
	result = result && h.Name != ""
	// result = result && h.PrivateKey != ""
	// result = result && h.Password != ""
	result = result && h.Properties != nil
	return result
}

// OK ...
func (h *Host) OK() bool {
	return h.IsConsistent()
}

func (i Image) OK() bool {
	result := true
	result = result && i.ID != ""
	result = result && i.Name != ""
	result = result && i.URL != ""
	return result
}

func (ht HostTemplate) OK() bool {
	result := true
	result = result && ht.ID != ""
	result = result && ht.Name != ""
	return result
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
	var ip string
	err := h.Properties.LockForRead(hostproperty.NetworkV1).ThenUse(
		func(clonable data.Clonable) error {
			hostNetworkV1 := clonable.(*propsv1.HostNetwork)
			ip = hostNetworkV1.PublicIPv4
			if ip == "" {
				ip = hostNetworkV1.PublicIPv6
			}
			return nil
		},
	)
	if err != nil {
		return ""
	}
	return ip
}

// GetPrivateIP ...
func (h *Host) GetPrivateIP() string {
	var ip string
	err := h.Properties.LockForRead(hostproperty.NetworkV1).ThenUse(
		func(clonable data.Clonable) error {
			hostNetworkV1 := clonable.(*propsv1.HostNetwork)
			if len(hostNetworkV1.IPv4Addresses) > 0 {
				ip = hostNetworkV1.IPv4Addresses[hostNetworkV1.DefaultNetworkID]
				if ip == "" {
					ip = hostNetworkV1.IPv6Addresses[hostNetworkV1.DefaultNetworkID]
				}
				if ip == "" { // FIXME: AWS Fix for subnetworks
					for _, value := range hostNetworkV1.IPv4Addresses {
						if value != "" {
							ip = value
							break
						}
					}
				}
			}
			return nil
		},
	)
	if err != nil {
		return ""
	}
	return ip
}

// Content ...
// satisfies interface data.Clonable
func (h *Host) Content() data.Clonable {
	return h
}

// Clone ...
// satisfies interface data.Clonable
func (h *Host) Clone() data.Clonable {
	return NewHost().Replace(h)
}

// Replace ...
// satisfies interface data.Clonable
func (h *Host) Replace(p data.Clonable) data.Clonable {
	if p != nil {
		src := p.(*Host)
		*h = *src
		// FIXME: h.Properties have to be cloned also... but this will move outside this Host struct very soon (WIP on this subject...)
		//        Is it worth it?
	}
	return h
}

// Serialize serializes Host instance into bytes (output json code)
func (h *Host) Serialize() ([]byte, error) {
	return serialize.ToJSON(h)
}

// Deserialize reads json code and reinstantiates an Host
func (h *Host) Deserialize(buf []byte) error {
	if h.Properties == nil {
		h.Properties = serialize.NewJSONProperties("abstract.host")
	}
	err := serialize.FromJSON(buf, h)
	if err != nil {
		return err
	}

	return nil
}
