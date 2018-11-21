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
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostState"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
)

// KeyPair represents a SSH key pair
type KeyPair struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
}

// SizingRequirements represents host sizing requirements to fulfil
type SizingRequirements struct {
	MinCores    int     `json:"min_cores,omitempty"`
	MinRAMSize  float32 `json:"min_ram_size,omitempty"`
	MinDiskSize int     `json:"min_disk_size,omitempty"`
	MinGPU 		int     `json:"min_gpu,omitempty"`
	MinFreq 	float32 `json:"min_freq,omitempty"`
}

type StoredCPUInfo struct {
	Id      string `bow:"key"`
	TenantName   string `json:"tenant_name,omitempty"`
	TemplateID   string `json:"template_id,omitempty"`
	TemplateName string `json:"template_name,omitempty"`
	ImageID      string `json:"image_id,omitempty"`
	ImageName    string `json:"image_name,omitempty"`
	LastUpdated  string `json:"last_updated,omitempty"`

	NumberOfCPU    int     `json:"number_of_cpu,omitempty"`
	NumberOfCore   int     `json:"number_of_core,omitempty"`
	NumberOfSocket int     `json:"number_of_socket,omitempty"`
	CPUFrequency   float64 `json:"cpu_frequency,omitempty"`
	CPUArch        string  `json:"cpu_arch,omitempty"`
	Hypervisor     string  `json:"hypervisor,omitempty"`
	CPUModel       string  `json:"cpu_model,omitempty"`
	RAMSize        float64 `json:"ram_size,omitempty"`
	RAMFreq        float64 `json:"ram_freq,omitempty"`
	GPU            int     `json:"gpu,omitempty"`
	GPUModel       string  `json:"gpu_model,omitempty"`
}

// Image representes an OS image
type Image struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// HostRequest represents requirements to create host
type HostRequest struct {
	// ResourceName contains the name of the compute resource
	ResourceName string `json:"resource_name,omitempty"`
	// HostName contains the hostname on the system (if empty, will use ResourceName)
	HostName string `json:"host_name,omitempty"`
	// NetworksIDs lists the network IDs the host must be connected to
	NetworkIDs []string `json:"network_ids,omitempty"`
	// PublicIP a flag telling if the host must have a public IP
	PublicIP bool `json:"public_ip,omitempty"`
	// TemplateID is the UUID of the template used to size the host (see SelectTemplates)
	TemplateID string `json:"template_id,omitempty"`
	// ImageID is the UUID of the image that contains the server's OS and initial state.
	ImageID string `json:"image_id,omitempty"`
	// KeyPair is the (optional) specific KeyPair to use (if not provided, a new KeyPair will be generated)
	KeyPair *KeyPair `json:"key_pair,omitempty"`
}

// HostSize ...
type HostSize struct {
	*propsv1.HostSize
}

// HostTemplate ...
type HostTemplate struct {
	*propsv1.HostTemplate
}

// Host contains the information about a host
type Host struct {
	ID         string         `json:"id,omitempty"`
	Name       string         `json:"name,omitempty"`
	LastState  HostState.Enum `json:"state,omitempty"`
	PrivateKey string         `json:"private_key,omitempty"`
	Properties *Extensions    `json:"properties,omitempty"`
}

// NewHost ...
func NewHost() *Host {
	return &Host{
		Properties: NewExtensions(),
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
	hostNetworkV1 := propsv1.NewHostNetwork()
	err := h.Properties.Get(HostProperty.NetworkV1, hostNetworkV1)
	if err != nil {
		return ""
	}
	ip := hostNetworkV1.PublicIPv4
	if ip == "" {
		ip = hostNetworkV1.PublicIPv6
	}
	return ip
}

// GetPrivateIP ...
func (h *Host) GetPrivateIP() string {
	hostNetworkV1 := propsv1.NewHostNetwork()
	err := h.Properties.Get(HostProperty.NetworkV1, hostNetworkV1)
	if err != nil {
		return ""
	}
	ip := ""
	if len(hostNetworkV1.IPv4Addresses) > 0 {
		ip = hostNetworkV1.IPv4Addresses[hostNetworkV1.DefaultNetworkID]
		if ip == "" {
			ip = hostNetworkV1.IPv6Addresses[hostNetworkV1.DefaultNetworkID]
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
	err := DeserializeFromJSON(buf, h)
	if err != nil {
		return err
	}
	if h.Properties == nil {
		h.Properties = NewExtensions()
	}
	return nil
}
