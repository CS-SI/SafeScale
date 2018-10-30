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

package resource

import (
	"github.com/CS-SI/SafeScale/iaas/resource/enums/HostState"
)

const (
	// DefaultUser Default Host user
	DefaultUser = "gpac"
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
}

// GetAccessIP computes access IP of the host
func (host *Host) GetAccessIP() string {
	ip := host.AccessIPv4
	if ip == "" {
		ip = host.AccessIPv6
	}
	// if ip == "" {
	// 	if len(host.PrivateIPsV4) > 0 {
	// 		ip = host.PrivateIPsV4[0]
	// 	} else {
	// 		ip = host.PrivateIPsV6[0]
	// 	}
	// }
	return ip
}

// // GetPublicIP computes public IP of the host
// func (host *Host) GetPublicIP() string {
// 	ip := host.AccessIPv4
// 	if ip == "" {
// 		ip = host.AccessIPv6
// 	}
// 	return ip
// }

// // GetPrivateIP computes private IP of the host
// func (host *Host) GetPrivateIP() string {
// 	anon, err := host.GetExtension(HostExtension.NetworkV1)
// 	if err != nil || anon == nil {
// 		return ""
// 	}
// 	ex := anon.(HostExtensionNetworkV1)
// 	ip := ""
// 	if len(ex.PrivateIPsV4) > 0 {
// 		ip = ex.PrivateIPsV4[0]
// 	} else {
// 		if len(ex.PrivateIPsV6) > 0 {
// 			ip = ex.PrivateIPsV6[0]
// 		}
// 	}
// 	return ip
// }

// HostRequest contains the properties corresponding to the requirements to create Host resource
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

// Image representes an OS image
type Image struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}
