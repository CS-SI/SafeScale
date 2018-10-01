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

package core

import (

	// "github.com/CS-SI/SafeScale/system"

	"github.com/CS-SI/SafeScale/providers/api/enums/IPVersion"
)

// GatewayRequest to create a Gateway into a network
type GatewayRequest struct {
	NetworkID string `json:"network_id,omitempty"`
	//TemplateID the UUID of the template used to size the host (see SelectTemplates)
	TemplateID string `json:"template_id,omitempty"`
	//ImageID is the UUID of the image that contains the server's OS and initial state.
	ImageID string   `json:"image_id,omitempty"`
	KeyPair *KeyPair `json:"key_pair,omitempty"`
	//GWName is the name to give to the gateway
	GWName string `json:"gw_name,omitempty"`
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
