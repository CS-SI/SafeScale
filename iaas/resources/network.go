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

package resources

import (
	"github.com/CS-SI/SafeScale/iaas/resources/enums/IPVersion"
	"github.com/CS-SI/SafeScale/utils/serialize"
)

// GatewayRequest to create a Gateway into a network
type GatewayRequest struct {
	Network *Network
	CIDR    string
	// TemplateID the UUID of the template used to size the host (see SelectTemplates)
	TemplateID string
	// ImageID is the UUID of the image that contains the server's OS and initial state.
	ImageID string
	KeyPair *KeyPair
	// Name is the name to give to the gateway
	Name string
}

// NetworkRequest represents network requirements to create a subnet where Mask is defined in CIDR notation
// like "192.0.2.0/24" or "2001:db8::/32", as defined in RFC 4632 and RFC 4291.
type NetworkRequest struct {
	Name string
	// IPVersion must be IPv4 or IPv6 (see IPVersion)
	IPVersion IPVersion.Enum
	// CIDR mask
	CIDR string
	// DNSServers
	DNSServers []string
}

// Network representes a virtual network
type Network struct {
	ID         string                    `json:"id,omitempty"`         // ID for the network (from provider)
	Name       string                    `json:"name,omitempty"`       // Name of the network
	CIDR       string                    `json:"mask,omitempty"`       // network in CIDR notation
	GatewayID  string                    `json:"gateway_id,omitempty"` // contains the id of the host acting as gateway for the network
	IPVersion  IPVersion.Enum            `json:"ip_version,omitempty"` // IPVersion is IPv4 or IPv6 (see IPVersion)
	Properties *serialize.JSONProperties `json:"properties,omitempty"` // contains optional supplemental information
}

// NewNetwork ...
func NewNetwork() *Network {
	return &Network{
		Properties: serialize.NewJSONProperties("resources.network"),
	}
}

// Serialize serializes Host instance into bytes (output json code)
func (n *Network) Serialize() ([]byte, error) {
	return serialize.ToJSON(n)
}

// Deserialize reads json code and reinstanciates an Host
func (n *Network) Deserialize(buf []byte) error {
	if n.Properties == nil {
		n.Properties = serialize.NewJSONProperties("resources.network")
	} else {
		n.Properties.SetModule("resources.network")
	}
	err := serialize.FromJSON(buf, n)
	if err != nil {
		return err
	}

	return nil
}
