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
	"encoding/json"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// NetworkRequest represents network requirements to create a network/VPC where CIDR contains a non-routable network
// like "192.0.2.0/24" or "2001:db8::/32", as defined in RFC 4632 and RFC 4291.
type NetworkRequest struct {
	Name          string   // contains name of Network/VPC
	CIDR          string   // contains the CIDR of the Network/VPC
	DNSServers    []string // list of dns servers to be used inside the Network/VPC
	KeepOnFailure bool     // KeepOnFailure tells if resources have to be kept in case of failure (default behavior is to delete them)
}

// Network represents a virtual network
type Network struct {
	ID         string   `json:"id,omitempty"`          // ID for the network (from provider)
	Name       string   `json:"name,omitempty"`        // name of the network
	CIDR       string   `json:"mask,omitempty"`        // network in CIDR notation (if it has a meaning...)
	DNSServers []string `json:"dns_servers,omitempty"` // list of dns servers to be used inside the Network/VPC
	//Subnets    []string `json:"subnets,omitempty"`     // contains the list of subnet IDs created in Networking

	//SubnetState networkstate_obsolete.Enum `json:"status,omitempty"`  // state of the Networking
}

// NewNetwork initializes a new instance of Network
func NewNetwork() *Network {
	return &Network{
		//SubnetState: networkstate_obsolete.UNKNOWNSTATE,
	}
}

// Clone ...
// satisfies interface data.Clonable
func (n Network) Clone() data.Clonable {
	return NewNetwork().Replace(&n)
}

// Replace ...
// satisfies interface data.Clonable
func (n *Network) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value...
	if n == nil || p == nil {
		return n
	}

	src := p.(*Network)
	*n = *src
	n.DNSServers = make([]string, 0, len(src.DNSServers))
	copy(n.DNSServers, src.DNSServers)
	//n.Subnets = make([]string, 0, len(src.Subnets))
	//copy(n.Subnets, src.Subnets)
	return n
}

// OK ...
func (n *Network) OK() bool {
	result := n != nil

	result = result && (n.ID != "")
	if n.ID == "" {
		logrus.Debug("Networking without ID")
	}
	result = result && (n.Name != "")
	if n.Name == "" {
		logrus.Debug("Networking without name")
	}
	result = result && (n.CIDR != "")
	if n.CIDR == "" {
		logrus.Debug("Networking without CIDR")
	}

	return result
}

// Serialize serializes IPAddress instance into bytes (output json code)
func (n *Network) Serialize() ([]byte, fail.Error) {
	if n == nil {
		return nil, fail.InvalidInstanceError()
	}
	r, err := json.Marshal(n)
	return r, fail.ConvertError(err)
}

// Deserialize reads json code and reinstantiates an IPAddress
func (n *Network) Deserialize(buf []byte) (xerr fail.Error) {
	if n == nil {
		return fail.InvalidInstanceError()
	}
	defer fail.OnPanic(&xerr) // json.Unmarshal may panic
	return fail.ConvertError(json.Unmarshal(buf, n))
}

// GetName ...
// satisfies interface data.Identifiable
func (n *Network) GetName() string {
	if n == nil {
		return ""
	}
	return n.Name
}

// GetID ...
// satisfies interface data.Identifiable
func (n *Network) GetID() string {
	if n == nil {
		return ""
	}
	return n.ID
}
