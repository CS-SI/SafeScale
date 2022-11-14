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
	"encoding/json"
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

const NetworkKind = "network"

// NetworkRequest represents network requirements to create a network/VPC where CIDR contains a non-routable network
// like "192.0.2.0/24" or "2001:db8::/32", as defined in RFC 4632 and RFC 4291.
type NetworkRequest struct {
	Name          string   // contains name of Network/VPC
	CIDR          string   // contains the CIDR of the Network/VPC
	DNSServers    []string // list of dns servers to be used inside the Network/VPC
	KeepOnFailure bool     // KeepOnFailure tells if resources have to be kept in case of failure (default behavior is to delete them)
}

// CleanOnFailure tells if request asks for cleaning created ressource on failure
func (nr NetworkRequest) CleanOnFailure() bool {
	return !nr.KeepOnFailure
}

// SubNetwork is deprecated
type SubNetwork struct { // DEPRECATED: deprecated
	CIDR string `json:"subnetmask,omitempty"` // DEPRECATED: deprecated
	ID   string `json:"subnetid,omitempty"`   // DEPRECATED: deprecated
}

// Network represents a virtual network
type Network struct {
	*Core
	ID                 string         `json:"id"`                             // ID for the network (from provider)
	CIDR               string         `json:"mask"`                           // network in CIDR notation (if it has a meaning...)
	DNSServers         []string       `json:"dns_servers,omitempty"`          // list of dns servers to be used inside the Network/VPC
	Imported           bool           `json:"imported,omitempty"`             // tells if the Network has been imported (making it not deletable by SafeScale)
	Domain             string         `json:"domain,omitempty"`               // DEPRECATED: contains the domain used to define host FQDN
	GatewayID          string         `json:"gateway_id,omitempty"`           // DEPRECATED: contains the id of the host acting as primary gateway for the network
	SecondaryGatewayID string         `json:"secondary_gateway_id,omitempty"` // DEPRECATED: contains the id of the host acting as secondary gateway for the network
	VIP                *VirtualIP     `json:"vip,omitempty"`                  // DEPRECATED: contains the VIP of the network if created with HA
	IPVersion          ipversion.Enum `json:"ip_version,omitempty"`           // DEPRECATED: IPVersion is IPv4 or IPv6 (see IPVersion)
	Subnetworks        []SubNetwork   `json:"subnetworks,omitempty"`          // DEPRECATED: deprecated
}

// NewNetwork initializes a new instance of Network
func NewNetwork(opts ...Option) (*Network, fail.Error) {
	opts = append(opts, withKind(NetworkKind))
	c, xerr := newCore(opts...)
	if xerr != nil {
		return nil, xerr
	}

	nn := &Network{
		Core:       c,
		DNSServers: make([]string, 0),
		// Tags:       data.NewMap[string, string](),
	}
	// nn.Tags["CreationDate"] = time.Now().Format(time.RFC3339)
	// nn.Tags["ManagedBy"] = "safescale"
	return nn, nil
}

// NewEmptyNetwork returns a empty, unnamed Network instance
func NewEmptyNetwork() *Network {
	out, _ := NewNetwork()
	return out
}

// IsNull ...
// satisfies interface clonable.Clonable
func (n *Network) IsNull() bool {
	return n == nil || n.Core.IsNull() || n.ID == ""
}

// Clone ...
// satisfies interface clonable.Clonable
func (n *Network) Clone() (clonable.Clonable, error) {
	if n == nil {
		return nil, fail.InvalidInstanceError()
	}

	nn, xerr := NewNetwork(WithName(n.Name))
	if xerr != nil {
		return nil, xerr
	}

	return nn, nn.Replace(n)
}

// Replace ...
// satisfies interface clonable.Clonable
func (n *Network) Replace(p clonable.Clonable) error {
	if n == nil {
		return fail.InvalidInstanceError()
	}
	if p == nil {
		return fail.InvalidParameterCannotBeNilError("p")
	}

	src, err := lang.Cast[*Network](p)
	if err != nil {
		return err
	}

	*n = *src
	n.Core, err = clonable.CastedClone[*Core](src.Core)
	if err != nil {
		return err
	}

	n.DNSServers = make([]string, len(src.DNSServers))
	copy(n.DNSServers, src.DNSServers)
	return nil
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

// Serialize serializes Network instance into bytes (output json code)
func (n *Network) Serialize() ([]byte, fail.Error) {
	if n == nil {
		return nil, fail.InvalidInstanceError()
	}

	r, err := json.Marshal(n)
	return r, fail.ConvertError(err)
}

// Deserialize reads json code and reinstantiates a Network
func (n *Network) Deserialize(buf []byte) (ferr fail.Error) {
	if n == nil {
		return fail.InvalidInstanceError()
	}
	defer fail.OnPanic(&ferr) // json.Unmarshal may panic

	return fail.ConvertError(json.Unmarshal(buf, n))
}

// GetName ...
// satisfies interface data.Identifiable
func (n *Network) GetName() string {
	return n.Name
}

// GetID ...
// satisfies interface data.Identifiable
func (n *Network) GetID() (string, error) {
	if n == nil {
		return "", fmt.Errorf("invalid instance")
	}
	return n.ID, nil
}
