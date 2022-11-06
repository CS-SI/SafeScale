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

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

// SubnetRequest represents requirements to create a subnet where Mask is defined in CIDR notation
// like "192.0.2.0/24" or "2001:db8::/32", as defined in RFC 4632 and RFC 4291.
type SubnetRequest struct {
	NetworkID      string         // contains the ID of the parent Network
	Name           string         // contains the name of the subnet (must be unique in a network)
	IPVersion      ipversion.Enum // must be IPv4 or IPv6 (see IPVersion)
	CIDR           string         // CIDR mask
	DNSServers     []string       // Contains the DNS servers to configure
	Domain         string         // contains the DNS suffix to use for this network
	HA             bool           // tells if 2 gateways and a VIP needs to be created; the VIP IP address will be used as gateway
	ImageRef       string         // contains the reference (ID or name) of the image requested for gateway(s)
	DefaultSSHPort uint32         // contains the port to use for SSH on all hosts of the subnet by default
	KeepOnFailure  bool           // tells if resources have to be kept in case of failure (default behavior is to delete them)
}

// CleanOnFailure tells if request asks for cleaning created ressource on failure
func (sr SubnetRequest) CleanOnFailure() bool {
	return !sr.KeepOnFailure
}

// Subnet represents a subnet4
type Subnet struct {
	*Core

	ID string `json:"id"` // ID of the subnet (from provider)
	// Name                    string            `json:"name"`                                 // Name of the subnet
	Network                 string           `json:"network"`                              // parent Network of the subnet
	CIDR                    string           `json:"mask"`                                 // ip network in CIDR notation
	Domain                  string           `json:"domain,omitempty"`                     // contains the domain used to define host FQDN
	DNSServers              []string         `json:"dns_servers,omitempty"`                // contains the DNSServers used on the subnet
	GatewayIDs              []string         `json:"gateway_id,omitempty"`                 // contains the id of the host(s) acting as gateway(s) for the subnet
	VIP                     *VirtualIP       `json:"vip,omitempty"`                        // contains the VIP of the network if created with HA
	IPVersion               ipversion.Enum   `json:"ip_version,omitempty"`                 // IPVersion is IPv4 or IPv6 (see IPVersion)
	State                   subnetstate.Enum `json:"status,omitempty"`                     // indicates the current state of the Subnet
	GWSecurityGroupID       string           `json:"gw_security_group_id,omitempty"`       // Contains the ID of the Security Group for external access of gateways in Subnet
	PublicIPSecurityGroupID string           `json:"publicip_security_group_id,omitempty"` // contains the ID of the Security Group for hosts with public IP in Subnet
	InternalSecurityGroupID string           `json:"internal_security_group_id,omitempty"` // contains the ID of the security group for internal access of hosts
	DefaultSSHPort          uint32           `json:"default_ssh_port,omitempty"`           // contains the port to use for SSH by default on gateways in the Subnet
	SingleHostCIDRIndex     uint             `json:"single_host_cidr_index,omitempty"`     // if > 0, contains the index of the CIDR in the single Host Network
	// Tags                    map[string]string `json:"tags,omitempty"`
}

// NewSubnet initializes a new instance of Subnet
func NewSubnet(opts ...Option) (*Subnet, fail.Error) {
	c, xerr := New(opts...)
	if xerr != nil {
		return nil, xerr
	}

	sn := &Subnet{
		Core:           c,
		State:          subnetstate.Unknown,
		DefaultSSHPort: 22,
	}
	return sn, nil
}

// IsNull ...
// satisfies interface clonable.Clonable
func (s *Subnet) IsNull() bool {
	return s == nil || s.Core.IsNull() || (s.ID == "" && s.Name == "")
}

// Clone ...
// satisfies interface clonable.Clonable
func (s *Subnet) Clone() (clonable.Clonable, error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	ns, xerr := NewSubnet(WithName(s.Name))
	if xerr != nil {
		return nil, xerr
	}

	return ns, ns.Replace(s)
}

// Replace ...
// satisfies interface clonable.Clonable
func (s *Subnet) Replace(p clonable.Clonable) error {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if p == nil {
		return fail.InvalidParameterCannotBeNilError("p")
	}

	src, err := lang.Cast[*Subnet](p)
	if err != nil {
		return err
	}

	*s = *src
	s.Core, err = clonable.CastedClone[*Core](src.Core)
	if err != nil {
		return err
	}

	s.DNSServers = make([]string, len(src.DNSServers), 0)
	copy(s.DNSServers, src.DNSServers)
	s.GatewayIDs = make([]string, len(src.GatewayIDs), 0)
	copy(s.GatewayIDs, src.GatewayIDs)

	return nil
}

// OK ...
func (s *Subnet) OK() bool {
	result := s != nil

	result = result && (s.ID != "")
	if s.ID == "" {
		logrus.Debug("Subnet without ID")
	}
	result = result && (s.Name != "")
	if s.Name == "" {
		logrus.Debug("Subnet without name")
	}
	result = result && (s.Network != "")
	if s.Name == "" {
		logrus.Debug("Subnet without parent Networking")
	}
	result = result && (s.CIDR != "")
	if s.CIDR == "" {
		logrus.Debug("Subnet without CIDR")
	}
	result = result && len(s.GatewayIDs) == 0

	return result
}

// Serialize serializes instance into bytes (output json code)
func (s *Subnet) Serialize() ([]byte, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	r, err := json.Marshal(s)
	return r, fail.ConvertError(err)
}

// Deserialize reads json code and reinstantiates a Subnet
func (s *Subnet) Deserialize(buf []byte) (ferr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	defer fail.OnPanic(&ferr) // json.Unmarshal may panic
	return fail.ConvertError(json.Unmarshal(buf, s))
}

// GetName ...
// satisfies interface data.Identifiable
func (s *Subnet) GetName() string {
	return s.Name
}

// GetID ...
// satisfies interface data.Identifiable
func (s *Subnet) GetID() (string, error) {
	if s == nil {
		return "", fmt.Errorf("invalid instance")
	}
	return s.ID, nil
}

func (s *Subnet) GetCIDR() string {
	return s.CIDR
}

// VirtualIP is a structure containing information needed to manage VIP (virtual IP)
type VirtualIP struct {
	*Core

	ID string `json:"id,omitempty"`
	// Name      string      `json:"name,omitempty"`    // Inside Core
	SubnetID  string      `json:"subnet_id,omitempty"`
	PrivateIP string      `json:"private_ip,omitempty"`
	PublicIP  string      `json:"public_ip,omitempty"`
	Hosts     []*HostCore `json:"hosts,omitempty"`

	NetworkID string `json:"network_id,omitempty"` // DEPRECATED: replaced by SubnetID
}

// NewVirtualIP ...
func NewVirtualIP(opts ...Option) (*VirtualIP, fail.Error) {
	nc, err := New(opts...)
	if err != nil {
		return nil, err
	}

	nvip := &VirtualIP{
		Core:  nc,
		Hosts: []*HostCore{},
	}
	return nvip, nil
}

// IsNull ...
// satisfies interface clonable.Clonable
func (vip *VirtualIP) IsNull() bool {
	return vip == nil || vip.Core.IsNull() || (vip.ID == "" && vip.Name == "")
}

// Clone ...
// satisfies interface clonable.Clonable
func (vip *VirtualIP) Clone() (clonable.Clonable, error) {
	if vip == nil {
		return nil, fail.InvalidInstanceError()
	}

	nvip, err := NewVirtualIP(WithName(vip.Name))
	if err != nil {
		return nil, err
	}

	return nvip, nvip.Replace(vip)
}

// Replace ...
// satisfies interface clonable.Clonable interface
func (vip *VirtualIP) Replace(p clonable.Clonable) error {
	if vip == nil {
		return fail.InvalidInstanceError()
	}

	src, ok := p.(*VirtualIP)
	if !ok {
		return fail.InconsistentError("failed to cast 'p' to '*VirtualIP'")
	}
	*vip = *src
	vip.Hosts = make([]*HostCore, 0, len(src.Hosts))
	for _, v := range src.Hosts {
		clone, err := clonable.CastedClone[*HostCore](v)
		if err != nil {
			return err
		}

		vip.Hosts = append(vip.Hosts, clone)
	}
	return nil
}
