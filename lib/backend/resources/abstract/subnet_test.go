/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubnet_NewSubnet(t *testing.T) {

	s, _ := NewSubnet()
	if !s.IsNull() {
		t.Error("Subnet is expected to be null!")
		t.Fail()
	}
	if s.OK() {
		t.Error("Subnet is expected not to be ok!")
		t.Fail()
	}
	s.ID = "Subnet ID"
	s.Name = "Subnet Name"
	s.Network = "Subnet Network"
	s.CIDR = "Subnet CIDR"
	if s.IsNull() {
		t.Error("Subnet is expected to be not null!")
		t.Fail()
	}
	if !s.OK() {
		t.Error("Subnet is expected to be ok!")
		t.Fail()
	}

}

func TestSubnet_Replace(t *testing.T) {
	var s *Subnet
	ns, _ := NewSubnet()
	err := s.Replace(ns)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
}

func TestSubnet_Clone(t *testing.T) {
	s, _ := NewSubnet()
	s.ID = "Subnet ID"
	s.Name = "Subnet Name"
	s.Network = "Subnet Network"
	s.CIDR = "Subnet CIDR"
	s.Domain = "Subnet Domain"
	s.DNSServers = []string{"DNS1", "DNS2", "DNS3"}
	s.GatewayIDs = []string{"GatewayID1", "GatewayID2", "GatewayID3"}

	var err error
	s.VIP, err = NewVirtualIP(WithName("vip"))
	require.Nil(t, err)

	s.IPVersion = ipversion.IPv4
	s.GWSecurityGroupID = "Subnet GWSecurityGroupID"
	s.PublicIPSecurityGroupID = "Subnet PublicIPSecurityGroupID"
	s.InternalSecurityGroupID = "Subnet InternalSecurityGroupID"
	s.DefaultSSHPort = 42
	s.SingleHostCIDRIndex = 14

	sc, err := clonable.CastedClone[*Subnet](s)
	require.Nil(t, err)

	assert.Equal(t, s, sc)
	require.EqualValues(t, s, sc)

	sc.Domain = "net.local"
	areEqual := reflect.DeepEqual(s, sc)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, s, sc)
}

func TestSubnet_Serialize(t *testing.T) {

	var s *Subnet = nil
	_, err := s.Serialize()
	if err == nil {
		t.Error("Can't serialize nil pointer")
		t.Fail()
	}

	s, _ = NewSubnet()
	s.ID = "Subnet ID"
	s.Name = "Subnet Name"
	s.Network = "Subnet Network"
	s.CIDR = "Subnet CIDR"
	s.Domain = "Subnet Domain"
	s.DNSServers = []string{"DNS1", "DNS2", "DNS3"}
	s.GatewayIDs = []string{"GatewayID1", "GatewayID2", "GatewayID3"}
	// s.VIP = NewVirtualIP() //DeepEqual does not work with pointer
	s.IPVersion = ipversion.IPv4
	s.GWSecurityGroupID = "Subnet GWSecurityGroupID"
	s.PublicIPSecurityGroupID = "Subnet PublicIPSecurityGroupID"
	s.InternalSecurityGroupID = "Subnet InternalSecurityGroupID"
	s.DefaultSSHPort = 42
	s.SingleHostCIDRIndex = 14

	serial, err := s.Serialize()
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	s2, _ := NewSubnet()
	err = s2.Deserialize(serial)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	areEqual := reflect.DeepEqual(s, s2)
	if !areEqual {
		t.Error("Serialize/Deserialize does not restitute values")
		t.Fail()
	}
}

func TestSubnet_Deserialize(t *testing.T) {
	serial := []byte("{\"id\":\"Subnet ID\",\"name\":\"Subnet Name\",\"network\":\"Subnet Network\",\"mask\":\"Subnet CIDR\",\"domain\":\"Subnet Domain\",\"dns_servers\":[\"DNS1\",\"DNS2\",\"DNS3\"], \"gateway_id\":[\"GatewayID1\",\"GatewayID2\",\"GatewayID3\"],\"ip_version\":4,\"gw_security_group_id\":\"Subnet GWSecurityGroupID\",\"publicip_security_group_id\":\"Subnet PublicIPSecurityGroupID\",\"internal_security_group_id\":\"Subnet InternalSecurityGroupID\",\"default_ssh_port\":42,\"single_host_cidr_index\":14,\"tags\":{\"CreationDate\":\"2022-01-21T16:46:55+01:00\",\"ManagedBy\":\"safescale\"}}\"")
	var s *Subnet
	err := s.Deserialize(serial)
	if err == nil {
		t.Error("Can't deserialize to nil pointer")
		t.Fail()
	}

}

func TestVirtualIP_Clone(t *testing.T) {
	v, _ := NewVirtualIP(WithName("VirtualIP Name"))
	v.ID = "VirtualIP ID"
	v.SubnetID = "VirtualIP SubnetID"
	v.PrivateIP = "VirtualIP PrivateIP"
	v.PublicIP = "VirtualIP PublicIP"
	v.NetworkID = "VirtualIP NetworkID"
	h1, _ := NewHostCore(WithName("h1"))
	h2, _ := NewHostCore(WithName("h2"))
	h3, _ := NewHostCore(WithName("h3"))
	v.Hosts = []*HostCore{h1, h2, h3}

	v2, err := clonable.CastedClone[*VirtualIP](v)
	require.Nil(t, err)

	areEqual := reflect.DeepEqual(v, v2)
	if !areEqual {
		t.Error("TestVirtualIP_Clone does not preserves values")
		t.Fail()
	}

	v2.SubnetID = "VirtualIP SubnetID2"
	areEqual = reflect.DeepEqual(v, v2)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}

	require.NotEqualValues(t, v, v2)

}

func TestSubnet_GetName(t *testing.T) {

	s, _ := NewSubnet()
	s.Name = "Subnet Name"
	name := s.GetName()
	if name != s.Name {
		t.Error("Wrong value restitution")
		t.Fail()
	}

}

func TestSubnet_GetID(t *testing.T) {

	s, _ := NewSubnet()
	s.ID = "Subnet ID"
	id, _ := s.GetID()
	if id != s.ID {
		t.Error("Wrong value restitution")
		t.Fail()
	}
}

func TestSubnet_GetCIDR(t *testing.T) {
	s, _ := NewSubnet()
	s.ID = "Subnet ID"
	cidr := s.GetCIDR()
	if cidr != s.CIDR {
		t.Error("Wrong value restitution")
		t.Fail()
	}
}

func TestVirtualIP_IsNull(t *testing.T) {
	v, _ := NewVirtualIP()
	if !v.IsNull() {
		t.Error("Virtual IP is expected to be null!")
		t.Fail()
	}
	v.ID = "VirtualIP ID"
	if v.IsNull() {
		t.Error("VirtualIP is expected to be not null!")
		t.Fail()
	}
	v.ID = ""
	v.Name = "VirtualIP Name"
	if v.IsNull() {
		t.Error("VirtualIP is expected to be not null!")
		t.Fail()
	}
}

func TestVirtualIP_Replace(t *testing.T) {
	var v *VirtualIP = nil
	v2, _ := NewVirtualIP()
	err := v.Replace(v2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
}
