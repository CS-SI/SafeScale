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
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubnet_NewSubnet(t *testing.T) {

	s := NewSubnet()
	if !s.IsNull() {
		t.Error("Subnet is null !")
		t.Fail()
	}
	if s.OK() {
		t.Error("Subnet is not ok !")
		t.Fail()
	}
	s.ID = "Subnet ID"
	s.Name = "Subnet Name"
	s.Network = "Subnet Network"
	s.CIDR = "Subnet CIDR"
	if s.IsNull() {
		t.Error("Subnet is not null !")
		t.Fail()
	}
	if !s.OK() {
		t.Error("Subnet is ok !")
		t.Fail()
	}

}

func TestSubnet_Clone(t *testing.T) {
	s := NewSubnet()
	s.ID = "Subnet ID"
	s.Name = "Subnet Name"
	s.Network = "Subnet Network"
	s.CIDR = "Subnet CIDR"
	s.Domain = "Subnet Domain"
	s.DNSServers = []string{"DNS1", "DNS2", "DNS3"}
	s.GatewayIDs = []string{"GatewayID1", "GatewayID2", "GatewayID3"}
	s.VIP = NewVirtualIP()
	s.IPVersion = ipversion.IPv4
	s.GWSecurityGroupID = "Subnet GWSecurityGroupID"
	s.PublicIPSecurityGroupID = "Subnet PublicIPSecurityGroupID"
	s.InternalSecurityGroupID = "Subnet InternalSecurityGroupID"
	s.DefaultSSHPort = 42
	s.SingleHostCIDRIndex = 14

	sc, ok := s.Clone().(*Subnet)
	if !ok {
		t.Fail()
	}

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

	s := NewSubnet()
	s.ID = "Subnet ID"
	s.Name = "Subnet Name"
	s.Network = "Subnet Network"
	s.CIDR = "Subnet CIDR"
	s.Domain = "Subnet Domain"
	s.DNSServers = []string{"DNS1", "DNS2", "DNS3"}
	s.GatewayIDs = []string{"GatewayID1", "GatewayID2", "GatewayID3"}
	//s.VIP = NewVirtualIP() //DeepEqual does not work with pointer
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

	s2 := NewSubnet()
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

func TestVirtualIP_Clone(t *testing.T) {

	v := NewVirtualIP()
	v.ID = "VirtualIP ID"
	v.Name = "VirtualIP Name"
	v.SubnetID = "VirtualIP SubnetID"
	v.PrivateIP = "VirtualIP PrivateIP"
	v.PublicIP = "VirtualIP PublicIP"
	v.Hosts = []*HostCore{NewHostCore(), NewHostCore(), NewHostCore()}
	v.NetworkID = "VirtualIP NetworkID"

	v2, ok := v.Clone().(*VirtualIP)
	if !ok {
		t.Fail()
	}

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
