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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetwork_NewNetwork(t *testing.T) {

	n := NewNetwork()
	if !n.IsNull() {
		t.Error("Network is null !")
		t.Fail()
	}
	if n.OK() {
		t.Error("Network is not ok !")
		t.Fail()
	}
	n.ID = "Network ID"
	n.Name = "Network Name"
	n.CIDR = "Network CIDR"
	if n.IsNull() {
		t.Error("Network is not null !")
		t.Fail()
	}
	if !n.OK() {
		t.Error("Network is ok !")
		t.Fail()
	}
}

func TestNetwork_Replace(t *testing.T) {

	var n1 *Network
	var n2 *Network
	result, err := n1.Replace(n2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

}

func TestNetwork_Clone(t *testing.T) {
	n := NewNetwork()
	n.ID = "Network ID"
	n.Name = "Network Name"
	n.CIDR = "Network CIDR"
	n.DNSServers = []string{"DNS1", "DNS2", "DNS3"}
	n.Imported = false

	at, err := n.Clone()
	if err != nil {
		t.Error(err)
	}

	n2, ok := at.(*Network)
	if !ok {
		t.Fail()
	}
	assert.Equal(t, n, n2)
	areEqual := reflect.DeepEqual(n, n2)
	if !areEqual {
		t.Error("Clone not restitute values")
		t.Fail()
	}

	n2.CIDR = "CIDR Changed"
	areEqual = reflect.DeepEqual(n, n2)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}

func TestNetwork_Clone_DNS(t *testing.T) {
	n := NewNetwork()
	n.ID = "Network ID"
	n.Name = "Network Name"
	n.CIDR = "Network CIDR"
	n.DNSServers = []string{"DNS1", "DNS2", "DNS3"}
	n.Imported = false

	at, err := n.Clone()
	if err != nil {
		t.Error(err)
	}

	n2, ok := at.(*Network)
	if !ok {
		t.Fail()
	}
	assert.Equal(t, n, n2)
	areEqual := reflect.DeepEqual(n, n2)
	if !areEqual {
		t.Error("Clone not restitute values")
		t.Fail()
	}

	n.DNSServers[1] = "MEH"
	areEqual = reflect.DeepEqual(n, n2)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}

func TestNetwork_Serialize(t *testing.T) {

	var n *Network = nil
	_, err := n.Serialize()
	if err == nil {
		t.Error("Can't serialize nil pointer")
		t.Fail()
	}

	n = NewNetwork()
	n.ID = "Network ID"
	n.Name = "Network Name"
	n.CIDR = "Network CIDR"
	n.DNSServers = []string{"DNS1", "DNS2", "DNS3"}
	n.Imported = false

	serial, err := n.Serialize()
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	n2 := NewNetwork()
	err = n2.Deserialize(serial)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	areEqual := reflect.DeepEqual(n, n2)
	if !areEqual {
		t.Error("Serialize/Deserialize does not restitute values")
		t.Fail()
	}

}

func TestNetwork_Deserialize(t *testing.T) {

	n := NewNetwork()
	n.ID = "Network ID"
	n.Name = "Network Name"
	n.CIDR = "Network CIDR"
	n.DNSServers = []string{"DNS1", "DNS2", "DNS3"}
	n.Imported = false

	serial, err := n.Serialize()
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	var n2 *Network
	err = n2.Deserialize(serial)
	if err == nil {
		t.Error("Can't deserialize nil pointer")
		t.Fail()
	}

}

func TestNetwork_GetName(t *testing.T) {

	n := NewNetwork()
	n.Name = "Network Name"
	name := n.GetName()
	if name != n.Name {
		t.Error("Wrong value restitution")
		t.Fail()
	}

}

func TestNetwork_GetID(t *testing.T) {

	n := NewNetwork()
	n.ID = "Network Name"
	id, _ := n.GetID()
	if id != n.ID {
		t.Error("Wrong value restitution")
		t.Fail()
	}

}
