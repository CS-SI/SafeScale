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

package propertiesv2

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostNetworking_IsNull(t *testing.T) {

	var hnw *HostNetworking = nil
	if !hnw.IsNull() {
		t.Error("HostNetworking nil pointer is null")
		t.Fail()
	}
	hnw = NewHostNetworking()
	if !hnw.IsNull() {
		t.Error("Empty HostNetworking is null")
		t.Fail()
	}
	hnw.DefaultSubnetID = "HostNetworking DefaultSubnetID"
	hnw.IPv4Addresses = map[string]string{
		"Ipv4": "0.0.0.0/0",
	}
	hnw.IPv6Addresses = map[string]string{
		"Ipv6": "::0",
	}

	if hnw.IsNull() {
		t.Error("HostNetworking is not null")
		t.Fail()
	}
}

func TestHostNetworking_Replace(t *testing.T) {
	var hnw *HostNetworking = nil
	hnw2 := newClusterNodes()
	result := hnw.Replace(hnw2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("HostNetworking nil pointer can't be replace")
		t.Fail()
	}
}

func TestHostNetworking_Clone(t *testing.T) {
	ct := &HostNetworking{
		DefaultSubnetID: "id1",
		SubnetsByID:     map[string]string{"id1": "subnet1"},
		SubnetsByName:   map[string]string{"subnet1": "id1"},
		PublicIPv4:      "195.32.4.1",
		IPv4Addresses:   map[string]string{"id1": "192.168.2.10"},
		IPv6Addresses:   map[string]string{"id1": "2001:db8:3333:4444:5555:6666:7777:8888"},
	}

	clonedCt, ok := ct.Clone().(*HostNetworking)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.SubnetsByID["id2"] = "subnet2"
	clonedCt.SubnetsByName["subnet2"] = "id2"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}

func TestHostNetworking_Reset(t *testing.T) {

	ct := &HostNetworking{
		DefaultSubnetID: "id1",
		SubnetsByID:     map[string]string{"id1": "subnet1"},
		SubnetsByName:   map[string]string{"subnet1": "id1"},
		PublicIPv4:      "195.32.4.1",
		IPv4Addresses:   map[string]string{"id1": "192.168.2.10"},
		IPv6Addresses:   map[string]string{"id1": "2001:db8:3333:4444:5555:6666:7777:8888"},
	}
	ct.Reset()

	if len(ct.SubnetsByID) > 0 {
		t.Error("HostNetworking Reset does not clean SubnetsByID")
		t.Fail()
	}
	if len(ct.SubnetsByName) > 0 {
		t.Error("HostNetworking Reset does not clean SubnetsByName")
		t.Fail()
	}
	if len(ct.IPv4Addresses) > 0 {
		t.Error("HostNetworking Reset does not clean IPv4Addresses")
		t.Fail()
	}
	if len(ct.IPv6Addresses) > 0 {
		t.Error("HostNetworking Reset does not clean IPv6Addresses")
		t.Fail()
	}

}
