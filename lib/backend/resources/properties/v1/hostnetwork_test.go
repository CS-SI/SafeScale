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

package propertiesv1

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
)

func TestHostNetwork_IsNull(t *testing.T) {

	var hn *HostNetwork = nil
	if !hn.IsNull() {
		t.Error("HostNetwork nil pointer is null")
		t.Fail()
	}
	hn = NewHostNetwork()
	if !hn.IsNull() {
		t.Error("Empty HostNetwork is null")
		t.Fail()
	}
	hn = &HostNetwork{
		IsGateway:               false,
		DefaultGatewayID:        "DefaultGatewayID",
		DefaultGatewayPrivateIP: "DefaultGatewayPrivateIP",
		DefaultNetworkID:        "DefaultNetworkID",
		NetworksByID: map[string]string{
			"ID": "Network",
		},
		NetworksByName: map[string]string{
			"Name": "Network",
		},
		PublicIPv4: "PublicIPv4",
		PublicIPv6: "PublicIPv6",
		IPv4Addresses: map[string]string{
			"Ipv4": "Network",
		},
		IPv6Addresses: map[string]string{
			"Ipv6": "Network",
		},
	}
	if hn.IsNull() {
		t.Error("HostNetwork is not null")
		t.Fail()
	}

}

func TestHostNetwork_Reset(t *testing.T) {

	hn := &HostNetwork{
		IsGateway:               false,
		DefaultGatewayID:        "DefaultGatewayID",
		DefaultGatewayPrivateIP: "DefaultGatewayPrivateIP",
		DefaultNetworkID:        "DefaultNetworkID",
		NetworksByID: map[string]string{
			"ID": "Network",
		},
		NetworksByName: map[string]string{
			"Name": "Network",
		},
		PublicIPv4: "PublicIPv4",
		PublicIPv6: "PublicIPv6",
		IPv4Addresses: map[string]string{
			"Ipv4": "Network",
		},
		IPv6Addresses: map[string]string{
			"Ipv6": "Network",
		},
	}
	hn.Reset()

	if len(hn.NetworksByID) > 0 {
		t.Error("HostNetwork reset fail to empty NetworksByID")
		t.Fail()
	}
	if len(hn.NetworksByName) > 0 {
		t.Error("HostNetwork reset fail to empty NetworksByName")
		t.Fail()
	}
	if len(hn.IPv4Addresses) > 0 {
		t.Error("HostNetwork reset fail to empty IPv4Addresses")
		t.Fail()
	}
	if len(hn.IPv6Addresses) > 0 {
		t.Error("HostNetwork reset fail to empty IPv6Addresses")
		t.Fail()
	}

}

func TestHostNetwork_Clone(t *testing.T) {
	ct := &HostNetwork{
		DefaultNetworkID: "id1",
		NetworksByID:     map[string]string{"id1": "subnet1"},
		NetworksByName:   map[string]string{"subnet1": "id1"},
		PublicIPv4:       "195.32.4.1",
		IPv4Addresses:    map[string]string{"id1": "192.168.2.10"},
		IPv6Addresses:    map[string]string{"id1": "2001:db8:3333:4444:5555:6666:7777:8888"},
	}

	cloned, err := ct.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedCt, ok := cloned.(*HostNetwork)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	require.EqualValues(t, ct, clonedCt)
	clonedCt.NetworksByID["id2"] = "subnet2"
	clonedCt.NetworksByName["subnet2"] = "id2"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}

func TestHostNetwork_Replace(t *testing.T) {

	var hn *HostNetwork = nil
	hn2 := NewHostNetwork()
	result, err := hn.Replace(hn2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := hn2.Replace(network)
	if xerr == nil {
		t.Error("HostNetwork.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *HostNetwork") {
		t.Errorf("Expect error \"p is not a *HostNetwork\", has \"%s\"", xerr.Error())
	}

}
