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

package propertiesv1

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkHosts_Reset(t *testing.T) {

	nh := &NetworkHosts{
		ByID: map[string]string{
			"ID": "NetworkHosts",
		},
		ByName: map[string]string{
			"Name": "NetworkHosts",
		},
	}
	nh.Reset()
	if len(nh.ByID) > 0 || len(nh.ByName) > 0 {
		t.Error("Reset does not clean properties")
		t.Fail()
	}

}

func TestNetworkHosts_IsNull(t *testing.T) {

	var nd *NetworkHosts = nil
	if !nd.IsNull() {
		t.Error("NetworkHosts nil pointer is null")
		t.Fail()
	}
	nd = NewNetworkHosts()
	if !nd.IsNull() {
		t.Error("Empty NetworkHosts is null")
		t.Fail()
	}
	nd.ByID["ID"] = "NetworkHosts"
	if nd.IsNull() {
		t.Error("NetworkHosts is not null")
		t.Fail()
	}
}

func TestNetworkHosts_Replace(t *testing.T) {
	var nd *NetworkHosts = nil
	nd2 := NewNetworkHosts()
	result := nd.Replace(nd2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("NetworkHosts nil pointer can't be replace")
		t.Fail()
	}
}

func TestNetworkHosts_Clone(t *testing.T) {

	nh := &NetworkHosts{
		ByID: map[string]string{
			"ID": "NetworkHosts",
		},
		ByName: map[string]string{
			"Name": "NetworkHosts",
		},
	}
	clonedNh, ok := nh.Clone().(*NetworkHosts)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, nh, clonedNh)
	require.EqualValues(t, nh, clonedNh)
	clonedNh.ByID["ID"] = "NetworkHosts 2"

	areEqual := reflect.DeepEqual(nh, clonedNh)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, nh, clonedNh)
}
