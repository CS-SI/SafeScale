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

func TestNetworkSecurityGroups_IsNull(t *testing.T) {

	var nsg *NetworkSecurityGroups = nil
	if !nsg.IsNull() {
		t.Error("NetworkSecurityGroups nil pointer is null")
		t.Fail()
	}
	nsg = NewNetworkSecurityGroups()
	if !nsg.IsNull() {
		t.Error("Empty NetworkSecurityGroups is null")
		t.Fail()
	}
	nsg.ByID["ID"] = "NetworkSecurityGroups"
	if nsg.IsNull() {
		t.Error("NetworkSecurityGroups is not null")
		t.Fail()
	}
}

func TestNetworkSecurityGroups_Replace(t *testing.T) {
	var nsg *NetworkSecurityGroups = nil
	nsg2 := NewNetworkSecurityGroups()
	result, _ := nsg.Replace(nsg2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("NetworkSecurityGroups nil pointer can't be replace")
		t.Fail()
	}
}

func TestNetworkSecurityGroups_Clone(t *testing.T) {

	nsg := &NetworkSecurityGroups{
		ByID: map[string]string{
			"ID": "NetworkSecurityGroups",
		},
		ByName: map[string]string{
			"Name": "NetworkSecurityGroups",
		},
	}

	cloned, err := nsg.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedNsg, ok := cloned.(*NetworkSecurityGroups)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, nsg, clonedNsg)
	require.EqualValues(t, nsg, clonedNsg)
	clonedNsg.ByID["ID"] = "NetworkSecurityGroups 2"

	areEqual := reflect.DeepEqual(nsg, clonedNsg)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, nsg, clonedNsg)
}
