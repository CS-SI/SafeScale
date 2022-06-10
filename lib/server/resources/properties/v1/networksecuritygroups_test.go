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
	"reflect"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
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
	result, err := nsg.Replace(nsg2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := nsg2.Replace(network)
	if xerr == nil {
		t.Error("NetworkSecurityGroups.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *NetworkSecurityGroups") {
		t.Errorf("Expect error \"p is not a *NetworkSecurityGroups\", has \"%s\"", xerr.Error())
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
		t.Error("Cloned BucketMounts not castable to *NetworkSecurityGroups", err)
		t.Fail()
	}

	assert.Equal(t, nsg, clonedNsg)
	require.EqualValues(t, nsg, clonedNsg)
	clonedNsg.ByID["ID"] = "NetworkSecurityGroups 2"

	areEqual := reflect.DeepEqual(nsg, clonedNsg)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, nsg, clonedNsg)
}
