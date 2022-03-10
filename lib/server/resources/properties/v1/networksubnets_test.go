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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkSubnets_IsNull(t *testing.T) {

	var ns *NetworkSubnets = nil
	if !ns.IsNull() {
		t.Error("NetworkSubnets nil pointer is null")
		t.Fail()
	}
	ns = NewNetworkSubnets()
	if !ns.IsNull() {
		t.Error("Empty NetworkSubnets is null")
		t.Fail()
	}
	ns.ByID["ID"] = "Network"
	if ns.IsNull() {
		t.Error("NetworkSubnets is not null")
		t.Fail()
	}
}

func TestNetworkSubnets_Replace(t *testing.T) {
	var ns *NetworkSubnets = nil
	ns2 := NewNetworkSubnets()
	result, err := ns.Replace(ns2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)
}

func TestNetworkSubnets_Clone(t *testing.T) {
	ns := &NetworkSubnets{
		ByID: map[string]string{
			"ID": "Network",
		},
		ByName: map[string]string{
			"Name": "Network",
		},
	}

	cloned, err := ns.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedNs, ok := cloned.(*NetworkSubnets)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ns, clonedNs)
	require.EqualValues(t, ns, clonedNs)
	clonedNs.ByID["ID"] = "Network2"

	areEqual := reflect.DeepEqual(ns, clonedNs)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, ns, clonedNs)
}
