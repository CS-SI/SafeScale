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

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := ns2.Replace(network)
	if xerr == nil {
		t.Error("NetworkSubnets.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *NetworkSubnets") {
		t.Errorf("Expect error \"p is not a *NetworkSubnets\", has \"%s\"", xerr.Error())
	}

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
		t.Error("Cloned NetworkSubnets not castable to *NetworkSubnets", err)
		t.Fail()
	}

	assert.Equal(t, ns, clonedNs)
	require.EqualValues(t, ns, clonedNs)
	clonedNs.ByID["ID"] = "Network2"

	areEqual := reflect.DeepEqual(ns, clonedNs)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, ns, clonedNs)
}
