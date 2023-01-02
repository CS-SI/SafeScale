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

func TestNetworkSingleHosts_IsNull(t *testing.T) {

	var nsh *NetworkSingleHosts = nil
	if !nsh.IsNull() {
		t.Error("NetworkSingleHosts nil pointer is null")
		t.Fail()
	}
	nsh = NewNetworkSingleHosts()
	if !nsh.IsNull() {
		t.Error("Empty NetworkSingleHosts is null")
		t.Fail()
	}
	nsh.FreeSlots = []FreeCIDRSlot{
		{
			First: 0,
			Last:  0,
		},
	}
	if nsh.IsNull() {
		t.Error("NetworkSingleHosts is not null")
		t.Fail()
	}
}

func TestNetworkSingleHosts_Replace(t *testing.T) {
	var nsh *NetworkSingleHosts = nil
	nsh2 := NewNetworkSingleHosts()
	result, err := nsh.Replace(nsh2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := nsh2.Replace(network)
	if xerr == nil {
		t.Error("NetworkSingleHosts.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *NetworkSingleHosts") {
		t.Errorf("Expect error \"p is not a *NetworkSingleHosts\", has \"%s\"", xerr.Error())
	}

}

func TestNetworkSingleHosts_Clone(t *testing.T) {
	ct := NewNetworkSingleHosts()
	ct.FreeSlots = append(ct.FreeSlots, FreeCIDRSlot{1, 5})

	cloned, err := ct.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedCt, ok := cloned.(*NetworkSingleHosts)
	if !ok {
		t.Error("Cloned NetworkSingleHosts not castable to *NetworkSingleHosts", err)
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	require.EqualValues(t, ct, clonedCt)
	clonedCt.FreeSlots = append(clonedCt.FreeSlots, FreeCIDRSlot{15, 16})

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}

func TestNetworkSingleHosts_ReserveSlot(t *testing.T) {
	ct := NewNetworkSingleHosts()
	index := ct.ReserveSlot()
	assert.Equal(t, index, uint(1))

	index = ct.ReserveSlot()
	assert.Equal(t, index, uint(2))

	index = ct.ReserveSlot()
	assert.Equal(t, index, uint(3))

	ct.FreeSlot(2)
	expected := []FreeCIDRSlot{
		{First: 2, Last: 2},
		{First: 4, Last: SingleHostsMaxCIDRSlotValue},
	}
	areEqual := reflect.DeepEqual(ct.FreeSlots, expected)
	if !areEqual {
		t.Error("content is unexpected!")
		t.Fail()
	}

	index = ct.ReserveSlot()
	assert.Equal(t, index, uint(2))

	expected = []FreeCIDRSlot{
		{First: 4, Last: SingleHostsMaxCIDRSlotValue},
	}
	areEqual = reflect.DeepEqual(ct.FreeSlots, expected)
	if !areEqual {
		t.Error("content is unexpected!")
		t.Fail()
	}
}

func TestNetworkSingleHosts_FreeSlot(t *testing.T) {

	nsh := NewNetworkSingleHosts()
	nsh.FreeSlots = []FreeCIDRSlot{
		{First: 3, Last: 5},
	}
	nsh.FreeSlot(2)
	if len(nsh.FreeSlots) != 1 || nsh.FreeSlots[0].First != 2 {
		t.Error("Fail to free slot 0")
		t.Fail()
	}
	nsh.FreeSlot(6)
	if len(nsh.FreeSlots) != 1 || nsh.FreeSlots[0].Last != 6 {
		t.Error("Fail to free slot 6")
		t.Fail()
	}
	nsh.FreeSlot(0)
	if len(nsh.FreeSlots) != 2 || nsh.FreeSlots[0].First != 0 {
		t.Error("Fail to free slot 0")
		t.Fail()
	}
	nsh.FreeSlot(8)
	if len(nsh.FreeSlots) != 3 || nsh.FreeSlots[2].Last != 8 {
		t.Error("Fail to free slot 8")
		t.Fail()
	}
	nsh.FreeSlots = []FreeCIDRSlot{
		{First: 3, Last: 5},
		{First: 9, Last: 11},
	}
	nsh.FreeSlot(7)
	if len(nsh.FreeSlots) != 2 || nsh.FreeSlots[0].Last != 7 {
		t.Error("Fail to free slot 7")
		t.Fail()
	}
	nsh.FreeSlots = []FreeCIDRSlot{
		{First: 0, Last: 1},
		{First: 1, Last: 2},
		{First: 2, Last: 3},
		{First: 3, Last: 4},
		{First: 4, Last: 5},
		{First: 5, Last: 6},
		{First: 6, Last: 7},
		{First: 7, Last: 8},
		{First: 8, Last: 9},
		{First: 9, Last: 10},
	}
	nsh.FreeSlot(0)
	if len(nsh.FreeSlots) != 1 {
		t.Error("FreeSlot merged invalid")
		t.Fail()
	}

}
