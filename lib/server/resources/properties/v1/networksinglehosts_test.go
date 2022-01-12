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

func TestNetworkSingleHosts_Clone(t *testing.T) {
	ct := NewNetworkSingleHosts()
	ct.FreeSlots = append(ct.FreeSlots, FreeCIDRSlot{1, 5})

	clonedCt, ok := ct.Clone().(*NetworkSingleHosts)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	require.EqualValues(t, ct, clonedCt)
	clonedCt.FreeSlots = append(clonedCt.FreeSlots, FreeCIDRSlot{15, 16})

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
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
