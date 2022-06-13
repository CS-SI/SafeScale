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

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
)

func TestHostSystem_IsNull(t *testing.T) {

	var hs *HostSystem = nil
	if !hs.IsNull() {
		t.Error("HostSystem nil pointer is null")
		t.Fail()
	}
	hs = NewHostSystem()
	if !hs.IsNull() {
		t.Error("Empty HostSystem is null")
		t.Fail()
	}
	hs.Type = "HostSystem Type"
	if hs.IsNull() {
		t.Error("HostSystem is not null")
		t.Fail()
	}

}

func TestHostSystem_Replace(t *testing.T) {

	var hs *HostSystem = nil
	hs2 := NewHostSystem()
	result, err := hs.Replace(hs2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := hs2.Replace(network)
	if xerr == nil {
		t.Error("HostSystem.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *HostSystem") {
		t.Errorf("Expect error \"p is not a *HostSystem\", has \"%s\"", xerr.Error())
	}

}

func TestHostSystem_Clone(t *testing.T) {

	hs := &HostSystem{
		Type:     "HostSystem Type",
		Flavor:   "HostSystem Flavor",
		Image:    "HostSystem Image",
		HostName: "HostSystem HostName",
	}

	cloned, err := hs.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedHs, ok := cloned.(*HostSystem)
	if !ok {
		t.Error("Cloned HostSystem not castable to *HostSystem", err)
		t.Fail()
	}

	assert.Equal(t, hs, clonedHs)
	require.EqualValues(t, hs, clonedHs)
	clonedHs.Type = "HostSystem Type2"

	areEqual := reflect.DeepEqual(hs, clonedHs)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, hs, clonedHs)
}
