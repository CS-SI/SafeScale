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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
)

func TestHostSecurityGroups_IsNull(t *testing.T) {

	var hsg *HostSecurityGroups = nil
	if !hsg.IsNull() {
		t.Error("HostSecurityGroups nil pointer is null")
		t.Fail()
	}
	hsg = NewHostSecurityGroups()
	if !hsg.IsNull() {
		t.Error("Empty HostSecurityGroups is null")
		t.Fail()
	}
	hsg.ByID = map[string]*SecurityGroupBond{
		"ID": {
			ID:       "SecurityGroupBond ID",
			Name:     "SecurityGroupBond Name",
			Disabled: false,
		},
	}
	if hsg.IsNull() {
		t.Error("HostSecurityGroups is not null")
		t.Fail()
	}
}

func TestHostSecurityGroups_Clone(t *testing.T) {

	hsg := &HostSecurityGroups{
		ByID: map[string]*SecurityGroupBond{
			"ID": {
				ID:       "SecurityGroupBond ID",
				Name:     "SecurityGroupBond Name",
				Disabled: false,
			},
		},
		ByName: map[string]string{
			"Name": "ID",
		},
	}

	cloned, err := hsg.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedHsg, ok := cloned.(*HostSecurityGroups)
	if !ok {
		t.Error("Cloned HostSecurityGroups not castable to *HostSecurityGroups", err)
		t.Fail()
	}

	assert.Equal(t, hsg, clonedHsg)
	require.EqualValues(t, hsg, clonedHsg)
	clonedHsg.ByName["Name2"] = "ID2"

	areEqual := reflect.DeepEqual(hsg, clonedHsg)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, hsg, clonedHsg)
}

func TestHostSecurityGroups_Replace(t *testing.T) {

	var hsg *HostSecurityGroups = nil
	hsg2 := NewHostSecurityGroups()
	result, err := hsg.Replace(hsg2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := hsg2.Replace(network)
	if xerr == nil {
		t.Error("HostSecurityGroups.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *HostSecurityGroups") {
		t.Errorf("Expect error \"p is not a *HostSecurityGroups\", has \"%s\"", xerr.Error())
	}

}
