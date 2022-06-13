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

func TestSubnetSecurityGroups_IsNull(t *testing.T) {

	var ssg *SubnetSecurityGroups = nil
	if !ssg.IsNull() {
		t.Error("SubnetSecurityGroups nil pointer is null")
		t.Fail()
	}
	ssg = NewSubnetSecurityGroups()
	if !ssg.IsNull() {
		t.Error("Empty SubnetSecurityGroups is null")
		t.Fail()
	}
	ssg.ByID["ID"] = NewSecurityGroupBond()
	if ssg.IsNull() {
		t.Error("SubnetSecurityGroups is not null")
		t.Fail()
	}
}

func TestSubnetSecurityGroups_Replace(t *testing.T) {
	var ssg *SubnetSecurityGroups = nil
	ssg2 := NewSubnetSecurityGroups()
	result, err := ssg.Replace(ssg2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := ssg2.Replace(network)
	if xerr == nil {
		t.Error("SubnetDescription.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *SubnetDescription") {
		t.Errorf("Expect error \"p is not a *SubnetDescription\", has \"%s\"", xerr.Error())
	}

}

func TestSubnetSecurityGroups_Clone(t *testing.T) {

	snh := &SubnetSecurityGroups{
		ByID: map[string]*SecurityGroupBond{
			"ID": NewSecurityGroupBond(),
		},
		ByName: map[string]string{
			"Name": "ID",
		},
	}

	cloned, err := snh.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedSnh, ok := cloned.(*SubnetSecurityGroups)
	if !ok {
		t.Error("Cloned SubnetSecurityGroups not castable to *SubnetSecurityGroups", err)
		t.Fail()
	}

	assert.Equal(t, snh, clonedSnh)
	require.EqualValues(t, snh, clonedSnh)
	clonedSnh.ByID = map[string]*SecurityGroupBond{
		"ID2": {
			Name:       "SecurityGroupBond Name2",
			ID:         "SecurityGroupBond ID2",
			Disabled:   false,
			FromSubnet: false,
		},
	}
	clonedSnh.ByName["Name"] = "ID2"

	areEqual := reflect.DeepEqual(snh, clonedSnh)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, snh, clonedSnh)
}
