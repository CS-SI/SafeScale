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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
)

func TestSecurityGroupSubnets_IsNull(t *testing.T) {

	var sgs *SecurityGroupSubnets = nil
	if !sgs.IsNull() {
		t.Error("SecurityGroupSubnets nil pointer is null")
		t.Fail()
	}
	sgs = NewSecurityGroupSubnets()
	if !sgs.IsNull() {
		t.Error("Empty SecurityGroupSubnets is null")
		t.Fail()
	}
	sgs.ByID["ID"] = NewSecurityGroupBond()
	if sgs.IsNull() {
		t.Error("SecurityGroupSubnets is not null")
		t.Fail()
	}
}

func TestSecurityGroupSubnets_Replace(t *testing.T) {
	var sgs *SecurityGroupSubnets = nil
	sgs2 := NewSecurityGroupSubnets()
	result, err := sgs.Replace(sgs2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, err = sgs2.Replace(network)
	require.Contains(t, err.Error(), "p is not a *SecurityGroupSubnets")
}

func TestSecurityGroupSubnets_Clone(t *testing.T) {

	sgs := &SecurityGroupSubnets{
		ByID: map[string]*SecurityGroupBond{
			"ID": {
				Name:       "SecurityGroupBond Name",
				ID:         "SecurityGroupBond ID",
				Disabled:   false,
				FromSubnet: false,
			},
		},
		ByName: map[string]string{
			"Name": "ID",
		},
	}

	cloned, err := sgs.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedSgs, ok := cloned.(*SecurityGroupSubnets)
	if !ok {
		t.Error("Cloned SecurityGroupSubnets not castable to *SecurityGroupSubnets", err)
		t.Fail()
	}

	assert.Equal(t, sgs, clonedSgs)
	require.EqualValues(t, sgs, clonedSgs)
	clonedSgs.ByID["ID"] = &SecurityGroupBond{
		Name:       "SecurityGroupBond Name 2",
		ID:         "SecurityGroupBond ID 2",
		Disabled:   false,
		FromSubnet: false,
	}

	areEqual := reflect.DeepEqual(sgs, clonedSgs)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, sgs, clonedSgs)
}
