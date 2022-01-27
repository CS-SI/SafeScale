/*
* Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	result := sgs.Replace(sgs2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("SecurityGroupSubnets nil pointer can't be replace")
		t.Fail()
	}
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
	clonedSgs, ok := sgs.Clone().(*SecurityGroupSubnets)
	if !ok {
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
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, sgs, clonedSgs)
}
