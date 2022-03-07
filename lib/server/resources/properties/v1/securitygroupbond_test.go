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
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityGroupBond_IsNull(t *testing.T) {

	var sgb *SecurityGroupBond = nil
	if !sgb.IsNull() {
		t.Error("SecurityGroupBond nil pointer is null")
		t.Fail()
	}
	sgb = NewSecurityGroupBond()
	if !sgb.IsNull() {
		t.Error("Empty SecurityGroupBond is null")
		t.Fail()
	}
	sgb.Name = "SecurityGroupBond Name"
	if sgb.IsNull() {
		t.Error("SecurityGroupBond is not null")
		t.Fail()
	}
}

func TestSecurityGroupBond_Replace(t *testing.T) {

	var sgb *SecurityGroupBond = nil
	sgb2 := NewSecurityGroupBond()
	result, _ := sgb.Replace(sgb2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("SecurityGroupBond nil pointer can't be replace")
		t.Fail()
	}

}

func TestSecurityGroupBond__Clone(t *testing.T) {

	sgb := &SecurityGroupBond{
		Name:       "SecurityGroupBond Name",
		ID:         "SecurityGroupBond ID",
		Disabled:   false,
		FromSubnet: false,
	}

	cloned, err := sgb.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedSgb, ok := cloned.(*SecurityGroupBond)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, sgb, clonedSgb)
	require.EqualValues(t, sgb, clonedSgb)
	clonedSgb.Name = "SecurityGroupBond Name2"

	areEqual := reflect.DeepEqual(sgb, clonedSgb)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, sgb, clonedSgb)
}
