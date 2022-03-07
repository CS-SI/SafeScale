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

func TestSecurityGroupHosts_IsNull(t *testing.T) {

	var sgh *SecurityGroupHosts = nil
	if !sgh.IsNull() {
		t.Error("SecurityGroupHosts nil pointer is null")
		t.Fail()
	}
	sgh = NewSecurityGroupHosts()
	if !sgh.IsNull() {
		t.Error("Empty SecurityGroupHosts is null")
		t.Fail()
	}
	sgh.ByID["ID"] = NewSecurityGroupBond()
	if sgh.IsNull() {
		t.Error("SecurityGroupHosts is not null")
		t.Fail()
	}
}

func TestSecurityGroupHosts_Replace(t *testing.T) {
	var sgh *SecurityGroupHosts = nil
	sgh2 := NewSecurityGroupHosts()
	result, _ := sgh.Replace(sgh2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("SecurityGroupHosts nil pointer can't be replace")
		t.Fail()
	}
}

func TestSecurityGroupHosts_Clone(t *testing.T) {

	sgh := &SecurityGroupHosts{
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

	cloned, err := sgh.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedSgh, ok := cloned.(*SecurityGroupHosts)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, sgh, clonedSgh)
	require.EqualValues(t, sgh, clonedSgh)
	clonedSgh.ByID["ID"] = NewSecurityGroupBond()
	clonedSgh.ByID["ID"].Name = "SecurityGroupBond Name 2"

	areEqual := reflect.DeepEqual(sgh, clonedSgh)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, sgh, clonedSgh)
}
