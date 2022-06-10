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
	result, err := sgh.Replace(sgh2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := sgh2.Replace(network)
	if xerr == nil {
		t.Error("SecurityGroupHosts.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *SecurityGroupHosts") {
		t.Errorf("Expect error \"p is not a *SecurityGroupHosts\", has \"%s\"", xerr.Error())
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
		t.Error("Cloned SecurityGroupHosts not castable to *SecurityGroupHosts", err)
		t.Fail()
	}

	assert.Equal(t, sgh, clonedSgh)
	require.EqualValues(t, sgh, clonedSgh)
	clonedSgh.ByID["ID"] = NewSecurityGroupBond()
	clonedSgh.ByID["ID"].Name = "SecurityGroupBond Name 2"

	areEqual := reflect.DeepEqual(sgh, clonedSgh)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, sgh, clonedSgh)
}
