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

func TestSubnetHosts_IsNull(t *testing.T) {

	var snh *SubnetHosts = nil
	if !snh.IsNull() {
		t.Error("SubnetHosts nil pointer is null")
		t.Fail()
	}
	snh = NewSubnetHosts()
	if !snh.IsNull() {
		t.Error("Empty SubnetHosts is null")
		t.Fail()
	}
	snh.ByID["ID"] = "SubnetHost"
	if snh.IsNull() {
		t.Error("SubnetHosts is not null")
		t.Fail()
	}
}

func TestSubnetHosts_Replace(t *testing.T) {
	var snh *SubnetHosts = nil
	snh2 := NewSubnetHosts()
	result, err := snh.Replace(snh2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := snh2.Replace(network)
	if xerr == nil {
		t.Error("SubnetHosts.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *SubnetHosts") {
		t.Errorf("Expect error \"p is not a *SubnetHosts\", has \"%s\"", xerr.Error())
	}

}

func TestSubnetHosts_Clone(t *testing.T) {

	snh := &SubnetHosts{
		ByID: map[string]string{
			"ID": "SubnetHost",
		},
		ByName: map[string]string{
			"Name": "ID",
		},
	}
	cloned, err := snh.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedSnh, ok := cloned.(*SubnetHosts)
	if !ok {
		t.Error("Cloned SubnetHosts not castable to *SubnetHosts", err)
		t.Fail()
	}

	assert.Equal(t, snh, clonedSnh)
	require.EqualValues(t, snh, clonedSnh)
	clonedSnh.ByID["ID"] = "SubnetHost2"

	areEqual := reflect.DeepEqual(snh, clonedSnh)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, snh, clonedSnh)
}
