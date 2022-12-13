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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
)

func TestSubnetDescription_IsNull(t *testing.T) {

	var sd *SubnetDescription = nil
	if !sd.IsNull() {
		t.Error("SubnetDescription nil pointer is null")
		t.Fail()
	}
	sd = NewSubnetDescription()
	if !sd.IsNull() {
		t.Error("Empty SubnetDescription is null")
		t.Fail()
	}
	sd.Purpose = "SubnetDescription Purpose"
	if sd.IsNull() {
		t.Error("SubnetDescription is not null")
		t.Fail()
	}
}

func TestSubnetDescription_Replace(t *testing.T) {
	var sd *SubnetDescription = nil
	sd2 := NewSubnetDescription()
	result, err := sd.Replace(sd2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := sd2.Replace(network)
	if xerr == nil {
		t.Error("SubnetDescription.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *SubnetDescription") {
		t.Errorf("Expect error \"p is not a *SubnetDescription\", has \"%s\"", xerr.Error())
	}

}

func TestSubnetDescription_Clone(t *testing.T) {

	sd := &SubnetDescription{
		Purpose: "SubnetDescription Purpose",
		Created: time.Now(),
		Domain:  "SubnetDescription Domain",
	}

	cloned, err := sd.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedSd, ok := cloned.(*SubnetDescription)
	if !ok {
		t.Error("Cloned SubnetDescription not castable to *SubnetDescription", err)
		t.Fail()
	}

	assert.Equal(t, sd, clonedSd)
	require.EqualValues(t, sd, clonedSd)
	clonedSd.Purpose = "SubnetDescription Purpose2"

	areEqual := reflect.DeepEqual(sd, clonedSd)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, sd, clonedSd)
}
