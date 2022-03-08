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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	result := sd.Replace(sd2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("SubnetDescription nil pointer can't be replace")
		t.Fail()
	}
}

func TestSubnetDescription_Clone(t *testing.T) {

	sd := &SubnetDescription{
		Purpose: "SubnetDescription Purpose",
		Created: time.Now(),
		Domain:  "SubnetDescription Domain",
	}
	clonedSd, ok := sd.Clone().(*SubnetDescription)
	if !ok {
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