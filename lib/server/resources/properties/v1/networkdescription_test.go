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

func TestNetworkDescription_IsNull(t *testing.T) {

	var nd *NetworkDescription = nil
	if !nd.IsNull() {
		t.Error("NetworkDescription nil pointer is null")
		t.Fail()
	}
	nd = NewNetworkDescription()
	if !nd.IsNull() {
		t.Error("Empty NetworkDescription is null")
		t.Fail()
	}
	nd.Purpose = "NetworkDescription Purpose"
	if nd.IsNull() {
		t.Error("NetworkDescription is not null")
		t.Fail()
	}
}

func TestNetworkDescription_Replace(t *testing.T) {
	var nd *NetworkDescription = nil
	nd2 := NewNetworkDescription()
	result := nd.Replace(nd2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("NetworkDescription nil pointer can't be replace")
		t.Fail()
	}
}

func TestNetworkDescription_Clone(t *testing.T) {

	nd := &NetworkDescription{
		Purpose: "NetworkDescription Purpose",
		Created: time.Now(),
		Domain:  "NetworkDescription Domain",
	}
	clonedNs, ok := nd.Clone().(*NetworkDescription)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, nd, clonedNs)
	require.EqualValues(t, nd, clonedNs)
	clonedNs.Purpose = "NetworkDescription Purpose 2"

	areEqual := reflect.DeepEqual(nd, clonedNs)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, nd, clonedNs)
}
