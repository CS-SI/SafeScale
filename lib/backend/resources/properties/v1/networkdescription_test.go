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
	err := nd.Replace(nd2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}

	network, _ := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	err = nd2.Replace(network)
	if err == nil {
		t.Error("NetworkDescription.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(err.Error(), "p is not a *NetworkDescription") {
		t.Errorf("Expect error \"p is not a *NetworkDescription\", has \"%s\"", err.Error())
	}

}

func TestNetworkDescription_Clone(t *testing.T) {

	nd := &NetworkDescription{
		Purpose: "NetworkDescription Purpose",
		Created: time.Now(),
		Domain:  "NetworkDescription Domain",
	}

	cloned, err := nd.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedNs, ok := cloned.(*NetworkDescription)
	if !ok {
		t.Error("Cloned NetworkDescription not castable to *NetworkDescription", err)
		t.Fail()
	}

	assert.Equal(t, nd, clonedNs)
	require.EqualValues(t, nd, clonedNs)
	clonedNs.Purpose = "NetworkDescription Purpose 2"

	areEqual := reflect.DeepEqual(nd, clonedNs)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, nd, clonedNs)
}
