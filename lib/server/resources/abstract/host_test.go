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

package abstract

import (
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostCore_NewHostCore(t *testing.T) {

	hc := NewHostCore()
	if !hc.IsNull() {
		t.Error("HostCore is null !")
		t.Fail()
	}
	if hc.IsConsistent() {
		t.Error("HostCore is not consistent !")
		t.Fail()
	}
	if hc.OK() {
		t.Error("HostCore is not ok !")
		t.Fail()
	}
	hc.SetID("hostcore ID")
	hc.SetName("hostcore name")
	if hc.IsNull() {
		t.Error("HostCore is not null !")
		t.Fail()
	}
	if !hc.IsConsistent() {
		t.Error("HostCore is consistent !")
		t.Fail()
	}
	if !hc.OK() {
		t.Error("HostCore is ok !")
		t.Fail()
	}

}

func TestHostCore_Clone(t *testing.T) {
	h := NewHostCore()
	h.Name = "host"

	hc, ok := h.Clone().(*HostCore)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, h, hc)
	require.EqualValues(t, h, hc)

	hc.Password = "changed password"

	areEqual := reflect.DeepEqual(h, hc)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, h, hc)
}

func TestHostCore_Serialize(t *testing.T) {

	hc := NewHostCore()
	hc.ID = "HostCore ID"
	hc.Name = "HostCore Name"
	hc.PrivateKey = "HostCore PrivateKey"
	hc.SSHPort = 42
	hc.Password = "HostCore Password"
	hc.LastState = hoststate.Unknown

	serial, err := hc.Serialize()
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	hc2 := NewHostCore()
	err = hc2.Deserialize(serial)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	areEqual := reflect.DeepEqual(hc, hc2)
	if !areEqual {
		t.Error("Serialize/Deserialize does not restitute values")
		t.Fail()
	}

}
