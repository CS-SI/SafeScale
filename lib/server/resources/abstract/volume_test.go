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

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumestate"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVolume_NewVolume(t *testing.T) {
	v := NewVolume()
	if !v.IsNull() {
		t.Error("Volume is null !")
		t.Fail()
	}
	if v.OK() {
		t.Error("Volume is not ok !")
		t.Fail()
	}
	v.ID = "Volume ID"
	v.Name = "Volume Name"
	v.Size = 42
	if v.IsNull() {
		t.Error("Volume is notnull !")
		t.Fail()
	}
	if !v.OK() {
		t.Error("Volume is ok !")
		t.Fail()
	}

}

func TestVolume_Clone(t *testing.T) {
	v := NewVolume()
	v.ID = "Volume ID"
	v.Name = "Volume Name"
	v.Size = 42
	v.Speed = volumespeed.Cold
	v.State = volumestate.Unknown

	vc, ok := v.Clone().(*Volume)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, v, vc)
	require.EqualValues(t, v, vc)

	vc.Size = 20

	areEqual := reflect.DeepEqual(v, vc)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, v, vc)
}

func TestVolume_Serialize(t *testing.T) {
	v := NewVolume()
	v.ID = "Volume ID"
	v.Name = "Volume Name"
	v.Size = 42
	v.Speed = volumespeed.Cold
	v.State = volumestate.Unknown

	serial, err := v.Serialize()
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	v2 := NewVolume()
	err = v2.Deserialize(serial)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	areEqual := reflect.DeepEqual(v, v2)
	if !areEqual {
		t.Error("Serialize/Deserialize does not restitute values")
		t.Fail()
	}

}
