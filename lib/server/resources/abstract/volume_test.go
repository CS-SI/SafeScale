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

package abstract

import (
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/volumestate"

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

func TestVolume_Replace(t *testing.T) {

	var v *Volume = nil
	replaced, err := v.Replace(NewVolume())
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, replaced)
}

func TestVolume_Clone(t *testing.T) {
	v := NewVolume()
	v.ID = "Volume ID"
	v.Name = "Volume Name"
	v.Size = 42
	v.Speed = volumespeed.Cold
	v.State = volumestate.Unknown

	cloned, err := v.Clone()
	if err != nil {
		t.Error(err)
	}

	vc, ok := cloned.(*Volume)
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

	var v2 *Volume = nil
	_, err := v2.Serialize()
	if err == nil {
		t.Error("Can't serialize nil pointer")
		t.Fail()
	}

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

	v2 = NewVolume()
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

func TestVolume_Deserialize(t *testing.T) {

	serial := []byte("{\"id\":\"Volume ID\",\"name\":\"Volume Name\",\"size\":42,\"state\":7,\"tags\":{\"CreationDate\":\"2022-01-21T17:07:34+01:00\",\"ManagedBy\":\"safescale\"}}")
	var v *Volume = nil
	err := v.Deserialize(serial)
	if err == nil {
		t.Error("Can't deserialize nil pointer")
		t.Fail()
	}

}

func TestVolume_GetName(t *testing.T) {

	v := NewVolume()
	v.Name = "Volume Name"
	name := v.GetName()
	if name != v.Name {
		t.Error("Wrong value restitution")
		t.Fail()
	}

}

func TestVolume_GetID(t *testing.T) {

	v := NewVolume()
	v.ID = "Volume ID"
	id := v.GetID()
	if id != v.ID {
		t.Error("Wrong value restitution")
		t.Fail()
	}

}

func Test_NewVolumeAttachment(t *testing.T) {

	va := NewVolumeAttachment()
	if reflect.TypeOf(va).String() != "*abstract.VolumeAttachment" {
		t.Error("Expect *abstract.VolumeAttachment")
		t.Fail()
	}

}

func TestVolumeAttachment_IsNull(t *testing.T) {

	var va *VolumeAttachment = nil
	if !va.IsNull() {
		t.Error("nil pointer is null")
		t.Fail()
	}
	va = NewVolumeAttachment()
	if !va.IsNull() {
		t.Error("VolumeAttachment require ID/name to not null")
		t.Fail()
	}
	va.ID = "VolumeAttachement ID"
	if va.IsNull() {
		t.Error("No, is not null")
		t.Fail()
	}

}

func TestVolumeAttachment_OK(t *testing.T) {

	var va *VolumeAttachment = nil
	if va.OK() {
		t.Error("nil pointer can't be ok")
		t.Fail()
	}
	va = NewVolumeAttachment()
	if va.OK() {
		t.Error("VolumeAttachment require being filled to be ok")
		t.Fail()
	}
	va.ID = "VolumeAttachment ID"
	if va.OK() {
		t.Error("VolumeAttachment require being filled to be ok")
		t.Fail()
	}
	va.Name = "VolumeAttachment Name"
	if va.OK() {
		t.Error("VolumeAttachment require being filled to be ok")
		t.Fail()
	}
	va.VolumeID = "VolumeAttachment VolumeID"
	if va.OK() {
		t.Error("VolumeAttachment require being filled to be ok")
		t.Fail()
	}
	va.ServerID = "VolumeAttachment ServerID"
	if va.OK() {
		t.Error("VolumeAttachment require being filled to be ok")
		t.Fail()
	}
	va.Device = "VolumeAttachment Device"
	if va.OK() {
		t.Error("VolumeAttachment require being filled to be ok")
		t.Fail()
	}
	va.MountPoint = "VolumeAttachment MountPoint"
	if va.OK() {
		t.Error("VolumeAttachment require being filled to be ok")
		t.Fail()
	}
	va.Format = "VolumeAttachment Format"
	if !va.OK() {
		t.Error("No, is ok")
		t.Fail()
	}

}
