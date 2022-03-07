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

func TestVolumeDescription_IsNull(t *testing.T) {

	var vd *VolumeDescription = nil
	if !vd.IsNull() {
		t.Error("VolumeDescription nil pointer is null")
		t.Fail()
	}
	vd = NewVolumeDescription()
	if !vd.IsNull() {
		t.Error("Empty VolumeDescription is null")
		t.Fail()
	}
	vd.Purpose = "VolumeDescription Purpose"
	if vd.IsNull() {
		t.Error("VolumeDescription is not null")
		t.Fail()
	}
}

func TestVolumeDescription_Replace(t *testing.T) {
	var ssg *VolumeDescription = nil
	ssg2 := NewVolumeDescription()
	result, _ := ssg.Replace(ssg2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("VolumeDescription nil pointer can't be replace")
		t.Fail()
	}
}

func TestVolumeDescription_Clone(t *testing.T) {

	vd := &VolumeDescription{
		Purpose: "VolumeDescription Purpose",
		Created: time.Now(),
	}

	cloned, err := vd.Clone()
	if err != nil {
		t.Error(err)
	}
	clonedVd, ok := cloned.(*VolumeDescription)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, vd, clonedVd)
	require.EqualValues(t, vd, clonedVd)
	clonedVd.Purpose = "VolumeDescription Purpose2"

	areEqual := reflect.DeepEqual(vd, clonedVd)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, vd, clonedVd)
}

func TestVolumeAttachments_IsNull(t *testing.T) {

	var ssg *VolumeAttachments = nil
	if !ssg.IsNull() {
		t.Error("VolumeAttachments nil pointer is null")
		t.Fail()
	}
	ssg = NewVolumeAttachments()
	if !ssg.IsNull() {
		t.Error("Empty VolumeAttachments is null")
		t.Fail()
	}
	ssg.Hosts["ID"] = "Host"
	if ssg.IsNull() {
		t.Error("VolumeAttachments is not null")
		t.Fail()
	}
}

func TestVolumeAttachments_Replace(t *testing.T) {
	var ssg *VolumeAttachments = nil
	ssg2 := NewVolumeAttachments()
	result, _ := ssg.Replace(ssg2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("VolumeAttachments nil pointer can't be replace")
		t.Fail()
	}
}

func TestVolumeAttachments_Clone(t *testing.T) {

	ct := NewVolumeAttachments()
	ct.Shareable = true
	ct.Hosts = map[string]string{"id1": "host1"}

	cloned, err := ct.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedCt, ok := cloned.(*VolumeAttachments)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	require.EqualValues(t, ct, clonedCt)
	clonedCt.Hosts["id2"] = "host2"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}
