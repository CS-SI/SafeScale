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

package propertiesv1

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostVolumes_IsNull(t *testing.T) {

	var hv *HostVolumes = nil
	if !hv.IsNull() {
		t.Error("HostVolumes nil pointer is null")
		t.Fail()
	}
	hv = NewHostVolumes()
	if !hv.IsNull() {
		t.Error("Empty HostVolumes is null")
		t.Fail()
	}
	hv.VolumesByID = map[string]*HostVolume{
		"ID": NewHostVolume(),
	}
	if hv.IsNull() {
		t.Error("HostVolumes is not null")
		t.Fail()
	}

}

func TestHostVolumes_Replace(t *testing.T) {

	var hs *HostVolumes = nil
	hs2 := NewHostVolumes()
	result := hs.Replace(hs2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("HostVolumes nil pointer can't be replace")
		t.Fail()
	}

	hs = &HostVolumes{
		VolumesByID: map[string]*HostVolume{
			"ID": {
				AttachID: "AttachID",
				Device:   "Device",
			},
		},
		VolumesByName: map[string]string{
			"Name": "Volumes",
		},
		VolumesByDevice: map[string]string{
			"Device": "Volumes",
		},
		DevicesByID: map[string]string{
			"ID": "Devices",
		},
	}
	result = hs2.Replace(hs)
	areEqual := reflect.DeepEqual(result, hs)
	if !areEqual {
		t.Error("Replace does not restitute values")
		t.Fail()
	}

}

func TestHostVolumes_Clone(t *testing.T) {

	hs := &HostVolumes{
		VolumesByID: map[string]*HostVolume{
			"ID": {
				AttachID: "AttachID",
				Device:   "Device",
			},
		},
		VolumesByName: map[string]string{
			"Name": "Volumes",
		},
		VolumesByDevice: map[string]string{
			"Device": "Volumes",
		},
		DevicesByID: map[string]string{
			"ID": "Devices",
		},
	}

	clonedHs, ok := hs.Clone().(*HostVolumes)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, hs, clonedHs)
	require.EqualValues(t, hs, clonedHs)
	clonedHs.VolumesByID = nil

	areEqual := reflect.DeepEqual(hs, clonedHs)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, hs, clonedHs)
}
