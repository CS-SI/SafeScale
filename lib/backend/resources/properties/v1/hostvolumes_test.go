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
	err := hs.Replace(hs2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
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
	err = hs2.Replace(hs)
	require.Nil(t, err)
	areEqual := reflect.DeepEqual(hs2, hs)
	if !areEqual {
		t.Error("Replace does not restitute values")
		t.Fail()
	}

	network, _ := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	err = hs2.Replace(network)
	if err == nil {
		t.Error("HostVolumes.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(err.Error(), "p is not a *HostVolumes") {
		t.Errorf("Expect error \"p is not a *HostVolumes\", has \"%s\"", err.Error())
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

	cloned, err := hs.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedHs, ok := cloned.(*HostVolumes)
	if !ok {
		t.Error("Cloned HostVolumes not castable to *HostVolumes", err)
		t.Fail()
	}

	assert.Equal(t, hs, clonedHs)
	require.EqualValues(t, hs, clonedHs)
	clonedHs.VolumesByID = nil

	areEqual := reflect.DeepEqual(hs, clonedHs)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, hs, clonedHs)
}
