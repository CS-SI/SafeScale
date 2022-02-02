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

func TestHostSizingRequirements_IsNull(t *testing.T) {

	var hsr *HostSizingRequirements = nil
	if !hsr.IsNull() {
		t.Error("HostSizingRequirements nil pointer is null")
		t.Fail()
	}
	hsr = NewHostSizingRequirements()
	if !hsr.IsNull() {
		t.Error("Empty HostSizingRequirements is null")
		t.Fail()
	}
	hsr.Cores = 1
	if hsr.IsNull() {
		t.Error("HostSizingRequirements is not null")
		t.Fail()
	}

}

func TestHostEffectiveSizing_IsNull(t *testing.T) {

	var hsr *HostEffectiveSizing = nil
	if !hsr.IsNull() {
		t.Error("HostEffectiveSizing nil pointer is null")
		t.Fail()
	}
	hsr = NewHostEffectiveSizing()
	if !hsr.IsNull() {
		t.Error("Empty HostEffectiveSizing is null")
		t.Fail()
	}
	hsr.Cores = 1
	if hsr.IsNull() {
		t.Error("HostEffectiveSizing is not null")
		t.Fail()
	}

}

func TestHostSizing_IsNull(t *testing.T) {

	var hsr *HostSizing = nil
	if !hsr.IsNull() {
		t.Error("HostSizing nil pointer is null")
		t.Fail()
	}
	hsr = NewHostSizing()
	if !hsr.IsNull() {
		t.Error("Empty HostSizing is null")
		t.Fail()
	}
	hsr.RequestedSize = NewHostSizingRequirements()
	hsr.RequestedSize.Cores = 1
	if hsr.IsNull() {
		t.Error("HostSizing is not null")
		t.Fail()
	}

}

func TestHostSizing_Replace(t *testing.T) {

	var hs *HostSizing = nil
	hs2 := NewHostSizing()
	result := hs.Replace(hs2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("HostSizing nil pointer can't be replace")
		t.Fail()
	}

}

func TestHostSizing_Clone(t *testing.T) {

	hs := &HostSizing{
		RequestedSize: &HostSizingRequirements{
			Cores:     1,
			RAMSize:   1024,
			DiskSize:  512,
			GPUNumber: 1,
			GPUType:   "RTX 3070 Ti",
			CPUFreq:   4800,
		},
		AllocatedSize: &HostEffectiveSizing{
			Cores:     1,
			RAMSize:   1024,
			DiskSize:  512,
			GPUNumber: 1,
			GPUType:   "RTX 3070 Ti",
			CPUFreq:   4800,
		},
	}

	clonedHs, ok := hs.Clone().(*HostSizing)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, hs, clonedHs)
	require.EqualValues(t, hs, clonedHs)
	clonedHs.AllocatedSize = nil

	areEqual := reflect.DeepEqual(hs, clonedHs)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, hs, clonedHs)
}
