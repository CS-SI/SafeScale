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

package propertiesv2

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
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
	hsr.MinCores = 1
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

	var hs *HostSizing = nil
	if !hs.IsNull() {
		t.Error("HostSizing nil pointer is null")
		t.Fail()
	}
	hs = NewHostSizing()
	if !hs.IsNull() {
		t.Error("Empty HostSizing is null")
		t.Fail()
	}
	hs.Template = "HostSizing Template"
	if hs.IsNull() {
		t.Error("HostSizing is not null")
		t.Fail()
	}
}

func TestHostSizing_Replace(t *testing.T) {
	var hs *HostSizing = nil
	hs2 := NewHostSizing()
	result, err := hs.Replace(hs2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := hs2.Replace(network)
	if xerr == nil {
		t.Error("HostSizing.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *HostSizing") {
		t.Errorf("Expect error \"p is not a *HostSizing\", has \"%s\"", xerr.Error())
	}
}

func TestHostSizing_Clone(t *testing.T) {
	hs := &HostSizing{
		RequestedSize: &HostSizingRequirements{
			MinCores:    0,
			MaxCores:    0,
			MinRAMSize:  0.0,
			MaxRAMSize:  0.0,
			MinDiskSize: 0,
			MinGPU:      0,
			MinCPUFreq:  0.0,
			Replaceable: false,
		},
		Template: "HostSizing Template",
		AllocatedSize: &HostEffectiveSizing{
			Cores:     0,
			RAMSize:   0.0,
			DiskSize:  0,
			GPUNumber: 0,
			GPUType:   "Nvidia RTX 3080 Ti",
			CPUFreq:   0.0,
		},
	}

	cloned, err := hs.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedHs, ok := cloned.(*HostSizing)
	if !ok {
		t.Error("Cloned HostSizing not castable to *HostSizing", err)
		t.Fail()
	}

	assert.Equal(t, hs, clonedHs)
	clonedHs.Template = "HostSizing Template2"
	areEqual := reflect.DeepEqual(hs, clonedHs)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, hs, clonedHs)
}
