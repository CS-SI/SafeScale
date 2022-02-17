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
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/hoststate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeypair_IsNull(t *testing.T) {

	var emptyKeypair *KeyPair = nil
	if !emptyKeypair.IsNull() {
		t.Error("No, it's null")
		t.Fail()
	}
	emptyKeypair = &KeyPair{
		ID:         "",
		Name:       "",
		PrivateKey: "",
		PublicKey:  "",
	}
	if !emptyKeypair.IsNull() {
		t.Error("No, it's null")
		t.Fail()
	}
	emptyKeypair.ID = "KayPairId"
	if !emptyKeypair.IsNull() {
		t.Error("No, it's null")
		t.Fail()
	}
	emptyKeypair.Name = "KayPairName"
	if !emptyKeypair.IsNull() {
		t.Error("No, it's null")
		t.Fail()
	}
	emptyKeypair.PrivateKey = "PrivateKey"
	if !emptyKeypair.IsNull() {
		t.Error("No, it's null")
		t.Fail()
	}
	emptyKeypair.PublicKey = "PublicKey"
	if emptyKeypair.IsNull() {
		t.Error("No, it's not null")
		t.Fail()
	}

}

func TestKeyPair_NewKeyPair(t *testing.T) {

	kp, err := NewKeyPair("")
	if err != nil {
		// Error is unexpected
		t.Error(err)
		t.Fail()
	}
	if len(kp.Name) < 3 || kp.Name[0:3] != "kp_" {
		t.Error("Expect KeyPair generate name from new uuid")
		t.Fail()
	}

}

func Test_almostEqual(t *testing.T) {

	var pow float32 = float32(rand.Intn(65535))
	var min float32 = 0.0
	var max float32 = float32(pow)
	var mid float32 = 0.0
	var limit int16 = 64 // Can't be > 2 ^ 32

	for {

		// Dichotomic sqrt
		mid = (min + max) / 2
		if mid*mid >= pow {
			max = mid
		} else {
			min = mid
		}

		if almostEqual(mid*mid, pow) {
			break
		}

		// Process deep limit
		limit--
		if limit <= 0 {
			break
		}
	}

	if limit == 0 {
		t.Error("almostEqual as unreachable limit (over 2^64)")
		t.Fail()
	}

}

func TestHostSizingRequirements_Equals(t *testing.T) {

	hsr1 := HostSizingRequirements{
		MinCores:    1,
		MaxCores:    8,
		MinRAMSize:  4092,
		MaxRAMSize:  8192,
		MinDiskSize: 1024,
		MinGPU:      1,
		MinCPUFreq:  2033,
		Replaceable: false,
		Image:       "HostSizingRequirements Image",
		Template:    "HostSizingRequirements Template",
	}
	hsr2 := HostSizingRequirements{}
	if hsr1.Equals(hsr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	hsr2.MinCores = hsr1.MinCores
	if hsr1.Equals(hsr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	hsr2.MaxCores = hsr1.MaxCores
	if hsr1.Equals(hsr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	hsr2.MinRAMSize = hsr1.MinRAMSize
	if hsr1.Equals(hsr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	hsr2.MaxRAMSize = hsr1.MaxRAMSize
	if hsr1.Equals(hsr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	hsr2.MinDiskSize = hsr1.MinDiskSize
	if hsr1.Equals(hsr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	hsr2.MinGPU = hsr1.MinGPU
	if hsr1.Equals(hsr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	hsr2.MinCPUFreq = hsr1.MinCPUFreq
	if !hsr1.Equals(hsr2) {
		t.Error("No, are equals")
		t.Fail()
	}

}

func TestImage_OK(t *testing.T) {

	i := Image{
		ID:   "",
		Name: "",
		URL:  "",
	}
	if i.OK() {
		t.Error("No, not OK")
		t.Fail()
	}
	i.ID = "Image ID"
	i.Name = "Image Name"
	i.URL = "Image URL"
	if !i.OK() {
		t.Error("No, it is OK")
		t.Fail()
	}

}

func Test_NewHostEffectiveSizing(t *testing.T) {

	hes := NewHostEffectiveSizing()
	if reflect.TypeOf(hes).String() != "*abstract.HostEffectiveSizing" {
		t.Error("Unexpected type \"" + reflect.TypeOf(hes).String() + "\", expect *abstract.HostEffectiveSizing")
		t.Fail()
	}

}

func TestHostEffectiveSizing_IsNull(t *testing.T) {
	var hse *HostEffectiveSizing = nil
	if !hse.IsNull() {
		t.Error("No, is null")
		t.Fail()
	}
	hse = &HostEffectiveSizing{
		Cores: 0,
	}
	if !hse.IsNull() {
		t.Error("No, no cores, is null")
		t.Fail()
	}
	hse.Cores = 1
	if hse.IsNull() {
		t.Error("No, has cores, not null")
		t.Fail()
	}
}

func TestHostTemplate_OK(t *testing.T) {

	ht := HostTemplate{
		ID:   "",
		Name: "",
	}
	if ht.OK() {
		t.Error("No, not OK")
		t.Fail()
	}
	ht.ID = "HostTemplate ID"
	ht.Name = "HostTemplate Name"
	if !ht.OK() {
		t.Error("No, it is OK")
		t.Fail()
	}
}

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

func TestHostCore_Replace(t *testing.T) {

	hc1 := NewHostCore()
	hc1.ID = "HostCore ID"
	hc1.Name = "HostCore Name"
	hc1.PrivateKey = "HostCore PrivateKey"
	hc1.SSHPort = 42
	hc1.Password = "HostCore Password"
	hc1.LastState = hoststate.Unknown

	var hc2 *HostCore = nil
	replaced := hc2.Replace(hc1)

	if fmt.Sprintf("%p", replaced) != "0x0" {
		t.Error("Can't Replace nil pointer")
		t.Fail()
	}

	replaced = hc2.Replace(hc1)
	if fmt.Sprintf("%p", replaced) != "0x0" {
		t.Error("Can't Replace nil data.Clonable pointer")
		t.Fail()
	}

}

func TestHostCore_Serialize(t *testing.T) {

	var emptyHc *HostCore = nil
	_, err := emptyHc.Serialize()
	if err == nil {
		t.Error("Can't serialize nil pointer")
		t.Fail()
	}

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

func TestHostCore_Deserialize(t *testing.T) {

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

	var emptyHc *HostCore = nil
	err = emptyHc.Deserialize(serial)
	if err == nil {
		t.Error("Can't deserialize nil pointer")
		t.Fail()
	}

	// Junk serial
	junkSerial := []byte("{ broken Json }")
	err = emptyHc.Deserialize(junkSerial)
	if err == nil {
		t.Error("Can't deserialize broken serial")
		t.Fail()
	}

}

func TestHostCore_GetName(t *testing.T) {

	var hc *HostCore = nil

	name := hc.GetName()
	if name != "" {
		t.Error("(nil) *HostCore has no name")
		t.Fail()
	}

	hc = &HostCore{
		Name: "HostCore Name",
	}
	name = hc.GetName()
	if name != hc.Name {
		t.Error("Wrong GetName value restitution")
		t.Fail()
	}

}

func TestHostCore_GetID(t *testing.T) {

	var hc *HostCore = nil

	id := hc.GetID()
	if id != "" {
		t.Error("(nil) *HostCore has no id")
		t.Fail()
	}

	hc = &HostCore{
		ID: "HostCore ID",
	}
	id = hc.GetID()
	if id != hc.ID {
		t.Error("Wrong GetID value restitution")
		t.Fail()
	}

}

func Test_NewHostNetworking(t *testing.T) {

	hn := NewHostNetworking()

	if reflect.TypeOf(hn).String() != "*abstract.HostNetworking" {
		t.Error("Expect new *abstract.HostNetworking")
		t.Fail()
	}

}

func Test_NewHostFull(t *testing.T) {

	hf := NewHostFull()
	if reflect.TypeOf(hf).String() != "*abstract.HostFull" {
		t.Error("Expect new *abstract.HostFull")
		t.Fail()
	}

}

func TestHostFull_IsNull(t *testing.T) {

	var hf *HostFull = nil
	if !hf.IsNull() {
		t.Error("(nil) *Hostfull is null")
		t.Fail()
	}
	if hf.IsConsistent() {
		t.Error("(nil) *Hostfull is not consistent")
		t.Fail()
	}
	if hf.OK() {
		t.Error("(nil) *Hostfull is not OK")
		t.Fail()
	}

	hf = NewHostFull()
	if !hf.IsNull() {
		t.Error("empty *Hostfull is null")
		t.Fail()
	}
	if hf.IsConsistent() {
		t.Error("empty *Hostfull is not consistent")
		t.Fail()
	}
	if hf.OK() {
		t.Error("empty *Hostfull is not OK")
		t.Fail()
	}

}

func TestHostFull_GetID(t *testing.T) {

	var hf *HostFull = nil
	id := hf.GetID()
	if id != "" {
		t.Error("(nil) *Hostfull has no id")
		t.Fail()
	}
	hf = NewHostFull()
	id = hf.GetID()
	if id != "" {
		t.Error("(empty) *Hostfull has no id")
		t.Fail()
	}
	hf.Core.ID = "HostFullId"
	id = hf.GetID()
	if id != hf.Core.ID {
		t.Error("Wrong value restitution")
		t.Fail()
	}
}

func TestHostFull_GetName(t *testing.T) {

	var hf *HostFull = nil
	name := hf.GetName()
	if name != "" {
		t.Error("(nil) *Hostfull has no id")
		t.Fail()
	}
	hf = NewHostFull()
	name = hf.GetName()
	if name != "" {
		t.Error("(empty) *Hostfull has no id")
		t.Fail()
	}
	hf.Core.Name = "HostFullId"
	name = hf.GetName()
	if name != hf.Core.Name {
		t.Error("Wrong value restitution")
		t.Fail()
	}
}

func TestHostFull_SetName(t *testing.T) {

	var hf *HostFull = nil
	hf.SetName("OhMyNilPointerName!!!")
	name := hf.GetName()
	if name != "" {
		t.Error("Can't set name to (nil) HostFull")
		t.Fail()
	}
	hf = NewHostFull()
	hf.SetName("HostFullName")
	name = hf.GetName()
	if name != "HostFullName" {
		t.Error("Empty HostFull can receive new name")
		t.Fail()
	}

}

func TestHostSizingRequirements_LowerThan(t *testing.T) {

	var hsr1 *HostSizingRequirements = nil
	var hsr2 *HostSizingRequirements = nil

	isLower, err := hsr1.LowerThan(hsr2)
	if err == nil {
		t.Error("Can't compare nil HostSizingRequirements")
		t.Fail()
	}
	hsr1 = &HostSizingRequirements{
		MinCores:    0,
		MaxCores:    0,
		MinRAMSize:  0,
		MaxRAMSize:  0,
		MinDiskSize: 0,
		MinGPU:      0,
		MinCPUFreq:  0,
		Replaceable: false,
		Image:       "",
		Template:    "",
	}
	isLower, err = hsr1.LowerThan(hsr2)
	if err == nil {
		t.Error("Can't compare nil HostSizingRequirements")
		t.Fail()
	}
	hsr2 = &HostSizingRequirements{
		MinCores:    0,
		MaxCores:    0,
		MinRAMSize:  0,
		MaxRAMSize:  0,
		MinDiskSize: 0,
		MinGPU:      0,
		MinCPUFreq:  0,
		Replaceable: false,
		Image:       "",
		Template:    "",
	}
	isLower, err = hsr1.LowerThan(hsr2)
	if isLower {
		t.Error("no, is greater")
		t.Fail()
	}
	hsr1.MinCores = 2
	hsr2.MinCores = 1
	isLower, err = hsr1.LowerThan(hsr2)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if isLower {
		t.Error("no, is greater")
		t.Fail()
	}
	hsr1.MinCores = 0
	hsr2.MinCores = 0
	hsr1.MaxCores = 1
	hsr2.MaxCores = 0
	isLower, err = hsr1.LowerThan(hsr2)
	if isLower {
		t.Error("no, is greater")
		t.Fail()
	}
	hsr1.MaxCores = 0
	hsr2.MaxCores = 0
	hsr1.MinRAMSize = 2
	hsr2.MinRAMSize = 1
	isLower, err = hsr1.LowerThan(hsr2)
	if isLower {
		t.Error("no, is greater")
		t.Fail()
	}
	hsr1.MinRAMSize = 0
	hsr2.MinRAMSize = 0
	hsr1.MaxRAMSize = 1
	hsr2.MaxRAMSize = 0
	isLower, err = hsr1.LowerThan(hsr2)
	if isLower {
		t.Error("no, is greater")
		t.Fail()
	}
	hsr1.MaxRAMSize = 0
	hsr2.MaxRAMSize = 0
	hsr1.MinDiskSize = 2
	hsr2.MinDiskSize = 1
	isLower, err = hsr1.LowerThan(hsr2)
	if isLower {
		t.Error("no, is greater")
		t.Fail()
	}
	hsr1.MinDiskSize = 0
	hsr2.MinDiskSize = 0
	hsr1.MaxRAMSize = 1
	hsr2.MaxRAMSize = 0
	isLower, err = hsr1.LowerThan(hsr2)
	if isLower {
		t.Error("no, is greater")
		t.Fail()
	}
	hsr1.MaxRAMSize = 0
	hsr2.MaxRAMSize = 0
	hsr1.MinGPU = 1
	hsr2.MinGPU = 2
	isLower, err = hsr1.LowerThan(hsr2)
	if isLower {
		t.Error("no, is greater")
		t.Fail()
	}
	hsr1.MinGPU = 0
	hsr2.MinGPU = 0
	hsr1.MinCPUFreq = 2
	hsr2.MinCPUFreq = 1
	isLower, err = hsr1.LowerThan(hsr2)
	if isLower {
		t.Error("no, is greater")
		t.Fail()
	}
	hsr1.MinCores = 0
	hsr2.MinCores = 1
	hsr1.MaxCores = 0
	hsr2.MaxCores = 1
	hsr1.MinRAMSize = 0
	hsr2.MinRAMSize = 1
	hsr1.MaxRAMSize = 0
	hsr2.MaxRAMSize = 1
	hsr1.MinDiskSize = 0
	hsr2.MinDiskSize = 1
	hsr1.MinGPU = 0
	hsr2.MinGPU = 1
	hsr1.MinCPUFreq = 0
	hsr2.MinCPUFreq = 1
	isLower, err = hsr1.LowerThan(hsr2)
	if !isLower {
		t.Error("no, is lower")
		t.Fail()
	}

}

func TestHostSizingRequirements_LowerOrEqualThan(t *testing.T) {

	var hsr1 *HostSizingRequirements = nil
	var hsr2 *HostSizingRequirements = nil

	isLowerOrEqual, err := hsr1.LowerOrEqualThan(hsr2)
	if err == nil {
		t.Error("Can't compare nil HostSizingRequirements")
		t.Fail()
	}
	hsr1 = &HostSizingRequirements{
		MinCores:    0,
		MaxCores:    0,
		MinRAMSize:  0,
		MaxRAMSize:  0,
		MinDiskSize: 0,
		MinGPU:      0,
		MinCPUFreq:  0,
		Replaceable: false,
		Image:       "",
		Template:    "",
	}
	isLowerOrEqual, err = hsr1.LowerOrEqualThan(hsr2)
	if err == nil {
		t.Error("Can't compare nil HostSizingRequirements")
		t.Fail()
	}
	hsr2 = &HostSizingRequirements{
		MinCores:    0,
		MaxCores:    0,
		MinRAMSize:  0,
		MaxRAMSize:  0,
		MinDiskSize: 0,
		MinGPU:      0,
		MinCPUFreq:  0,
		Replaceable: false,
		Image:       "",
		Template:    "",
	}
	isLowerOrEqual, err = hsr1.LowerOrEqualThan(hsr2)
	if !isLowerOrEqual {
		t.Error("no, is equal")
		t.Fail()
	}
	hsr1.MinCores = 1
	isLowerOrEqual, err = hsr1.LowerOrEqualThan(hsr2)
	if isLowerOrEqual {
		t.Error("no, is greater")
		t.Fail()
	}
	hsr1.MinCores = 0
	hsr1.MaxCores = 1
	isLowerOrEqual, err = hsr1.LowerOrEqualThan(hsr2)
	if isLowerOrEqual {
		t.Error("no, is greater")
		t.Fail()
	}
	hsr1.MaxCores = 0
	hsr1.MinRAMSize = 1
	isLowerOrEqual, err = hsr1.LowerOrEqualThan(hsr2)
	if isLowerOrEqual {
		t.Error("no, is greater")
		t.Fail()
	}
	hsr1.MinRAMSize = 0
	hsr1.MaxRAMSize = 1
	isLowerOrEqual, err = hsr1.LowerOrEqualThan(hsr2)
	if isLowerOrEqual {
		t.Error("no, is greater")
		t.Fail()
	}
	hsr1.MaxRAMSize = 0
	hsr1.MinDiskSize = 1
	isLowerOrEqual, err = hsr1.LowerOrEqualThan(hsr2)
	if isLowerOrEqual {
		t.Error("no, is greater")
		t.Fail()
	}
	hsr1.MinDiskSize = 0
	hsr1.MinGPU = 2
	hsr2.MinGPU = 1
	isLowerOrEqual, err = hsr1.LowerOrEqualThan(hsr2)
	if isLowerOrEqual {
		t.Error("no, is greater")
		t.Fail()
	}
	hsr1.MinGPU = 0
	hsr2.MinGPU = 0
	hsr1.MinCPUFreq = 1
	isLowerOrEqual, err = hsr1.LowerOrEqualThan(hsr2)
	if isLowerOrEqual {
		t.Error("no, is greater")
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
