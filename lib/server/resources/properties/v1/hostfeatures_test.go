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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostInstalledFeature_IsNull(t *testing.T) {

	var hf *HostInstalledFeature = nil
	if !hf.IsNull() {
		t.Error("Nil pointer HostInstalledFeature is null")
		t.Fail()
	}
	hf = NewHostInstalledFeature()
	if !hf.IsNull() {
		t.Error("Empty HostInstalledFeature is null")
		t.Fail()
	}
	hf = &HostInstalledFeature{
		RequiredBy: map[string]struct{}{
			"Feature1": {},
		},
		Requires: map[string]struct{}{
			"Feature2": {},
		},
	}
	if hf.IsNull() {
		t.Error("HostInstalledFeature is not null")
		t.Fail()
	}

}

func TestHostInstalledFeature_Replace(t *testing.T) {

	var hif *HostInstalledFeature = nil
	hif2 := &HostInstalledFeature{
		RequiredBy: map[string]struct{}{
			"Feature1": {},
		},
		Requires: map[string]struct{}{
			"Feature2": {},
		},
	}
	result := hif.Replace(hif2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("Nil pointer can't be replaced")
		t.Fail()
	}
	hif = &HostInstalledFeature{
		RequiredBy: map[string]struct{}{
			"ParentFeature1": {},
			"ParentFeature2": {},
		},
	}
	result = hif2.Replace(hif)
	areEqual := reflect.DeepEqual(hif.RequiredBy, result.(*HostInstalledFeature).RequiredBy)
	if !areEqual {
		t.Error("Replace does not restitute RequiredBy values")
		t.Fail()
	}
	hif = &HostInstalledFeature{
		Requires: map[string]struct{}{
			"ParentFeature3": {},
			"ParentFeature4": {},
		},
	}
	result = hif2.Replace(hif)
	areEqual = reflect.DeepEqual(hif.Requires, result.(*HostInstalledFeature).Requires)
	if !areEqual {
		t.Error("Replace does not restitute Requires values")
		t.Fail()
	}

}

func TestHostInstalledFeature_Clone(t *testing.T) {

	hif := &HostInstalledFeature{
		RequiredBy: map[string]struct{}{
			"Feature1": {},
		},
		Requires: map[string]struct{}{
			"Feature2": {},
		},
	}

	clonedHif, ok := hif.Clone().(*HostInstalledFeature)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, hif, clonedHif)
	require.EqualValues(t, hif, clonedHif)

	clonedHif.RequiredBy["other"] = struct{}{}

	areEqual := reflect.DeepEqual(hif, clonedHif)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, hif, clonedHif)
}

func TestHostFeatures_Reset(t *testing.T) {

	hf := &HostFeatures{
		Installed: map[string]*HostInstalledFeature{
			"Feature": {
				RequiredBy: map[string]struct{}{
					"Feature1": {},
				},
				Requires: map[string]struct{}{
					"Feature2": {},
				},
			},
		},
	}
	hf.Reset()
	if len(hf.Installed) > 0 {
		t.Error("Reset does not clean HostFeatures")
		t.Fail()
	}

}

func TestHostFeatures_IsNull(t *testing.T) {

	var hf *HostFeatures = nil
	if !hf.IsNull() {
		t.Error("Nil pointer HostFeatures is null")
		t.Fail()
	}
	hf = NewHostFeatures()
	if !hf.IsNull() {
		t.Error("Empty HostFeatures is null")
		t.Fail()
	}
	hf = &HostFeatures{
		Installed: map[string]*HostInstalledFeature{
			"Feature": {
				RequiredBy: map[string]struct{}{
					"Feature1": {},
				},
				Requires: map[string]struct{}{
					"Feature2": {},
				},
			},
		},
	}
	if hf.IsNull() {
		t.Error("HostFeatures is not null")
		t.Fail()
	}

}

func TestHostFeatures_Clone(t *testing.T) {

	hf := &HostFeatures{
		Installed: map[string]*HostInstalledFeature{
			"Feature": {
				RequiredBy: map[string]struct{}{
					"Feature1": {},
				},
				Requires: map[string]struct{}{
					"Feature2": {},
				},
			},
		},
	}

	clonedHf, ok := hf.Clone().(*HostFeatures)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, hf, clonedHf)
	require.EqualValues(t, hf, clonedHf)

}

func TestHostFeatures_Replace(t *testing.T) {

	var hf *HostFeatures = nil
	hf2 := &HostFeatures{
		Installed: map[string]*HostInstalledFeature{
			"Feature": {
				RequiredBy: map[string]struct{}{
					"Feature1": {},
				},
				Requires: map[string]struct{}{
					"Feature2": {},
				},
			},
		},
	}
	result := hf.Replace(hf2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("Nil pointer can't be replaced")
		t.Fail()
	}
	hf = &HostFeatures{
		Installed: map[string]*HostInstalledFeature{
			"Feature": {
				RequiredBy: map[string]struct{}{
					"Feature3": {},
				},
				Requires: map[string]struct{}{
					"Feature4": {},
				},
			},
		},
	}
	result = hf2.Replace(hf)
	areEqual := reflect.DeepEqual(hf, result.(*HostFeatures))
	if !areEqual {
		t.Error("Replace does not restitute values")
		t.Fail()
	}

}
