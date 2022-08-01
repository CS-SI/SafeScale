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
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
)

func TestHostInstalledFeature_IsNull(t *testing.T) {

	var hf *HostInstalledFeature
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
	result, err := hif.Replace(hif2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)
	hif = &HostInstalledFeature{
		RequiredBy: map[string]struct{}{
			"ParentFeature1": {},
			"ParentFeature2": {},
		},
	}
	result, _ = hif2.Replace(hif)
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
	result, _ = hif2.Replace(hif)
	areEqual = reflect.DeepEqual(hif.Requires, result.(*HostInstalledFeature).Requires)
	if !areEqual {
		t.Error("Replace does not restitute Requires values")
		t.Fail()
	}

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, err = hif2.Replace(network)
	require.Contains(t, err.Error(), "p is not a *HostInstalledFeature")

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

	cloned, err := hif.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedHif, ok := cloned.(*HostInstalledFeature)
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

	var hf *HostFeatures
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

	cloned, err := hf.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedHf, ok := cloned.(*HostFeatures)
	if !ok {
		t.Error("Cloned HostFeatures not castable to *HostFeatures", err)
		t.Fail()
	}

	assert.Equal(t, hf, clonedHf)
	require.EqualValues(t, hf, clonedHf)

}

func TestHostFeatures_Replace(t *testing.T) {

	var hf *HostFeatures
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
	result, err := hf.Replace(hf2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)
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
	result, _ = hf2.Replace(hf)
	areEqual := reflect.DeepEqual(hf, result.(*HostFeatures))
	if !areEqual {
		t.Error("Replace does not restitute values")
		t.Fail()
	}

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := hf2.Replace(network)
	if xerr == nil {
		t.Error("HostFeatures.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *HostFeatures") {
		t.Errorf("Expect error \"p is not a *HostFeatures\", has \"%s\"", xerr.Error())
	}

}
