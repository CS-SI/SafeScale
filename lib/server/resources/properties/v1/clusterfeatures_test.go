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

func TestClusterInstalledFeature_IsNull(t *testing.T) {

	var cif *ClusterInstalledFeature = nil
	if !cif.IsNull() {
		t.Error("Nil pointer ClusterInstalledFeature is null")
		t.Fail()
	}
	cif = &ClusterInstalledFeature{
		Name: "",
	}
	if !cif.IsNull() {
		t.Error("ClusterInstalledFeature without name is null")
		t.Fail()
	}
	cif = &ClusterInstalledFeature{
		Name: "Feature Name",
	}
	if cif.IsNull() {
		t.Error("ClusterInstalledFeature is not null")
		t.Fail()
	}
}

func TestClusterInstalledFeature_Replace(t *testing.T) {

	var cif *ClusterInstalledFeature = nil
	cif2 := &ClusterInstalledFeature{
		Name: "Feature Name",
	}
	result := cif.Replace(cif2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("Nil pointer can't be replaced")
		t.Fail()
	}
	cif = &ClusterInstalledFeature{
		Name: "Feature Name 2",
		RequiredBy: map[string]struct{}{
			"ParentFeature1": {},
			"ParentFeature2": {},
		},
	}
	result = cif2.Replace(cif)
	areEqual := reflect.DeepEqual(cif.RequiredBy, result.(*ClusterInstalledFeature).RequiredBy)
	if !areEqual {
		t.Error("Replace does not restitute RequiredBy values")
		t.Fail()
	}
	cif = &ClusterInstalledFeature{
		Name: "Feature Name 2",
		Requires: map[string]struct{}{
			"ParentFeature3": {},
			"ParentFeature4": {},
		},
	}
	result = cif2.Replace(cif)
	areEqual = reflect.DeepEqual(cif.Requires, result.(*ClusterInstalledFeature).Requires)
	if !areEqual {
		t.Error("Replace does not restitute Requires values")
		t.Fail()
	}

}

func TestClusterInstalledFeature_Clone(t *testing.T) {
	ct := NewClusterInstalledFeature()
	ct.Requires["something"] = struct{}{}

	clonedCt, ok := ct.Clone().(*ClusterInstalledFeature)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	require.EqualValues(t, ct, clonedCt)

	clonedCt.RequiredBy["other"] = struct{}{}

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}

func TestClusterFeatures_IsNull(t *testing.T) {

	var cf *ClusterFeatures = nil
	if !cf.IsNull() {
		t.Error("Nil pointer ClusterFeatures is null")
		t.Fail()
	}
	cf = &ClusterFeatures{
		Installed: make(map[string]*ClusterInstalledFeature, 0),
		Disabled:  make(map[string]struct{}, 0),
	}
	if !cf.IsNull() {
		t.Error("ClusterFeatures without Installed or Disabledis null")
		t.Fail()
	}
	cf = &ClusterFeatures{
		Installed: map[string]*ClusterInstalledFeature{
			"Feature": {
				Name: "Feature",
			},
		},
		Disabled: make(map[string]struct{}, 0),
	}
	if cf.IsNull() {
		t.Error("ClusterFeatures is not null")
		t.Fail()
	}

}

func TestClusterFeatures_Replace(t *testing.T) {

	var cif *ClusterFeatures = nil
	cif2 := newClusterFeatures()

	result := cif.Replace(cif2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("Nil pointer can't be replaced")
		t.Fail()
	}

}

func TestClusterFeatures_Clone(t *testing.T) {
	ct := newClusterFeatures()
	ct.Installed["fair"] = NewClusterInstalledFeature()
	ct.Installed["fair"].Requires["something"] = struct{}{}
	ct.Disabled["kind"] = struct{}{}

	clonedCt, ok := ct.Clone().(*ClusterFeatures)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	require.EqualValues(t, ct, clonedCt)
	clonedCt.Installed["fair"].Requires = map[string]struct{}{"commitment": {}}

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}
