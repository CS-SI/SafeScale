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
	err := cif.Replace(cif2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}

	cif = &ClusterInstalledFeature{
		Name: "Feature Name 2",
		RequiredBy: map[string]struct{}{
			"ParentFeature1": {},
			"ParentFeature2": {},
		},
	}
	err = cif2.Replace(cif)
	require.Nil(t, err)
	areEqual := reflect.DeepEqual(cif.RequiredBy, cif2.RequiredBy)
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
	err = cif2.Replace(cif)
	require.Nil(t, err)
	areEqual = reflect.DeepEqual(cif.Requires, cif2.Requires)
	if !areEqual {
		t.Error("Replace does not restitute Requires values")
		t.Fail()
	}

	network, _ := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"
	err = cif2.Replace(network)
	require.NotNil(t, err)
}

func TestClusterInstalledFeature_Clone(t *testing.T) {
	ct := NewClusterInstalledFeature()
	ct.Requires["something"] = struct{}{}

	cloned, err := ct.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedCt, ok := cloned.(*ClusterInstalledFeature)
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
		Installed: make(map[string]*ClusterInstalledFeature),
		Disabled:  make(map[string]struct{}),
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
		Disabled: make(map[string]struct{}),
	}
	if cf.IsNull() {
		t.Error("ClusterFeatures is not null")
		t.Fail()
	}

}

func TestClusterFeatures_Replace(t *testing.T) {

	var cif *ClusterFeatures = nil
	cif2 := newClusterFeatures()

	err := cif.Replace(cif2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}

	network, _ := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	err = cif2.Replace(network)
	if err == nil {
		t.Error("ClusterFeatures.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(err.Error(), "p is not a *ClusterFeatures") {
		t.Errorf("Expect error \"p is not a *ClusterFeatures\", has \"%s\"", err.Error())
	}

}

func TestClusterFeatures_Clone(t *testing.T) {
	ct := newClusterFeatures()
	ct.Installed["fair"] = NewClusterInstalledFeature()
	ct.Installed["fair"].Requires["something"] = struct{}{}
	ct.Disabled["kind"] = struct{}{}

	cloned, err := ct.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedCt, ok := cloned.(*ClusterFeatures)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	require.EqualValues(t, ct, clonedCt)
	clonedCt.Installed["fair"].Requires = map[string]struct{}{"commitment": {}}

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}
