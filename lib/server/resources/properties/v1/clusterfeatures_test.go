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
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFeatures_Clone(t *testing.T) {
	ct := newClusterFeatures()

	ct.Installed["fair"] = &ClusterInstalledFeature{
		Requires: map[string]struct{}{
			"something": struct{}{},
		},
	}
	ct.Disabled["kind"] = struct{}{}

	clonedCt, ok := ct.Clone().(*ClusterFeatures)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.Installed["fair"] = &ClusterInstalledFeature{
		Requires: map[string]struct{}{
			"commitment": struct{}{},
		},
	}

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}

func TestFeatures_Clone_Bis(t *testing.T) {
	ct := newClusterFeatures()
	ct.Installed["fair"] = NewClusterInstalledFeature()
	ct.Installed["fair"].Requires["something"] = struct{}{}
	ct.Disabled["kind"] = struct{}{}

	clonedCt, ok := ct.Clone().(*ClusterFeatures)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.Installed["fair"].Requires = map[string]struct{}{"commitment": {}}

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
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

	clonedCt.RequiredBy["other"] = struct{}{}

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
