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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostLabels_IsNull(t *testing.T) {

	var ht *HostLabels = nil
	if !ht.IsNull() {
		t.Error("HostLabels nil pointer is null")
		t.Fail()
	}
	ht = NewHostLabels()
	if !ht.IsNull() {
		t.Error("Empty HostLabels is null")
		t.Fail()
	}

	ht.ByID["tag id"] = "tag name"
	ht.ByName["tag name"] = "tag id"
	if ht.IsNull() {
		t.Error("HostTag is not null")
		t.Fail()
	}

}

func TestHostLabels_Replace(t *testing.T) {

	var ht *HostLabels = nil
	ht2 := NewHostLabels()
	err := ht.Replace(ht2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
}

func TestHostLabels_Clone(t *testing.T) {

	ht := &HostLabels{
		ByID:   map[string]string{"id": "name"},
		ByName: map[string]string{"name": "id"},
	}

	cloned, err := ht.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedHt, ok := cloned.(*HostLabels)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ht, clonedHt)
	require.EqualValues(t, ht, clonedHt)
	clonedHt.ByID["id"] = "different name"
	clonedHt.ByName["name"] = "different id"

	areEqual := reflect.DeepEqual(ht, clonedHt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, ht, clonedHt)
}
