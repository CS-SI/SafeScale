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

func TestLabelHosts_IsNull(t *testing.T) {

	var ht *LabelHosts = nil
	if !ht.IsNull() {
		t.Error("LabelHosts nil pointer is null")
		t.Fail()
	}
	ht = NewLabelHosts()
	if !ht.IsNull() {
		t.Error("Empty LabelHosts is null")
		t.Fail()
	}

	ht.ByID["host id"] = "label value"
	ht.ByName["host name"] = "label value"
	if ht.IsNull() {
		t.Error("LabelHosts is not null")
		t.Fail()
	}

}

func TestLabelHosts_Replace(t *testing.T) {

	var ht *LabelHosts = nil
	ht2 := NewLabelHosts()
	result, err := ht.Replace(ht2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

}

func TestLabelHosts_Clone(t *testing.T) {

	ht := &LabelHosts{
		ByID:   map[string]string{"host id": "value"},
		ByName: map[string]string{"host name": "value"},
	}

	cloned, err := ht.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedHt, ok := cloned.(*LabelHosts)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ht, clonedHt)
	require.EqualValues(t, ht, clonedHt)
	clonedHt.ByID["host id"] = "different value"
	clonedHt.ByName["host name"] = "different value"

	areEqual := reflect.DeepEqual(ht, clonedHt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, ht, clonedHt)
}
