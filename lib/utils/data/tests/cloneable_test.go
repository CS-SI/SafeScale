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

package tests

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEasyCloneable(t *testing.T) {
	a := NewStructWithoutPointers()
	a.Content = "easy"
	a.Rumba = 9

	at, err := a.Clone()
	if err != nil {
		t.Error(err)
	}

	b, ok := at.(*StructWithoutPointers)
	if !ok {
		t.Error("invalid cast")
	}

	a.Rumba = 3
	ieq := reflect.DeepEqual(a, b)
	assert.False(t, ieq)

	a.Rumba = 9
	ieq = reflect.DeepEqual(a, b)
	require.EqualValues(t, a, b)
	assert.True(t, ieq)

	a.Content = "whatever"
	ieq = reflect.DeepEqual(a, b)
	assert.False(t, ieq)
}

/*type Memoria struct {
	content []string
	painful int
}

func NewMemoria(num int, cts ...string) *Memoria {
	return &Memoria{
		content: cts[:],
		painful: num,
	}
}

func (m Memoria) Clone() data.Clonable {
	return NewMemoria(0, "").Replace(&m)
}

func (m *Memoria) Replace(clonable data.Clonable) data.Clonable {
	*m = *clonable.(*Memoria)
	return m
}
*/

// This test, if it succeeds, means the 'Replace' implementation is defective
func TestDefectiveCloneableImplementation(t *testing.T) {
	a := NewStructWithPointersAndDefectiveReplace()
	a.Rumba = 9
	a.List = []string{"death", "comes", "to", "all"}
	a.Map = map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	at, err := a.Clone()
	if err != nil {
		t.Error(err)
	}

	b, ok := at.(*StructWithPointersAndDefectiveReplace)
	if !ok {
		t.Error("Invalid cast")
	}

	a.Rumba = 3
	ieq := reflect.DeepEqual(a, b)
	assert.False(t, ieq)

	a.Rumba = 9
	ieq = reflect.DeepEqual(a, b)
	assert.True(t, ieq)

	a.List[1] = "despair"
	ieq = reflect.DeepEqual(a, b)
	assert.True(t, ieq)
}

func TestValidCloneableImplementation(t *testing.T) {
	a := NewStructWithPointersAndCorrectReplace()
	a.content = "Let it burn"
	a.Rumba = 9
	a.List = []string{"death", "comes", "to", "all"}
	a.Map = map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	at, err := a.Clone()
	if err != nil {
		t.Error(err)
	}

	b, ok := at.(*StructWithPointersAndCorrectReplace)
	if !ok {
		t.Error("Invalid cast")
	}

	a.Rumba = 3
	ieq := reflect.DeepEqual(a, b)
	assert.False(t, ieq)

	a.Rumba = 9
	ieq = reflect.DeepEqual(a, b)
	assert.True(t, ieq)

	a.List[1] = "despair"
	ieq = reflect.DeepEqual(a, b)
	assert.False(t, ieq)

	a.content = "on fire"
	ieq = reflect.DeepEqual(a, b)
	assert.False(t, ieq)

	a.content = "Let it burn"
	ieq = reflect.DeepEqual(a, b)
	assert.False(t, ieq)
}
