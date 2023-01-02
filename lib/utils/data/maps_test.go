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

package data

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_NewMap(t *testing.T) {

	m := NewMap()
	require.EqualValues(t, reflect.TypeOf(m).String(), "data.Map")

}

func TestMap_Clone(t *testing.T) {

	m := Map{
		"0": "first",
		"1": "second",
		"2": "third",
	}
	c, err := FromMap(m)
	if err != nil {
		t.Error(err)
	}
	areEqual := reflect.DeepEqual(m, c)
	if !areEqual {
		t.Error("Clone not restitute values")
		t.Fail()
	}

	c["0"] = "new first"
	areEqual = reflect.DeepEqual(m, c)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}

}

func TestMap_Merge(t *testing.T) {

	a := Map{
		"0": "first",
	}
	b := Map{
		"1": "second",
	}
	c := Map{
		"2": "third",
	}
	m := Map{
		"0": "first",
		"1": "second",
		"2": "third",
	}

	a.Merge(b)
	a.Merge(c)
	areEqual := reflect.DeepEqual(a, m)
	if !areEqual {
		t.Error("Merge not restitute values")
		t.Fail()
	}

}

func TestMap_ForceMerge(t *testing.T) {

	a := Map{
		"0": "first",
		"1": "second",
	}
	b := Map{
		"1": "new second",
		"2": "third",
	}
	m := Map{
		"0": "first",
		"1": "new second",
		"2": "third",
	}

	a.ForceMerge(b)
	areEqual := reflect.DeepEqual(a, m)
	if !areEqual {
		t.Error("ForceMerge not restitute values")
		t.Fail()
	}

}

func TestMap_Contains(t *testing.T) {

	a := Map{
		"0": "first",
		"1": "second",
		"2": "third",
	}
	require.EqualValues(t, a.Contains("0"), true)
	require.EqualValues(t, a.Contains("a"), false)

}

func TestMap_Keys(t *testing.T) {

	a := Map{
		"0": "first",
		"1": "second",
		"2": "third",
	}
	k := a.Keys()
	for i := range k {
		l := k[i]
		if l != "0" && l != "1" && l != "2" {
			t.Errorf("Unexpected key %s", l)
			t.Fail()
		}
	}

}
func TestMap_Values(t *testing.T) {

	a := Map{
		"0": "first",
		"1": "second",
		"2": "third",
	}
	v := a.Values()
	for i := range v {
		l := v[i].(string)
		if l != "first" && l != "second" && l != "third" {
			t.Errorf("Unexpected value %s", l)
			t.Fail()
		}
	}

}

func TestIndexedListOfStrings_KeysAndValues(t *testing.T) {

	v := IndexedListOfStrings{}
	keys, values := v.KeysAndValues()
	require.EqualValues(t, len(keys), 0)
	require.EqualValues(t, len(values), 0)

	v = IndexedListOfStrings{
		0: "first",
		1: "second",
		2: "third",
	}
	keys, values = v.KeysAndValues()
	for i := range keys {
		if /*keys[i] < 0 || (na, uint)*/ keys[i] > 2 {
			t.Errorf("Unexpected index %d", keys[i])
			t.Fail()
		}
		if values[i] != "first" && values[i] != "second" && values[i] != "third" {
			t.Errorf("Unexpected value %s", values[i])
			t.Fail()
		}
	}

}
func TestIndexedListOfStrings_Keys(t *testing.T) {

	v := IndexedListOfStrings{}
	keys := v.Keys()
	require.EqualValues(t, len(keys), 0)

	v = IndexedListOfStrings{
		0: "first",
		1: "second",
		2: "third",
	}

	keys = v.Keys()
	for i := range keys {
		if /* keys[i] < 0 || (na, uint) */ keys[i] > 2 {
			t.Errorf("Unexpected index %d", keys[i])
			t.Fail()
		}
	}

}
func TestIndexedListOfStrings_Values(t *testing.T) {

	v := IndexedListOfStrings{}
	values := v.Values()
	require.EqualValues(t, len(values), 0)

	v = IndexedListOfStrings{
		0: "first",
		1: "second",
		2: "third",
	}

	values = v.Values()
	for i := range values {
		if values[i] != "first" && values[i] != "second" && values[i] != "third" {
			t.Errorf("Unexpected value %s", values[i])
			t.Fail()
		}
	}

}
