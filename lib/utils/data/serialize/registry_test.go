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

package serialize

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
)

type Item struct {
	clonable.Clonable
	value string
}

func (e Item) IsNull() bool {
	return false
}
func (e Item) Clone() (clonable.Clonable, error) {
	var v clonable.Clonable = &Item{value: e.value}
	return v, nil
}

func (e Item) Replace(i clonable.Clonable) error {
	r, ok := i.(*Item)
	if !ok {
		return fmt.Errorf("i is not a *Item")
	}

	e.value = r.value
	return nil
}
func (e Item) Value() string {
	return e.value
}

func NewItem(value string) Item {
	return Item{value: value}
}

func TestPropertyTypeRegistry_Register(t *testing.T) {

	z := NewItem("zero")
	p := propertyTypeRegistry{
		"module1": {
			"key1": NewItem("value1"),
			"key2": NewItem("value2"),
			"key3": NewItem("value3"),
		},
		"module2": {
			"key1": NewItem("value4"),
			"key2": NewItem("value5"),
			"key3": NewItem("value6"),
		},
	}

	p.Register("module1", "key1", z)
	require.EqualValues(t, p["module1"]["key1"], z)
	p.Register("module1", "key4", z)
	require.EqualValues(t, p["module1"]["key4"], z)
	p.Register("module3", "key1", z)
	require.EqualValues(t, p["module3"]["key1"], z)

}

func TestPropertyTypeRegistry_Lookup(t *testing.T) {

	p := propertyTypeRegistry{
		"module1": {
			"key1": NewItem("value1"),
			"key2": NewItem("value2"),
			"key3": NewItem("value3"),
		},
		"module2": {
			"key1": NewItem("value4"),
			"key2": NewItem("value5"),
			"key3": NewItem("value6"),
		},
	}
	require.EqualValues(t, p.Lookup("module1", "key1"), true)
	require.EqualValues(t, p.Lookup("module1", "key3"), true)
	require.EqualValues(t, p.Lookup("module1", "key4"), false)
	require.EqualValues(t, p.Lookup("module3", "key1"), false)

}

func TestPropertyTypeRegistry_ZeroValue(t *testing.T) {

	p := propertyTypeRegistry{
		"module1": {
			"key1": NewItem("value1"),
			"key2": NewItem("value2"),
			"key3": NewItem("value3"),
		},
		"module2": {
			"key1": NewItem("value4"),
			"key2": NewItem("value5"),
			"key3": NewItem("value6"),
		},
	}
	fmt.Println(p.ZeroValue("module1", "key1"))

}
