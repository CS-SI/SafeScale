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

package providers

import (
	"reflect"
	"testing"
)

func TestConfigMap_GetString(t *testing.T) {

	c := ConfigMap{}
	c.Set("value1", 42)
	c.Set("value2", "string")

	result := c.GetString("value3")
	if result != "" {
		t.Error("Wrong GetString value restitution when no key")
		t.Fail()
	}

	defer func() {
		if q := recover(); q == nil {
			t.Error("GetString on non map[string]string value expect panic")
			t.Fail()
		}
	}()
	_ = c.GetString("value1")

	result = c.GetString("value2")
	if result != "string" {
		t.Error("Wrong GetString value restitution")
		t.Fail()
	}

}

func TestConfigMap_GetSliceOfStrings(t *testing.T) {

	var v = []string{"a", "b", "c"}
	c := ConfigMap{}
	c.Set("value1", "string")
	c.Set("value2", v)

	result := c.GetSliceOfStrings("value3")
	var emptySliceOfString []string = []string{}

	areEqual := reflect.DeepEqual(result, emptySliceOfString)
	if !areEqual {
		t.Error("Wrong GetString value restitution when no key")
		t.Fail()
	}
	func() {
		defer func() {
			if q := recover(); q == nil {
				t.Error("GetSliceOfStrings on non map[string]string value expect panic")
				t.Fail()
			}
		}()
		_ = c.GetSliceOfStrings("value1")
	}()

	result = c.GetSliceOfStrings("value2")
	areEqual = reflect.DeepEqual(result, v)
	if !areEqual {
		t.Error("Wrong GetSliceOfStrings value restitution")
		t.Fail()
	}

}

func TestConfigMap_GetMapOfStrings(t *testing.T) {

	var v = map[string]string{"a": "un", "b": "deux", "c": "trois"}
	c := ConfigMap{}
	c.Set("value1", "string")
	c.Set("value2", v)

	result := c.GetMapOfStrings("value3")
	emptyMapString := map[string]string{}
	areEqual := reflect.DeepEqual(result, emptyMapString)
	if !areEqual {
		t.Error("Wrong GetString value restitution when no key")
		t.Fail()
	}

	defer func() {
		if q := recover(); q == nil {
			t.Error("GetMapOfStrings on non map[string]string value expect panic")
			t.Fail()
		}
	}()
	_ = c.GetMapOfStrings("value1")

	result = c.GetMapOfStrings("value2")
	areEqual = reflect.DeepEqual(result, v)
	if !areEqual {
		t.Error("Wrong GetMapOfStrings value restitution")
		t.Fail()
	}

}

func TestConfigMap_GetInteger(t *testing.T) {

	c := ConfigMap{}
	c.Set("value1", "string")
	c.Set("value2", 42)

	result := c.GetInteger("value3")
	if result != 0 {
		t.Error("Wrong GetString value restitution when no key")
		t.Fail()
	}

	defer func() {
		if q := recover(); q == nil {
			t.Error("GetInteger on non integer value expect panic")
			t.Fail()
		}
	}()
	_ = c.GetInteger("value1")

	result = c.GetInteger("value2")
	if result != 42 {
		t.Error("Wrong GetInteger value restitution")
		t.Fail()
	}

}
