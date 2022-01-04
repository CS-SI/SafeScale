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

package abstract

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigMap_GetString(t *testing.T) {

	c := ConfigMap{}
	c.Set("value1", 42)
	c.Set("value2", "string")

	defer func() {
		if q := recover(); q == nil {
			t.Error("GetString on non map[string]string value expect panic")
			t.Fail()
		}
	}()
	_ = c.GetString("value1")

	result := c.GetString("value2")
	if result != "string" {
		t.Error("Wrong GetString value restitution")
		t.Fail()
	}

}

func TestConfigMap_GetSliceOfStrings(t *testing.T) {

	var v []string = []string{"a", "b", "c"}
	c := ConfigMap{}
	c.Set("value1", "string")
	c.Set("value2", v)

	defer func() {
		if q := recover(); q == nil {
			t.Error("GetSliceOfStrings on non map[string]string value expect panic")
			t.Fail()
		}
	}()
	_ = c.GetSliceOfStrings("value1")

	result := c.GetSliceOfStrings("value2")
	areEqual := reflect.DeepEqual(result, v)
	if !areEqual {
		t.Error("Wrong GetSliceOfStrings value restitution")
		t.Fail()
	}

}

func TestConfigMap_GetMapOfStrings(t *testing.T) {

	var v map[string]string = map[string]string{"a": "un", "b": "deux", "c": "trois"}
	c := ConfigMap{}
	c.Set("value1", "string")
	c.Set("value2", v)

	defer func() {
		if q := recover(); q == nil {
			t.Error("GetMapOfStrings on non map[string]string value expect panic")
			t.Fail()
		}
	}()
	_ = c.GetMapOfStrings("value1")

	result := c.GetMapOfStrings("value2")
	areEqual := reflect.DeepEqual(result, v)
	if !areEqual {
		t.Error("Wrong GetMapOfStrings value restitution")
		t.Fail()
	}

}

func TestConfigMap_GetInteger(t *testing.T) {

	c := ConfigMap{}
	c.Set("value1", "string")
	c.Set("value2", 42)

	defer func() {
		if q := recover(); q == nil {
			t.Error("GetInteger on non integer value expect panic")
			t.Fail()
		}
	}()
	_ = c.GetInteger("value1")

	result := c.GetInteger("value2")
	assert.Equal(t, result, 42)
	if result != 42 {
		t.Error("Wrong GetInteger value restitution")
		t.Fail()
	}

}
