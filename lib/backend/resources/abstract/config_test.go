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

package abstract

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigMap_Config(t *testing.T) {

	// FIXME: panic
	//	var c Config = nil
	//	_, _ = c.Config("some")

	c := ConfigMap{}
	v, found := c.Config("some")
	require.Nil(t, v)
	require.False(t, found)

	c = ConfigMap{
		"some": 42,
	}
	v, found = c.Config("some")
	require.EqualValues(t, v, 42)
	require.True(t, found)

}

func TestConfigMap_Get(t *testing.T) {

	c := ConfigMap{}
	v, found := c.Get("some")
	require.Nil(t, v)
	require.False(t, found)

	c = ConfigMap{
		"some": 42,
	}
	v, found = c.Get("some")
	require.EqualValues(t, v, 42)
	require.True(t, found)

}

func TestConfigMap_GetString(t *testing.T) {

	c := ConfigMap{}
	v := c.GetString("some")
	require.EqualValues(t, v, "")

	c = ConfigMap{
		"some":   42,
		"string": "this",
	}
	v = c.GetString("some")
	require.EqualValues(t, v, "")
	v = c.GetString("string")
	require.EqualValues(t, v, "this")

}

func TestConfigMap_GetSliceOfStrings(t *testing.T) {

	c := ConfigMap{}
	v := c.GetSliceOfStrings("some")
	require.EqualValues(t, v, []string{})

	c = ConfigMap{
		"some":        42,
		"stringslice": []string{"this", "that"},
	}
	v = c.GetSliceOfStrings("some")
	require.EqualValues(t, v, []string{})
	v = c.GetSliceOfStrings("stringslice")
	require.EqualValues(t, v, []string{"this", "that"})

}

func TestConfigMap_GetMapOfStrings(t *testing.T) {

	c := ConfigMap{}
	v := c.GetMapOfStrings("some")
	require.EqualValues(t, v, map[string]string{})

	c = ConfigMap{
		"some":      42,
		"mapstring": map[string]string{"this": "that"},
	}
	v = c.GetMapOfStrings("some")
	require.EqualValues(t, v, map[string]string{})
	v = c.GetMapOfStrings("mapstring")
	require.EqualValues(t, v, map[string]string{"this": "that"})

}

func TestConfigMap_GetInteger(t *testing.T) {

	c := ConfigMap{}
	v := c.GetInteger("some")
	require.EqualValues(t, v, 0)

	c = ConfigMap{
		"some":      "42",
		"mapstring": 42,
	}
	v = c.GetInteger("some")
	require.EqualValues(t, v, 0)
	v = c.GetInteger("mapstring")
	require.EqualValues(t, v, 42)

}

func TestConfigMap_Set(t *testing.T) {

	c := ConfigMap{}
	c.Set("some", 42)
	v, found := c.Get("some")
	require.EqualValues(t, v, 42)
	require.True(t, found)

}
