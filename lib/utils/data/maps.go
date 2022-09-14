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

package data

import (
	"fmt"
)

// AnonymousMap ...
type AnonymousMap map[interface{}]interface{}

func AnonymousMapToStringMap(in map[interface{}]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		key := fmt.Sprintf("%v", k)
		out[key] = v
	}
	return out
}

// Map ...
type Map map[string]interface{}

func (m Map) IsNull() bool {
	return false
}

// NewMap ...
func NewMap() Map {
	return Map{}
}

func FromMap(m Map) (Map, error) {
	if m == nil {
		return NewMap(), nil
	}
	cm := NewMap()
	return (&cm).Replace(&m)
}

func (m Map) Clone() Map {
	out := make(Map, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (m *Map) Replace(src *Map) (Map, error) {
	*m = make(Map, len(*src))
	for k, v := range *src {
		(*m)[k] = v
	}
	return *m, nil
}

// Merge add missing keys from source
func (m Map) Merge(src Map) Map {
	for k, v := range src {
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}
	return m
}

// ForceMerge adds missing keys from source in p and replace the ones in source already in p
func (m Map) ForceMerge(src Map) Map {
	for k, v := range src {
		m[k] = v
	}
	return m
}

// Contains tells if a key is present in Map
func (m Map) Contains(key string) bool {
	_, ok := m[key]
	return ok
}

// Keys returns a slice with all keys of the map
func (m Map) Keys() []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Values returns a slice with all values of the map
func (m Map) Values() []interface{} {
	values := make([]interface{}, 0, len(m))
	for _, v := range m {
		values = append(values, v)
	}
	return values
}

// IndexedListOfStrings contains a list of string (being ID, IP, ...) of nodes indexed by node Numerical ID.
type IndexedListOfStrings map[uint]string

// KeysAndValues returns a slice with keys and a slice with values from map[uint]string
func (ilos IndexedListOfStrings) KeysAndValues() ([]uint, []string) {
	length := len(ilos)
	if length <= 0 {
		return []uint{}, []string{}
	}

	keys := make([]uint, 0, length)
	values := make([]string, 0, length)
	for k, v := range ilos {
		keys = append(keys, k)
		values = append(values, v)
	}
	return keys, values
}

// Keys returns a slice with keys from map[uint]string
func (ilos IndexedListOfStrings) Keys() []uint {
	length := len(ilos)
	if length <= 0 {
		return []uint{}
	}

	keys := make([]uint, 0, length)
	for k := range ilos {
		keys = append(keys, k)
	}
	return keys
}

// Values returns a slice with values from map[uint]string
func (ilos IndexedListOfStrings) Values() []string {
	length := len(ilos)
	if length <= 0 {
		return []string{}
	}

	values := make([]string, 0, length)
	for _, v := range ilos {
		values = append(values, v)
	}
	return values
}

// ToMapStringOfString converts a map[interface{}]interface{} (something that viper may return for example) to a map[string]string
func ToMapStringOfString(in map[interface{}]interface{}) map[string]string {
	out := make(map[string]string)
	for k, v := range in {
		out[fmt.Sprintf("%v", k)] = fmt.Sprintf("%v", v)
	}
	return out
}
