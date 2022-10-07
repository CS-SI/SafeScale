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

// // AnonymousMap ...
// type AnonymousMap map[any]any
//
// func AnonymousMapToStringMap(in map[any]any) map[string]any {
// 	out := make(map[string]interface{}, len(in))
// 	for k, v := range in {
// 		key := fmt.Sprintf("%v", k)
// 		out[key] = v
// 	}
// 	return out
// }

// Map ...
type Map[K comparable, V any] map[K]V

// NewMap ...
func NewMap[K comparable, V any](o ...int) Map[K, V] {
	capability := 0
	if len(o) > 0 {
		capability = o[0]
	}
	return make(map[K]V, capability)
}

// Length ...
func (m Map[K, V]) Length() int {
	return len(m)
}

// Clone ...
func (m Map[K, V]) Clone() Map[K, V] {
	cm := NewMap[K, V](0)
	cm.Replace(m)
	return cm
}

// Replace ...
func (m *Map[K, V]) Replace(src Map[K, V]) {
	if m == nil {
		return
	}

	*m = NewMap[K, V](src.Length())
	for k, v := range src {
		(*m)[k] = v
	}
}

// Merge add missing keys from source
func (m Map[K, V]) Merge(src Map[K, V]) Map[K, V] {
	for k, v := range src {
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}
	return m
}

// ForceMerge adds missing keys from source in p and replace the ones in source already in p
func (m Map[K, V]) ForceMerge(src Map[K, V]) Map[K, V] {
	for k, v := range src {
		m[k] = v
	}
	return m
}

// Contains tells if a key is present in Map
func (m Map[K, V]) Contains(key K) bool {
	_, ok := m[key]
	return ok
}

// Keys returns a slice with all keys of the map
func (m Map[K, V]) Keys() Slice[K] {
	keys := make(Slice[K], 0, m.Length())
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Values returns a slice with all values of the map
func (m Map[K, V]) Values() Slice[V] {
	values := make(Slice[V], 0, m.Length())
	for _, v := range m {
		values = append(values, v)
	}
	return values
}

// KeysAndValues returns a slice with all values of the map
func (m Map[K, V]) KeysAndValues() (Slice[K], Slice[V]) {
	l := m.Length()
	keys := make(Slice[K], 0, l)
	values := make(Slice[V], 0, l)
	for k, v := range m {
		keys = append(keys, k)
		values = append(values, v)
	}
	return keys, values
}

// IndexedListOfStrings contains a list of string (being ID, IP, ...) of nodes indexed by node Numerical ID.
type IndexedListOfStrings = Map[uint, string]

// // KeysAndValues returns a slice with keys and a slice with values from map[uint]string
// func (ilos IndexedListOfStrings) KeysAndValues() ([]uint, []string) {
// 	length := len(ilos)
// 	if length <= 0 {
// 		return []uint{}, []string{}
// 	}
//
// 	keys := make([]uint, 0, length)
// 	values := make([]string, 0, length)
// 	for k, v := range ilos {
// 		keys = append(keys, k)
// 		values = append(values, v)
// 	}
// 	return keys, values
// }

// // Keys returns a slice with keys from map[uint]string
// func (ilos IndexedListOfStrings) Keys() []uint {
// 	length := len(ilos)
// 	if length <= 0 {
// 		return []uint{}
// 	}
//
// 	keys := make([]uint, 0, length)
// 	for k := range ilos {
// 		keys = append(keys, k)
// 	}
// 	return keys
// }

// // Values returns a slice with values from map[uint]string
// func (ilos IndexedListOfStrings) Values() []string {
// 	length := len(ilos)
// 	if length <= 0 {
// 		return []string{}
// 	}
//
// 	values := make([]string, 0, length)
// 	for _, v := range ilos {
// 		values = append(values, v)
// 	}
// 	return values
// }

// ToStringMapOfString converts a map[interface{}]interface{} (something that viper may return for example) to a map[string]string
func ToStringMapOfString(in map[any]any) Map[string, string] {
	out := NewMap[string, string](len(in))
	for k, v := range in {
		out[fmt.Sprintf("%v", k)] = fmt.Sprintf("%v", v)
	}
	return out
}
