/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

// Map ...
type Map map[string]interface{}

// NewMap ...
func NewMap() Map {
	return Map{}
}

// Clone clones the content of a Variables
// satisfies interface Clonable
func (m Map) Clone() Map {
	return Map{}.Replace(m)
}

// Replace replaces the content of the Map with content of another one
// satisfies interface Clonable
func (m Map) Replace(src Map) Map {
	m = Map{}
	for k, v := range src {
		m[k] = v
	}
	return m
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

// ForceMerge add missing keys from source in p and replace the ones in source already in p
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
