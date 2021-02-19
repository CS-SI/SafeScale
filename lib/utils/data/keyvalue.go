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

package data

import (
	"sync"
)

// keyValue describes the content of a key/value pair
type keyValue struct {
	name  string
	value interface{}
}

// Key returns the key of the key/value
func (kv keyValue) Key() string {
	return kv.name
}

// Value returns the value of the key/value
func (kv keyValue) Value() interface{} {
	return kv.value
}

// ImmutableKeyValue is a key/value that cannot be changed
type ImmutableKeyValue struct {
	keyValue
}

// NewImmutableKeyValue creates a new immutable key/Value
// If no values is passed, sets the content of value to nil
// If at least 1 value is passed, the first one only is considered (trick to allow to create an instance with nil value)
func NewImmutableKeyValue(key string, values ...interface{}) ImmutableKeyValue {
	var v interface{}
	if len(values) > 0 {
		v = values[0]
	}
	return ImmutableKeyValue{
		keyValue: keyValue{
			name:  key,
			value: v,
		},
	}
}

// Mutate creates a MutableKeyValue from ImmutableKeyValue
func (i ImmutableKeyValue) Mutate() MutableKeyValue {
	return NewMutableKeyValue(i.Key(), i.Value())
}

// MutableKeyValue is a key/value that can be updated
type MutableKeyValue struct {
	keyValue
	mu sync.Mutex
}

// NewMutableKeyValue creates a new mutable Key/Value
func NewMutableKeyValue(name string, values ...interface{}) MutableKeyValue {
	var v interface{}
	if len(values) > 0 {
		v = values[0]
	}
	return MutableKeyValue{
		keyValue: keyValue{
			name:  name,
			value: v,
		},
	}
}

// SetValue changes the value of the mutable key/value
func (m *MutableKeyValue) SetValue(value interface{}) {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.value = value
}
