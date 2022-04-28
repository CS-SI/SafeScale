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
	"sync/atomic"
)

// keyValue describes the content of a key/value pair
type keyValue struct {
	// Note: value MUST be the first field in the struct to ensure it is 64-bit aligned, condition to make the use
	//       of native atomic instructions of the processor
	value atomic.Value
	name  string
}

// Key returns the key of the key/value
func (kv keyValue) Key() string {
	return kv.name
}

// Value returns the value of the key/value
func (kv keyValue) Value() interface{} {
	return kv.value.Load()
}

// ImmutableKeyValue is a key/value that cannot be changed
type ImmutableKeyValue struct {
	keyValue
}

// NewImmutableKeyValue creates a new immutable key/Value
// If no values is passed, sets the content of value to nil
// If at least 1 value is passed, the first one only is considered (trick to allow to create an instance without value parameter)
func NewImmutableKeyValue(key string, values ...interface{}) ImmutableKeyValue {
	var v interface{}
	if len(values) > 0 {
		v = values[0]
	}
	ikv := ImmutableKeyValue{
		keyValue: keyValue{
			name: key,
		},
	}
	ikv.value.Store(v)
	return ikv
}

// Mutate creates a KeyValue from ImmutableKeyValue
func (i ImmutableKeyValue) Mutate() KeyValue {
	return NewKeyValue(i.Key(), i.Value())
}

// KeyValue is a key/value that can be updated (mutable)
type KeyValue struct {
	keyValue
}

// NewKeyValue creates a new mutable Key/Value
func NewKeyValue(name string, values ...interface{}) KeyValue {
	var v interface{}
	if len(values) > 0 {
		v = values[0]
	}
	kv := KeyValue{
		keyValue: keyValue{
			name: name,
		},
	}
	kv.value.Store(v)
	return kv
}

// SetValue changes the value of the mutable key/value
func (m *KeyValue) SetValue(value interface{}) {
	if m == nil {
		return
	}

	m.value.Store(value)
}
