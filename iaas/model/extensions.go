/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package model

import (
	"encoding/json"
	"fmt"
)

// extensions ...
type extensions map[string]string

// Extensions ...
type Extensions struct {
	extensions
}

// NewExtensions creates a new Extensions instance
func NewExtensions() *Extensions {
	return &Extensions{
		extensions: extensions{},
	}
}

// Lookup tells if a key is present in Extensions
func (x *Extensions) Lookup(key string) bool {
	_, ok := x.extensions[key]
	return ok
}

// Get returns the value of extension identified by key
// if returns nil, 'key' is not found and 'value' is unchanged
func (x *Extensions) Get(key string, value interface{}) error {
	if x == nil {
		panic("Calling x.ForceGet() with x==nil!")
	}
	if x.extensions == nil {
		panic("Extensions.extensions is nil!")
	}

	err := x.ForceGet(key, value)
	if err != nil {
		if _, ok := err.(ErrResourceNotFound); !ok {
			return err
		}
	}
	return nil
}

// ForceGet is like Get, but returns error if key not found
func (x *Extensions) ForceGet(key string, value interface{}) error {
	if x == nil {
		panic("Calling x.ForceGet() with x==nil!")
	}
	if x.extensions == nil {
		panic("Extensions.extensions is nil!")
	}

	if jsoned, ok := x.extensions[key]; ok {
		return json.Unmarshal([]byte(jsoned), value)
	}
	return ResourceNotFoundError("extension", fmt.Sprintf("key '%s' not found", key))
}

// Set adds/replaces the content of key 'key' with 'value'
func (x *Extensions) Set(key string, value interface{}) error {
	if x == nil {
		panic("Calling x.Set() with x==nil!")
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if x.extensions == nil {
		x.extensions = extensions{}
	}
	x.extensions[key] = string(encoded)
	return nil
}

// MarshalJSON implements json.Marshaller
func (x *Extensions) MarshalJSON() ([]byte, error) {
	return SerializeToJSON(&(x.extensions))
}

// UnmarshalJSON implement json.Unmarshaller
func (x *Extensions) UnmarshalJSON(b []byte) error {
	return DeserializeFromJSON(b, &(x.extensions))
}
