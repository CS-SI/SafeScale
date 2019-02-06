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

package serialize

import (
	"sync"
)

// jsonProperty contains data and a RWMutex to handle sync
type jsonProperty struct {
	Data interface{}
	sync.RWMutex
	module, key string
}

// MarshalJSON (json.Marshaller interface)
func (jp *jsonProperty) MarshalJSON() ([]byte, error) {
	jp.Lock()
	defer jp.Unlock()

	jsoned, err := ToJSON(jp.Data)
	if err != nil {
		return nil, err
	}
	return ToJSON(string(jsoned))
}

// SyncedJSONProperty is used to manipulate jsonProperty with type of lock asked (as returns by JSONProperties.LockBy<x>)
type SyncedJSONProperty struct {
	*jsonProperty
	readLock bool
}

// ThenUse allows to run a function with 'key' decoded content passed as parameter after a
// call to JSonProperties.LockForRead() or JSonProperties.LockForWrite().
// If the extension is locked for write, changes to the decoded data are encoded back into the extension
// on 'apply' success.
// If the extension is locked for read, no change will be encoded into the extension.
// The lock applied on the extension is automatically released on exit.
func (sp *SyncedJSONProperty) ThenUse(apply func(interface{}) error) error {
	if sp == nil {
		panic("Calling sp.ThenUse() with sp==nil!")
	}
	if sp.jsonProperty == nil {
		panic("sp.jsonProperty is nil!")
	}
	if apply == nil {
		panic("apply is nil!")
	}
	defer sp.unlock()

	var err error
	if sp.readLock {
		// In case of read lock, the changes in property is disabled by cloning the property
		if data, ok := sp.jsonProperty.Data.(Property); ok {
			clone := data.Clone()
			err = apply(clone.Content())
		}
	} else {
		err = apply((sp.jsonProperty.Data).(Property).Content())
	}
	if err != nil {
		return err
	}
	return nil
}

// unlock ...
func (sp *SyncedJSONProperty) unlock() {
	if sp == nil {
		panic("Calling sp.unlock() with sp==nil!")
	}
	if !sp.readLock {
		sp.jsonProperty.Unlock()
	} else {
		sp.jsonProperty.RUnlock()
	}
}

// jsonProperties ...
type jsonProperties map[string]*jsonProperty

// JSONProperties ...
type JSONProperties struct {
	Properties jsonProperties
	// This lock is used to make sure addition or removal of keys in JSonProperties won't collide in go routines
	sync.Mutex
	module string
}

// NewJSONProperties creates a new JSonProperties instance
func NewJSONProperties(module string) *JSONProperties {
	if module == "" {
		panic("module is empty!")
	}
	return &JSONProperties{
		Properties: jsonProperties{},
		module:     module,
	}
}

// Lookup tells if a key is present in JSonProperties
func (x *JSONProperties) Lookup(key string) bool {
	x.Lock()
	defer x.Unlock()

	_, ok := x.Properties[key]
	return ok
}

// LockForRead is used to lock an extension for read
// Returns a pointer to LockedEncodedExtension, on which can be applied method 'Use()'
// If no extension exists corresponding to the key, an empty extension is created (in other words, this call
// can't fail because a key doesn't exist).
func (x *JSONProperties) LockForRead(key string) *SyncedJSONProperty {
	if x == nil {
		panic("Calling x.LockForRead() with x==nil!")
	}
	if x.Properties == nil {
		panic("JSonProperties.JSonProperties is nil!")
	}
	if x.module == "" {
		panic("JSonProperties.module is empty!")
	}
	if key == "" {
		panic("key is empty!")
	}

	x.Lock()
	defer x.Unlock()

	var (
		item  *jsonProperty
		found bool
	)
	if item, found = x.Properties[key]; !found {
		zeroValue := PropertyTypeRegistry.ZeroValue(x.module, key)
		item = &jsonProperty{
			Data:   zeroValue,
			module: x.module,
			key:    key,
		}
		x.Properties[key] = item
	}
	item.RLock()
	return &SyncedJSONProperty{jsonProperty: item, readLock: true}
}

// LockForWrite is used to lock an extension for write
// Returns a pointer to LockedEncodedExtension, on which can be applied method 'Use()'
// If no extension exists corresponding to the key, an empty one is created (in other words, this call
// can't fail because a key doesn't exist).
func (x *JSONProperties) LockForWrite(key string) *SyncedJSONProperty {
	if x == nil {
		panic("Calling x.LockForWrite() with x==nil!")
	}
	if x.Properties == nil {
		panic("x.jsonProperties is nil!")
	}
	if x.module == "" {
		panic("x.module is empty!")
	}
	if key == "" {
		panic("key is empty!")
	}

	x.Lock()
	defer x.Unlock()

	var (
		item  *jsonProperty
		found bool
	)
	if item, found = x.Properties[key]; !found {
		zeroValue := PropertyTypeRegistry.ZeroValue(x.module, key)
		item = &jsonProperty{
			Data:   zeroValue,
			module: x.module,
			key:    key,
		}
		x.Properties[key] = item
	}
	item.Lock()
	return &SyncedJSONProperty{jsonProperty: item, readLock: false}
}

// SetModule allows to change the module of the JSONProperties (used to "contextualize" Property Types)
func (x *JSONProperties) SetModule(module string) {
	if module != "" && x.module == module {
		return
	}
	if x.module != "" {
		panic("x.SetModule() can't be changed if x.module is already set!")
	}
	if module == "" {
		panic("module is empty!")
	}
	x.Lock()
	defer x.Unlock()

	if x.module == "" {
		x.module = module
	}
}

// MarshalJSON implements json.Marshaller
// Note: DO NOT LOCK property here, deadlock risk
func (x *JSONProperties) MarshalJSON() ([]byte, error) {
	return ToJSON(&(x.Properties))
}

// UnmarshalJSON implement json.Unmarshaller
// Note: DO NOT LOCK property here, deadlock risk
func (x *JSONProperties) UnmarshalJSON(b []byte) error {
	// Decode JSON data
	unjsoned := map[string]string{}
	err := FromJSON(b, &unjsoned)
	if err != nil {
		return err
	}

	// Now do the real work
	for key, value := range unjsoned {
		zeroValue := PropertyTypeRegistry.ZeroValue(x.module, key)
		err := FromJSON([]byte(value), zeroValue)
		if err != nil {
			return err
		}
		item := &jsonProperty{
			Data:   zeroValue,
			module: x.module,
			key:    key,
		}
		x.Properties[key] = item
	}
	return nil
}
