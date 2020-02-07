/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"encoding/json"
	"sync"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// jsonProperty contains data and a RWMutex to handle sync
type jsonProperty struct {
	*concurrency.Shielded
	module, key string
}

func (jp *jsonProperty) Clone() data.Clonable {
	newP := &jsonProperty{}
	return newP.Replace(jp)
}

func (jp *jsonProperty) Replace(clonable data.Clonable) data.Clonable {
	srcP := clonable.(*jsonProperty)
	*jp = *srcP
	jp.Shielded = srcP.Shielded.Clone()
	return jp
}

// // MarshalJSON ...
// // satisfies json.Marshaller interface
// func (jp *jsonProperty) MarshalJSON() ([]byte, error) {
// 	var jsoned []byte
// 	err := jp.Shielded.Inspect(concurrency.VoidTask(), func(clonable data.Clonable) error {
// 		var inErr error
// 		jsoned, inErr = ToJSON(clonable)
// 		return inErr
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	return ToJSON(string(jsoned))
// }

// JSONProperties ...
type JSONProperties struct {
	// Properties jsonProperties
	Properties data.Map
	// This lock is used to make sure addition or removal of keys in JSonProperties won't collide in go routines
	sync.RWMutex
	module string
}

// NewJSONProperties creates a new JSonProperties instance
func NewJSONProperties(module string) (*JSONProperties, error) {
	if module == "" {
		return nil, scerr.InvalidParameterError("module", "can't be empty string")
	}
	return &JSONProperties{
		Properties: data.Map{},
		module:     module,
	}, nil
}

// Lookup tells if a key is present in JSonProperties
func (x *JSONProperties) Lookup(key string) bool {
	x.RLock()
	defer x.RUnlock()

	_, ok := x.Properties[key]
	return ok
}

// Clone ...
func (x *JSONProperties) Clone() *JSONProperties {
	x.RLock()
	defer x.RUnlock()

	newP := &JSONProperties{
		module: x.module,
	}
	for k, v := range x.Properties {
		newP.Properties[k] = v
	}
	return newP
}

// Inspect allows to consult the content of the property 'key' inside 'inspector' function
// Changes in the property won't be kept
func (x *JSONProperties) Inspect(key string, inspector func(clonable data.Clonable) error) error {
	if x == nil {
		return scerr.InvalidInstanceError()
	}
	if x.Properties == nil {
		return scerr.InvalidInstanceContentError("x.Properties", "can't be nil")
	}
	if x.module == "" {
		return scerr.InvalidInstanceContentError("x.module", "can't be empty string")
	}
	if key == "" {
		return scerr.InvalidParameterError("key", "cannot be empty string")
	}
	if inspector == nil {
		return scerr.InvalidParameterError("inspector", "cannot be nil")
	}

	var (
		item  *jsonProperty
		found bool
	)
	x.RLock()
	if item, found = x.Properties[key].(*jsonProperty); !found {
		zeroValue := PropertyTypeRegistry.ZeroValue(x.module, key)
		item = &jsonProperty{
			Shielded: concurrency.NewShielded(zeroValue),
			module:   x.module,
			key:      key,
		}
		x.Properties[key] = item
	}
	clone := item.Clone()
	x.RUnlock()

	return inspector(clone)
}

// Alter is used to lock an extension for write
// Returns a pointer to LockedEncodedExtension, on which can be applied method 'Use()'
// If no extension exists corresponding to the key, an empty one is created (in other words, this call
// can't fail because a key doesn't exist).
func (x *JSONProperties) Alter(key string, alterer func(data.Clonable) error) error {
	if x == nil {
		return scerr.InvalidInstanceError()
	}
	if x.Properties == nil {
		return scerr.InvalidInstanceContentError("x.Properties", "cannot be nil")
	}
	if x.module == "" {
		return scerr.InvalidInstanceContentError("x.module", "cannot be empty string")
	}
	if key == "" {
		return scerr.InvalidParameterError("key", "cannot be empty string")
	}
	if alterer == nil {
		return scerr.InvalidParameterError("alterer", "cannot be nil")
	}

	var (
		item  *jsonProperty
		found bool
	)
	x.Lock()
	defer x.Unlock()

	if item, found = x.Properties[key].(*jsonProperty); !found {
		zeroValue := PropertyTypeRegistry.ZeroValue(x.module, key)
		item = &jsonProperty{
			Shielded: concurrency.NewShielded(zeroValue),
			module:   x.module,
			key:      key,
		}
		x.Properties[key] = item
	}
	clone := item.Clone()

	err := alterer(clone)
	if err != nil {
		return err
	}

	_ = item.Replace(clone)
	return nil
}

// SetModule allows to change the module of the JSONProperties (used to "contextualize" Property Types)
func (x *JSONProperties) SetModule(module string) error {
	if x == nil {
		return scerr.InvalidInstanceError()
	}
	if module == "" {
		return scerr.InvalidParameterError("key", "can't be empty string")
	}

	x.Lock()
	defer x.Unlock()

	if x.module == "" {
		x.module = module
	}
	return nil
}

// MarshalJSON implements json.Marshaller
// Note: DO NOT LOCK property here, deadlock risk
func (x *JSONProperties) MarshalJSON() ([]byte, error) {
	if x == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if x.Properties == nil {
		return nil, scerr.InvalidParameterError("x.Properties", "can't be nil")
	}

	return ToJSON(&(x.Properties))
}

// UnmarshalJSON implement json.Unmarshaller
// Note: DO NOT LOCK property here, deadlock risk
func (x *JSONProperties) UnmarshalJSON(b []byte) (err error) {
	if x == nil {
		return scerr.InvalidInstanceError()
	}

	defer scerr.OnPanic(&err)()

	// Decode JSON data
	unjsoned := map[string]string{}
	err = FromJSON(b, &unjsoned)
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
			Shielded: concurrency.NewShielded(zeroValue),
			module:   x.module,
			key:      key,
		}
		x.Properties[key] = item
	}
	return nil
}

// ToJSON serializes data into JSON
func ToJSON(data interface{}) ([]byte, error) {
	jsoned, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return jsoned, nil
}

// FromJSON reads json code and restores data
func FromJSON(buf []byte, data interface{}) error {
	err := json.Unmarshal(buf, data)
	return err
}
