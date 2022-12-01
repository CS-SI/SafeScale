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

package serialize

import (
	stdjson "encoding/json"
	"fmt"
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sanity-io/litter"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/shielded"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// JSONProperty contains data and a RWMutex to handle sync
type JSONProperty struct {
	*shielded.Shielded
	module, key string
}

// IsNull tells if the JSONProperty is a Null Value
func (jp *JSONProperty) IsNull() bool {
	return jp == nil || valid.IsNil(jp.Shielded)
}

func (jp JSONProperty) Clone() (data.Clonable, error) {
	newP := &JSONProperty{}
	return newP.Replace(&jp)
}

func (jp *JSONProperty) Replace(clonable data.Clonable) (data.Clonable, error) {
	if jp == nil || clonable == nil {
		return nil, fail.InvalidInstanceError()
	}

	srcP, ok := clonable.(*JSONProperty)
	if !ok {
		return nil, fmt.Errorf("clonable is not a *JSONProperty")
	}

	*jp = *srcP

	var err error
	jp.Shielded, err = srcP.Shielded.Clone()
	if err != nil {
		return nil, err
	}

	return jp, nil
}

// JSONProperties ...
type JSONProperties struct {
	// properties jsonProperties
	Properties map[string]*JSONProperty
	// This lock is used to make sure addition or removal of keys in JSonProperties won't collide in go routines
	sync.RWMutex
	module string
}

// NewJSONProperties creates a new JSonProperties instance
func NewJSONProperties(module string) (_ *JSONProperties, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if module == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("module")
	}
	return &JSONProperties{
		Properties: map[string]*JSONProperty{},
		module:     module,
	}, nil
}

// Lookup tells if a key is present in JSonProperties
func (x *JSONProperties) Lookup(key string) bool {
	if x == nil {
		return false
	}

	x.RLock()
	defer x.RUnlock()

	p, ok := x.Properties[key]
	return ok && !valid.IsNil(p)
}

// UnWrap is the fastest way to get a clone of the shielded data
func (x *JSONProperties) UnWrap() (map[string]*JSONProperty, error) {
	ak, err := x.Clone()
	if err != nil {
		return nil, err
	}
	return ak.Properties, nil
}

func (x *JSONProperties) Clone() (*JSONProperties, error) {

	if x == nil {
		return x, nil
	}

	x.RLock()
	defer x.RUnlock()
	newP := &JSONProperties{
		module:     x.module,
		Properties: map[string]*JSONProperty{},
	}
	if len(x.Properties) > 0 {
		for k, v := range x.Properties {
			b, err := v.Clone()
			if err == nil {
				newP.Properties[k], _ = b.(*JSONProperty) // nolint
			}
		}
	}
	return newP, nil

}

func (x *JSONProperties) hasKey(key string) (*JSONProperty, bool) {
	x.RLock()
	defer x.RUnlock()

	jsp, found := x.Properties[key]
	return jsp, found
}

func (x *JSONProperties) storeZero(key string) (*JSONProperty, error) {
	x.Lock()
	defer x.Unlock()

	zeroValue := PropertyTypeRegistry.ZeroValue(x.module, key)
	nsh, err := shielded.NewShielded(zeroValue)
	if err != nil {
		return nil, err
	}

	item := &JSONProperty{
		Shielded: nsh,
		module:   x.module,
		key:      key,
	}
	x.Properties[key] = item
	return item, nil
}

// Count returns the number of properties available
func (x *JSONProperties) Count() uint {
	if x == nil {
		return 0
	}

	x.RLock()
	defer x.RUnlock()

	return uint(len(x.Properties))
}

// Inspect allows to consult the content of the property 'key' inside 'inspector' function
// Changes in the property won't be kept
func (x *JSONProperties) Inspect(key string, inspector func(clonable data.Clonable) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if x == nil {
		return fail.InvalidInstanceError()
	}
	if x.Properties == nil {
		return fail.InvalidInstanceContentError("x.properties", "can't be nil")
	}
	if x.module == "" {
		return fail.InvalidInstanceContentError("x.module", "can't be empty string")
	}
	if key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}
	if inspector == nil {
		return fail.InvalidParameterCannotBeNilError("inspector")
	}

	var (
		item  *JSONProperty
		found bool
	)

	var err error
	item, found = x.hasKey(key)
	if !found {
		item, err = x.storeZero(key)
		if err != nil {
			return fail.Wrap(err)
		}
	}

	x.RLock()
	clone, err := item.Clone()
	x.RUnlock() // nolint
	if err != nil {
		return fail.Wrap(err)
	}

	cloned, ok := clone.(*JSONProperty)
	if !ok {
		return fail.InconsistentError("clone is expected to be a *JSONProperty and it's not: %v", clone)
	}

	xerr := cloned.Shielded.Inspect(inspector)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Alter is used to lock an extension for write
// Returns a pointer to LockedEncodedExtension, on which can be applied method 'Use()'
// If no extension exists corresponding to the key, an empty one is created (in other words, this call
// can't fail because a key doesn't exist).
// 'alterer' can use a special error to tell the outside there was no change : fail.ErrAlteredNothing, which can be
// generated with fail.AlteredNothingError().
func (x *JSONProperties) Alter(key string, alterer func(data.Clonable) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if x == nil {
		return fail.InvalidInstanceError()
	}
	if x.Properties == nil {
		return fail.InvalidInstanceContentError("x.properties", "cannot be nil")
	}
	if x.module == "" {
		return fail.InvalidInstanceContentError("x.module", "cannot be empty string")
	}
	if key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}
	if alterer == nil {
		return fail.InvalidParameterCannotBeNilError("alterer")
	}

	x.Lock()
	defer x.Unlock()

	var (
		item  *JSONProperty
		found bool
	)

	if item, found = x.Properties[key]; !found {
		zeroValue := PropertyTypeRegistry.ZeroValue(x.module, key)
		nsh, err := shielded.NewShielded(zeroValue)
		if err != nil {
			return fail.Wrap(err)
		}
		item = &JSONProperty{
			Shielded: nsh,
			module:   x.module,
			key:      key,
		}
		x.Properties[key] = item
	}

	clone, err := item.Clone()
	if err != nil {
		return fail.ConvertError(err)
	}
	castedClone, ok := clone.(*JSONProperty)
	if !ok {
		return fail.InconsistentError("failed to cast clone to '*JSONProperty'")
	}

	xerr := castedClone.Alter(alterer)
	if xerr != nil {
		return xerr
	}

	_, err = item.Replace(clone)
	if err != nil {
		return fail.Wrap(err)
	}
	return nil
}

// SetModule allows to change the module of the JSONProperties (used to "contextualize" Property Types)
func (x *JSONProperties) SetModule(module string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if x == nil {
		return fail.InvalidInstanceError()
	}
	if module == "" {
		return fail.InvalidParameterError("key", "can't be empty string")
	}

	x.Lock()
	defer x.Unlock()

	if x.module == "" {
		x.module = module
	}
	return nil
}

// Serialize ...
// satisfies interface data.Serializable
func (x *JSONProperties) Serialize() (_ []byte, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if x == nil {
		return nil, fail.InvalidInstanceError()
	}
	if x.Properties == nil {
		return nil, fail.InvalidParameterError("x.properties", "can't be nil")
	}

	x.RLock()
	defer x.RUnlock()

	var mapped = map[string]string{}
	for k, v := range x.Properties {
		ser, err := v.Serialize()
		if err != nil {
			return nil, err
		}
		mapped[k] = string(ser)
	}
	r, jserr := json.Marshal(mapped)
	if jserr != nil {
		return nil, fail.Wrap(jserr)
	}
	return r, nil
}

func (x *JSONProperties) Sdump() (string, fail.Error) {
	sq := litter.Options{
		HidePrivateFields: false,
	}
	return sq.Sdump(x.Properties), nil
}

// Deserialize ...
// Returns fail.SyntaxError if an JSON syntax error happens
// satisfies interface data.Serializable
func (x *JSONProperties) Deserialize(buf []byte) (ferr fail.Error) {
	defer fail.OnPanic(&ferr) // json.Unmarshal may panic

	if x == nil {
		return fail.InvalidInstanceError()
	}

	x.Lock()
	defer x.Unlock()

	// Decode JSON data
	var unjsoned = map[string]string{}
	if jserr := json.Unmarshal(buf, &unjsoned); jserr != nil {
		switch jserr.(type) {
		case *stdjson.SyntaxError:
			return fail.SyntaxError(jserr.Error())
		default:
			logrus.Tracef("*JSONProperties.Deserialize(): Unmarshalling buf to string failed: %s", jserr.Error())
			return fail.Wrap(jserr)
		}
	}

	var (
		prop *JSONProperty
		ok   bool
	)
	for k, v := range unjsoned {
		if prop, ok = x.Properties[k]; !ok {
			zeroValue := PropertyTypeRegistry.ZeroValue(x.module, k)
			nsh, err := shielded.NewShielded(zeroValue)
			if err != nil {
				return fail.Wrap(err)
			}
			item := &JSONProperty{
				Shielded: nsh,
				module:   x.module,
				key:      k,
			}
			x.Properties[k] = item
			prop = item
		}
		err := prop.Shielded.Deserialize([]byte(v))
		if err != nil {
			return err
		}
	}
	return nil
}
