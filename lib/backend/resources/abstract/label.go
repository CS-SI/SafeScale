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
	"encoding/json"
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

type Label struct {
	*Core
	ID           string `json:"id"`
	HasDefault   bool   `json:"has_default"` // if false, this represents a Tag
	DefaultValue string `json:"default_value,omitempty"`
}

// NewLabel creates a new empty Label...
func NewLabel(opts ...Option) (*Label, fail.Error) {
	c, xerr := newCore(opts...)
	if xerr != nil {
		return nil, xerr
	}

	out := &Label{
		Core:       c,
		HasDefault: true,
	}
	return out, nil
}

// IsNull ...
// satisfies interface clonable.Clonable
func (instance *Label) IsNull() bool {
	return instance == nil || (instance.ID == "" && instance.Name == "")
}

// Clone ...
// satisfies interface clonable.Clonable
func (instance *Label) Clone() (clonable.Clonable, error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}

	nl, _ := NewLabel()
	return nl, nl.Replace(instance)
}

// Replace ...
// satisfies interface clonable.Clonable
func (instance *Label) Replace(p clonable.Clonable) error {
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*Label](p)
	if err != nil {
		return err
	}

	*instance = *src
	return nil
}

// Valid checks if content of Label is valid
func (instance *Label) Valid() bool {
	result := instance != nil
	result = result && instance.ID != ""
	result = result && instance.Name != ""
	return result
}

// OK is a synonym for Valid
func (instance *Label) OK() bool {
	if instance == nil {
		return false
	}

	return instance.Valid()
}

// Serialize serializes instance into bytes (output json code)
func (instance *Label) Serialize() ([]byte, fail.Error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}

	r, err := json.Marshal(instance)
	return r, fail.ConvertError(err)
}

// Deserialize reads json code and restores a Tag
func (instance *Label) Deserialize(buf []byte) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	defer fail.OnPanic(&ferr) // json.Unmarshal may panic
	return fail.ConvertError(json.Unmarshal(buf, instance))
}

// GetName returns the name of the tag
// Satisfies interface data.Identifiable
func (instance *Label) GetName() string {
	return instance.Name
}

// GetID returns the ID of the tag
// Satisfies interface data.Identifiable
func (instance *Label) GetID() (string, error) {
	if instance == nil {
		return "", fmt.Errorf("invalid instance")
	}
	return instance.ID, nil
}

// IsTag tells of the Label represents a Tag (ie a Label without value)
func (instance *Label) IsTag() bool {
	if instance == nil {
		return false
	}

	return instance.HasDefault
}
