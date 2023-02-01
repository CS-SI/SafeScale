/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type Label struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	HasDefault   bool   `json:"has_default"` // if false, this represents a Tag
	DefaultValue string `json:"default_value,omitempty"`
}

// NewLabel creates a new empty Label...
func NewLabel() *Label {
	return &Label{
		HasDefault: true,
	}
}

// IsNull ...
// satisfies interface data.Clonable
func (t *Label) IsNull() bool {
	return t == nil || (t.ID == "" && t.Name == "")
}

// Clone ...
// satisfies interface data.Clonable
func (t Label) Clone() (data.Clonable, error) {
	return NewLabel().Replace(&t)
}

// Replace ...
// satisfies interface data.Clonable
func (t *Label) Replace(p data.Clonable) (data.Clonable, error) {
	if t == nil {
		return nil, fail.InvalidInstanceError()
	}
	if p == nil {
		return nil, fail.InvalidParameterCannotBeNilError("p")
	}

	src, ok := p.(*Label) // nolint
	if !ok {
		return nil, fmt.Errorf("p is not a *Label")
	}

	*t = *src
	return t, nil
}

// Valid checks if content of Label is valid
func (t *Label) Valid() bool {
	result := t != nil
	result = result && t.ID != ""
	result = result && t.Name != ""
	return result
}

// OK is a synonym for Valid
func (t Label) OK() bool {
	return t.Valid()
}

// Serialize serializes instance into bytes (output json code)
func (t *Label) Serialize() ([]byte, fail.Error) {
	if t == nil {
		return nil, fail.InvalidInstanceError()
	}

	r, err := json.Marshal(t)
	return r, fail.ConvertError(err)
}

// Deserialize reads json code and restores a Tag
func (t *Label) Deserialize(buf []byte) (ferr fail.Error) {
	if t == nil {
		return fail.InvalidInstanceError()
	}

	defer fail.OnPanic(&ferr) // json.Unmarshal may panic
	return fail.ConvertError(json.Unmarshal(buf, t))
}

// GetName returns the name of the tag
// Satisfies interface data.Identifiable
func (t *Label) GetName() string {
	return t.Name
}

// GetID returns the ID of the tag
// Satisfies interface data.Identifiable
func (t *Label) GetID() (string, error) {
	if t == nil {
		return "", fmt.Errorf("invalid instance")
	}
	return t.ID, nil
}

// IsTag tells of the Label represents a Tag (ie a Label without value)
func (t *Label) IsTag() bool {
	if t == nil {
		return false
	}

	return t.HasDefault
}
