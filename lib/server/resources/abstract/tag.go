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

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// TagRequest represents a tag request (tagging or untagging operation)
type TagRequest struct {
	Name string `json:"name,omitempty"`
}

// Tag represents a block tag
type Tag struct {
	ID          string            `json:"id,omitempty"`
	Name        string            `json:"name,omitempty"`
	HostsByID   map[string]string `json:"hosts_by_id,omitempty"`
	HostsByName map[string]string `json:"hosts_by_name,omitempty"`
}

// NewTag ...
func NewTag() *Tag {
	return &Tag{
		HostsByID:   map[string]string{},
		HostsByName: map[string]string{},
	}
}

// IsNull ...
// satisfies interface data.Clonable
func (t *Tag) IsNull() bool {
	return t == nil || (t.ID == "" && t.Name == "")
}

// Clone ...
// satisfies interface data.Clonable
func (t Tag) Clone() (data.Clonable, error) {
	return NewTag().Replace(&t)
}

// Replace ...
//
// satisfies interface data.Clonable
func (t *Tag) Replace(p data.Clonable) (data.Clonable, error) {
	if t == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*Tag) // nolint
	if !ok {
		return nil, fmt.Errorf("p is not a *Tag")
	}
	*t = *src
	t.HostsByID = make(map[string]string, len(src.HostsByID))
	for k, v := range src.HostsByID {
		t.HostsByID[k] = v
	}
	t.HostsByName = make(map[string]string, len(src.HostsByName))
	for k, v := range src.HostsByName {
		t.HostsByName[k] = v
	}
	return t, nil
}

// OK ...
func (t *Tag) OK() bool {
	result := true
	result = result && t != nil
	return result
}

// Serialize serializes instance into bytes (output json code)
func (t *Tag) Serialize() ([]byte, fail.Error) {
	if t == nil {
		return nil, fail.InvalidInstanceError()
	}
	r, err := json.Marshal(t)
	return r, fail.ConvertError(err)
}

// Deserialize reads json code and restores a Tag
func (t *Tag) Deserialize(buf []byte) (ferr fail.Error) {
	if t == nil {
		return fail.InvalidInstanceError()
	}

	defer fail.OnPanic(&ferr) // json.Unmarshal may panic
	return fail.ConvertError(json.Unmarshal(buf, t))
}

// GetName returns the name of the tag
// Satisfies interface data.Identifiable
func (t *Tag) GetName() string {
	if t == nil {
		return ""
	}
	return t.Name
}

// GetID returns the ID of the tag
// Satisfies interface data.Identifiable
func (t *Tag) GetID() string {
	if t == nil {
		return ""
	}
	return t.ID
}
