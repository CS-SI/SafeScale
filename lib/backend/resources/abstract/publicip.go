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
	"github.com/CS-SI/SafeScale/v22/lib"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// PublicIPRequest represents a PublicIP request
type PublicIPRequest struct {
	Name string         `json:"name"`
	Kind ipversion.Enum `json:"kind,omitempty"`
}

// PublicIP represents a public IP
type PublicIP struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"` // == IP
	Kind        ipversion.Enum    `json:"kind,omitempty"`
	Description string            `json:"description,omitempty"`
	MacAddress  string            `json:"mac_address;omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// NewPublicIP ...
func NewPublicIP() *PublicIP {
	instance := &PublicIP{
		Tags: make(map[string]string),
	}
	instance.Tags["CreationDate"] = time.Now().Format(time.RFC3339)
	instance.Tags["ManagedBy"] = "safescale"
	instance.Tags["Revision"] = lib.Revision
	return instance
}

// IsNull ...
// satisfies interface data.Clonable
func (pip *PublicIP) IsNull() bool {
	return pip == nil || pip.ID == "" || pip.Name == ""
}

// Clone ...
// satisfies interface data.Clonable
func (pip PublicIP) Clone() (data.Clonable, error) {
	return NewPublicIP().Replace(&pip)
}

// Replace ...
//
// satisfies interface data.Clonable
func (pip *PublicIP) Replace(p data.Clonable) (data.Clonable, error) {
	if pip == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*PublicIP)
	if !ok {
		return nil, fmt.Errorf("p is not a *PublicIP")
	}
	*pip = *src
	return pip, nil
}

// OK ...
func (pip *PublicIP) OK() bool {
	result := true
	result = result && pip != nil
	result = result && pip.ID != ""
	result = result && pip.Name != ""
	result = result && pip.Kind != ipversion.Unknown
	return result
}

// Serialize serializes instance into bytes (output json code)
func (pip *PublicIP) Serialize() ([]byte, fail.Error) {
	if pip == nil {
		return nil, fail.InvalidInstanceError()
	}

	r, err := json.Marshal(pip)
	return r, fail.Wrap(err)
}

// Deserialize reads json code and restores a Volume
func (pip *PublicIP) Deserialize(buf []byte) (ferr fail.Error) {
	if valid.IsNil(pip) {
		return fail.InvalidInstanceError()
	}

	defer fail.OnPanic(&ferr) // json.Unmarshal may panic
	return fail.Wrap(json.Unmarshal(buf, pip))
}

// GetName returns the name of the volume
// Satisfies interface data.Identifiable
func (pip *PublicIP) GetName() string {
	if pip == nil {
		return ""
	}
	return pip.Name
}

// GetID returns the ID of the volume
// Satisfies interface data.Identifiable
func (pip *PublicIP) GetID() string {
	if pip == nil {
		return ""
	}
	return pip.ID
}
