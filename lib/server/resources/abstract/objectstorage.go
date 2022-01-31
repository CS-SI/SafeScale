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
	stdjson "encoding/json"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ObjectStorageBucket abstracts an Objet Storage container (also known as bucket in some implementations)
type ObjectStorageBucket struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Host       string `json:"host,omitempty"`
	MountPoint string `json:"mountPoint,omitempty"`
}

// NewObjectStorageBucket ...
func NewObjectStorageBucket() *ObjectStorageBucket {
	return &ObjectStorageBucket{}
}

// IsConsistent tells if host struct is consistent
func (self ObjectStorageBucket) IsConsistent() bool {
	result := true
	result = result && self.ID != ""
	result = result && self.Name != ""
	return result
}

func (self *ObjectStorageBucket) IsNull() bool {
	return self == nil || self.Name == ""
}

// OK ...
func (self ObjectStorageBucket) OK() bool {
	return self.IsConsistent()
}

// Clone does a deep-copy of the Host
//
// satisfies interface data.Clonable
func (self ObjectStorageBucket) Clone() data.Clonable {
	newB := NewObjectStorageBucket()
	return newB.Replace(&self)
}

// Replace ...
//
// satisfies interface data.Clonable
func (self *ObjectStorageBucket) Replace(p data.Clonable) data.Clonable {
	if self == nil || p == nil {
		return self
	}

	*self = *p.(*ObjectStorageBucket)
	return self
}

// Serialize serializes Host instance into bytes (output json code)
func (self *ObjectStorageBucket) Serialize() ([]byte, fail.Error) {
	if self.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	r, jserr := json.Marshal(self)
	if jserr != nil {
		return nil, fail.NewError(jserr.Error())
	}
	return r, nil
}

// Deserialize reads json code and instantiates an ObjectStorageItem
func (self *ObjectStorageBucket) Deserialize(buf []byte) (ferr fail.Error) {
	// Note: Do not validate with .IsNull(), self may be a null value of ObjectStorageBucket when deserializing
	if self == nil {
		return fail.InvalidInstanceError()
	}

	var panicErr error
	defer func() {
		if panicErr != nil {
			ferr = fail.ConvertError(panicErr) // If panic occurred, transforms err to a fail.Error if needed
		}
	}()
	defer fail.OnPanic(&panicErr) // json.Unmarshal may panic

	if jserr := json.Unmarshal(buf, self); jserr != nil {
		switch jserr.(type) {
		case *stdjson.SyntaxError:
			return fail.SyntaxError(jserr.Error())
		default:
			return fail.NewError(jserr.Error())
		}
	}
	return nil
}

// GetName name returns the name of the host
// Satisfies interface data.Identifiable
func (self ObjectStorageBucket) GetName() string {
	if self.IsNull() {
		return ""
	}
	return self.Name
}

// GetID returns the ID of the host
// Satisfies interface data.Identifiable
func (self ObjectStorageBucket) GetID() string {
	if self.IsNull() {
		return ""
	}
	return self.ID
}

// ObjectStorageItemMetadata ...
type ObjectStorageItemMetadata map[string]interface{}

// Clone creates a copy of ObjectMetadata
func (osim ObjectStorageItemMetadata) Clone() ObjectStorageItemMetadata {
	cloned := ObjectStorageItemMetadata{}
	for k, v := range osim {
		cloned[k] = v
	}
	return cloned
}

// ObjectStorageItem is an abstracted representation of an object in object storage
type ObjectStorageItem struct {
	BucketName string
	ItemID     string
	ItemName   string
	Metadata   ObjectStorageItemMetadata
}

// GetName returns the name of the host
// Satisfies interface data.Identifiable
func (osi ObjectStorageItem) GetName() string {
	return osi.ItemName
}

// GetID returns the ID of the host
// Satisfies interface data.Identifiable
func (osi ObjectStorageItem) GetID() string {
	return osi.ItemID
}
