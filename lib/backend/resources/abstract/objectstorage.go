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

	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// ObjectStorageBucket abstracts an Objet Storage container (also known as bucket in some implementations)
type ObjectStorageBucket struct {
	*Core
	ID         string `json:"id,omitempty"`
	Host       string `json:"host,omitempty"`
	MountPoint string `json:"mountPoint,omitempty"`
}

// NewObjectStorageBucket ...
func NewObjectStorageBucket(opts ...Option) (*ObjectStorageBucket, fail.Error) {
	c, xerr := New(opts...)
	if xerr != nil {
		return nil, xerr
	}

	out := &ObjectStorageBucket{Core: c}
	return out, nil
}

// IsConsistent tells if host struct is consistent
func (instance ObjectStorageBucket) IsConsistent() bool {
	result := true
	result = result && instance.ID != ""
	result = result && instance.Name != ""
	return result
}

// OK ...
func (instance ObjectStorageBucket) OK() bool {
	return instance.IsConsistent()
}

func (instance *ObjectStorageBucket) IsNull() bool {
	return instance == nil || instance.Core.IsNull() || (instance.Name == "" && instance.ID == "")
}

// Clone does a deep-copy of the ObjectStorageBucket
//
// satisfies interface clonable.Clonable
func (instance *ObjectStorageBucket) Clone() (clonable.Clonable, error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}

	newB, _ := NewObjectStorageBucket()
	return newB, newB.Replace(instance)
}

// Replace ...
//
// satisfies interface clonable.Clonable
func (instance *ObjectStorageBucket) Replace(p clonable.Clonable) error {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if p == nil {
		return fail.InvalidParameterCannotBeNilError("p")
	}

	src, err := lang.Cast[*ObjectStorageBucket](p)
	if err != nil {
		return err
	}

	*instance = *src
	instance.Core, err = clonable.CastedClone[*Core](src.Core)
	if err != nil {
		return err
	}

	return nil
}

// Serialize serializes Host 'instance' into bytes (output json code)
func (instance *ObjectStorageBucket) Serialize() ([]byte, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	r, jserr := json.Marshal(instance)
	if jserr != nil {
		return nil, fail.NewError(jserr.Error())
	}
	return r, nil
}

// Deserialize reads json code and instantiates an ObjectStorageItem
func (instance *ObjectStorageBucket) Deserialize(buf []byte) (ferr fail.Error) {
	// Note: Do not validate with .IsNull(), instance may be a null value of ObjectStorageBucket when deserializing
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	var panicErr error
	defer func() {
		if panicErr != nil {
			ferr = fail.ConvertError(panicErr) // If panic occurred, transforms err to a fail.Error if needed
		}
	}()
	defer fail.OnPanic(&panicErr) // json.Unmarshal may panic

	if jserr := json.Unmarshal(buf, instance); jserr != nil {
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
func (instance ObjectStorageBucket) GetName() string {
	return instance.Name
}

// GetID returns the ID of the host
// Satisfies interface data.Identifiable
func (instance ObjectStorageBucket) GetID() (string, error) {
	return instance.ID, nil
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
func (osi ObjectStorageItem) GetID() (string, error) {
	return osi.ItemID, nil
}
