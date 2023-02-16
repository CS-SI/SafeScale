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
	stdjson "encoding/json"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// Bucket abstracts an Objet Storage container (also known as bucket in some implementations)
type Bucket struct {
	*core
	ID         string `json:"id,omitempty"`
	Host       string `json:"host,omitempty"`
	MountPoint string `json:"mountPoint,omitempty"`
}

// NewBucket ...
func NewBucket(opts ...Option) (*Bucket, fail.Error) {
	opts = append(opts, withKind(BucketKind))
	c, xerr := newCore(opts...)
	if xerr != nil {
		return nil, xerr
	}

	out := &Bucket{core: c}
	return out, nil
}

// NewEmptyBucket returns a empty, unnamed Bucket instance
func NewEmptyBucket() *Bucket {
	out, _ := NewBucket()
	return out
}

// IsConsistent tells if host struct is consistent
func (instance Bucket) IsConsistent() bool {
	result := true
	result = result && instance.ID != ""
	result = result && instance.Name != ""
	return result
}

// OK ...
func (instance Bucket) OK() bool {
	return instance.IsConsistent()
}

func (instance *Bucket) IsNull() bool {
	return instance == nil || instance.core.IsNull() || (instance.ID == "" && (instance.Name == "" || instance.Name == Unnamed))
}

// Clone does a deep-copy of the Bucket
//
// satisfies interface clonable.Clonable
func (instance *Bucket) Clone() (clonable.Clonable, error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}

	newB, _ := NewBucket()
	return newB, newB.Replace(instance)
}

// Replace ...
//
// satisfies interface clonable.Clonable
func (instance *Bucket) Replace(p clonable.Clonable) error {
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*Bucket](p)
	if err != nil {
		return err
	}

	instance.ID = src.ID
	instance.Host = src.Host
	instance.MountPoint = src.MountPoint

	return instance.core.Replace(src.core)
}

// Serialize serializes Host 'instance' into bytes (output json code)
func (instance *Bucket) Serialize() ([]byte, fail.Error) {
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
func (instance *Bucket) Deserialize(buf []byte) (ferr fail.Error) {
	// Note: Do not validate with .IsNull(), instance may be a null value of Bucket when deserializing
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	var panicErr error
	defer func() {
		if panicErr != nil {
			ferr = fail.Wrap(panicErr) // If panic occurred, transforms err to a fail.Error if needed
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

// // GetName name returns the name of the host
// // Satisfies interface data.Identifiable
// func (instance *Bucket) GetName() string {
// 	if instance == nil || valid.IsNull(instance.Core) {
// 		return ""
// 	}
//
// 	return instance.Name
// }

// GetID returns the ID of the host
// Satisfies interface data.Identifiable
func (instance *Bucket) GetID() (string, error) {
	if valid.IsNull(instance) {
		return "", fail.InvalidInstanceError()
	}

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
