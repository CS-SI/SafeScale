package abstract

import (
	"encoding/json"

	"github.com/CS-SI/SafeScale/lib/utils/data"
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
func NewObjectStorageBucket() ObjectStorageBucket {
	return ObjectStorageBucket{}
}

// IsConsistent tells if host struct is consistent
func (osb ObjectStorageBucket) IsConsistent() bool {
	result := true
	result = result && osb.ID != ""
	result = result && osb.Name != ""
	return result
}

func (osb *ObjectStorageBucket) IsNull() bool {
	return osb == nil || osb.Name == ""
}

// OK ...
func (osb ObjectStorageBucket) OK() bool {
	return osb.IsConsistent()
}

// Clone does a deep-copy of the Host
//
// satisfies interface data.Clonable
func (osb ObjectStorageBucket) Clone() data.Clonable {
	newB := NewObjectStorageBucket()
	return (&newB).Replace(&osb)
}

// Replace ...
//
// satisfies interface data.Clonable
func (osb *ObjectStorageBucket) Replace(p data.Clonable) data.Clonable {
	if osb == nil || p == nil {
		return osb
	}

	*osb = *p.(*ObjectStorageBucket)
	return osb
}

// Serialize serializes Host instance into bytes (output json code)
func (osb *ObjectStorageBucket) Serialize() ([]byte, fail.Error) {
	if osb.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	r, jserr := json.Marshal(osb)
	if jserr != nil {
		return nil, fail.NewError(jserr.Error())
	}
	return r, nil
}

// Deserialize reads json code and reinstantiates an ObjectStorageItem
func (osb *ObjectStorageBucket) Deserialize(buf []byte) (xerr fail.Error) {
	if osb.IsNull() {
		return fail.InvalidInstanceError()
	}

	var panicErr error
	defer func() {
		if panicErr != nil {
			xerr = fail.ConvertError(panicErr) // If panic occured, transforms err to a fail.Error if needed
		}
	}()
	defer fail.OnPanic(&panicErr) // json.Unmarshal may panic

	if jserr := json.Unmarshal(buf, osb); jserr != nil {
		switch jserr.(type) {
		case *json.SyntaxError:
			return fail.SyntaxError(jserr.Error())
		default:
			return fail.NewError(jserr.Error())
		}
	}
	return nil
}

// GetName name returns the name of the host
// Satisfies interface data.Identifiable
func (osb ObjectStorageBucket) GetName() string {
	if osb.IsNull() {
		return ""
	}
	return osb.Name
}

// GetID returns the ID of the host
// Satisfies interface data.Identifiable
func (osb ObjectStorageBucket) GetID() string {
	if osb.IsNull() {
		return ""
	}
	return osb.ID
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
