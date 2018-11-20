package objectstorage

import (
	"io"
	"time"

	"github.com/CS-SI/SafeScale/providers/model"
)

// Location ...
type Location interface {
	// ReadTenant(projectName string, provider string) (Config, error)
	Connect() error
	//Inspect() (map[string][]string, error)
	// SumSize() string
	// Count(key string, pattern string) (int, error)
	// WaitAllPutITemTerminated(key string, valuePattern string) error
	// FilterByMetadata(key string, valuePattern string) (map[string][]string, error)

	// ListBuckets ...
	ListBuckets() ([]string, error)
	// FindBucket returns true of bucket exists in location
	FindBucket(string) (bool, error)
	// GetBucket returns info of the Bucket
	GetBucket(string) (Bucket, error)
	// Create a bucket
	CreateBucket(string) (Bucket, error)
	// DeleteBucket removes a bucket (need to be cleared before)
	DeleteBucket(string) error
	// ClearBucket empties a Bucket
	ClearBucket(string) error

	// ListObjects lists the objects in a Bucket
	ListObjects(string, model.ObjectFilter) ([]string, error)
	// GetObject ...
	GetObject(string, string) (Object, error)
	// ReadObject ...
	ReadObject(string, string, io.Writer, []model.Range) error
	// WriteMultiChunkObject ...
	WriteMultiPartObject(string, string, io.Reader, int64, int, ObjectMetadata) (Object, error)
	// WriteObject ...
	WriteObject(string, string, io.Reader, int64, ObjectMetadata) (Object, error)
	// // CopyObject copies an object
	// CopyObject(string, string, string) error
	// DeleteObject delete an object from a container
	DeleteObject(string, string) error
	// FilterItemsByMetadata(ContainerName string, key string, pattern string) (map[string][]string, error)

	// // ItemSize ?
	// ItemSize(ContainerName string, item string) (int64, error)
	// // ItemEtag returns the Etag of an item
	// ItemEtag(ContainerName string, item string) (string, error)
	// // ItemLastMod returns the dagte of last update
	// ItemLastMod(ContainerName string, item string) (time.Time, error)
	// // ItemID returns the ID of the item
	// ItemID(ContainerName string, item string) (id string)
	// // ItemMetadata returns the metadata of an Item
	// ItemMetadata(ContainerName string, item string) (map[string]interface{}, error)
}

// Bucket interface
type Bucket interface {
	// List list object names in a Bucket
	List(model.ObjectFilter) ([]string, error)
	// BrowseObjects browses inside the Bucket and execute a callback on each Object found
	Browse(model.ObjectFilter, func(Object) error) error

	// CreateObject creates a new object in the bucket
	CreateObject(string) (Object, error)
	// GetObject returns Object instance of an object in the Bucket
	GetObject(string) (Object, error)
	// DeleteObject delete an object from a container
	DeleteObject(string) error
	// ReadObject reads the content of an object
	ReadObject(string, io.Writer, []model.Range) (Object, error)
	// WriteObject writes into an object
	WriteObject(string, io.Reader, int64, ObjectMetadata) (Object, error)
	// WriteMultiPartObject writes a lot of data into an object, cut in pieces
	WriteMultiPartObject(string, io.Reader, int64, int, ObjectMetadata) (Object, error)
	// // CopyObject copies an object
	// CopyObject(string, string) error

	// GetName returns the name of the bucket
	GetName() string
	// GetCount returns the number of objects in the Bucket
	GetCount(model.ObjectFilter) (int64, error)
	// GetSize returns the total size of all objects in the bucket
	GetSize(model.ObjectFilter) (int64, string, error)
}

// ObjectMetadata ...
type ObjectMetadata map[string]interface{}

// Clone creates a copy of ObjectMetadata
func (om ObjectMetadata) Clone() ObjectMetadata {
	cloned := ObjectMetadata{}
	for k, v := range om {
		cloned[k] = v
	}
	return cloned
}

// Object interface
type Object interface {
	Stored() bool

	Read(io.Writer, []model.Range) error
	Write(io.Reader, int64) error
	WriteMultiPart(io.Reader, int64, int) error
	Reload() error
	Delete() error
	AddMetadata(ObjectMetadata)
	ForceAddMetadata(ObjectMetadata)
	ReplaceMetadata(ObjectMetadata)

	GetID() string
	GetName() string
	GetLastUpdate() (time.Time, error)
	GetSize() int64
	GetETag() string
	GetMetadata() ObjectMetadata
}

// Config ...
type Config struct {
	Types        string
	Envauth      bool
	Authversion  int
	Auth         string
	Endpointtype string
	Tenantdomain string
	Tenant       string
	Domain       string
	User         string
	Key          string
	Region       string
	Secretkey    string
	Endpoint     string
}
