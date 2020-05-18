/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package objectstorage

import (
	"io"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

const (
	// RootPath defines the path corresponding of the root of a Bucket
	RootPath = ""
	// NoPrefix corresponds to ... no prefix...
	NoPrefix = ""
)

//go:generate mockgen -destination=../mocks/mock_location.go -package=mocks github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage Location

// Location ...
type Location interface {
	// SafeGetObjectStorageProtocol returns the name of the Object Storage protocol corresponding to this location
	SafeGetObjectStorageProtocol() string

	// ListBuckets returns all bucket prefixed by a string given as a parameter
	ListBuckets(string) ([]string, fail.Error)
	// FindBucket returns true of bucket exists in location
	FindBucket(string) (bool, fail.Error)
	// InspectBucket returns info of the Bucket
	InspectBucket(string) (Bucket, fail.Error)
	// Create a bucket
	CreateBucket(string) (Bucket, fail.Error)
	// DeleteBucket removes a bucket (need to be cleared before)
	DeleteBucket(string) fail.Error
	// ClearBucket empties a Bucket
	ClearBucket(string, string, string) fail.Error

	// ListObjects lists the objects in a Bucket
	ListObjects(string, string, string) ([]string, fail.Error)
	// InspectObject ...
	InspectObject(string, string) (Object, fail.Error)
	// ReadObject ...
	ReadObject(string, string, io.Writer, int64, int64) fail.Error
	// WriteMultiChunkObject ...
	WriteMultiPartObject(string, string, io.Reader, int64, int, ObjectMetadata) (Object, fail.Error)
	// WriteObject ...
	WriteObject(string, string, io.Reader, int64, ObjectMetadata) (Object, fail.Error)
	// // CopyObject copies an object
	// CopyObject(string, string, string) fail.Error
	// DeleteObject delete an object from a container
	DeleteObject(string, string) fail.Error
	// FilterItemsByMetadata(ContainerName string, key string, pattern string) (map[string][]string, fail.Error)

	// // ItemSize ?
	// ItemSize(ContainerName string, item string) (int64, fail.Error)
	// // ItemEtag returns the Etag of an item
	// ItemEtag(ContainerName string, item string) (string, fail.Error)
	// // ItemLastMod returns the dagte of last update
	// ItemLastMod(ContainerName string, item string) (time.Time, fail.Error)
	// // ItemID returns the ID of the item
	// ItemID(ContainerName string, item string) (id string)
	// // ItemMetadata returns the metadata of an Item
	// ItemMetadata(ContainerName string, item string) (map[string]interface{}, fail.Error)
}

//go:generate mockgen -destination=../mocks/mock_bucket.go -package=mocks github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage Bucket

// Bucket interface
type Bucket interface {
	// List list object names in a Bucket
	List(string, string) ([]string, fail.Error)
	// BrowseObjects browses inside the Bucket and execute a callback on each Object found
	Browse(string, string, func(Object) fail.Error) fail.Error

	// CreateObject creates a new object in the bucket
	CreateObject(string) (Object, fail.Error)
	// InspectObject returns Object instance of an object in the Bucket
	InspectObject(string) (Object, fail.Error)
	// DeleteObject delete an object from a container
	DeleteObject(string) fail.Error
	// ReadObject reads the content of an object
	ReadObject(string, io.Writer, int64, int64) (Object, fail.Error)
	// WriteObject writes into an object
	WriteObject(string, io.Reader, int64, ObjectMetadata) (Object, fail.Error)
	// WriteMultiPartObject writes a lot of data into an object, cut in pieces
	WriteMultiPartObject(string, io.Reader, int64, int, ObjectMetadata) (Object, fail.Error)
	// // CopyObject copies an object
	// CopyObject(string, string) fail.Error

	// GetName returns the name of the bucket
	GetName() (string, fail.Error)
	// GetCount returns the number of objects in the Bucket
	GetCount(string, string) (int64, fail.Error)
	// GetSize returns the total size of all objects in the bucket
	GetSize(string, string) (int64, string, fail.Error)
	// SafeeGetName returns the name of the bucket
	SafeGetName() string
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

//go:generate mockgen -destination=../mocks/mock_object.go -package=mocks github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage Object

// Object interface
type Object interface {
	Stored() bool

	Read(io.Writer, int64, int64) fail.Error
	Write(io.Reader, int64) fail.Error
	WriteMultiPart(io.Reader, int64, int) fail.Error
	Reload() fail.Error
	Delete() fail.Error
	AddMetadata(ObjectMetadata) fail.Error
	ForceAddMetadata(ObjectMetadata) fail.Error
	ReplaceMetadata(ObjectMetadata) fail.Error

	GetID() (string, fail.Error)
	GetName() (string, fail.Error)
	GetLastUpdate() (time.Time, fail.Error)
	GetSize() (int64, fail.Error)
	GetETag() (string, fail.Error)
	GetMetadata() (ObjectMetadata, fail.Error)

	SafeGetID() string
	SafeGetName() string
	SafeGetLastUpdate() time.Time
	SafeGetSize() int64
	SafeGetETag() string
	SafeGetMetadata() ObjectMetadata
}

// FIXME: GCP Remove specific driver code

// Config ...
type Config struct {
	Type             string
	EnvAuth          bool
	AuthVersion      int
	AuthURL          string
	EndpointType     string
	Endpoint         string
	TenantDomain     string
	Tenant           string
	Domain           string
	User             string
	Key              string
	SecretKey        string
	Region           string
	AvailabilityZone string
	ProjectID        string
	Credentials      string
}
