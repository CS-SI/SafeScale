/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
)

const (
	// RootPath defines the path corresponding of the root of a Bucket
	RootPath = ""
	// NoPrefix corresponds to ... no prefix...
	NoPrefix = ""
)

// Location ...
type Location interface {
	// ReadTenant(projectName string, provider string) (Config, error)
	GetType() string
	//Inspect() (map[string][]string, error)
	// SumSize() string
	// Count(key string, pattern string) (int, error)
	// WaitAllPutITemTerminated(key string, valuePattern string) error
	// FilterByMetadata(key string, valuePattern string) (map[string][]string, error)

	// ListBuckets ...
	ListBuckets(string) ([]string, error)
	// FindBucket returns true of bucket exists in location
	FindBucket(string) (bool, error)
	// GetBucket returns info of the Bucket
	GetBucket(string) (Bucket, error)
	// Create a bucket
	CreateBucket(string) (Bucket, error)
	// DeleteBucket removes a bucket (need to be cleared before)
	DeleteBucket(string) error
	// ClearBucket empties a Bucket
	ClearBucket(string, string, string) error

	// ListObjects lists the objects in a Bucket
	ListObjects(string, string, string) ([]string, error)
	// GetObject ...
	GetObject(string, string) (Object, error)
	// ReadObject ...
	ReadObject(string, string, io.Writer, int64, int64) error
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
	List(string, string) ([]string, error)
	// BrowseObjects browses inside the Bucket and execute a callback on each Object found
	Browse(string, string, func(Object) error) error

	// CreateObject creates a new object in the bucket
	CreateObject(string) (Object, error)
	// GetObject returns Object instance of an object in the Bucket
	GetObject(string) (Object, error)
	// DeleteObject delete an object from a container
	DeleteObject(string) error
	// ReadObject reads the content of an object
	ReadObject(string, io.Writer, int64, int64) (Object, error)
	// WriteObject writes into an object
	WriteObject(string, io.Reader, int64, ObjectMetadata) (Object, error)
	// WriteMultiPartObject writes a lot of data into an object, cut in pieces
	WriteMultiPartObject(string, io.Reader, int64, int, ObjectMetadata) (Object, error)
	// // CopyObject copies an object
	// CopyObject(string, string) error

	// GetName returns the name of the bucket
	GetName() string
	// GetCount returns the number of objects in the Bucket
	GetCount(string, string) (int64, error)
	// GetSize returns the total size of all objects in the bucket
	GetSize(string, string) (int64, string, error)
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

	Read(io.Writer, int64, int64) error
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
	Type         string
	EnvAuth      bool
	AuthVersion  int
	AuthURL      string
	EndpointType string
	Endpoint     string
	TenantDomain string
	Tenant       string
	Domain       string
	User         string
	Key          string
	SecretKey    string
	Region       string
}
