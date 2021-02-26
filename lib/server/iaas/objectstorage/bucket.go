/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"fmt"
	"io"
	"strings"

	"gomodules.xyz/stow"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate mockgen -destination=../mocks/mock_bucket.go -package=mocks github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage Bucket

const (
	// RootPath defines the path corresponding of the root of a Bucket
	RootPath = ""
	// NoPrefix corresponds to ... no prefix...
	NoPrefix = ""
)

// Bucket interface
type Bucket interface {
	//	data.Identifiable

	// ListObjects list object names in a GetBucket
	ListObjects(string, string) ([]string, fail.Error)
	// Browse browses inside the GetBucket and execute a callback on each Object found
	Browse(string, string, func(Object) fail.Error) fail.Error
	// Clear deletes all the objects in path inside a bucket
	Clear(path, prefix string) fail.Error
	// CreateObject creates a new object in the bucket
	CreateObject(string) (Object, fail.Error)
	// InspectObject returns Object instance of an object in the GetBucket
	InspectObject(string) (Object, fail.Error)
	// DeleteObject delete an object from a stowContainer
	DeleteObject(string) fail.Error
	// ReadObject reads the content of an object
	ReadObject(string, io.Writer, int64, int64) (Object, fail.Error)
	// WriteObject writes into an object
	WriteObject(string, io.Reader, int64, abstract.ObjectStorageItemMetadata) (Object, fail.Error)
	// WriteMultiPartObject writes a lot of data into an object, cut in pieces
	WriteMultiPartObject(string, io.Reader, int64, int, abstract.ObjectStorageItemMetadata) (Object, fail.Error)
	// // CopyObject copies an object
	// CopyObject(string, string) fail.Error

	// GetName returns the name of the bucket
	GetName() (string, fail.Error)
	// GetCount returns the number of objects in the GetBucket
	GetCount(string, string) (int64, fail.Error)
	// GetSize returns the total size of all objects in the bucket
	GetSize(string, string) (int64, string, fail.Error)
}

// bucket describes a GetBucket
type bucket struct {
	stowLocation  stow.Location
	stowContainer stow.Container

	name string
	// // NbItems int `json:"nbitems,omitempty"`
}

// newBucket ...
func newBucket(location stow.Location) (bucket, fail.Error) {
	if location == nil {
		return bucket{}, fail.InvalidParameterCannotBeNilError("location")
	}
	return bucket{stowLocation: location}, nil
}

// NullBucket returns a bucket instance corresponding to null value
func NullBucket() Bucket {
	return &bucket{}
}

// IsNull tells if the bucket corresponds to its null value
func (b *bucket) IsNull() bool {
	return b == nil || b.stowLocation == nil
}

// CreateObject ...
func (b bucket) CreateObject(objectName string) (Object, fail.Error) {
	if b.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage"), "(%s)", objectName).Entering().Exiting()

	o, err := newObject(&b, objectName)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// InspectObject ...
func (b bucket) InspectObject(objectName string) (Object, fail.Error) {
	if b.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage"), "(%s)", objectName).Entering().Exiting()

	o, err := newObject(&b, objectName)
	if err != nil {
		return nil, err
	}
	if o.item == nil {
		return nil, fail.NotFoundError("not found")
	}
	return &o, nil
}

// ListObjects list objects of a GetBucket
func (b bucket) ListObjects(path, prefix string) ([]string, fail.Error) {
	if b.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage"), "(%s, %s)", path, prefix).Entering().Exiting()

	var list []string

	fullPath := buildFullPath(path, prefix)

	// log.Println("location.Container => : ", c.GetName()
	err := stow.Walk(b.stowContainer, path, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			if strings.Index(item.Name(), fullPath) == 0 {
				list = append(list, item.Name())
			}
			return nil
		},
	)
	if err != nil {
		return nil, fail.ConvertError(err)
	}
	return list, nil
}

// Browse walks through the objects in the GetBucket and executes callback on each Object found
func (b bucket) Browse(path, prefix string, callback func(Object) fail.Error) fail.Error {
	if b.IsNull() {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage"), "('%s', '%s')", path, prefix).Entering().Exiting()

	fullPath := buildFullPath(path, prefix)

	err := stow.Walk(b.stowContainer, path, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			if strings.Index(item.Name(), fullPath) == 0 {
				o := newObjectFromStow(&b, item)
				return callback(&o)
			}
			return nil
		},
	)
	return fail.ConvertError(err)
}

// Clear empties a bucket
func (b bucket) Clear(path, prefix string) fail.Error {
	if b.IsNull() {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage"), "('%s', '%s')", path, prefix).Entering().Exiting()

	fullPath := buildFullPath(path, prefix)

	err := stow.Walk(b.stowContainer, path, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			if strings.Index(item.Name(), fullPath) == 0 {
				err = b.stowContainer.RemoveItem(item.Name())
				if err != nil {
					// log.Println("erreur RemoveItem => : ", err)
					return err
				}
				// l.NbItem = 0
			}
			return nil
		},
	)
	return fail.ConvertError(err)
}

// DeleteObject deletes an object from a bucket
func (b bucket) DeleteObject(objectName string) fail.Error {
	if b.IsNull() {
		return fail.InvalidInstanceError()
	}
	if objectName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("objectName")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage"), "('%s')", objectName).Entering().Exiting()

	o, err := newObject(&b, objectName)
	if err != nil {
		return err
	}
	return o.Delete()
}

// ReadObject ...
func (b bucket) ReadObject(objectName string, target io.Writer, from int64, to int64) (Object, fail.Error) {
	if b.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage"), "('%s', %d, %d)", objectName, from, to).Entering().Exiting()

	o, err := newObject(&b, objectName)
	if err != nil {
		return nil, err
	}
	err = o.Read(target, from, to)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// WriteObject ...
func (b bucket) WriteObject(objectName string, source io.Reader, sourceSize int64, metadata abstract.ObjectStorageItemMetadata) (Object, fail.Error) {
	if b.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage"), "('%s', %d)", objectName, sourceSize).Entering().Exiting()

	o, err := newObject(&b, objectName)
	if err != nil {
		return nil, err
	}

	err = o.AddMetadata(metadata)
	if err != nil {
		return nil, err
	}

	err = o.Write(source, sourceSize)
	if err != nil {
		return nil, err
	}

	return &o, nil
}

// WriteMultiPartObject ...
func (b bucket) WriteMultiPartObject(
	objectName string,
	source io.Reader, sourceSize int64,
	chunkSize int,
	metadata abstract.ObjectStorageItemMetadata,
) (Object, fail.Error) {

	if b.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage"), "('%s', <source>, %d, %d, <metadata>)", objectName, sourceSize, chunkSize).Entering().Exiting()

	o, err := newObject(&b, objectName)
	if err != nil {
		return nil, err
	}
	err = o.AddMetadata(metadata)
	if err != nil {
		return nil, err
	}
	err = o.WriteMultiPart(source, sourceSize, chunkSize)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// GetName returns the name of the GetBucket
func (b bucket) GetName() (string, fail.Error) {
	if b.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	return b.name, nil
}

// GetCount returns the count of objects in the GetBucket
// 'path' corresponds to stow prefix, and 'prefix' allows to filter what to count
func (b bucket) GetCount(path, prefix string) (int64, fail.Error) {
	if b.IsNull() {
		return 0, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage"), "('%s', '%s')", path, prefix).Entering().Exiting()

	var count int64
	fullPath := buildFullPath(path, prefix)

	err := stow.Walk(b.stowContainer, path, 100,
		func(c stow.Item, err error) error {
			if err != nil {
				return err
			}
			if strings.Index(c.Name(), fullPath) == 0 {
				count++
			}
			return nil
		},
	)
	if err != nil {
		return -1, fail.ConvertError(err)
	}
	return count, nil
}

// GetSize returns the total size of the Objects inside the GetBucket
func (b bucket) GetSize(path, prefix string) (int64, string, fail.Error) {
	if b.IsNull() {
		return 0, "", fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage"), "('%s', '%s')", path, prefix).Entering().Exiting()

	fullPath := buildFullPath(path, prefix)

	var totalSize int64
	err := stow.Walk(b.stowContainer, path, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			if strings.Index(item.Name(), fullPath) != 0 {
				return nil
			}

			sizeItem, innerErr := item.Size()
			if innerErr != nil {
				return innerErr
			}
			totalSize += sizeItem
			return nil
		},
	)
	if err != nil {
		return -1, "", fail.ConvertError(err)
	}
	return totalSize, humanReadableSize(totalSize), nil
}

func humanReadableSize(bytes int64) string {
	const (
		cBYTE = 1.0 << (10 * iota)
		cKILOBYTE
		cMEGABYTE
		cGIGABYTE
		cTERABYTE
		cPETABYTE
	)

	unit := ""
	value := float32(bytes)

	switch {
	case bytes >= cPETABYTE:
		unit = "P"
		value /= cPETABYTE
	case bytes >= cTERABYTE:
		unit = "T"
		value /= cTERABYTE
	case bytes >= cGIGABYTE:
		unit = "G"
		value /= cGIGABYTE
	case bytes >= cMEGABYTE:
		unit = "M"
		value /= cMEGABYTE
	case bytes >= cKILOBYTE:
		unit = "K"
		value /= cKILOBYTE
	case bytes >= cBYTE:
		unit = "B"
	case bytes == 0:
		return "0"
	}

	stringValue := fmt.Sprintf("%.1f", value)
	stringValue = strings.TrimSuffix(stringValue, ".0")
	return fmt.Sprintf("%s%s", stringValue, unit)
}

// buildFullPath builds the full path to use in object storage
func buildFullPath(path, prefix string) string {
	if path != "" {
		path += "/"
	}
	return strings.TrimRight(path, "/") + prefix
}
