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

package objectstorage

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"gomodules.xyz/stow"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -o ../mocks/mock_bucket.go -i github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage.Bucket

const (
	// RootPath defines the path corresponding of the root of a Bucket
	RootPath = ""
	// NoPrefix corresponds to ... no prefix...
	NoPrefix = ""
	// NotFound is the 'Not found' error according to stow internals
	NotFound = "not found"
)

// Bucket interface
type Bucket interface {
	// ListObjects list object names in a GetBucket
	ListObjects(context.Context, string, string) ([]string, fail.Error)
	// Browse browses inside the GetBucket and execute a callback on each Object found
	Browse(context.Context, string, string, func(Object) fail.Error) fail.Error
	// Clear deletes all the objects in path inside a bucket
	Clear(ctx context.Context, path, prefix string) fail.Error
	// CreateObject creates a new object in the bucket
	CreateObject(context.Context, string) (Object, fail.Error)
	// InspectObject returns Object instance of an object in the GetBucket
	InspectObject(context.Context, string) (Object, fail.Error)
	// DeleteObject delete an object from a stowContainer
	DeleteObject(context.Context, string) fail.Error
	// ReadObject reads the content of an object
	ReadObject(context.Context, string, io.Writer, int64, int64) (Object, fail.Error)
	// WriteObject writes into an object
	WriteObject(context.Context, string, io.Reader, int64, abstract.ObjectStorageItemMetadata) (Object, fail.Error)
	// // CopyObject copies an object
	// CopyObject(string, string) fail.Error

	// GetName returns the name of the bucket
	GetName() (string, fail.Error)
	// GetCount returns the number of objects in the GetBucket
	GetCount(context.Context, string, string) (int64, fail.Error)
	// GetSize returns the total size of all objects in the bucket
	GetSize(context.Context, string, string) (int64, string, fail.Error)
}

// bucket describes a GetBucket
type bucket struct {
	stowLocation  stow.Location
	stowContainer stow.Container

	name string
}

// newBucket ...
func newBucket(location stow.Location) (bucket, fail.Error) {
	if location == nil {
		return bucket{}, fail.InvalidParameterCannotBeNilError("location")
	}
	return bucket{stowLocation: location}, nil
}

// IsNull tells if the bucket corresponds to its null value
func (instance *bucket) IsNull() bool {
	return instance == nil || instance.stowLocation == nil
}

// CreateObject ...
func (instance bucket) CreateObject(ctx context.Context, objectName string) (_ Object, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	o, err := newObject(&instance, objectName)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// InspectObject ...
func (instance bucket) InspectObject(ctx context.Context, objectName string) (_ Object, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	o, err := newObject(&instance, objectName)
	if err != nil {
		return nil, err
	}
	if o.item == nil {
		return nil, fail.NotFoundError(NotFound)
	}
	return &o, nil
}

func (instance bucket) estimateSize(path, prefix string) (int, error) {
	itemSet := make(map[string]bool) // New empty set
	currentPageSize := 10

	for {
		err := stow.Walk(
			instance.stowContainer, path, currentPageSize,
			func(item stow.Item, err error) error {
				if err != nil {
					return err
				}

				if itemSet[item.Name()] {
					return fail.DuplicateError(fmt.Sprintf("we found a duplicate (prefix %s): %s, we had %d items by then", prefix, item.Name(), len(itemSet)))
				}
				itemSet[item.Name()] = true

				return nil
			},
		)
		if err != nil {
			if _, ok := err.(fail.ErrDuplicate); ok { // begin again with twice the capacity
				currentPageSize = 2 * currentPageSize
				itemSet = make(map[string]bool)
				continue
			}
			if _, ok := err.(*fail.ErrDuplicate); ok { // begin again with twice the capacity
				currentPageSize = 2 * currentPageSize
				itemSet = make(map[string]bool)
				continue
			}
			return -1, err // it was something else, just drop it
		}
		break
	}
	return currentPageSize, nil
}

// ListObjects list objects of a GetBucket
func (instance bucket) ListObjects(ctx context.Context, path string, prefix string) (_ []string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	var list []string

	fullPath := buildFullPath(path, prefix)

	estimatedPageSize, err := instance.estimateSize(path, prefix)
	if err != nil {
		return list, fail.ConvertError(err)
	}

	// log.Println("location.Container => : ", c.GetName()
	err = stow.Walk(instance.stowContainer, path, estimatedPageSize,
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
func (instance bucket) Browse(
	ctx context.Context, path string, prefix string, callback func(Object) fail.Error,
) (ferr fail.Error) {
	// FIXME: Use context to stop remote calls
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	fullPath := buildFullPath(path, prefix)

	estimatedPageSize, err := instance.estimateSize(path, prefix)
	if err != nil {
		return fail.ConvertError(err)
	}

	err = stow.Walk(instance.stowContainer, path, estimatedPageSize,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			if strings.Index(item.Name(), fullPath) == 0 {
				o := newObjectFromStow(&instance, item)
				return callback(o)
			}
			return nil
		},
	)
	return fail.ConvertError(err)
}

// Clear empties a bucket
func (instance bucket) Clear(ctx context.Context, path, prefix string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	fullPath := buildFullPath(path, prefix)

	estimatedPageSize, err := instance.estimateSize(path, prefix)
	if err != nil {
		return fail.ConvertError(err)
	}

	err = stow.Walk(instance.stowContainer, path, estimatedPageSize,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			if strings.Index(item.Name(), fullPath) == 0 {
				err = instance.stowContainer.RemoveItem(item.Name())
				if err != nil {
					return err
				}
			}
			return nil
		},
	)
	return fail.ConvertError(err)
}

// DeleteObject deletes an object from a bucket
func (instance bucket) DeleteObject(ctx context.Context, objectName string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if objectName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("objectName")
	}

	o, err := newObject(&instance, objectName)
	if err != nil {
		return err
	}
	return o.Delete(ctx)
}

// ReadObject ...
func (instance bucket) ReadObject(
	ctx context.Context, objectName string, target io.Writer, from int64, to int64,
) (_ Object, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	o, err := newObject(&instance, objectName)
	if err != nil {
		return nil, err
	}
	err = o.Read(ctx, target, from, to)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// WriteObject ...
func (instance bucket) WriteObject(
	ctx context.Context, objectName string, source io.Reader, sourceSize int64,
	metadata abstract.ObjectStorageItemMetadata,
) (_ Object, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	o, err := newObject(&instance, objectName)
	if err != nil {
		return nil, err
	}

	err = o.AddMetadata(ctx, metadata)
	if err != nil {
		return nil, err
	}

	err = o.Write(ctx, source, sourceSize)
	if err != nil {
		return nil, err
	}

	return &o, nil
}

// GetName returns the name of the GetBucket
func (instance bucket) GetName() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	return instance.name, nil
}

// GetCount returns the count of objects in the GetBucket
// 'path' corresponds to stow prefix, and 'prefix' allows filtering what to count
func (instance bucket) GetCount(ctx context.Context, path string, prefix string) (_ int64, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	var count int64
	fullPath := buildFullPath(path, prefix)

	estimatedPageSize, err := instance.estimateSize(path, prefix)
	if err != nil {
		return -1, fail.ConvertError(err)
	}

	err = stow.Walk(instance.stowContainer, path, estimatedPageSize,
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
func (instance bucket) GetSize(ctx context.Context, path string, prefix string) (_ int64, _ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return 0, "", fail.InvalidInstanceError()
	}

	fullPath := buildFullPath(path, prefix)

	estimatedPageSize, err := instance.estimateSize(path, prefix)
	if err != nil {
		return -1, "", fail.ConvertError(err)
	}

	var totalSize int64
	err = stow.Walk(instance.stowContainer, path, estimatedPageSize,
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
