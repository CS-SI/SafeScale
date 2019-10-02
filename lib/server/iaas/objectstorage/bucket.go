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
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"io"
	"strings"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/graymeta/stow"
)

// bucket describes a Bucket
type bucket struct {
	location  stow.Location
	container stow.Container

	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	// Host       string `json:"host,omitempty"`
	// MountPoint string `json:"mountPoint,omitempty"`
	// NbItems int `json:"nbitems,omitempty"`
}

// newBucket ...
func newBucket(location stow.Location, bucketName string) (*bucket, error) {
	return &bucket{
		location: location,
		Name:     bucketName,
	}, nil
}

// CreateObject ...
func (b *bucket) CreateObject(objectName string) (Object, error) {
	defer concurrency.NewTracer(nil, fmt.Sprintf("(%s)", objectName), false /*Trace.Controller*/).GoingIn().OnExitTrace()

	return newObject(b, objectName)
}

// GetObject ...
func (b *bucket) GetObject(objectName string) (Object, error) {
	defer concurrency.NewTracer(nil, fmt.Sprintf("(%s)", objectName), false /*Trace.Controller*/).GoingIn().OnExitTrace()

	o, err := newObject(b, objectName)
	if err != nil {
		return nil, err
	}
	if o.item == nil {
		return nil, fmt.Errorf("not found")
	}
	return o, nil
}

// ListObjects list objects of a Bucket
func (b *bucket) List(path, prefix string) ([]string, error) {
	if b == nil {
		return nil, scerr.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("(%s, %s)", path, prefix), false /*Trace.Controller*/).GoingIn().OnExitTrace()

	list := []string{}

	fullPath := buildFullPath(path, prefix)

	//log.Println("Location.Container => : ", c.Name())
	err := stow.Walk(b.container, path, 100,
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
		return nil, err
	}
	return list, nil
}

// Browse walks through the objects in the Bucket and executes callback on each Object found
func (b *bucket) Browse(path, prefix string, callback func(Object) error) error {
	if b == nil {
		return scerr.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s')", path, prefix), false /*Trace.Controller*/).GoingIn().OnExitTrace()

	fullPath := buildFullPath(path, prefix)

	err := stow.Walk(b.container, path, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			if strings.Index(item.Name(), fullPath) == 0 {

				return callback(newObjectFromStow(b, item))
			}
			return nil
		},
	)
	return err
}

// Clear empties a bucket
func (b *bucket) Clear(path, prefix string) error {
	if b == nil {
		return scerr.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s')", path, prefix), false /* Trace.ObjectStorage */).GoingIn().OnExitTrace()

	fullPath := buildFullPath(path, prefix)

	return stow.Walk(b.container, path, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			if strings.Index(item.Name(), fullPath) == 0 {
				err = b.container.RemoveItem(item.Name())
				if err != nil {
					// log.Println("erreur RemoveItem => : ", err)
					return err
				}
				// l.NbItem = 0
			}
			return nil
		},
	)
}

// DeleteObject deletes an object from a bucket
func (b *bucket) DeleteObject(objectName string) error {
	if b == nil {
		return scerr.InvalidInstanceError()
	}
	if objectName == "" {
		return scerr.InvalidParameterError("objectName", "can't be empty string")
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s')", objectName), false /* Trace.ObjectStorage */).GoingIn().OnExitTrace()

	o, err := newObject(b, objectName)
	if err != nil {
		return err
	}
	return o.Delete()
}

// ReadObject ...
func (b *bucket) ReadObject(objectName string, target io.Writer, from int64, to int64) (Object, error) {
	if b == nil {
		return nil, scerr.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s', %d, %d)", objectName, from, to), false /* Trace.ObjectStorage */).GoingIn().OnExitTrace()

	o, err := newObject(b, objectName)
	if err != nil {
		return nil, err
	}
	err = o.Read(target, from, to)
	if err != nil {
		return nil, err
	}
	return o, nil
}

// WriteObject ...
func (b *bucket) WriteObject(objectName string, source io.Reader, sourceSize int64, metadata ObjectMetadata) (Object, error) {
	if b == nil {
		return nil, scerr.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s', %d)", objectName, sourceSize), false /* Trace.ObjectStorage */).GoingIn().OnExitTrace()

	o, err := newObject(b, objectName)
	if err != nil {
		return nil, err
	}
	o.AddMetadata(metadata)
	err = o.Write(source, sourceSize)
	if err != nil {
		return nil, err
	}
	return o, nil
}

// WriteMultiPartObject ...
func (b *bucket) WriteMultiPartObject(
	objectName string,
	source io.Reader, sourceSize int64,
	chunkSize int,
	metadata ObjectMetadata,
) (Object, error) {

	if b == nil {
		return nil, scerr.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s', <source>, %d, %d, <metadata>)", objectName, sourceSize, chunkSize), false /* Trace.ObjectStorage */).GoingIn().OnExitTrace()

	o, err := newObject(b, objectName)
	if err != nil {
		return nil, err
	}
	o.AddMetadata(metadata)
	err = o.WriteMultiPart(source, sourceSize, chunkSize)
	if err != nil {
		return nil, err
	}
	return o, nil
}

// GetName returns the name of the Bucket
func (b *bucket) GetName() string {
	return b.Name
}

// GetCount returns the count of objects in the Bucket
// 'path' corresponds to stow prefix, and 'prefix' allows to filter what to count
func (b *bucket) GetCount(path, prefix string) (int64, error) {
	if b == nil {
		return 0, scerr.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s')", path, prefix), false /* Trace.ObjectStorage */).GoingIn().OnExitTrace()

	var count int64
	fullPath := buildFullPath(path, prefix)

	err := stow.Walk(b.container, path, 100,
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
		return -1, err
	}
	return count, nil
}

// GetSize returns the total size of the Objects inside the Bucket
func (b *bucket) GetSize(path, prefix string) (int64, string, error) {
	if b == nil {
		return 0, "", scerr.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s')", path, prefix), false /* Trace.ObjectStorage */).GoingIn().OnExitTrace()

	var err error
	var totalSize int64

	fullPath := buildFullPath(path, prefix)

	err = stow.Walk(b.container, path, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			if strings.Index(item.Name(), fullPath) != 0 {
				return nil
			}

			sizeItem, err := item.Size()
			if err != nil {
				return err
			}
			totalSize += sizeItem
			return nil
		},
	)
	if err != nil {
		return -1, "", err
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
		value = value / cPETABYTE
	case bytes >= cTERABYTE:
		unit = "T"
		value = value / cTERABYTE
	case bytes >= cGIGABYTE:
		unit = "G"
		value = value / cGIGABYTE
	case bytes >= cMEGABYTE:
		unit = "M"
		value = value / cMEGABYTE
	case bytes >= cKILOBYTE:
		unit = "K"
		value = value / cKILOBYTE
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
