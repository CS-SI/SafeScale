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

package objectstorage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"
	"gomodules.xyz/stow"

	// necessary for connect
	_ "gomodules.xyz/stow/google"
	_ "gomodules.xyz/stow/s3"
	_ "gomodules.xyz/stow/swift"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -o ../mocks/mock_object.go -i github.com/CS-SI/SafeScale/v22/lib/server/iaas/objectstorage.Object

// Object interface
type Object interface {
	Stored() (bool, fail.Error)

	Read(io.Writer, int64, int64) fail.Error
	Write(io.Reader, int64) fail.Error
	WriteMultiPart(io.Reader, int64, int) fail.Error
	Reload() fail.Error
	Delete() fail.Error
	AddMetadata(abstract.ObjectStorageItemMetadata) fail.Error
	ForceAddMetadata(abstract.ObjectStorageItemMetadata) fail.Error
	ReplaceMetadata(abstract.ObjectStorageItemMetadata) fail.Error

	GetID() (string, fail.Error)
	GetName() (string, fail.Error)
	GetLastUpdate() (time.Time, fail.Error)
	GetSize() (int64, fail.Error)
	GetETag() (string, fail.Error)
	GetMetadata() (abstract.ObjectStorageItemMetadata, fail.Error)
}

// object is an implementation of Object interface
type object struct {
	bucket   *bucket
	item     stow.Item
	name     string
	metadata abstract.ObjectStorageItemMetadata
}

// NewObject gets the object 'objectName' if it's in the bucket, if not, it creates a new empty object, it's like a GetOrCreate function
func newObject(bucket *bucket, objectName string) (object, fail.Error) {
	if bucket == nil {
		return object{}, fail.InvalidInstanceError()
	}

	o := object{
		bucket: bucket,
		name:   objectName,
	}
	item, err := bucket.stowContainer.Item(objectName)
	if err != nil {
		switch err.Error() {
		case NotFound: // this is an implementation detail of stow
			return o, nil // nolint, we get an empty object
		default:
			return o, fail.ConvertError(err)
		}
	}

	if item == nil {
		return o, fail.InvalidInstanceContentError("item", "should NOT be nil")
	}

	// if the object exists, we get its content
	o.item = item
	return o, nil
}

// nullObject returns an instance of object corresponding to null value
func nullObject() object {
	return object{}
}

// IsNull tells if the instance correspond to null value
func (instance *object) IsNull() bool {
	return instance == nil || instance.name == ""
}

// newObjectFromStow ...
func newObjectFromStow(b *bucket, item stow.Item) object {
	if valid.IsNil(b) || item == nil {
		return nullObject()
	}
	return object{
		bucket: b,
		item:   item,
		name:   item.Name(),
	}
}

// Stored return true if the object exists in Object Storage
func (instance object) Stored() (bool, fail.Error) {
	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}
	return instance.item != nil, nil
}

// Reload reloads the data of the Object from the Object Storage
func (instance *object) Reload() fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("objectstorage"), "").Entering().Exiting()

	item, err := instance.bucket.stowContainer.Item(instance.name)
	if err != nil {
		switch err.Error() {
		case NotFound: // this is an implementation detail of stow
			return fail.NotFoundError("failed to reload '%s:%s' from Object Storage", instance.bucket.name, instance.name)
		default:
			return fail.ConvertError(err)
		}
	}

	return instance.reloadFromItem(item)
}

// reloadFromItem reloads object instance with stow.Item
func (instance *object) reloadFromItem(item stow.Item) fail.Error {
	instance.item = item
	newMetadata, err := item.Metadata()
	if err != nil {
		return fail.ConvertError(err)
	}
	instance.metadata = newMetadata
	return nil
}

// Read reads the content of the object from Object Storage and writes it in 'target'
func (instance *object) Read(target io.Writer, from, to int64) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	if target == nil {
		return fail.InvalidInstanceError()
	}
	if from > to {
		return fail.InvalidParameterError("from", "cannot be greater than 'to'")
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("objectstorage"), "(%d, %d)", from, to).Entering().Exiting()

	var seekTo int64
	var length int64

	// 1st reload information about object, to be sure to have the last
	if err := instance.Reload(); err != nil {
		return err
	}

	size, err := instance.GetSize()
	if err != nil {
		return fail.Wrap(err, "failed to get bucket size")
	}
	if size < 0 {
		return fail.NewError("unknown size of object")
	}

	length = size
	if from > 0 {
		seekTo = from
	}
	if to > 0 && to > from {
		length = to - from
	}

	source, serr := instance.item.Open()
	if serr != nil {
		return fail.ConvertError(err)
	}
	defer func() {
		if clerr := source.Close(); clerr != nil {
			if ferr != nil {
				_ = ferr.AddConsequence(clerr)
			}
			logrus.Warnf("error closing item")
		}
	}()

	if seekTo == 0 && length >= size {
		r, err := io.CopyN(target, source, size)
		if err != nil {
			return fail.ConvertError(err)
		}
		if r != size {
			return fail.InconsistentError("read %d bytes instead of expected %d", r, size)
		}
	} else {
		buf := make([]byte, seekTo)
		r, err := io.ReadAtLeast(source, buf, int(seekTo))
		if err != nil {
			return fail.ConvertError(fail.Wrap(err, "failed to seek Object Storage item"))
		}
		if r != int(seekTo) {
			return fail.InconsistentError("seeked %d bytes instead of expected %d", r, seekTo)
		}

		bufbis := make([]byte, length)
		r, err = io.ReadAtLeast(source, bufbis, int(length))
		if err != nil {
			return fail.ConvertError(fail.Wrap(err, "failed to read from Object Storage item"))
		}
		if r != int(length) {
			return fail.InconsistentError("read %d bytes instead of expected %d", r, length)
		}

		readerbis := bytes.NewReader(bufbis)
		_, err = io.CopyBuffer(target, readerbis, bufbis)
		if err != nil {
			return fail.ConvertError(err)
		}
	}
	return nil
}

// Write the source to the object in Object Storage
func (instance *object) Write(source io.Reader, sourceSize int64) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if source == nil {
		return fail.InvalidParameterCannotBeNilError("source")
	}
	if instance.bucket == nil {
		return fail.InvalidInstanceContentError("instance.bucket", "cannot be nil")
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("objectstorage"), "(%d)", sourceSize).Entering().Exiting()

	item, err := instance.bucket.stowContainer.Put(instance.name, source, sourceSize, instance.metadata)
	if err != nil {
		return fail.ConvertError(err)
	}
	return instance.reloadFromItem(item)
}

// WriteMultiPart writes big data to Object, by parts (also called chunks)
// Note: nothing to do with multi-chunk abilities of various object storage technologies
func (instance *object) WriteMultiPart(source io.Reader, sourceSize int64, chunkSize int) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if source == nil { // If source is nil, do nothing and don't trigger an error
		return nil
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("objectstorage"), "(%d, %d)", sourceSize, chunkSize).Entering().Exiting()

	metadataCopy := instance.metadata.Clone()

	var chunkIndex int
	remaining := sourceSize
	for {
		if remaining < int64(chunkSize) {
			chunkSize = int(remaining)
		}
		err := writeChunk(instance.bucket.stowContainer, instance.name, source, chunkSize, metadataCopy, chunkIndex)
		if err != nil {
			return err
		}
		remaining -= int64(chunkSize)
		// client.NbItem = client.NbItem + 1
		if remaining <= 0 {
			break
		}
		chunkIndex++
	}
	return nil
}

// writeChunk writes a chunk of data for object
func writeChunk(container stow.Container, objectName string, source io.Reader, nBytesToRead int, metadata abstract.ObjectStorageItemMetadata, chunkIndex int) fail.Error {
	buf := make([]byte, nBytesToRead)
	nBytesRead, err := source.Read(buf)
	if err == io.EOF {
		msg := fmt.Sprintf("failed to read data from source to write in chunk of object '%s' in bucket '%s'", objectName, container.Name())
		logrus.Errorf(msg)
		return fail.NewError(msg)
	}
	r := bytes.NewReader(buf)
	objectNamePart := objectName + strconv.Itoa(chunkIndex)
	metadata["Split"] = objectName
	_, err = container.Put(objectNamePart, r, int64(nBytesRead), metadata)
	if err != nil {
		return fail.Wrap(err, "failed to write in chunk of object '%s' in bucket '%s'", objectName, container.Name())
	}
	logrus.Debugf("written chunk #%d (%d bytes) of data in object '%s:%s'", nBytesRead, chunkIndex, container.Name(), objectName)
	return fail.ConvertError(err)
}

// Delete deletes the object from Object Storage
func (instance *object) Delete() fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if instance.item == nil {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("objectstorage"), "").Entering().Exiting()

	err := instance.bucket.stowContainer.RemoveItem(instance.name)
	if err != nil {
		return fail.ConvertError(err)
	}
	instance.item = nil
	return nil
}

// ForceAddMetadata overwrites the metadata entries of the object by the ones provided in parameter
func (instance *object) ForceAddMetadata(newMetadata abstract.ObjectStorageItemMetadata) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("objectstorage"), "").Entering().Exiting()

	for k, v := range newMetadata {
		instance.metadata[k] = v
	}
	return nil
}

// AddMetadata adds missing entries in object metadata
func (instance *object) AddMetadata(newMetadata abstract.ObjectStorageItemMetadata) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("objectstorage"), "").Entering().Exiting()

	for k, v := range newMetadata {
		_, found := instance.metadata[k]
		if !found {
			instance.metadata[k] = v
		}
	}
	return nil
}

// ReplaceMetadata replaces object metadata with the ones provided in parameter
func (instance *object) ReplaceMetadata(newMetadata abstract.ObjectStorageItemMetadata) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("objectstorage"), "").Entering().Exiting()

	instance.metadata = newMetadata
	return nil
}

// GetLastUpdate returns the date of last update
func (instance object) GetLastUpdate() (time.Time, fail.Error) {
	if valid.IsNil(instance) {
		return time.Time{}, fail.InvalidInstanceError()
	}
	if instance.item == nil {
		return time.Time{}, fail.InvalidInstanceContentError("instance.item", "cannot be nil")
	}
	t, err := instance.item.LastMod()
	if err != nil {
		return time.Time{}, fail.NewError(err, nil, "")
	}
	return t, nil
}

// GetMetadata returns the metadata of the object in Object Storage
func (instance object) GetMetadata() (abstract.ObjectStorageItemMetadata, fail.Error) {
	if valid.IsNil(instance) {
		return abstract.ObjectStorageItemMetadata{}, fail.InvalidInstanceError()
	}
	return instance.metadata.Clone(), nil
}

// GetSize returns the size of the content of the object
func (instance object) GetSize() (int64, fail.Error) {
	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}
	if instance.item == nil {
		return -1, fail.InvalidInstanceContentError("instance.item", "cannot be nil")
	}
	size, err := instance.item.Size()
	if err != nil {
		return -1, fail.ConvertError(err)
	}
	return size, nil
}

// GetETag returns the value of the ETag (+/- md5sum of the content...)
func (instance object) GetETag() (string, fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	if instance.item == nil {
		return "", fail.InvalidInstanceContentError("instance.item", "cannot be nil")
	}
	etag, err := instance.item.ETag()
	if err != nil {
		return "", fail.ConvertError(err)
	}
	return etag, nil
}

// GetID returns the ID of the object
func (instance object) GetID() (string, fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	if instance.item == nil {
		return "", fail.InvalidInstanceContentError("instance.item", "cannot be nil")
	}
	return instance.item.ID(), nil
}

// GetName returns the name of the object
func (instance object) GetName() (string, fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	return instance.name, nil
}
