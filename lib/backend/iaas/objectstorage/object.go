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
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"gomodules.xyz/stow"

	// necessary for connect
	_ "gomodules.xyz/stow/google"
	_ "gomodules.xyz/stow/s3"
	_ "gomodules.xyz/stow/swift"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -o ../mocks/mock_object.go -i github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage.Object

// Object interface
type Object interface {
	Read(context.Context, io.Writer, int64, int64) fail.Error
	Write(context.Context, io.Reader, int64) fail.Error
	Reload(context.Context) fail.Error
	Delete(context.Context) fail.Error
	AddMetadata(context.Context, abstract.ObjectStorageItemMetadata) fail.Error
	GetID(context.Context) (string, fail.Error)
	GetName(context.Context) (string, fail.Error)
	GetLastUpdate(context.Context) (time.Time, fail.Error)
	GetSize(context.Context) (int64, fail.Error)
	GetETag(context.Context) (string, fail.Error)
	GetMetadata(context.Context) (abstract.ObjectStorageItemMetadata, fail.Error)
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

// IsNull tells if the instance correspond to null value
func (instance *object) IsNull() bool {
	return instance == nil || instance.name == ""
}

// newObjectFromStow ...
func newObjectFromStow(b *bucket, item stow.Item) *object {
	if valid.IsNil(b) || item == nil {
		return nil
	}
	return &object{
		bucket: b,
		item:   item,
		name:   item.Name(),
	}
}

// Reload reloads the data of the Object from the Object Storage
func (instance *object) Reload(ctx context.Context) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

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
func (instance *object) Read(ctx context.Context, target io.Writer, from int64, to int64) (ferr fail.Error) {
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

	var seekTo int64
	var length int64

	// 1st reload information about object, to be sure to have the last
	if err := instance.Reload(ctx); err != nil {
		return err
	}

	size, err := instance.GetSize(ctx)
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
		ferr = debug.InjectPlannedFail(ferr)
		if clerr := source.Close(); clerr != nil {
			if ferr != nil {
				_ = ferr.AddConsequence(clerr)
			}
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
func (instance *object) Write(ctx context.Context, source io.Reader, sourceSize int64) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if source == nil {
		return fail.InvalidParameterCannotBeNilError("source")
	}
	if instance.bucket == nil {
		return fail.InvalidInstanceContentError("instance.bucket", "cannot be nil")
	}

	item, err := instance.bucket.stowContainer.Put(instance.name, source, sourceSize, instance.metadata)
	if err != nil {
		return fail.ConvertError(err)
	}
	return instance.reloadFromItem(item)
}

// writeChunk writes a chunk of data for object
func writeChunk(container stow.Container, objectName string, source io.Reader, nBytesToRead int, metadata abstract.ObjectStorageItemMetadata, chunkIndex int) fail.Error {
	buf := make([]byte, nBytesToRead)
	nBytesRead, err := source.Read(buf)
	if err == io.EOF {
		msg := fmt.Sprintf("failed to read data from source to write in chunk of object '%s' in bucket '%s'", objectName, container.Name())
		return fail.NewError(msg)
	}
	r := bytes.NewReader(buf)
	objectNamePart := objectName + strconv.Itoa(chunkIndex)
	metadata["Split"] = objectName
	_, err = container.Put(objectNamePart, r, int64(nBytesRead), metadata)
	if err != nil {
		return fail.Wrap(err, "failed to write in chunk of object '%s' in bucket '%s'", objectName, container.Name())
	}
	return nil
}

// Delete deletes the object from Object Storage
func (instance *object) Delete(ctx context.Context) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if instance.item == nil {
		return fail.InvalidInstanceError()
	}

	err := instance.bucket.stowContainer.RemoveItem(instance.name)
	if err != nil {
		return fail.ConvertError(err)
	}
	instance.item = nil
	return nil
}

// AddMetadata adds missing entries in object metadata
func (instance *object) AddMetadata(ctx context.Context, newMetadata abstract.ObjectStorageItemMetadata) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	for k, v := range newMetadata {
		_, found := instance.metadata[k]
		if !found {
			instance.metadata[k] = v
		}
	}
	return nil
}

// GetLastUpdate returns the date of last update
func (instance object) GetLastUpdate(ctx context.Context) (time.Time, fail.Error) {
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
func (instance object) GetMetadata(ctx context.Context) (abstract.ObjectStorageItemMetadata, fail.Error) {
	if valid.IsNil(instance) {
		return abstract.ObjectStorageItemMetadata{}, fail.InvalidInstanceError()
	}
	return instance.metadata.Clone(), nil
}

// GetSize returns the size of the content of the object
func (instance object) GetSize(ctx context.Context) (int64, fail.Error) {
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
func (instance object) GetETag(ctx context.Context) (string, fail.Error) {
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
func (instance object) GetID(ctx context.Context) (string, fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	if instance.item == nil {
		return "", fail.InvalidInstanceContentError("instance.item", "cannot be nil")
	}
	return instance.item.ID(), nil
}

// GetName returns the name of the object
func (instance object) GetName(ctx context.Context) (string, fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	return instance.name, nil
}
