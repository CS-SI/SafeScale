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
	"bytes"
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"io"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"gomodules.xyz/stow"

	// necessary for connect
	// _ "gomodules.xyz/stow/azure"
	_ "gomodules.xyz/stow/google"
	_ "gomodules.xyz/stow/s3"
	_ "gomodules.xyz/stow/swift"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate mockgen -destination=../mocks/mock_object.go -package=mocks github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage Object

// Object interface
type Object interface {
//	data.Identifiable

	Stored() bool

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

// NewObject ...
func newObject(bucket *bucket, objectName string) (object, fail.Error) {
	o := object{
		bucket: bucket,
		name:   objectName,
	}
	item, err := bucket.stowContainer.Item(objectName)
	if err == nil {
		o.item = item
	}
	return o, nil
}

// nullObject returns an instance of object corresponding to null value
func nullObject() object {
	return object{}
}

// IsNull tells if the instance correspond to null value
func (o *object) IsNull() bool {
	return o == nil || o.name == ""
}

// newObjectFromStow ...
func newObjectFromStow(b *bucket, item stow.Item) object {
	if b.IsNull() || item == nil {
		return nullObject()
	}
	return object{
		bucket:   b,
		item:     item,
		name:     item.Name(),
	}
}

// Stored return true if the object exists in Object Storage
func (o object) Stored() bool {
	if o.IsNull() {
		return false
	}
	return o.item != nil
}

// Reload reloads the data of the Object from the Object Storage
func (o *object) Reload() fail.Error {
	if o.IsNull() {
		return fail.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage"), "").Entering().OnExitTrace()

	item, err := o.bucket.stowContainer.Item(o.name)
	if err != nil {
		return fail.ToError(err)
	}
	return o.reloadFromItem(item)
}

// reloadFromItem reloads object instance with stow.Item
func (o *object) reloadFromItem(item stow.Item) fail.Error {
	o.item = item
	newMetadata, err := item.Metadata()
	if err != nil {
		return fail.ToError(err)
	}
	o.metadata = newMetadata
	return nil
}

// Read reads the content of the object from Object Storage and writes it in 'target'
func (o object) Read(target io.Writer, from, to int64) fail.Error {
	if o.IsNull() {
		return fail.InvalidInstanceError()
	}

	if target == nil {
		return fail.InvalidInstanceError()
	}
	if from > to {
		return fail.InvalidParameterError("from", "cannot be greater than 'to'")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage"), "(%d, %d)", from, to).Entering().OnExitTrace()

	var seekTo int64
	var length int64

	// 1st reload information about object, to be sure to have the last
	err := o.Reload()
	if err != nil {
		return err
	}

	size, err := o.GetSize()
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

	source, serr := o.item.Open()
	if serr != nil {
		return fail.ToError(err)
	}
	defer func() {
		clerr := source.Close()
		if clerr != nil {
			logrus.Error("Error closing item")
		}
	}()

	if seekTo == 0 && length >= size {
		_, err := io.CopyN(target, source, size)
		if err != nil {
			return fail.ToError(err)
		}
	} else {
		buf := make([]byte, seekTo)
		if _, err := io.ReadAtLeast(source, buf, int(seekTo)); err != nil {
			logrus.Fatal(err)
		}

		bufbis := make([]byte, length)
		if _, err := io.ReadAtLeast(source, bufbis, int(length)); err != nil {
			logrus.Println("error ")
			logrus.Fatal(err)
		}

		readerbis := bytes.NewReader(bufbis)
		_, err := io.CopyBuffer(target, readerbis, bufbis)
		if err != nil {
			return fail.ToError(err)
		}
	}
	return nil
}

// Write the source to the object in Object Storage
func (o object) Write(source io.Reader, sourceSize int64) fail.Error {
	if o.IsNull() {
		return fail.InvalidInstanceError()
	}
	if source == nil {
		return fail.InvalidParameterError("source", "cannot be nil")
	}
	if o.bucket == nil {
		return fail.InvalidInstanceContentError("o.bucket", "cannot be nil")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage"), "(%d)", sourceSize).Entering().OnExitTrace()

	item, err := o.bucket.stowContainer.Put(o.name, source, sourceSize, o.metadata)
	if err != nil {
		return fail.ToError(err)
	}
	return o.reloadFromItem(item)
}

// WriteMultiPart writes big data to Object, by parts (also called chunks)
// Note: nothing to do with multi-chunk abilities of various object storage technologies
func (o object) WriteMultiPart(source io.Reader, sourceSize int64, chunkSize int) fail.Error {
	if o.IsNull() {
		return fail.InvalidInstanceError()
	}
	if source == nil { // If source is nil, do nothing and don't trigger an error
		return nil
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage"), "(%d, %d)", sourceSize, chunkSize).Entering().OnExitTrace()

	metadataCopy := o.metadata.Clone()

	var chunkIndex int
	remaining := sourceSize
	for {
		if remaining < int64(chunkSize) {
			chunkSize = int(remaining)
		}
		err := writeChunk(o.bucket.stowContainer, o.name, source, chunkSize, metadataCopy, chunkIndex)
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
	return fail.ToError(err)
}

// Delete deletes the object from Object Storage
func (o *object) Delete() fail.Error {
	if o.IsNull() {
		return fail.InvalidInstanceError()
	}
	if o.item == nil {
		return fail.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage"), "").Entering().OnExitTrace()

	err := o.bucket.stowContainer.RemoveItem(o.name)
	if err != nil {
		return fail.ToError(err)
	}
	o.item = nil
	return nil
}

// ForceAddMetadata overwrites the metadata entries of the object by the ones provided in parameter
func (o *object) ForceAddMetadata(newMetadata abstract.ObjectStorageItemMetadata) fail.Error {
	if o.IsNull() {
		return fail.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage"), "").Entering().OnExitTrace()

	for k, v := range newMetadata {
		o.metadata[k] = v
	}
	return nil
}

// AddMetadata adds missing entries in object metadata
func (o *object) AddMetadata(newMetadata abstract.ObjectStorageItemMetadata) fail.Error {
	if o.IsNull() {
		return fail.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage"), "").Entering().OnExitTrace()

	for k, v := range newMetadata {
		_, found := o.metadata[k]
		if !found {
			o.metadata[k] = v
		}
	}
	return nil
}

// ReplaceMetadata replaces object metadata with the ones provided in parameter
func (o *object) ReplaceMetadata(newMetadata abstract.ObjectStorageItemMetadata) fail.Error {
	if o.IsNull() {
		return fail.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage"), "").Entering().OnExitTrace()

	o.metadata = newMetadata
	return nil
}

// GetLastUpdate returns the date of last update
func (o object) GetLastUpdate() (time.Time, fail.Error) {
	if o.IsNull() {
		return time.Time{}, fail.InvalidInstanceError()
	}
	if o.item == nil {
		return time.Time{}, fail.InvalidInstanceContentError("o.item", "cannot be nil")
	}
	t, err := o.item.LastMod()
	if err != nil {
		return time.Time{}, fail.NewError(err, nil, "")
	}
	return t, nil
}

// GetMetadata returns the metadata of the object in Object Storage
func (o object) GetMetadata() (abstract.ObjectStorageItemMetadata, fail.Error) {
	if o.IsNull() {
		return abstract.ObjectStorageItemMetadata{}, fail.InvalidInstanceError()
	}
	return o.metadata.Clone(), nil
}

// GetSize returns the size of the content of the object
func (o object) GetSize() (int64, fail.Error) {
	if o.IsNull() {
		return 0, fail.InvalidInstanceError()
	}
	if o.item == nil {
		return -1, fail.InvalidInstanceContentError("o.item", "cannot be nil")
	}
	size, err := o.item.Size()
	if err != nil {
		return -1, fail.ToError(err)
	}
	return size, nil
}

// GetETag returns the value of the ETag (+/- md5sum of the content...)
func (o object) GetETag() (string, fail.Error) {
	if o.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if o.item == nil {
		return "", fail.InvalidInstanceContentError("o.item", "cannot be nil")
	}
	etag, err := o.item.ETag()
	if err != nil {
		return "", fail.ToError(err)
	}
	return etag, nil
}

// GetID returns the GetID of the object
func (o object) GetID() (string, fail.Error) {
	if o.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if o.item == nil {
		return "", fail.InvalidInstanceContentError("o.item", "cannot be nil")
	}
	return o.item.ID(), nil
}

// GetName returns the name of the object
func (o object) GetName() (string, fail.Error) {
	if o.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	return o.name, nil
}
