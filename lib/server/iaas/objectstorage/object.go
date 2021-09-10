/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"io"
	"strconv"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"

	"github.com/graymeta/stow"
	log "github.com/sirupsen/logrus"

	// necessary for connect
	// _ "github.com/graymeta/stow/azure"
	_ "github.com/graymeta/stow/google"
	_ "github.com/graymeta/stow/s3"
	_ "github.com/graymeta/stow/swift"
)

// object implementation of Object interface
type object struct {
	bucket *bucket
	item   stow.Item

	ID       string         `json:"id,omitempty"`
	Name     string         `json:"name,omitempty"`
	Metadata ObjectMetadata `json:"metadata,omitempty"`
	// DeleteAt     time.Time              `json:"delete_at,omitempty"`
	// LastModified time.Time              `json:"last_modified,omitempty"`
	// ContentType   string                 `json:"content_type,omitempty"`
	// ContentLength int64                  `json:"content_length,omitempty"`
	// ETag          string                 `json:"etag,omitempty"`
	// Size          int64                  `json:"size,omitempty"`
	// Date          time.Time              `json:"date,omitempty"`
	// Content       io.ReadSeeker          `json:"content,omitempty"`
}

// NewObject ...
func newObject(bucket *bucket, objectName string) (*object, error) {
	o := &object{
		bucket: bucket,
		Name:   objectName,
	}
	item, err := bucket.container.Item(objectName)
	if err != nil {
		if err != stow.ErrNotFound { // FIXME: Remove stow dependency
			return nil, err
		}
	}

	o.item = item
	return o, nil
}

// newObjectFromStow ...
func newObjectFromStow(bucket *bucket, item stow.Item) *object {
	return &object{
		bucket:   bucket,
		item:     item,
		Name:     item.Name(),
		Metadata: ObjectMetadata{},
	}
}

// Stored return true if the object exists in Object Storage
func (o *object) Stored() (bool, error) {
	if o == nil {
		return false, fail.InvalidInstanceError()
	}

	return o.item != nil, nil
}

// Reload reloads the data of the Object from the Object Storage
func (o *object) Reload() error {
	if o == nil {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, "", false /*Trace.Controller*/).GoingIn().OnExitTrace()()

	item, err := o.bucket.container.Item(o.Name)
	if err != nil {
		return err
	}
	return o.reloadFromItem(item)
}

// reloadFromItem reloads object instance with stow.Item
func (o *object) reloadFromItem(item stow.Item) error {
	o.item = item
	newMetadata, err := item.Metadata()
	if err != nil {
		return err
	}
	o.Metadata = newMetadata
	return nil
}

// Read reads the content of the object from Object Storage and writes it in 'target'
func (o *object) Read(target io.Writer, from, to int64) error {
	if o == nil {
		return fail.InvalidInstanceError()
	}
	if target == nil {
		return fail.InvalidInstanceError()
	}
	if from > to {
		return fail.InvalidParameterError("from", "cannot be greater than 'to'")
	}

	defer debug.NewTracer(nil, fmt.Sprintf("(%d, %d)", from, to), false /*Trace.Controller*/).GoingIn().OnExitTrace()()

	var seekTo int64
	var length int64

	// 1st reload information about object, to be sure to have the last
	err := o.Reload()
	if err != nil {
		return err
	}

	size, err := o.GetSize()
	if err != nil {
		return err
	}
	if size < 0 {
		return fmt.Errorf("unknown size of object")
	}

	length = size
	if from > 0 {
		seekTo = from
	}
	if to > 0 && to > from {
		length = to - from
	}

	source, err := o.item.Open()
	if err != nil {
		return err
	}
	defer func() {
		clerr := source.Close()
		if clerr != nil {
			log.Error("Error closing item")
		}
	}()

	if seekTo == 0 && length >= size {
		_, err := io.CopyN(target, source, size)
		if err != nil {
			return err
		}
	} else {
		buf := make([]byte, seekTo)
		if _, err := io.ReadAtLeast(source, buf, int(seekTo)); err != nil {
			log.Error(err)
			return err
		}

		bufbis := make([]byte, length)
		if _, err := io.ReadAtLeast(source, bufbis, int(length)); err != nil {
			log.Error(err)
			return err
		}

		readerbis := bytes.NewReader(bufbis)
		_, err := io.CopyBuffer(target, readerbis, bufbis)
		if err != nil {
			return err
		}
	}
	return nil
}

// Write the source to the object in Object Storage
func (o *object) Write(source io.Reader, sourceSize int64) error {
	if o == nil {
		return fail.InvalidInstanceError()
	}
	if source == nil {
		return fail.InvalidParameterError("source", "cannot be nil")
	}
	if o.bucket == nil {
		return fail.InvalidParameterError("o.bucket", "cannot be nil")
	}

	defer debug.NewTracer(nil, fmt.Sprintf("(%d)", sourceSize), false /*Trace.Controller*/).GoingIn().OnExitTrace()()

	metaData, err := o.GetMetadata()
	if err != nil {
		return err
	}

	item, err := o.bucket.container.Put(o.Name, source, sourceSize, metaData)
	if err != nil {
		return err
	}
	return o.reloadFromItem(item)
}

// WriteMultiPart writes big data to Object, by parts (also called chunks)
// Note: nothing to do with multi-chunk abilities of various object storage technologies
func (o *object) WriteMultiPart(source io.Reader, sourceSize int64, chunkSize int) error {
	if o == nil {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(
		nil, fmt.Sprintf("(%d, %d)", sourceSize, chunkSize), false, /*Trace.Controller*/
	).GoingIn().OnExitTrace()()

	metaData, err := o.GetMetadata()
	if err != nil {
		return err
	}

	metadataCopy := metaData.Clone()

	var chunkIndex int
	remaining := sourceSize
	for {
		if remaining < int64(chunkSize) {
			chunkSize = int(remaining)
		}
		err := writeChunk(o.bucket.container, o.Name, source, chunkSize, metadataCopy, chunkIndex)
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
func writeChunk(
	container stow.Container, objectName string,
	source io.Reader, nBytesToRead int,
	metadata ObjectMetadata,
	chunkIndex int,
) error {

	buf := make([]byte, nBytesToRead)
	nBytesRead, err := source.Read(buf)
	if err == io.EOF {
		msg := fmt.Sprintf(
			"failed to read data from source to write in chunk of object '%s' in bucket '%s'", objectName,
			container.Name(),
		)
		log.Errorf(msg)
		return fmt.Errorf(msg)
	}
	r := bytes.NewReader(buf)
	objectNamePart := objectName + strconv.Itoa(chunkIndex)
	metadata["Split"] = objectName
	_, err = container.Put(objectNamePart, r, int64(nBytesRead), metadata)
	if err != nil {
		return err
	}
	log.Debugf(
		"written chunk #%d (%d bytes) of data in object '%s:%s'", nBytesRead, chunkIndex, container.Name(), objectName,
	)
	return err
}

// Delete deletes the object from Object Storage
func (o *object) Delete() error {
	if o == nil {
		return fail.InvalidInstanceError()
	}
	if o.item == nil {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, "", false /*Trace.Controller*/).GoingIn().OnExitTrace()()

	err := o.bucket.container.RemoveItem(o.Name)
	if err != nil {
		return err
	}
	o.item = nil
	return nil
}

// ForceAddMetadata overwrites the metadata entries of the object by the ones provided in parameter
func (o *object) ForceAddMetadata(newMetadata ObjectMetadata) error {
	if o == nil {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, "", false /*Trace.Controller*/).GoingIn().OnExitTrace()()

	for k, v := range newMetadata {
		o.Metadata[k] = v
	}

	return nil
}

// AddMetadata adds missing entries in object metadata
func (o *object) AddMetadata(newMetadata ObjectMetadata) error {
	if o == nil {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, "", false /*Trace.Controller*/).GoingIn().OnExitTrace()()

	for k, v := range newMetadata {
		_, found := o.Metadata[k]
		if !found {
			o.Metadata[k] = v
		}
	}

	return nil
}

// ReplaceMetadata replaces object metadata with the ones provided in parameter
func (o *object) ReplaceMetadata(newMetadata ObjectMetadata) error {
	if o == nil {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, "", false /*Trace.Controller*/).GoingIn().OnExitTrace()()

	o.Metadata = newMetadata

	return nil
}

// GetName returns the name of the object
func (o *object) GetName() (string, error) {
	if o == nil {
		return "", fail.InvalidInstanceError()
	}

	return o.Name, nil
}

// GetLastUpdate returns the date of last update
func (o *object) GetLastUpdate() (time.Time, error) {
	if o == nil {
		return time.Time{}, fail.InvalidInstanceError()
	}

	if o.item != nil {
		return o.item.LastMod()
	}
	return time.Now(), fmt.Errorf("object metadata not found")
}

// GetMetadata returns the metadata of the object in Object Storage
func (o *object) GetMetadata() (ObjectMetadata, error) {
	if o == nil {
		return nil, fail.InvalidInstanceError()
	}

	return o.Metadata.Clone(), nil
}

// GetSize returns the size of the content of the object
func (o *object) GetSize() (int64, error) {
	if o.item != nil {
		size, err := o.item.Size()
		if err == nil {
			return size, nil
		}
	}
	return -1, fail.Errorf("metadata item without size", nil)
}

// GetETag returns the value of the ETag (+/- md5sum of the content...)
func (o *object) GetETag() (string, error) {
	if o == nil {
		return "", fail.InvalidInstanceError()
	}

	if o.item != nil {
		etag, err := o.item.ETag()
		if err == nil {
			return etag, nil
		}
	}
	return "", fail.Errorf("metadata item without etag", nil)
}

// GetID ...
func (o *object) GetID() (string, error) {
	if o == nil {
		return "", fail.InvalidInstanceError()
	}

	if o.item != nil {
		return o.item.ID(), nil
	}

	return "", fail.Errorf("metadata item without id", nil)
}
