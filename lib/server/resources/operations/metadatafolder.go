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

package operations

import (
	"bytes"
	"strings"
	"time"

	datadef "github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"

	"github.com/CS-SI/SafeScale/v21/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v21/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/v21/lib/utils/net"
	"github.com/CS-SI/SafeScale/v21/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v21/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/v21/lib/utils/temporal"
)

// MetadataFolder describes a metadata MetadataFolder
type MetadataFolder struct {
	// path contains the base path where to read/write record in Object Storage
	path     string
	service  iaas.Service
	crypt    bool
	cryptKey *crypt.Key
}

// folderDecoderCallback is the prototype of the function that will decode data read from Metadata
type folderDecoderCallback func([]byte) fail.Error

// NewMetadataFolder creates a new Metadata MetadataFolder object, ready to help access the metadata inside it
func NewMetadataFolder(svc iaas.Service, path string) (MetadataFolder, fail.Error) {
	if svc == nil {
		return MetadataFolder{}, fail.InvalidInstanceError()
	}

	f := MetadataFolder{
		path:    strings.Trim(path, "/"),
		service: svc,
	}

	cryptKey, xerr := svc.GetMetadataKey()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok || xerr.IsNull() {
			return MetadataFolder{}, xerr
		}
		debug.IgnoreError(xerr)
	} else {
		f.crypt = cryptKey != nil && len(cryptKey) > 0
		if f.crypt {
			f.cryptKey = cryptKey
		}
	}
	return f, nil
}

// IsNull tells if the MetadataFolder instance should be considered as a null value
func (instance *MetadataFolder) IsNull() bool {
	return instance == nil || instance.service == nil
}

// Service returns the service used by the MetadataFolder
func (instance MetadataFolder) Service() iaas.Service {
	if instance.IsNull() {
		return iaas.NullService()
	}
	return instance.service
}

// GetBucket returns the bucket used by the MetadataFolder to store Object Storage
func (instance MetadataFolder) GetBucket() (abstract.ObjectStorageBucket, fail.Error) {
	if instance.IsNull() {
		return abstract.ObjectStorageBucket{}, nil
	}

	bucket, xerr := instance.service.GetMetadataBucket()
	if xerr != nil {
		return abstract.ObjectStorageBucket{}, xerr
	}

	return bucket, nil
}

// getBucket is the same as GetBucket without instance validation (for internal use)
func (instance MetadataFolder) getBucket() (abstract.ObjectStorageBucket, fail.Error) {
	bucket, xerr := instance.service.GetMetadataBucket()
	if xerr != nil {
		return abstract.ObjectStorageBucket{}, xerr
	}
	return bucket, nil
}

// Path returns the base path of the MetadataFolder
func (instance MetadataFolder) Path() string {
	if instance.IsNull() {
		return ""
	}
	return instance.path
}

// absolutePath returns the full path to reach the 'path'+'name' starting from the MetadataFolder path
func (instance MetadataFolder) absolutePath(path ...string) string {
	for len(path) > 0 && (path[0] == "" || path[0] == ".") {
		path = path[1:]
	}
	var relativePath string
	for _, item := range path {
		if item != "" && item != "/" {
			relativePath += "/" + item
		}
	}
	relativePath = strings.Trim(relativePath, "/")
	if relativePath != "" {
		absolutePath := strings.ReplaceAll(relativePath, "//", "/")
		if instance.path != "" {
			absolutePath = instance.path + "/" + relativePath
			absolutePath = strings.ReplaceAll(absolutePath, "//", "/")
		}
		return absolutePath
	}
	return instance.path
}

// Lookup tells if the object named 'name' is inside the ObjectStorage MetadataFolder
func (instance MetadataFolder) Lookup(path string, name string) fail.Error {
	if instance.IsNull() {
		return fail.InvalidInstanceError()
	}

	absPath := strings.Trim(instance.absolutePath(path), "/")
	bucket, xerr := instance.getBucket()
	if xerr != nil {
		return xerr
	}

	list, xerr := instance.service.ListObjects(bucket.Name, absPath, objectstorage.NoPrefix)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if absPath != "" {
		absPath += "/"
	}
	fullPath := absPath + name
	for _, item := range list {
		if item == fullPath {
			return nil
		}
	}
	return fail.NotFoundError("failed to find metadata '%s'", fullPath)
}

// Delete removes metadata passed as parameter
func (instance MetadataFolder) Delete(path string, name string) fail.Error {
	if instance.IsNull() {
		return fail.InvalidInstanceError()
	}

	bucket, xerr := instance.getBucket()
	if xerr != nil {
		return xerr
	}

	xerr = instance.service.DeleteObject(bucket.Name, instance.absolutePath(path, name))
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to remove metadata in Object Storage")
	}
	return nil
}

// Read loads the content of the object stored in metadata bucket
// returns true, nil if the object has been found
// returns false, fail.Error if an error occurred (including object not found)
// The callback function has to know how to decode it and where to store the result
func (instance MetadataFolder) Read(path string, name string, callback func([]byte) fail.Error, options ...datadef.ImmutableKeyValue) fail.Error {
	if instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if name = strings.TrimSpace(name); name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	var buffer bytes.Buffer
	xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			bucket, iErr := instance.getBucket()
			if iErr != nil {
				return iErr
			}
			return instance.service.ReadObject(bucket.Name, instance.absolutePath(path, name), &buffer, 0, 0)
		},
		instance.service.Timings().CommunicationTimeout(),
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			return fail.Wrap(xerr.Cause(), "timeout")
		case *retry.ErrStopRetry:
			return fail.Wrap(xerr.Cause(), "stopping retries")
		default:
			return fail.Wrap(xerr, "failed to read '%s/%s' in Metadata Storage", path, name)
		}
	}

	doCrypt := instance.crypt
	for _, v := range options {
		switch v.Key() {
		case "doNotCrypt":
			anon := v.Value()
			if anon != nil {
				switch c := anon.(type) {
				case bool:
					doCrypt = !c
				case string:
					switch c {
					case "true", "yes":
						doCrypt = false
					case "false", "no":
						doCrypt = true
					}
				}
			}
		default:
		}
	}
	datas := buffer.Bytes()
	if doCrypt {
		var err error
		datas, err = crypt.Decrypt(datas, instance.cryptKey)
		err = debug.InjectPlannedError(err)
		if err != nil {
			return fail.NotFoundError("failed to decrypt metadata '%s/%s': %v", path, name, err)
		}
	}

	xerr = callback(datas)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.NotFoundError("failed to decode metadata '%s/%s': %v", path, name, xerr)
	}

	return nil
}

// Write writes the content in Object Storage, and check the write is committed.
// Returns nil on success (with assurance the write has been committed on remote side)
// May return fail.ErrTimeout if the read-after-write operation timed out.
// Return any other errors that can occur from the remote side
func (instance MetadataFolder) Write(path string, name string, content []byte, options ...datadef.ImmutableKeyValue) fail.Error {
	if instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	doCrypt := instance.crypt
	for _, v := range options {
		switch v.Key() {
		case "doNotCrypt":
			doCrypt = !v.Value().(bool)
		default:
		}
	}
	var data []byte
	if doCrypt {
		var err error
		data, err = crypt.Encrypt(content, instance.cryptKey)
		err = debug.InjectPlannedError(err)
		if err != nil {
			return fail.ConvertError(err)
		}
	} else {
		data = content
	}

	bucket, xerr := instance.getBucket()
	if xerr != nil {
		return xerr
	}

	bucketName := bucket.Name
	absolutePath := instance.absolutePath(path, name)
	timeout := instance.service.Timings().MetadataReadAfterWriteTimeout()

	// Outer retry will write the metadata at most 3 times
	xerr = retry.Action(
		func() error {
			var innerXErr fail.Error
			source := bytes.NewBuffer(data)
			// sourceHash := md5.New()
			// _, _ = sourceHash.Write(source.Bytes())
			// srcHex := hex.EncodeToString(sourceHash.Sum(nil))
			if _, innerXErr = instance.service.WriteObject(bucketName, absolutePath, source, int64(source.Len()), nil); innerXErr != nil {
				return innerXErr
			}

			// inner retry does read-after-write; if timeout consider write has failed, then retry write
			var target bytes.Buffer
			innerXErr = retry.Action(
				func() error {
					// Read after write until the data is up-to-date (or timeout reached, considering the write as failed)
					if innerErr := instance.service.ReadObject(bucketName, absolutePath, &target, 0, 0); innerErr != nil {
						return innerErr
					}

					if !bytes.Equal(data, target.Bytes()) {
						return fail.NewError("remote content is different from local reference")
					}

					return nil
				},
				retry.PrevailDone(retry.Unsuccessful(), retry.Timeout(timeout)),
				retry.Fibonacci(instance.service.Timings().SmallDelay()),
				nil,
				nil,
				func(t retry.Try, v verdict.Enum) {
					switch v { // nolint
					case verdict.Retry:
						logrus.Warnf("metadata '%s:%s' write not yet acknowledged: %s; retrying check...", bucketName, absolutePath, t.Err.Error())
					}
				},
			)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *retry.ErrStopRetry:
					return fail.Wrap(innerXErr.Cause(), "stopping retries")
				case *retry.ErrTimeout:
					return fail.Wrap(innerXErr.Cause(), "failed to acknowledge metadata '%s:%s' write after %s", bucketName, absolutePath, temporal.FormatDuration(timeout))
				default:
					return innerXErr
				}
			}
			return nil
		},
		retry.PrevailDone(retry.Unsuccessful(), retry.Max(5)),
		retry.Constant(instance.service.Timings().SmallDelay()),
		nil,
		nil,
		func(t retry.Try, v verdict.Enum) {
			switch v { // nolint
			case verdict.Retry:
				logrus.Warnf("metadata '%s:%s' write not acknowledged after %s; considering write lost, retrying...", bucketName, absolutePath, temporal.FormatDuration(timeout+30*time.Second))
			}
		},
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			return fail.Wrap(xerr.Cause(), "timeout")
		case *retry.ErrStopRetry:
			return fail.Wrap(xerr.Cause(), "failed to acknowledge metadata '%s:%s'", bucketName, absolutePath)
		default:
			return xerr
		}
	}
	return nil
}

// Browse browses the content of a specific path in Metadata and executes 'callback' on each entry
func (instance MetadataFolder) Browse(path string, callback folderDecoderCallback) fail.Error {
	if instance.IsNull() {
		return fail.InvalidInstanceError()
	}

	absPath := instance.absolutePath(path)
	metadataBucket, xerr := instance.getBucket()
	if xerr != nil {
		return xerr
	}

	list, xerr := instance.service.ListObjects(metadataBucket.Name, absPath, objectstorage.NoPrefix)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "Error browsing metadata: listing objects")
	}

	// If there is a single entry equals to absolute path, then there is nothing, it's an empty MetadataFolder
	if len(list) == 1 && strings.Trim(list[0], "/") == absPath {
		return nil
	}

	var err error
	for _, i := range list {
		i = strings.Trim(i, "/")
		if i == absPath {
			continue
		}
		var buffer bytes.Buffer
		xerr = instance.service.ReadObject(metadataBucket.Name, i, &buffer, 0, 0)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "Error browsing metadata: reading from buffer")
		}

		data := buffer.Bytes()
		if instance.crypt {
			data, err = crypt.Decrypt(data, instance.cryptKey)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return fail.Wrap(fail.ConvertError(err), "Error browsing metadata: decrypting data")
			}
		}
		xerr = callback(data)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "Error browsing metadata: running callback")
		}
	}
	return nil
}
