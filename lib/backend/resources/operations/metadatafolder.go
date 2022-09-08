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
	"context"
	"strings"
	"time"

	datadef "github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
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
		if _, ok := xerr.(*fail.ErrNotFound); !ok || valid.IsNil(xerr) {
			return MetadataFolder{}, xerr
		}
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
	return instance.service
}

// GetBucket returns the bucket used by the MetadataFolder to store Object Storage
func (instance MetadataFolder) GetBucket(ctx context.Context) (abstract.ObjectStorageBucket, fail.Error) {
	if valid.IsNil(instance) {
		return abstract.ObjectStorageBucket{}, fail.InvalidInstanceError()
	}

	bucket, xerr := instance.service.GetMetadataBucket(ctx)
	if xerr != nil {
		return abstract.ObjectStorageBucket{}, xerr
	}

	return bucket, nil
}

// getBucket is the same as GetBucket without instance validation (for internal use)
func (instance MetadataFolder) getBucket(ctx context.Context) (abstract.ObjectStorageBucket, fail.Error) {
	bucket, xerr := instance.service.GetMetadataBucket(ctx)
	if xerr != nil {
		return abstract.ObjectStorageBucket{}, xerr
	}
	return bucket, nil
}

// Path returns the base path of the MetadataFolder
func (instance MetadataFolder) Path() string {
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
func (instance MetadataFolder) Lookup(ctx context.Context, path string, name string) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	absPath := strings.Trim(instance.absolutePath(path), "/")
	bucket, xerr := instance.getBucket(ctx)
	if xerr != nil {
		return xerr
	}

	list, xerr := instance.service.ListObjects(ctx, bucket.Name, absPath, objectstorage.NoPrefix)
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
func (instance MetadataFolder) Delete(ctx context.Context, path string, name string) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	bucket, xerr := instance.getBucket(ctx)
	if xerr != nil {
		return xerr
	}

	has, xerr := instance.service.HasObject(ctx, bucket.Name, instance.absolutePath(path, name))
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to remove metadata in Object Storage")
	}
	if !has {
		return nil
	}

	xerr = instance.service.DeleteObject(ctx, bucket.Name, instance.absolutePath(path, name))
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
func (instance MetadataFolder) Read(ctx context.Context, path string, name string, callback func([]byte) fail.Error, options ...datadef.ImmutableKeyValue) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if name = strings.TrimSpace(name); name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	var goodBuffer bytes.Buffer
	xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			var buffer bytes.Buffer
			bucket, iErr := instance.getBucket(ctx)
			if iErr != nil {
				return iErr
			}
			iErr = instance.service.ReadObject(ctx, bucket.Name, instance.absolutePath(path, name), &buffer, 0, 0)
			if iErr != nil {
				switch iErr.(type) {
				case *fail.ErrNotFound:
					return retry.StopRetryError(iErr, "does NOT exist")
				default:
					_ = instance.service.InvalidateObject(ctx, bucket.Name, instance.absolutePath(path, name))
					return iErr
				}
			}
			goodBuffer = buffer
			return nil
		},
		timings.CommunicationTimeout(),
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

	datas := goodBuffer.Bytes()
	if doCrypt {
		decrypted, err := crypt.Decrypt(datas, instance.cryptKey)
		err = debug.InjectPlannedError(err)
		if err != nil {
			return fail.NotFoundError("failed to decrypt metadata '%s/%s': %v", path, name, err)
		}
		datas = decrypted
	}

	xerr = callback(datas)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.NotFoundError("failed to decode metadata '%s/%s': %v", path, name, xerr)
	}

	return nil
}

// Write writes the content in Object Storage, and check the write operation is committed.
// Returns nil on success (with assurance the write operation has been committed on remote side)
// May return fail.ErrTimeout if the read-after-write operation timed out.
// Return any other errors that can occur from the remote side
func (instance MetadataFolder) Write(ctx context.Context, path string, name string, content []byte, options ...datadef.ImmutableKeyValue) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
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

	bucket, xerr := instance.getBucket(ctx)
	if xerr != nil {
		return xerr
	}

	bucketName := bucket.Name
	absolutePath := instance.absolutePath(path, name)
	timeout := timings.MetadataReadAfterWriteTimeout()

	readAfterWrite := time.Now()
	iterations := 0
	innerIterations := 0

	// Outer retry will write the metadata at most 3 times
	xerr = retry.Action(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			iterations++

			var innerXErr fail.Error
			source := bytes.NewBuffer(data)
			if _, innerXErr = instance.service.WriteObject(ctx, bucketName, absolutePath, source, int64(source.Len()), nil); innerXErr != nil {
				return innerXErr
			}

			// inner retry does read-after-write; if timeout consider write has failed, then retry write
			innerXErr = retry.Action(
				func() error {
					select {
					case <-ctx.Done():
						return retry.StopRetryError(ctx.Err())
					default:
					}

					innerIterations++

					var target bytes.Buffer
					// Read after write until the data is up-to-date (or timeout reached, considering the write as failed)
					if innerErr := instance.service.ReadObject(ctx, bucketName, absolutePath, &target, 0, int64(source.Len())); innerErr != nil {
						_ = instance.service.InvalidateObject(ctx, bucketName, absolutePath)
						logrus.WithContext(ctx).Warnf(innerErr.Error())
						return innerErr
					}

					if !bytes.Equal(data, target.Bytes()) {
						_ = instance.service.InvalidateObject(ctx, bucketName, absolutePath)
						innerErr := fail.NewError("remote content is different from local reference")
						logrus.WithContext(ctx).Warnf(innerErr.Error())
						return innerErr
					}

					return nil
				},
				retry.PrevailDone(retry.Unsuccessful(), retry.Timeout(timeout), retry.Max(15)),
				retry.Linear(timings.SmallDelay()),
				nil,
				nil,
				func(t retry.Try, v verdict.Enum) {
					switch v { // nolint
					case verdict.Retry:
						logrus.WithContext(ctx).Warnf("metadata '%s:%s' write not yet acknowledged: %s; retrying check...", bucketName, absolutePath, t.Err.Error())
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
		retry.PrevailDone(retry.Unsuccessful(), retry.Max(15)),
		retry.Constant(0),
		nil,
		nil,
		func(t retry.Try, v verdict.Enum) {
			switch v { // nolint
			case verdict.Retry:
				logrus.WithContext(ctx).Warnf("metadata '%s:%s' write not acknowledged after %s; considering write lost, retrying...", bucketName, absolutePath, temporal.FormatDuration(time.Since(readAfterWrite)))
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

	if iterations > 1 {
		logrus.WithContext(ctx).Warnf("Read after write of '%s:%s' acknowledged after %s and %d iterations and %d reads", bucketName, absolutePath, time.Since(readAfterWrite), iterations, innerIterations)
	}

	return nil
}

// Browse browses the content of a specific path in Metadata and executes 'callback' on each entry
func (instance MetadataFolder) Browse(ctx context.Context, path string, callback folderDecoderCallback) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	absPath := instance.absolutePath(path)
	metadataBucket, xerr := instance.getBucket(ctx)
	if xerr != nil {
		return xerr
	}

	list, xerr := instance.service.ListObjects(ctx, metadataBucket.Name, absPath, objectstorage.NoPrefix)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "Error browsing metadata: listing objects")
	}

	// If there is a single entry equals to absolute path, then there is nothing, it's an empty MetadataFolder
	if len(list) == 1 && strings.Trim(list[0], "/") == absPath {
		return nil
	}

	for _, i := range list {
		var err error
		i = strings.Trim(i, "/")
		if i == absPath {
			continue
		}
		var buffer bytes.Buffer
		xerr = instance.service.ReadObject(ctx, metadataBucket.Name, i, &buffer, 0, 0)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			_ = instance.service.InvalidateObject(ctx, metadataBucket.Name, i)
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
