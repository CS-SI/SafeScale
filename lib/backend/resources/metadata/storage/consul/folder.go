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

package consul

import (
	"bytes"
	"context"
	"strings"
	"time"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/consul/consumer"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata/storage"
	"github.com/CS-SI/SafeScale/v22/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// folder describes a metadata folder
type folder struct {
	// path contains the base path where to read/write record in Object Storage
	path     string
	job      jobapi.Job
	kv       *consumer.KV
	crypt    bool
	cryptKey *crypt.Key
}

// NewFolder creates a new Metadata folder object, ready to help access the metadata inside it
func NewFolder(job jobapi.Job, path string) (*folder, fail.Error) {
	if valid.IsNull(job) {
		return nil, fail.InvalidInstanceError()
	}

	f := &folder{
		path: strings.Trim(path, "/"),
		job:  job,
		kv:   job.Scope().ConsulKV(),
	}

	// FIXME: consul not yet able to crypt
	// cryptKey, xerr := svc.GetMetadataKey()
	// xerr = debug.InjectPlannedFail(xerr)
	// if xerr != nil {
	// 	if _, ok := xerr.(*fail.ErrNotFound); !ok || valid.IsNil(xerr) {
	// 		return &folder{}, xerr
	// 	}
	// } else {
	// 	f.crypt = cryptKey != nil && len(cryptKey) > 0
	// 	if f.crypt {
	// 		f.cryptKey = cryptKey
	// 	}
	// }
	return f, nil
}

// IsNull tells if the folder instance should be considered as a null value
func (instance *folder) IsNull() bool {
	return instance == nil || valid.IsNull(instance.job)
}

// Service returns the service used by the folder
func (instance folder) Service() iaasapi.Service {
	if valid.IsNull(instance) {
		return nil
	}

	return instance.job.Service()
}

// Job returns the job of the folder
func (instance *folder) Job() jobapi.Job {
	if valid.IsNull(instance) {
		return nil
	}

	return instance.job
}

// Prefix returns the base path of the folder
func (instance folder) Prefix() string {
	return instance.path
}

// absolutePath returns the full path to reach the 'path'
func (instance folder) absolutePath(path ...string) string {
	return storage.AbsolutePath(instance.path, "/", path...)
}

// relativePath returns the relative path from folder
func (instance folder) relativePath(path ...string) string {
	return strings.Join(path, "/")
}

// Lookup tells if the object named 'name' is inside the folder
func (instance folder) Lookup(ctx context.Context, path string, name string) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	absPath := strings.Trim(instance.absolutePath(path, name), "/")
	_, xerr := instance.kv.Get(ctx, absPath)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return fail.NotFoundError("failed to find entry '%s' in folder")
		}
		return xerr
	}

	if absPath != "" {
		absPath += "/"
	}
	fullPath := absPath + name

	list, xerr := instance.kv.List(ctx, fullPath)
	if xerr != nil {
		return xerr
	}

	for _, item := range list {
		if item.Key == fullPath {
			return nil
		}
	}

	return fail.NotFoundError("failed to find metadata '%s'", fullPath)
}

// Delete removes metadata passed as parameter
func (instance folder) Delete(ctx context.Context, path string, name string) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	xerr := instance.kv.Delete(ctx, instance.absolutePath(path, name))
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to remove metadata in Storage")
	}

	return nil
}

// Read loads the content of the object stored in metadata bucket
// returns true, nil if the object has been found
// returns false, fail.Error if an error occurred (including object not found)
// The callback function has to know how to decode it and where to store the result
func (instance folder) Read(ctx context.Context, path string, name string, callback storage.FolderCallback, opts ...options.Option) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if name = strings.TrimSpace(name); name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	o, xerr := options.New(opts...)
	if xerr != nil {
		return xerr
	}
	_ = o

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	var read []byte
	fullPath := instance.absolutePath(path, name)
	xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			var innerXErr fail.Error
			read, innerXErr = instance.kv.Get(ctx, fullPath)
			if xerr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					return retry.StopRetryError(innerXErr)
				default:
					return innerXErr
				}
			}

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

	// doCrypt := instance.determineIfCryptIsEnabledInOptions(o)
	// if xerr != nil {
	//  return xerr
	// }
	// datas := goodBuffer.Bytes()
	// if doCrypt {
	// 	decrypted, err := crypt.Decrypt(datas, instance.cryptKey)
	// 	err = debug.InjectPlannedError(err)
	// 	if err != nil {
	// 		return fail.NotFoundError("failed to decrypt metadata '%s/%s': %v", path, name, err)
	// 	}
	// 	datas = decrypted
	// }

	// xerr = callback(datas)
	xerr = callback(read)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.NotFoundError("failed to decode metadata '%s': %v", fullPath, xerr)
	}

	return nil
}

func (instance *folder) determineIfCryptIsEnabled(opts options.Options) (bool, fail.Error) {
	if !instance.crypt {
		return false, nil
	}

	enabled, xerr := storage.DetermineIfCryptIsEnabledInOptions(opts)
	if xerr != nil {
		return false, xerr
	}

	return enabled, nil
}

// Write writes the content in Object Storage, and check the write operation is committed.
// Returns nil on success (with assurance the write operation has been committed on remote side)
// May return fail.ErrTimeout if the read-after-write operation timed out.
// Return any other errors that can occur from the remote side
func (instance folder) Write(ctx context.Context, path string, name string, content []byte, opts ...options.Option) fail.Error {
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

	// FIXME: no crypt in consul yet
	// doCrypt := instance.determineIfCryptIsEnabledInOptions(o)
	// if xerr != nil {
	//  return xerr
	// }
	var data []byte
	// if doCrypt {
	// 	var err error
	// 	data, err = crypt.Encrypt(content, instance.cryptKey)
	// 	err = debug.InjectPlannedError(err)
	// 	if err != nil {
	// 		return fail.ConvertError(err)
	// 	}
	// } else {
	data = content
	// }

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
			innerXErr = instance.kv.Put(ctx, absolutePath, data)
			if innerXErr != nil {
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

					// Read after write until the data is up-to-date (or timeout reached, considering the write as failed)
					target, readXErr := instance.kv.Get(ctx, absolutePath)
					if readXErr != nil {
						logrus.WithContext(ctx).Warn(readXErr.Error())
						return readXErr
					}

					if !bytes.Equal(data, target) {
						cmpXErr := fail.NewError("remote content is different from local reference")
						logrus.WithContext(ctx).Warn(cmpXErr.Error())
						return cmpXErr
					}

					return nil
				},
				retry.PrevailDone(retry.Unsuccessful(), retry.Timeout(timeout), retry.Max(3)),
				retry.Linear(timings.SmallDelay()),
				nil,
				nil,
				func(t retry.Try, v verdict.Enum) {
					switch v { // nolint
					case verdict.Retry:
						logrus.WithContext(ctx).Warnf("metadata '%s' write not yet acknowledged: %s; retrying check...", absolutePath, t.Err.Error())
					}
				},
			)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *retry.ErrStopRetry:
					return fail.Wrap(innerXErr.Cause(), "stopping retries")
				case *retry.ErrTimeout:
					return fail.Wrap(innerXErr.Cause(), "failed to acknowledge metadata '%s' write after %s", absolutePath, temporal.FormatDuration(timeout))
				default:
					return innerXErr
				}
			}
			return nil
		},
		retry.PrevailDone(retry.Unsuccessful(), retry.Max(3)),
		retry.Constant(0),
		nil,
		nil,
		func(t retry.Try, v verdict.Enum) {
			switch v { // nolint
			case verdict.Retry:
				logrus.WithContext(ctx).Warnf("metadata '%s' write not acknowledged after %s; considering write lost, retrying...", absolutePath, temporal.FormatDuration(time.Since(readAfterWrite)))
			}
		},
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			return fail.Wrap(xerr.Cause(), "timeout")
		case *retry.ErrStopRetry:
			return fail.Wrap(xerr.Cause(), "failed to acknowledge metadata '%s'", absolutePath)
		default:
			return xerr
		}
	}

	if iterations > 1 {
		logrus.WithContext(ctx).Warnf("Read after write of '%s' acknowledged after %s and %d iterations and %d reads", absolutePath, time.Since(readAfterWrite), iterations, innerIterations)
	} else {
		logrus.WithContext(ctx).Debugf("Read after write of '%s' acknowledged after %s and %d iterations and %d reads", absolutePath, time.Since(readAfterWrite), iterations, innerIterations)
	}

	return nil
}

// AbsolutePath returns the full path to reach the 'path'+'name' starting from the folder path
func (instance folder) AbsolutePath(path ...string) string {
	return storage.AbsolutePath(instance.path, "/", path...)
}

// Browse browses the content of a specific path in Metadata and executes 'callback' on each entry
func (instance folder) Browse(ctx context.Context, path string, callback storage.FolderCallback) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	absolutePath := instance.absolutePath(path)

	list, xerr := instance.kv.List(ctx, absolutePath)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "Error browsing metadata: listing objects")
	}

	for _, i := range list {
		key := strings.Trim(i.Key, "/")
		if key == absolutePath {
			continue
		}

		read, xerr := instance.kv.Get(ctx, key)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "Error browsing metadata: reading from buffer")
		}

		// FIXME: no crypt in consul yet
		// if instance.crypt {
		// 	data, err = crypt.Decrypt(data, instance.cryptKey)
		// 	err = debug.InjectPlannedError(err)
		// 	if err != nil {
		// 		return fail.Wrap(fail.ConvertError(err), "Error browsing metadata: decrypting data")
		// 	}
		// }
		// xerr = callback(data)
		xerr = callback(read)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "Error browsing metadata: running callback")
		}
	}
	return nil
}
