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

package operations

import (
	"bytes"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// folder describes a metadata folder
type folder struct {
	// path contains the base path where to read/write record in Object Storage
	path     string
	service  iaas.Service
	crypt    bool
	cryptKey *crypt.Key
}

// folderDecoderCallback is the prototype of the function that will decode data read from Metadata
type folderDecoderCallback func([]byte) fail.Error

// newFolder creates a new Metadata Folder object, ready to help access the metadata inside it
func newFolder(svc iaas.Service, path string) (folder, fail.Error) {
	if svc == nil {
		return folder{}, fail.InvalidInstanceError()
	}

	f := folder{
		path:    strings.Trim(path, "/"),
		service: svc,
	}

	cryptKey, xerr := svc.GetMetadataKey()
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return folder{}, xerr
		}
	} else {
		f.crypt = cryptKey != nil && len(cryptKey) > 0
		if f.crypt {
			f.cryptKey = cryptKey
		}
	}
	return f, nil
}

// IsNull tells if the folder instance should be considered as a null value
func (f *folder) IsNull() bool {
	return f == nil || f.service == nil
}

// GetService returns the service used by the folder
func (f folder) GetService() iaas.Service {
	if f.IsNull() {
		return iaas.NullService()
	}
	return f.service
}

// GetBucket returns the bucket used by the folder to store Object Storage
func (f folder) GetBucket() abstract.ObjectStorageBucket {
	if f.IsNull() {
		return abstract.ObjectStorageBucket{}
	}
	return f.service.GetMetadataBucket()
}

// getBucket is the same than GetBucket without instance validation (for internal use)
func (f folder) getBucket() abstract.ObjectStorageBucket {
	return f.service.GetMetadataBucket()
}

// Path returns the base path of the folder
func (f folder) Path() string {
	if f.IsNull() {
		return ""
	}
	return f.path
}

// absolutePath returns the fullpath to reach the 'path'+'name' starting from the folder path
func (f folder) absolutePath(path ...string) string {
	for len(path) > 0 && (path[0] == "" || path[0] == ".") {
		path = path[1:]
	}
	var relativePath string
	for _, item := range path {
		if item != "" {
			relativePath += "/" + item
		}
	}
	return strings.Join([]string{f.path, strings.Trim(relativePath, "/")}, "/")
}

// Lookup tells if the object named 'name' is inside the ObjectStorage folder
func (f folder) Lookup(path string, name string) fail.Error {
	if f.IsNull() {
		return fail.InvalidInstanceError()
	}

	absPath := strings.Trim(f.absolutePath(path), "/")
	list, xerr := f.service.ListObjects(f.getBucket().Name, absPath, objectstorage.NoPrefix)
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
func (f folder) Delete(path string, name string) fail.Error {
	if f.IsNull() {
		return fail.InvalidInstanceError()
	}

	if xerr := f.service.DeleteObject(f.getBucket().Name, f.absolutePath(path, name)); xerr != nil {
		return fail.Wrap(xerr, "failed to remove metadata in Object Storage")
	}
	return nil
}

// Read loads the content of the object stored in metadata bucket
// returns true, nil if the object has been found
// returns false, fail.Error if an error occured (including object not found)
// The callback function has to know how to decode it and where to store the result
func (f folder) Read(path string, name string, callback func([]byte) fail.Error) fail.Error {
	if f.IsNull() {
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
			return f.service.ReadObject(f.getBucket().Name, f.absolutePath(path, name), &buffer, 0, 0)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return fail.NotFoundError("failed to read '%s/%s' in Metadata Storage: %v", path, name, xerr)
	}

	data := buffer.Bytes()
	if f.crypt {
		var err error
		if data, err = crypt.Decrypt(data, f.cryptKey); err != nil {
			return fail.NotFoundError("failed to decrypt metadata '%s/%s': %v", path, name, err)
		}
	}

	if xerr = callback(data); xerr != nil {
		return fail.NotFoundError("failed to decode metadata '%s/%s': %v", path, name, xerr)
	}

	return nil
}

// Write writes the content in Object Storage, and check the write is committed.
// Returns nil on success (with assurance the write has been committed on remote side)
// May return fail.ErrTimeout if the read-after-write operation timed out.
// Return any other errors that can occur from the remote side
func (f folder) Write(path string, name string, content []byte) fail.Error {
	if f.IsNull() {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	var data []byte
	if f.crypt {
		var err error
		if data, err = crypt.Encrypt(content, f.cryptKey); err != nil {
			return fail.ToError(err)
		}
	} else {
		data = content
	}

	bucketName := f.getBucket().Name
	absolutePath := f.absolutePath(path, name)
	timeout := temporal.GetMetadataReadAfterWriteTimeout()

	// Outer retry will write the metadata at most 3 times
	xerr := retry.Action(
		func() error {
			var innerXErr fail.Error
			source := bytes.NewBuffer(data)
			// sourceHash := md5.New()
			// _, _ = sourceHash.Write(source.Bytes())
			// srcHex := hex.EncodeToString(sourceHash.Sum(nil))
			if _, innerXErr = f.service.WriteObject(bucketName, absolutePath, source, int64(source.Len()), nil); innerXErr != nil {
				return innerXErr
			}

			// inner retry does read-after-write; if timeout consider write has failed, then retry write
			var target bytes.Buffer
			innerXErr = retry.Action(
				func() error {
					// Read after write until the data is up-to-date (or timeout reached, considering the write as failed)
					if innerErr := f.service.ReadObject(bucketName, absolutePath, &target, 0, 0); innerErr != nil {
						return innerErr
					}

					if !bytes.Equal(data, target.Bytes()) {
						return fail.NewError("remote content is different from local reference")
					}

					return nil
				},
				retry.PrevailDone(retry.Unsuccessful(), retry.Timeout(timeout)),
				retry.Fibonacci(1*time.Second),
				nil,
				nil,
				func(t retry.Try, v verdict.Enum) {
					switch v { //nolint
					case verdict.Retry:
						logrus.Warnf("metadata '%s:%s' write not yet acknowledged: %s; retrying check...", bucketName, absolutePath, t.Err.Error())
					}
				},
			)
			if innerXErr != nil {
				switch innerXErr.(type) { //nolint
				case *retry.ErrTimeout:
					innerXErr = fail.Wrap(innerXErr.Cause(), "failed to acknowledge metadata '%s:%s' write after %s", bucketName, absolutePath, temporal.FormatDuration(timeout))
				}
			}
			return innerXErr
		},
		retry.PrevailDone(retry.Unsuccessful(), retry.Max(5)),
		retry.Constant(1*time.Second),
		nil,
		nil,
		func(t retry.Try, v verdict.Enum) {
			switch v { //nolint
			case verdict.Retry:
				logrus.Warnf("metadata '%s:%s' write not acknowledged after %s; considering write lost, retrying...", bucketName, absolutePath, temporal.FormatDuration(timeout))
			}
		},
	)
	if xerr != nil {
		switch xerr.(type) { //nolint
		case *retry.ErrStopRetry:
			xerr = fail.ToError(fail.Wrap(xerr.Cause(), "failed to acknowledge metadata '%s:%s'", bucketName, absolutePath))
		}
	}
	return xerr
}

// Browse browses the content of a specific path in Metadata and executes 'callback' on each entry
func (f folder) Browse(path string, callback folderDecoderCallback) fail.Error {
	if f.IsNull() {
		return fail.InvalidInstanceError()
	}

	absPath := f.absolutePath(path)
	metadataBucket := f.getBucket()
	list, xerr := f.service.ListObjects(metadataBucket.Name, absPath, objectstorage.NoPrefix)
	if xerr != nil {
		logrus.Errorf("Error browsing metadata: listing objects: %+v", xerr)
		return xerr
	}

	// If there is a single entry equals to absolute path, then there is nothing, it's an empty folder
	if len(list) == 1 && list[0] == absPath {
		return nil
	}

	var err error
	for _, i := range list {
		var buffer bytes.Buffer
		if xerr = f.service.ReadObject(metadataBucket.Name, i, &buffer, 0, 0); xerr != nil {
			logrus.Errorf("Error browsing metadata: reading from buffer: %+v", xerr)
			return xerr
		}

		data := buffer.Bytes()
		if f.crypt {
			if data, err = crypt.Decrypt(data, f.cryptKey); err != nil {
				return fail.ToError(err)
			}
		}
		if xerr = callback(data); xerr != nil {
			logrus.Errorf("Error browsing metadata: running callback: %+v", xerr)
			return xerr
		}
	}
	return nil
}
