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

package operations

import (
	"bytes"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/lib/utils/net"
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
func newFolder(svc iaas.Service, path string) (*folder, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidInstanceError()
	}

	f := &folder{
		path:    strings.Trim(path, "/"),
		service: svc,
	}

	cryptKey, xerr := svc.GetMetadataKey()
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return nil, xerr
		}
	} else {
		f.crypt = cryptKey != nil && len(cryptKey) > 0
		if f.crypt {
			f.cryptKey = cryptKey
		}
	}
	return f, nil
}

// IsNull ...
// satisfies interface data.NullValue
func (f *folder) IsNull() bool {
	return f == nil || f.service.IsNull()
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

// Search tells if the object named 'name' is inside the ObjectStorage folder
func (f folder) Search(path string, name string) fail.Error {
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
func (f *folder) Delete(path string, name string) fail.Error {
	if xerr := f.service.DeleteObject(f.getBucket().Name, f.absolutePath(path, name)); xerr != nil {
		return fail.Wrap(xerr, "failed to remove metadata in Object Storage")
	}
	return nil
}

// Read loads the content of the object stored in metadata bucket
// returns false, nil if the object is not found
// returns false, err if an error occured
// returns true, nil if the object has been found
// The callback function has to know how to decode it and where to store the result
func (f *folder) Read(path string, name string, callback func([]byte) fail.Error) fail.Error {
	xerr := f.Search(path, name)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); ok {
			return xerr
		}
		return fail.Wrap(xerr, "failed to search in Metadata Storage")
	}

	var buffer bytes.Buffer
	xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
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
		data, err = crypt.Decrypt(data, f.cryptKey)
		if err != nil {
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
func (f *folder) Write(path string, name string, content []byte) fail.Error {
	if f == nil {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	var data []byte
	if f.crypt {
		var err error
		data, err = crypt.Encrypt(content, f.cryptKey)
		if err != nil {
			return fail.ToError(err)
		}
	} else {
		data = content
	}

	bucketName := f.getBucket().Name
	absolutePath := f.absolutePath(path, name)
	source := bytes.NewBuffer(data)
	_, xerr := f.service.WriteObject(bucketName, absolutePath, source, int64(source.Len()), nil)
	if xerr != nil {
		return xerr
	}

	// Read after write until the data is up-to-date (or timeout reached, considering the write as failed)

	// FIXME: find a way to raise the delay at each turnm
	return retry.WhileUnsuccessfulDelay1Second(
		func() error {
			var target bytes.Buffer
			innerErr := f.service.ReadObject(bucketName, absolutePath, &target, 0, 0)
			if innerErr != nil {
				return innerErr
			}
			check := target.Bytes()
			if bytes.Compare(data, check) != 0 {
				return fail.NewError("remote content is different than source")
			}
			return nil
		},
		temporal.GetBigDelay(),
	)
}

// Browse browses the content of a specific path in Metadata and executes 'cb' on each entry
func (f *folder) Browse(path string, callback folderDecoderCallback) fail.Error {
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

	for _, i := range list {
		var buffer bytes.Buffer
		xerr = f.service.ReadObject(metadataBucket.Name, i, &buffer, 0, 0)
		if xerr != nil {
			logrus.Errorf("Error browsing metadata: reading from buffer: %+v", xerr)
			return xerr
		}
		data := buffer.Bytes()
		var err error
		if f.crypt {
			data, err = crypt.Decrypt(data, f.cryptKey)
			if err != nil {
				return fail.ToError(err)
			}
		}
		xerr = callback(data)
		if xerr != nil {
			logrus.Errorf("Error browsing metadata: running callback: %+v", xerr)
			return xerr
		}
	}
	return nil
}
