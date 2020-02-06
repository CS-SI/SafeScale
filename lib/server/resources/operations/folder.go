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

package payloads

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// folder describes a metadata folder
type folder struct {
	//path contains the base path where to read/write record in Object Storage
	path     string
	service  iaas.Service
	crypt    bool
	cryptKey *crypt.Key
}

// folderDecoderCallback is the prototype of the function that will decode data read from Metadata
type folderDecoderCallback func([]byte) error

// newFolder creates a new Metadata Folder object, ready to help access the metadata inside it
func newFolder(svc iaas.Service, path string) (*folder, error) {
	if svc == nil {
		return nil, scerr.InvalidInstanceError()
	}

	cryptKey := svc.GetMetadataKey()
	crypt := cryptKey != nil && len(cryptKey) > 0
	f := &folder{
		path:    strings.Trim(path, "/"),
		service: svc,
		crypt:   crypt,
	}
	if crypt {
		f.cryptKey = cryptKey
	}
	return f, nil
}

// Service returns the service used by the folder
func (f *folder) Service() iaas.Service {
	return f.service
}

// Bucket returns the bucket used by the folder to store Object Storage
func (f *folder) Bucket() objectstorage.Bucket {
	return f.service.GetMetadataBucket()
}

// Path returns the base path of the folder
func (f *folder) Path() string {
	return f.path
}

// absolutePath returns the fullpath to reach the 'path'+'name' starting from the folder path
func (f *folder) absolutePath(path ...string) string {
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
func (f *folder) Search(path string, name string) error {
	absPath := strings.Trim(f.absolutePath(path), "/")
	list, err := f.service.GetMetadataBucket().List(absPath, objectstorage.NoPrefix)
	if err != nil {
		return err
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
	return scerr.NotFoundError(fmt.Sprintf("failed to find '%s'", fullPath))
}

// Delete removes metadata passed as parameter
func (f *folder) Delete(path string, name string) error {
	err := f.service.GetMetadataBucket().DeleteObject(f.absolutePath(path, name))
	if err != nil {
		return scerr.Wrap(err, "failed to remove metadata in Object Storage")
	}
	return nil
}

// Read loads the content of the object stored in metadata bucket
// returns false, nil if the object is not found
// returns false, err if an error occured
// returns true, nil if the object has been found
// The callback function has to know how to decode it and where to store the result
func (f *folder) Read(path string, name string, callback folderDecoderCallback) error {
	err := f.Search(path, name)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			return err
		}
		return scerr.Wrap(err, "failed to search in Metadata Storage")
	}

	var buffer bytes.Buffer
	_, err = f.service.GetMetadataBucket().ReadObject(f.absolutePath(path, name), &buffer, 0, 0)
	if err != nil {
		return scerr.NotFoundError(fmt.Sprintf("failed to read '%s/%s' in Metadata Storage: %v", path, name, err))
	}
	data := buffer.Bytes()
	if f.crypt {
		data, err = crypt.Decrypt(data, f.cryptKey)
		if err != nil {
			return scerr.NotFoundError(fmt.Sprintf("failed to decrypt metadata '%s/%s': %v", path, name, err))
		}
	}
	err = callback(data)
	if err != nil {
		return scerr.NotFoundError(fmt.Sprintf("failed to decode metadata '%s/%s': %v", path, name, err))
	}
	return nil
}

// Write writes the content in Object Storage
func (f *folder) Write(path string, name string, content []byte) error {
	if f == nil {
		return scerr.InvalidInstanceError()
	}
	if name == "" {
		return scerr.InvalidParameterError("name", "cannot be empty string")
	}

	var (
		data []byte
		err  error
	)

	if f.crypt {
		data, err = crypt.Encrypt(content, f.cryptKey)
		if err != nil {
			return err
		}
	} else {
		data = content
	}

	source := bytes.NewBuffer(data)
	_, err = f.service.GetMetadataBucket().WriteObject(f.absolutePath(path, name), source, int64(source.Len()), nil)
	return err
}

// Browse browses the content of a specific path in Metadata and executes 'cb' on each entry
func (f *folder) Browse(path string, callback folderDecoderCallback) error {
	list, err := f.service.GetMetadataBucket().List(f.absolutePath(path), objectstorage.NoPrefix)
	if err != nil {
		logrus.Errorf("Error browsing metadata: listing objects: %+v", err)
		return err
	}

	for _, i := range list {
		var buffer bytes.Buffer
		_, err = f.service.GetMetadataBucket().ReadObject(i, &buffer, 0, 0)
		if err != nil {
			logrus.Errorf("Error browsing metadata: reading from buffer: %+v", err)
			return err
		}
		data := buffer.Bytes()
		if f.crypt {
			data, err = crypt.Decrypt(data, f.cryptKey)
			if err != nil {
				return err
			}
		}
		err = callback(data)
		if err != nil {
			logrus.Errorf("Error browsing metadata: running callback: %+v", err)
			return err
		}
	}
	return nil
}
