/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package metadata

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/model"

	"github.com/aws/aws-sdk-go/aws/awserr"
)

// Folder describes a metadata folder
type Folder struct {
	//path contains the base path where to read/write record in Object Storage
	path       string
	svc        api.ClientAPI
	bucketName string
	crypt      bool
	cryptKey   []byte
}

// FolderDecoderCallback is the prototype of the function that will decode data read from Metadata
type FolderDecoderCallback func([]byte) error

// NewFolder creates a new Metadata Folder object, ready to help access the metadata inside it
func NewFolder(svc api.ClientAPI, path string) *Folder {
	if svc == nil {
		panic("svc is nil!")
	}
	cfg, err := svc.GetCfgOpts()
	if err != nil {
		panic(fmt.Sprintf("config options are not available! %s", err.Error()))
	}
	name, found := cfg.Get("MetadataBucket")
	if !found {
		panic("config option 'MetadataBucket' is not set!")
	}
	cryptKey, crypt := cfg.Get("MetadataKey")
	f := &Folder{
		path:       strings.Trim(path, "/"),
		svc:        svc,
		bucketName: name.(string),
		crypt:      crypt,
	}
	if crypt {
		f.cryptKey = []byte(cryptKey.(string))
	}
	return f
}

// GetService returns the service used by the folder
func (f *Folder) GetService() api.ClientAPI {
	return f.svc
}

// GetPath returns the base path of the folder
func (f *Folder) GetPath() string {
	return f.path
}

// absolutePath returns the fullpath to reach the 'path'+'name' starting from the folder path
func (f *Folder) absolutePath(path ...string) string {
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
func (f *Folder) Search(path string, name string) (bool, error) {
	absPath := strings.Trim(f.absolutePath(path), "/")
	list, err := f.svc.ListObjects(f.bucketName, model.ObjectFilter{
		Path: absPath,
	})
	if err != nil {
		return false, err
	}
	if absPath != "" {
		absPath += "/"
	}
	found := false
	for _, item := range list {
		if item == absPath+name {
			found = true
			break
		}
	}
	return found, nil
}

// Delete removes metadata passed as parameter
func (f *Folder) Delete(path string, name string) error {
	err := f.svc.DeleteObject(f.bucketName, f.absolutePath(path, name))
	if err != nil {
		return fmt.Errorf("failed to remove metadata in Object Storage: %s", err.Error())
	}
	return nil
}

// Read loads the content of the object stored in metadata container
// returns false, nil if the object is not found
// returns false, err if an error occured
// returns true, nil if the object has been found
// The callback function has to know how to decode it and where to store the result
func (f *Folder) Read(path string, name string, callback FolderDecoderCallback) (bool, error) {
	found, err := f.Search(path, name)
	if err != nil {
		return false, err
	}
	if found {
		o, err := f.svc.GetObject(f.bucketName, f.absolutePath(path, name), nil)
		if err != nil {
			logrus.Errorf("Error reading metadata: getting object: %+v", err)
			return false, err
		}
		var buffer bytes.Buffer
		_, err = buffer.ReadFrom(o.Content)
		if err != nil {
			return false, err
		}
		data := buffer.Bytes()
		if f.crypt {
			data, err = decrypt(f.cryptKey, data)
			if err != nil {
				return false, err
			}
		}
		return true, callback(data)
	}
	return false, nil
}

// Write writes the content in Object Storage
func (f *Folder) Write(path string, name string, content []byte) error {
	var (
		data []byte
		err  error
	)

	if f.crypt {
		data, err = encrypt(f.cryptKey, content)
		if err != nil {
			return err
		}
	} else {
		data = content
	}

	return f.svc.PutObject(f.bucketName, model.Object{
		Name:    f.absolutePath(path, name),
		Content: bytes.NewReader(data),
	})
}

// Browse browses the content of a specific path in Metadata and executes 'cb' on each entry
func (f *Folder) Browse(path string, callback FolderDecoderCallback) error {
	list, err := f.svc.ListObjects(f.bucketName, model.ObjectFilter{
		Path: strings.Trim(f.absolutePath(path), "/"),
	})
	if err != nil {
		//TODO: AWS adherance, to be changed !!!
		// If bucket not found, return nil; no item will be processed, meaning empty path
		if awsError, ok := err.(awserr.RequestFailure); ok {
			if awsError.StatusCode() == 404 {
				return nil
			}
		}
		logrus.Errorf("Error browsing metadata: listing objects: %+v", err)
		return err
	}

	for _, i := range list {
		o, err := f.svc.GetObject(f.bucketName, i, nil)
		if err != nil {
			logrus.Errorf("Error browsing metadata: getting object: %+v", err)
			return err
		}
		var buffer bytes.Buffer
		_, err = buffer.ReadFrom(o.Content)
		if err != nil {
			logrus.Errorf("Error browsing metadata: reading from buffer: %+v", err)
			return err
		}
		data := buffer.Bytes()
		if f.crypt {
			data, err = decrypt(f.cryptKey, data)
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
