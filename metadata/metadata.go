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
	"encoding/gob"
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/utils"

	"github.com/aws/aws-sdk-go/aws/awserr"
)

const (
	//ContainerName is the name of the Object Storage Container/Bucket used to store metadata
	ContainerName string = "0.safescale"
)

//InitializeContainer creates the Object Storage Container/Bucket that will store the metadata
func InitializeContainer(client api.ClientAPI) error {
	svc := providers.FromClient(client)
	err := svc.CreateContainer(ContainerName)
	if err != nil {
		fmt.Printf("failed to create Object Container %s: %s\n", ContainerName, err.Error())
	}
	return err
}

//Folder describes a metadata folder
type Folder struct {
	//path contains the base path where to read/write record in Object Storage
	path string
	svc  *providers.Service
}

//DecoderCallback is the prototype of the function that will decode data read from Metadata
type DecoderCallback func(buf *bytes.Buffer) error

//NewFolder creates a new Metadata Folder object, ready to help access the metadata inside it
func NewFolder(path string) (*Folder, error) {
	svc, err := utils.GetProviderService()
	if err != nil {
		return nil, err
	}
	return &Folder{
		path: strings.Trim(path, "/"),
		svc:  svc,
	}, nil
}

//GetPath returns the base path of the folder
func (f *Folder) GetPath() string {
	return f.path
}

//absolutePath returns the fullpath to reach the 'path'+'name' starting from the folder path
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

//Search tells if the object named 'name' is inside the ObjectStorage folder
func (f *Folder) Search(path string, name string) (bool, error) {
	absPath := strings.Trim(f.absolutePath(path), "/")
	list, err := f.svc.ListObjects(ContainerName, api.ObjectFilter{
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

//Delete removes metadata passed as parameter
func (f *Folder) Delete(path string, name string) error {
	err := f.svc.DeleteObject(ContainerName, f.absolutePath(path, name))
	if err != nil {
		return fmt.Errorf("failed to remove cluster definition in Object Storage: %s", err.Error())
	}
	return nil
}

//Read loads the content of the object stored in metadata container
// returns false, nil if the object is not found
// returns false, err if an error occured
// returns true, nil if the object has been found
// The callback function has to know how to decode it and where to store the result
func (f *Folder) Read(path string, name string, callback DecoderCallback) (bool, error) {
	found, err := f.Search(path, name)
	if err != nil {
		return false, err
	}
	if found {
		o, err := f.svc.GetObject(ContainerName, f.absolutePath(path, name), nil)
		if err != nil {
			return false, err
		}
		var buffer bytes.Buffer
		buffer.ReadFrom(o.Content)
		if err != nil {
			return true, err
		}
		return true, callback(&buffer)
	}
	return false, nil
}

//Write writes the content in Object Storage
func (f *Folder) Write(path string, name string, content interface{}) error {
	var buffer bytes.Buffer
	err := gob.NewEncoder(&buffer).Encode(content)
	if err != nil {
		return err
	}

	return f.svc.PutObject(ContainerName, api.Object{
		Name:    f.absolutePath(path, name),
		Content: bytes.NewReader(buffer.Bytes()),
	})
}

//Browse browses the content of a specific path in Metadata and executes 'cb' on each entry
func (f *Folder) Browse(path string, callback DecoderCallback) error {
	list, err := f.svc.ListObjects(ContainerName, api.ObjectFilter{
		Path: strings.Trim(f.absolutePath(path), "/"),
	})
	if err != nil {
		// If bucket not found, return nil; no item will be processed, meaning empty path
		if awsError, ok := err.(awserr.RequestFailure); ok {
			if awsError.StatusCode() == 404 {
				return nil
			}
		}
		return err
	}

	for _, i := range list {
		o, err := f.svc.GetObject(ContainerName, i, nil)
		if err != nil {
			return err
		}
		var buffer bytes.Buffer
		buffer.ReadFrom(o.Content)
		err = callback(&buffer)
		if err != nil {
			return err
		}
	}
	return nil
}
