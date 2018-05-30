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

package utils

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"reflect"
	"strings"

	"github.com/CS-SI/SafeScale/providers/api"
	_ "github.com/CS-SI/SafeScale/providers/cloudwatt"      // Imported to initialise tenants
	_ "github.com/CS-SI/SafeScale/providers/flexibleengine" // Imported to initialise tenants
	_ "github.com/CS-SI/SafeScale/providers/ovh"            // Imported to initialise tenants
	"github.com/CS-SI/SafeScale/utils"

	"github.com/aws/aws-sdk-go/aws/awserr"
)

//Find returns the full path of the metadata search if it exists in Object Storage
// If the returned string is "" and error is nil, metadata doesn't exist
func Find(path string, name string) (bool, error) {
	svc, err := utils.GetProviderService()
	if err != nil {
		return false, err
	}

	list, err := svc.ListObjects(utils.MetadataContainerName, api.ObjectFilter{
		Path:   strings.TrimLeft(name, "/"),
		Prefix: strings.TrimRight(path, "/"),
	})
	if err != nil {
		return false, err
	}
	return len(list) > 0, nil
}

//Delete removes metadata passed as parameter
func Delete(path string, name string) error {
	svc, err := utils.GetProviderService()
	if err != nil {
		return err
	}
	fullPath := strings.TrimRight(path, "/") + "/" + strings.TrimLeft(name, "/")
	err = svc.DeleteObject(utils.MetadataContainerName, fullPath)
	if err != nil {
		return fmt.Errorf("failed to remove cluster definition in Object Storage: %s", err.Error())
	}
	return nil
}

//DecoderCallback is the prototype of the function that will decode data read from Metadata
type DecoderCallback func(buffer *bytes.Buffer) error

//Read loads the content of the object stored in metadata container
func Read(path string, name string, call DecoderCallback) error {
	svc, err := utils.GetProviderService()
	if err != nil {
		return err
	}

	fullPath := strings.TrimRight(path, "/") + "/" + strings.TrimLeft(name, "/")
	o, err := svc.GetObject(utils.MetadataContainerName, fullPath, nil)
	if err != nil {
		return err
	}
	var buffer bytes.Buffer
	buffer.ReadFrom(o.Content)
	return call(&buffer)
}

//Write writes the content in Object Storage
func Write(path string, name string, content interface{}) error {
	var buffer bytes.Buffer
	err := gob.NewEncoder(&buffer).Encode(content)
	if err != nil {
		return err
	}

	svc, err := utils.GetProviderService()
	if err != nil {
		return err
	}

	fullPath := strings.TrimRight(path, "/") + "/" + strings.TrimLeft(name, "/")
	return svc.PutObject(utils.MetadataContainerName, api.Object{
		Name:    fullPath,
		Content: bytes.NewReader(buffer.Bytes()),
	})
}

//Browse browses the content of a specific path in Metadata and executes 'call' on each entry
func Browse(path string, cb DecoderCallback) error {
	svc, err := utils.GetProviderService()
	if err != nil {
		return err
	}

	list, err := svc.ListObjects(utils.MetadataContainerName, api.ObjectFilter{
		Path: strings.Trim(path, "/"),
	})
	if err != nil {
		log.Printf("err type = %s", reflect.TypeOf(err))
		// If bucket not found, return nil; no item will be processed, meaning empty path
		if awsError, ok := err.(awserr.RequestFailure); ok {
			if awsError.StatusCode() == 404 {
				return nil
			}
		}
		return err
	}

	for _, i := range list {
		o, err := svc.GetObject(utils.MetadataContainerName, i, nil)
		if err != nil {
			return err
		}
		var buffer bytes.Buffer
		buffer.ReadFrom(o.Content)
		err = cb(&buffer)
		if err != nil {
			return err
		}
	}
	return nil
}
