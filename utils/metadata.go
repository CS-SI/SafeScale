package utils

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"

	"github.com/aws/aws-sdk-go/aws/awserr"
)

//InitializeMetadataContainer creates the Object Storage Container/Bucket that will store the metadata
func InitializeMetadataContainer(client api.ClientAPI) error {
	svc := providers.FromClient(client)
	err := svc.CreateContainer(MetadataContainerName)
	if err != nil {
		fmt.Printf("failed to create Object Container %s: %s\n", MetadataContainerName, err.Error())
	}
	return err
}

//FindMetadata returns the full path of the metadata search if it exists in Object Storage
// If the returned string is "" and error is nil, metadata doesn't exist
func FindMetadata(path string, name string) (bool, error) {
	svc, err := GetProviderService()
	if err != nil {
		return false, err
	}

	list, err := svc.ListObjects(MetadataContainerName, api.ObjectFilter{
		Path:   strings.TrimLeft(name, "/"),
		Prefix: strings.TrimRight(path, "/"),
	})
	if err != nil {
		return false, err
	}
	return len(list) > 0, nil
}

//DeleteMetadata removes metadata passed as parameter
func DeleteMetadata(path string, name string) error {
	svc, err := GetProviderService()
	if err != nil {
		return err
	}
	fullPath := strings.TrimRight(path, "/") + "/" + strings.TrimLeft(name, "/")
	err = svc.DeleteObject(MetadataContainerName, fullPath)
	if err != nil {
		return fmt.Errorf("failed to remove cluster definition in Object Storage: %s", err.Error())
	}
	return nil
}

//MetadataDecoderCallback is the prototype of the function that will decode data read from Metadata
type MetadataDecoderCallback func(buf *bytes.Buffer) error

//ReadMetadata loads the content of the object stored in metadata container
func ReadMetadata(path string, name string, call MetadataDecoderCallback) error {
	svc, err := GetProviderService()
	if err != nil {
		return err
	}

	fullPath := strings.TrimRight(path, "/") + "/" + strings.TrimLeft(name, "/")
	o, err := svc.GetObject(MetadataContainerName, fullPath, nil)
	if err != nil {
		return err
	}
	var buffer bytes.Buffer
	buffer.ReadFrom(o.Content)
	if err != nil {
		return err
	}
	return call(&buffer)
}

//WriteMetadata writes the content in Object Storage
func WriteMetadata(path string, name string, content interface{}) error {
	var buffer bytes.Buffer
	err := gob.NewEncoder(&buffer).Encode(content)
	if err != nil {
		return err
	}

	svc, err := GetProviderService()
	if err != nil {
		return err
	}

	fullPath := strings.TrimRight(path, "/") + "/" + strings.TrimLeft(name, "/")
	return svc.PutObject(MetadataContainerName, api.Object{
		Name:    fullPath,
		Content: bytes.NewReader(buffer.Bytes()),
	})
}

//BrowseMetadata browses the content of a specific path in Metadata and executes 'cb' on each entry
func BrowseMetadata(path string, cb MetadataDecoderCallback) error {
	svc, err := GetProviderService()
	if err != nil {
		return err
	}

	list, err := svc.ListObjects(MetadataContainerName, api.ObjectFilter{
		Path: strings.Trim(path, "/"),
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
		o, err := svc.GetObject(MetadataContainerName, i, nil)
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
