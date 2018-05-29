package utils

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"strings"

	"github.com/SafeScale/providers/api"
	_ "github.com/SafeScale/providers/cloudwatt"      // Imported to initialise tenants
	_ "github.com/SafeScale/providers/flexibleengine" // Imported to initialise tenants
	_ "github.com/SafeScale/providers/ovh"            // Imported to initialise tenants
)

const (
	metadataContainerName string = "0.safescale"
)

//FindMetadata returns the full path of the metadata search if it exists in Object Storage
// If the returned string is "" and error is nil, metadata doesn't exist
func FindMetadata(path string, name string) (bool, error) {
	CreateMetadataContainer()

	svc, err := GetProviderService()
	if err != nil {
		return false, err
	}

	list, err := svc.ListObjects(metadataContainerName, api.ObjectFilter{
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
	err = svc.DeleteObject(metadataContainerName, fullPath)
	if err != nil {
		return fmt.Errorf("failed to remove cluster definition in Object Storage: %s", err.Error())
	}
	return nil
}

//MetadataDecoder is the prototype of the function that will decode data read from Metadata
type MetadataDecoder func(*bytes.Buffer) error

//ReadMetadata loads the content of the object stored in metadata container
func ReadMetadata(path string, name string, call MetadataDecoder) error {
	svc, err := GetProviderService()
	if err != nil {
		return err
	}

	fullPath := strings.TrimRight(path, "/") + "/" + strings.TrimLeft(name, "/")
	o, err := svc.GetObject(metadataContainerName, fullPath, nil)
	if err != nil {
		return err
	}
	var buffer bytes.Buffer
	buffer.ReadFrom(o.Content)
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
	return svc.PutObject(metadataContainerName, api.Object{
		Name:    fullPath,
		Content: bytes.NewReader(buffer.Bytes()),
	})
}

//BrowseMetadataContent browses the content of a specific path in Metadata and executes 'call' on each entry
func BrowseMetadataContent(path string, call MetadataDecoder) error {
	svc, err := GetProviderService()
	if err != nil {
		return err
	}

	list, err := svc.ListObjects(metadataContainerName, api.ObjectFilter{
		Prefix: strings.TrimRight(path, "/"),
	})
	if err != nil {
		return err
	}

	for _, i := range list {
		o, err := svc.GetObject(metadataContainerName, i, nil)
		if err != nil {
			return err
		}
		var buffer bytes.Buffer
		buffer.ReadFrom(o.Content)
		err = call(&buffer)
		if err != nil {
			return err
		}
	}
	return nil
}
