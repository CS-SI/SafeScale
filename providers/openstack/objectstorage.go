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

package openstack

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/containers"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/objects"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/utils"
)

// CreateContainer creates an object container
func (client *Client) CreateContainer(name string) error {
	opts := containers.CreateOpts{
		//		Metadata: meta,
	}
	_, err := containers.Create(client.Container, name, opts).Extract()
	if err != nil {
		log.Debugf("Error creating container: container creation call: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error creating container %s: %s", name, ProviderErrorToString(err)))
	}

	return nil
}

// DeleteContainer deletes an object container
func (client *Client) DeleteContainer(name string) error {
	_, err := containers.Delete(client.Container, name).Extract()
	if err != nil {
		log.Debugf("Error deleting container: container deletion call: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting container %s: %s", name, ProviderErrorToString(err)))
	}
	return err
}

// UpdateContainer updates an object container
func (client *Client) UpdateContainer(name string, meta map[string]string) error {
	_, err := containers.Update(client.Container, name, containers.UpdateOpts{
		Metadata: meta,
	}).Extract()
	if err != nil {
		log.Debugf("Error updating container: container update call: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error updating container %s: %s", name, ProviderErrorToString(err)))
	}
	return nil
}

// GetContainerMetadata get an object container metadata
func (client *Client) GetContainerMetadata(name string) (map[string]string, error) {
	meta, err := containers.Get(client.Container, name, containers.GetOpts{}).ExtractMetadata()
	if err != nil {
		log.Debugf("Error getting container metadata: getting container call: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting container %s: %s", name, ProviderErrorToString(err)))
	}
	return meta, nil

}

// GetContainer get container info
func (client *Client) GetContainer(name string) (*model.ContainerInfo, error) {
	meta, err := containers.Get(client.Container, name, containers.GetOpts{}).ExtractMetadata()
	_ = meta

	if err != nil {
		log.Debugf("Error getting container: getting container call: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting container %s: %s", name, ProviderErrorToString(err)))
	}
	return &model.ContainerInfo{
		Name:       name,
		Host:       "TODO Host",
		MountPoint: "TODO mountpoint",
		NbItems:    -1,
	}, nil

}

// ListContainers list object containers
func (client *Client) ListContainers() ([]string, error) {
	opts := &containers.ListOpts{Full: true}

	pager := containers.List(client.Container, opts)

	var containerList []string
	err := pager.EachPage(func(page pagination.Page) (bool, error) {

		// Get a slice of strings, i.e. container names
		containerNames, err := containers.ExtractNames(page)
		if err != nil {
			log.Errorf("Error listing containers: extracting container names: %+v", err)
			return false, err
		}
		for _, n := range containerNames {
			containerList = append(containerList, n)
		}

		return true, nil
	})
	if err != nil {
		log.Debugf("Error listing containers: pagination error: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error listing containers: %s", ProviderErrorToString(err)))
	}
	return containerList, nil
}

// PutObject put an object into an object container
func (client *Client) PutObject(container string, obj model.Object) error {
	var ti time.Time
	opts := objects.CreateOpts{
		Metadata:    obj.Metadata,
		ContentType: obj.ContentType,
		Content:     obj.Content,
	}
	if ti != obj.DeleteAt {
		opts.DeleteAt = int(obj.DeleteAt.Unix())
	}
	_, err := objects.Create(client.Container, container, obj.Name, opts).Extract()
	if err != nil {
		log.Debugf("Error putting object: object creation error: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error creating object %s in container %s : %s", obj.Name, container, ProviderErrorToString(err)))
	}
	return nil
}

// UpdateObjectMetadata update an object into an object container
func (client *Client) UpdateObjectMetadata(container string, obj model.Object) error {
	var ti time.Time
	opts := objects.UpdateOpts{
		Metadata: obj.Metadata,
	}
	if ti != obj.DeleteAt {
		opts.DeleteAt = int(obj.DeleteAt.Unix())
	}
	_, err := objects.Update(client.Container, container, obj.Name, opts).Extract()
	if err != nil {
		log.Debugf("Error updating object metadata: object update call: %+v", err)
		return errors.Wrap(err, "Error updating object metadata: object update call")
	}
	return nil
}

// GetObject get  object content from an object container
func (client *Client) GetObject(container string, name string, ranges []model.Range) (*model.Object, error) {
	var rList []string
	for _, r := range ranges {
		rList = append(rList, r.String())
	}

	sRanges := strings.Join(rList, ",")
	//log.Debugf("Getting object from object container: downloading the range [%s]", sRanges)

	// TODO Why we have a bad range ??
	var res objects.DownloadResult
	if len(sRanges) == 0 {
		res = objects.Download(client.Container, container, name, objects.DownloadOpts{})
	} else {
		res = objects.Download(client.Container, container, name, objects.DownloadOpts{
			Range: fmt.Sprintf("bytes=%s", sRanges),
		})
	}

	content, err := res.ExtractContent()
	if err != nil {
		log.Debugf("Error getting object: content extraction call: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting object %s from %s : %s", name, container, ProviderErrorToString(err)))
	}
	recoveredMetadata := make(map[string]string)
	for k, v := range res.Header {
		if strings.HasPrefix(k, "X-Object-Meta-") {
			key := strings.TrimPrefix(k, "X-Object-Meta-")
			recoveredMetadata[key] = v[0]
		}
	}
	header, err := res.Extract()
	if err != nil {
		log.Debugf("Error getting object: extraction call: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting object %s from %s : %s", name, container, ProviderErrorToString(err)))
	}

	if len(ranges) > 1 {
		var buff bytes.Buffer
		sc := string(content)
		tokens := strings.Split(sc, "\r\n")
		read := false
		for _, t := range tokens {
			if len(t) == 0 {
				continue
			}
			if strings.HasPrefix(t, "Content-Range:") {
				read = true
			} else if read {
				buff.Write([]byte(t))
				read = false
			}
		}
		content = buff.Bytes()
	}

	return &model.Object{
		Content:       bytes.NewReader(content),
		DeleteAt:      header.DeleteAt,
		Metadata:      recoveredMetadata,
		Date:          header.Date,
		LastModified:  header.LastModified,
		ContentType:   header.ContentType,
		ContentLength: header.ContentLength,
	}, nil
}

// GetObjectMetadata get  object metadata from an object container
func (client *Client) GetObjectMetadata(container string, name string) (*model.Object, error) {

	res := objects.Get(client.Container, container, name, objects.GetOpts{})
	meta, err := res.ExtractMetadata()

	if err != nil {
		log.Debugf("Error getting object metadata: metadata extraction call: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting object content: %s", ProviderErrorToString(err)))
	}
	header, err := res.Extract()
	if err != nil {
		log.Debugf("Error getting object metadata: extraction call: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting object content: %s", ProviderErrorToString(err)))
	}

	return &model.Object{
		DeleteAt:      header.DeleteAt,
		Metadata:      meta,
		Date:          header.Date,
		LastModified:  header.LastModified,
		ContentType:   header.ContentType,
		ContentLength: header.ContentLength,
	}, nil
}

// ListObjects list objects of a container
func (client *Client) ListObjects(container string, filter model.ObjectFilter) ([]string, error) {
	// We have the option of filtering objects by their attributes
	opts := &objects.ListOpts{
		Full:   false,
		Path:   filter.Path,
		Prefix: filter.Prefix,
	}

	pager := objects.List(client.Container, container, opts)
	var objectList []string
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		objectNames, err := objects.ExtractNames(page)
		if err != nil {
			log.Errorf("Error listing objects: name extraction call: %+v", err)
			return false, err
		}
		objectList = append(objectList, objectNames...)
		return true, nil
	})
	if err != nil {
		log.Debugf("Error listing objects: pagination error: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error listing objects of container '%s': %s", container, ProviderErrorToString(err)))
	}
	return objectList, nil
}

// CopyObject copies an object
func (client *Client) CopyObject(containerSrc, objectSrc, objectDst string) error {
	opts := &objects.CopyOpts{
		Destination: objectDst,
	}

	result := objects.Copy(client.Container, containerSrc, objectSrc, opts)

	_, err := result.Extract()
	if err != nil {
		log.Debugf("Error copying object: extraction call: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error copying object %s into %s from container %s : %s", objectSrc, objectDst, containerSrc, ProviderErrorToString(err)))
	}
	return nil
}

// DeleteObject deletes an object from a container
func (client *Client) DeleteObject(container, object string) error {
	log.Debugf("providers.openstack.DeleteObject(%s:%s) called", container, object)
	defer log.Debugf("providers.openstack.DeleteObject(%s:%s) done", container, object)

	_, err := objects.Delete(client.Container, container, object, objects.DeleteOpts{}).Extract()
	if err != nil {
		msg := fmt.Sprintf("failed to delete object '%s:%s': %s", container, object, ProviderErrorToString(err))
		log.Debugf(utils.TitleFirst(msg))
		return fmt.Errorf(msg)
	}
	return nil
}
