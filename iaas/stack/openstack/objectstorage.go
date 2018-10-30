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

	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/containers"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/objects"
	"github.com/gophercloud/gophercloud/pagination"
)

// CreateBucket creates an object container
func (s *Stack) CreateBucket(name string) error {
	opts := containers.CreateOpts{
		//		Metadata: meta,
	}
	_, err := containers.Create(s.ObjectStorage, name, opts).Extract()
	if err != nil {
		return fmt.Errorf("Error creating container %s: %s", name, ErrorToString(err))
	}

	return nil
}

// DeleteBucket deletes an object container
func (s *Stack) DeleteBucket(name string) error {
	_, err := containers.Delete(s.ObjectStorage, name).Extract()
	if err != nil {
		return fmt.Errorf("Error deleting bucket %s: %s", name, ErrorToString(err))
	}
	return err
}

// UpdateBucket updates an object container
func (s *Stack) UpdateBucket(name string, meta map[string]string) error {
	_, err := containers.Update(s.ObjectStorage, name, containers.UpdateOpts{
		Metadata: meta,
	}).Extract()
	if err != nil {
		return fmt.Errorf("Error updating container %s: %s", name, ErrorToString(err))
	}
	return nil
}

// GetBucketMetadata get an object container metadata
func (s *Stack) GetBucketMetadata(name string) (map[string]string, error) {
	meta, err := containers.Get(s.ObjectStorage, name, containers.GetOpts{}).ExtractMetadata()
	if err != nil {
		return nil, fmt.Errorf("Error getting container %s: %s", name, ErrorToString(err))
	}
	return meta, nil

}

// GetBucket gets bucket info
func (s *Stack) GetBucket(name string) (*model.BucketInfo, error) {
	meta, err := containers.Get(s.ObjectStorage, name, containers.GetOpts{}).ExtractMetadata()
	_ = meta

	if err != nil {
		return nil, fmt.Errorf("Error getting container %s: %s", name, ErrorToString(err))
	}
	return &model.BucketInfo{
		Name:       name,
		Host:       "TODO Host",
		MountPoint: "TODO mountpoint",
		NbItems:    -1,
	}, nil

}

// ListBuckets list object containers
func (s *Stack) ListBuckets() ([]string, error) {
	opts := &containers.ListOpts{Full: true}

	pager := containers.List(s.ObjectStorage, opts)

	var bucketList []string
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		// Get a slice of strings, i.e. container names
		bucketNames, err := containers.ExtractNames(page)
		if err != nil {
			return false, err
		}
		// for _, n := range bucketNames {
		// 	bucketList = append(bucketList, n)
		// }
		bucketList = append(bucketList, bucketNames...)
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error listing containers: %s", ErrorToString(err))
	}
	return bucketList, nil
}

// PutObject put an object into an object container
func (s *Stack) PutObject(bucket string, obj model.Object) error {
	var ti time.Time
	opts := objects.CreateOpts{
		Metadata:    obj.Metadata,
		ContentType: obj.ContentType,
		Content:     obj.Content,
	}
	if ti != obj.DeleteAt {
		opts.DeleteAt = int(obj.DeleteAt.Unix())
	}
	_, err := objects.Create(s.ObjectStorage, bucket, obj.Name, opts).Extract()
	if err != nil {
		return fmt.Errorf("Error creating object %s in container %s : %s", obj.Name, bucket, ErrorToString(err))
	}
	return nil
}

// UpdateObjectMetadata update an object into an object container
func (s *Stack) UpdateObjectMetadata(bucket string, obj model.Object) error {
	var ti time.Time
	opts := objects.UpdateOpts{
		Metadata: obj.Metadata,
	}
	if ti != obj.DeleteAt {
		opts.DeleteAt = int(obj.DeleteAt.Unix())
	}
	_, err := objects.Update(s.ObjectStorage, bucket, obj.Name, opts).Extract()
	return err
}

// GetObject get  object content from an object container
func (s *Stack) GetObject(bucket string, name string, ranges []model.Range) (*model.Object, error) {
	var rList []string
	for _, r := range ranges {
		rList = append(rList, r.String())
	}
	sRanges := strings.Join(rList, ",")
	res := objects.Download(s.ObjectStorage, bucket, name, objects.DownloadOpts{
		Range: fmt.Sprintf("bytes=%s", sRanges),
	})
	content, err := res.ExtractContent()
	if err != nil {
		return nil, fmt.Errorf("Error getting object %s from %s : %s", name, bucket, ErrorToString(err))
	}
	metadata := make(map[string]string)
	for k, v := range res.Header {
		if strings.HasPrefix(k, "X-Object-Meta-") {
			key := strings.TrimPrefix(k, "X-Object-Meta-")
			metadata[key] = v[0]
		}
	}
	header, err := res.Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting object %s from %s : %s", name, bucket, ErrorToString(err))
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
		Metadata:      metadata,
		Date:          header.Date,
		LastModified:  header.LastModified,
		ContentType:   header.ContentType,
		ContentLength: header.ContentLength,
	}, nil
}

// GetObjectMetadata gets object metadata from an object bucket
func (s *Stack) GetObjectMetadata(bucket string, name string) (*model.Object, error) {
	res := objects.Get(s.ObjectStorage, bucket, name, objects.GetOpts{})
	meta, err := res.ExtractMetadata()

	if err != nil {
		return nil, fmt.Errorf("Error getting object content: %s", ErrorToString(err))
	}
	header, err := res.Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting object content: %s", ErrorToString(err))
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
func (s *Stack) ListObjects(bucket string, filter model.ObjectFilter) ([]string, error) {
	// We have the option of filtering objects by their attributes
	opts := &objects.ListOpts{
		Full:   false,
		Path:   filter.Path,
		Prefix: filter.Prefix,
	}

	pager := objects.List(s.ObjectStorage, bucket, opts)
	var objectList []string
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		objectNames, err := objects.ExtractNames(page)
		if err != nil {
			return false, err
		}
		objectList = append(objectList, objectNames...)
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error listing objects of bucket '%s': %s", bucket, ErrorToString(err))
	}
	return objectList, nil
}

// CopyObject copies an object
func (s *Stack) CopyObject(bucketSrc, objectSrc, objectDst string) error {

	opts := &objects.CopyOpts{
		Destination: objectDst,
	}

	result := objects.Copy(s.ObjectStorage, bucketSrc, objectSrc, opts)

	_, err := result.Extract()
	if err != nil {
		return fmt.Errorf("Error copying object '%s' into '%s' from bucket '%s': %s", objectSrc, objectDst, bucketSrc, ErrorToString(err))
	}
	return nil
}

// DeleteObject deleta an object from a container
func (s *Stack) DeleteObject(bucket, object string) error {
	_, err := objects.Delete(s.ObjectStorage, bucket, object, objects.DeleteOpts{}).Extract()
	if err != nil {
		return fmt.Errorf("Error deleting object '%s' of bucket '%s': %s", object, bucket, ErrorToString(err))
	}
	return nil
}
