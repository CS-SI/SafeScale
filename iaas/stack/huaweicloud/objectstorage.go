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

package huaweicloud

import (
	"fmt"

	"github.com/CS-SI/SafeScale/providers/aws/s3"

	awss3 "github.com/aws/aws-sdk-go/service/s3"
)

// CreateBucket creates an object bucket
func (s *Stack) CreateBucket(name string) error {
	return s3.CreateBucket(awss3.New(s.S3Session), name, client.Opts.Region)
}

// GetBucket get bucket info
func (s *s) GetBucket(name string) (*model.BucketInfo, error) {
	//	return s3.GetBucket(awss3.New(s.S3Session), name)
	return nil, fmt.Errorf("flexibleengine GetBucket not implemented")
}

// DeleteBucket deletes an object bucket
func (s *Stack) DeleteBucket(name string) error {
	return s3.DeleteBucket(awss3.New(s.S3Session), name)
}

// ListBuckets list object buckets
func (s *Stack) ListBuckets() ([]string, error) {
	return s3.ListBuckets(awss3.New(s.S3Session))
}

// PutObject put an object into an object bucket
func (s *Stack) PutObject(bucket string, obj model.Object) error {
	return s3.PutObject(awss3.New(s.S3Session), bucket, obj)
}

// UpdateObjectMetadata update an object into an object bucket
func (s *Stack) UpdateObjectMetadata(bucket string, obj model.Object) error {
	return s3.UpdateObjectMetadata(awss3.New(s.S3Session), bucket, obj)
}

// GetObject get object content from an object bucket
func (s *Stack) GetObject(bucket string, name string, ranges []model.Range) (*model.Object, error) {
	return s3.GetObject(awss3.New(client.S3Session), bucket, name, ranges)
}

// GetObjectMetadata get  object metadata from an object bucket
func (s *Stack) GetObjectMetadata(bucket string, name string) (*model.Object, error) {
	return s3.GetObjectMetadata(awss3.New(client.S3Session), bucket, name)
}

// ListObjects list objects of a bucket
func (s *Stack) ListObjects(bucket string, filter model.ObjectFilter) ([]string, error) {
	return s3.ListObjects(awss3.New(s.S3Session), bucket, filter)
}

// CopyObject copies an object
func (s *Stack) CopyObject(bucketSrc, objectSrc, objectDst string) error {
	return s3.CopyObject(awss3.New(s.S3Session), bucketSrc, objectSrc, objectDst)
}

// DeleteObject deleta an object from a bucket
func (s *Stack) DeleteObject(bucket, object string) error {
	return s3.DeleteObject(awss3.New(s.S3Session), bucket, object)
}
