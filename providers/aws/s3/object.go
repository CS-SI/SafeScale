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

package s3

import (
	"bytes"
	"fmt"
	"github.com/CS-SI/SafeScale/providers/model"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	awss3 "github.com/aws/aws-sdk-go/service/s3"
)

func createTagging(m map[string]interface{}) string {
	tags := []string{}
	for k, v := range m {
		tags = append(tags, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(tags, "&")
}

//PutObject put an object into an object container
func PutObject(service *awss3.S3, container string, obj model.Object) error {
	//Manage object life cycle
	expires := obj.DeleteAt != time.Time{}
	if expires {
		_, err := service.PutBucketLifecycle(&awss3.PutBucketLifecycleInput{
			Bucket: aws.String(container),
			LifecycleConfiguration: &awss3.LifecycleConfiguration{
				Rules: []*awss3.Rule{
					&awss3.Rule{
						Expiration: &awss3.LifecycleExpiration{
							Date: &obj.DeleteAt,
						},
						Prefix: aws.String(obj.Name),
						Status: aws.String("Enabled"),
					},
				},
			},
		})
		if err != nil {
			return err
		}
	}

	if obj.Metadata == nil {
		obj.Metadata = map[string]interface{}{}
	}
	dateBytes, _ := time.Now().MarshalText()
	obj.Metadata["__date__"] = string(dateBytes)
	dateBytes, _ = obj.DeleteAt.MarshalText()
	obj.Metadata["__delete_at__"] = string(dateBytes)
	input := &awss3.PutObjectInput{
		Body:        aws.ReadSeekCloser(obj.Content),
		Bucket:      aws.String(container),
		Key:         aws.String(obj.Name),
		ContentType: aws.String(obj.ContentType),
		Tagging:     aws.String(createTagging(obj.Metadata)),
	}

	_, err := service.PutObject(input)

	return err
}

//UpdateObjectMetadata update an object into an object container
func UpdateObjectMetadata(service *awss3.S3, container string, obj model.Object) error {
	//meta, err := c.GetObjectMetadata(container, obj.Name
	tags := []*awss3.Tag{}
	for k, v := range obj.Metadata {
		tags = append(tags, &awss3.Tag{
			Key:   aws.String(k),
			Value: aws.String(v.(string)),
		})
	}
	input := &awss3.PutObjectTaggingInput{
		Bucket: aws.String(container),
		Key:    aws.String(obj.Name),
		Tagging: &awss3.Tagging{
			TagSet: tags,
		},
	}
	_, err := service.PutObjectTagging(input)
	return err
}

func pStr(s *string) string {
	if s == nil {
		var s string
		return s
	}
	return *s
}
func pTime(p *time.Time) time.Time {
	if p == nil {
		return time.Time{}
	}
	return *p
}
func pInt64(p *int64) int64 {
	if p == nil {
		var v int64
		return v
	}
	return *p
}

//GetObject get object content from an object container
func GetObject(service *awss3.S3, container string, name string, ranges []model.Range) (*model.Object, error) {
	var rList []string
	for _, r := range ranges {
		rList = append(rList, r.String())
	}
	sRanges := strings.Join(rList, ",")
	out, err := service.GetObject(&awss3.GetObjectInput{
		Bucket: aws.String(container),
		Key:    aws.String(name),
		Range:  aws.String(sRanges),
	})
	if err != nil {
		return nil, err
	}

	obj, err := GetObjectMetadata(service, container, name)
	if err != nil {
		return nil, err
	}
	return &model.Object{
		Content:       aws.ReadSeekCloser(out.Body),
		ContentLength: pInt64(out.ContentLength),
		ContentType:   pStr(out.ContentType),
		LastModified:  pTime(out.LastModified),
		Name:          name,
		Metadata:      obj.Metadata,
		Date:          obj.Date,
		DeleteAt:      obj.DeleteAt,
	}, nil
}

//GetObjectMetadata get  object metadata from an object container
func GetObjectMetadata(service *awss3.S3, container string, name string) (*model.Object, error) {
	tagging, err := service.GetObjectTagging(&awss3.GetObjectTaggingInput{
		Bucket: aws.String(container),
		Key:    aws.String(name),
	})
	meta := map[string]interface{}{}
	date := time.Time{}
	deleteAt := time.Time{}
	if err != nil {
		for _, t := range tagging.TagSet {
			if *t.Key == "__date__" {
				buffer := bytes.Buffer{}
				buffer.WriteString(*t.Value)
				date.UnmarshalText(buffer.Bytes())
			} else if *t.Key == "__delete_at__" {
				buffer := bytes.Buffer{}
				buffer.WriteString(*t.Value)
				deleteAt.UnmarshalText(buffer.Bytes())
			}
			meta[*t.Key] = *t.Value
		}
	}
	return &model.Object{
		Name:     name,
		Metadata: meta,
		Date:     date,
		DeleteAt: deleteAt,
	}, nil
}

//ListObjects list objects of a container
func ListObjects(service *awss3.S3, container string, filter model.ObjectFilter) ([]string, error) {
	var objs []string

	var prefix string
	if filter.Path != "" || filter.Prefix != "" {
		prefix = strings.Join([]string{filter.Path, filter.Prefix}, "/")
	}
	err := service.ListObjectsV2Pages(&awss3.ListObjectsV2Input{Bucket: aws.String(container), Prefix: aws.String(prefix)},
		func(out *awss3.ListObjectsV2Output, last bool) bool {
			for _, o := range out.Contents {
				objs = append(objs, *o.Key)
			}
			return last
		},
	)
	if err != nil {
		return nil, err
	}
	return objs, err
}

//CopyObject copies an object
func CopyObject(service *awss3.S3, containerSrc, objectSrc, objectDst string) error {
	src := strings.Join([]string{containerSrc, objectDst}, "/")
	_, err := service.CopyObject(&awss3.CopyObjectInput{
		Bucket:     aws.String(containerSrc),
		Key:        aws.String(objectSrc),
		CopySource: aws.String(src),
	})
	return err
}

//DeleteObject deleta an object from a container
func DeleteObject(service *awss3.S3, container, object string) error {
	_, err := service.DeleteObject(&awss3.DeleteObjectInput{
		Bucket: aws.String(container),
		Key:    aws.String(object),
	})
	return err
}
