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

package resources

import (
	"fmt"
	"io"
	"time"

	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
)

// Bucket describes a Bucket
type Bucket struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Host       string `json:"host,omitempty"`
	MountPoint string `json:"mountPoint,omitempty"`
	// NbItems    int    `json:"nbitems,omitempty"`
}

// Object object to put in a container
type Object struct {
	ID            string                       `json:"id,omitempty"`
	Name          string                       `json:"name,omitempty"`
	DeleteAt      time.Time                    `json:"delete_at,omitempty"`
	Date          time.Time                    `json:"date,omitempty"`
	ContentType   string                       `json:"content_type,omitempty"`
	ContentLength int64                        `json:"content_length,omitempty"`
	Content       io.ReadSeeker                `json:"content,omitempty"`
	Size          int64                        `json:"size,omitempty"`
	Metadata      objectstorage.ObjectMetadata `json:"metadata,omitempty"`
	LastModified  time.Time                    `json:"last_modified,omitempty"`
	ETag          string                       `json:"etag,omitempty"`
}

// ObjectFilter filter object
type ObjectFilter struct {
	Path   string `json:"path,omitempty"`
	Prefix string `json:"prefix,omitempty"`
}

// Range Defines a range of bytes
type Range struct {
	From *int `json:"from,omitempty"`
	To   *int `json:"to,omitempty"`
}

// NewRange creates a range
func NewRange(from, to int) Range {
	return Range{&from, &to}
}

// OK ...
func (r *Range) OK() bool {
	result := true
	result = result && r.From != nil
	result = result && r.To != nil
	return result
}

func (r Range) String() string {
	if r.From != nil && r.To != nil {
		return fmt.Sprintf("%d-%d", *r.From, *r.To)
	}
	if r.From != nil {
		return fmt.Sprintf("%d-", *r.From)
	}
	if r.To != nil {
		return fmt.Sprintf("%d", *r.To)
	}
	return ""
}
