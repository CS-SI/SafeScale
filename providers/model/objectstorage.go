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

package model

import (
	"fmt"
	"io"
	"time"
)

// ContainerInfo represents a container description
type ContainerInfo struct {
	Name       string `json:"name,omitempty"`
	Host       string `json:"host,omitempty"`
	MountPoint string `json:"mountPoint,omitempty"`
	NbItems    int    `json:"nbitems,omitempty"`
}

// Object object to put in a container
type Object struct {
	Name          string            `json:"name,omitempty"`
	Content       io.ReadSeeker     `json:"content,omitempty"`
	DeleteAt      time.Time         `json:"delete_at,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Date          time.Time         `json:"date,omitempty"`
	LastModified  time.Time         `json:"last_modified,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	ContentLength int64             `json:"content_length,omitempty"`
}

// ObjectFilter filter object
type ObjectFilter struct {
	Prefix string `json:"prefix,omitempty"`
	Path   string `json:"path,omitempty"`
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
