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
	"sync"

	"github.com/CS-SI/SafeScale/providers"
)

// Item is an entry in the ObjectStorage
type Item struct {
	payload interface{}
	folder  *Folder
	lock    sync.Mutex
}

// ItemDecoderCallback ...
type ItemDecoderCallback func(buf *bytes.Buffer) (interface{}, error)

// NewItem creates a new item with 'name' and in 'path'
func NewItem(svc *providers.Service, path string) *Item {
	return &Item{
		folder:  NewFolder(svc, path),
		payload: nil,
	}
}

// GetService returns the service providers used by Item
func (i *Item) GetService() *providers.Service {
	return i.folder.GetService()
}

// GetPath returns the path in the Object Storage where the Item is stored
func (i *Item) GetPath() string {
	return i.folder.GetPath()
}

// Carry links metadata with cluster struct
func (i *Item) Carry(data interface{}) *Item {
	i.payload = data
	return i
}

// Get returns payload in item
func (i *Item) Get() interface{} {
	return i.payload
}

// DeleteFrom removes a metadata from a folder
func (i *Item) DeleteFrom(path string, name string) error {
	if name == "" {
		panic("name is empty!")
	}
	if path == "" {
		path = "."
	}

	if there, err := i.folder.Search(path, name); err != nil || !there {
		if err != nil {
			return err
		}
		if !there {
			return nil
		}
	}

	return i.folder.Delete(path, name)
}

// Delete removes a metadata
func (i *Item) Delete(name string) error {
	return i.DeleteFrom(".", name)
}

// ReadFrom reads metadata of item from Object Storage in a subfolder
func (i *Item) ReadFrom(path string, name string, callback ItemDecoderCallback) (bool, error) {
	var data interface{}
	found, err := i.folder.Read(path, name, func(buf *bytes.Buffer) error {
		var err error
		data, err = callback(buf)
		return err
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	i.payload = data
	return true, nil
}

// Read read metadata of item from Object Storage (in current folder)
func (i *Item) Read(name string, callback ItemDecoderCallback) (bool, error) {
	return i.ReadFrom(".", name, callback)
}

// WriteInto saves the content of Item in a subfolder to the Object Storage
func (i *Item) WriteInto(path string, name string) error {
	return i.folder.Write(path, name, i.payload)
}

// Write saves the content of Item to the Object Storage
func (i *Item) Write(name string) error {
	return i.WriteInto(".", name)
}

// BrowseInto walks through a subfolder ogf item folder and executes a callback for each entry
func (i *Item) BrowseInto(path string, callback func(*bytes.Buffer) error) error {
	if callback == nil {
		panic("callback is nil!")
	}

	if path == "" {
		path = "."
	}
	return i.folder.Browse(path, func(buf *bytes.Buffer) error {
		return callback(buf)
	})
}

// Browse walks through folder of item and executes a callback for each entry
func (i *Item) Browse(callback func(*bytes.Buffer) error) error {
	return i.BrowseInto(".", func(buf *bytes.Buffer) error {
		return callback(buf)
	})
}

// Acquire waits until the write lock is available, then locks the metadata
func (i *Item) Acquire() {
	i.lock.Lock()
}

// Release unlocks the metadata
func (i *Item) Release() {
	i.lock.Unlock()
}
