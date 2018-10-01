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
	"encoding/gob"
	"fmt"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"

	"github.com/CS-SI/SafeScale/utils/metadata"
)

const (
	// nasFolderName is the technical name of the container used to store nas info
	nasFolderName = "nas"
)

// Nas links Object Storage folder and Network
type Nas struct {
	item *metadata.Item
	name string
	id   string
}

// NewNas creates an instance of metadata.Nas
func NewNas(svc *providers.Service) *Nas {
	return &Nas{
		item: metadata.NewItem(svc, nasFolderName),
	}
}

// Carry links a Nas instance to the Metadata instance
func (m *Nas) Carry(nas *api.Nas) *Nas {
	if nas == nil {
		panic("nas is nil!")
	}
	if m.item == nil {
		panic("m.item is nil!")
	}
	m.item.Carry(nas)
	m.name = nas.Name
	m.id = nas.ID
	return m
}

// Get returns the Nas instance linked to metadata
func (m *Nas) Get() *api.Nas {
	if m.item == nil {
		panic("m.item is nil!")
	}
	if n, ok := m.item.Get().(*api.Nas); ok {
		return n
	}
	panic("invalid content in metadata!")
}

// Write updates the metadata corresponding to the nas in the Object Storage
func (m *Nas) Write() error {
	if m.item == nil {
		panic("m.item is nil!")
	}
	err := m.item.WriteInto(ByIDFolderName, m.id)
	if err != nil {
		return err
	}
	return m.item.WriteInto(ByNameFolderName, m.name)
}

// ReadByID reads the metadata of a nas identified by ID from Object Storage
func (m *Nas) ReadByID(id string) (bool, error) {
	if m.item == nil {
		panic("m.item is nil!")
	}
	var data api.Nas
	found, err := m.item.ReadFrom(ByIDFolderName, id, func(buf *bytes.Buffer) (interface{}, error) {
		err := gob.NewDecoder(buf).Decode(&data)
		if err != nil {
			return nil, err
		}
		return &data, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.id = id
	m.name = data.Name
	return true, nil
}

// ReadByName reads the metadata of a nas identified by name
func (m *Nas) ReadByName(name string) (bool, error) {
	if m.item == nil {
		panic("m.name is nil!")
	}
	var data api.Nas
	found, err := m.item.ReadFrom(ByNameFolderName, name, func(buf *bytes.Buffer) (interface{}, error) {
		err := gob.NewDecoder(buf).Decode(&data)
		if err != nil {
			return nil, err
		}
		return &data, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.name = name
	m.id = data.ID
	return true, nil
}

// Delete updates the metadata corresponding to the nas
func (m *Nas) Delete() error {
	err := m.item.DeleteFrom(ByIDFolderName, m.id)
	if err != nil {
		return err
	}
	return m.item.DeleteFrom(ByNameFolderName, m.name)
}

// Browse walks through nas folder and executes a callback for each entries
func (m *Nas) Browse(callback func(*api.Nas) error) error {
	return m.item.BrowseInto(ByNameFolderName, func(buf *bytes.Buffer) error {
		var nas api.Nas
		err := gob.NewDecoder(buf).Decode(&nas)
		if err != nil {
			return err
		}
		return callback(&nas)
	})
}

// AddClient adds a client to the Nas definition in Object Storage
func (m *Nas) AddClient(nas *api.Nas) error {
	return NewNas(m.item.GetService()).Carry(nas).item.WriteInto(m.id, nas.ID)
	// return m.item.WriteInto(m.id, nas.ID)
}

//RemoveClient removes a client to the Nas definition in Object Storage
func (m *Nas) RemoveClient(nas *api.Nas) error {
	return m.item.DeleteFrom(m.id, nas.ID)
}

//Listclients returns the list of ID of hosts clients of the NAS server
func (m *Nas) Listclients() ([]*api.Nas, error) {
	var list []*api.Nas
	err := m.item.BrowseInto(m.id, func(buf *bytes.Buffer) error {
		var nas api.Nas
		err := gob.NewDecoder(buf).Decode(&nas)
		if err != nil {
			return err
		}
		list = append(list, &nas)
		return nil
	})
	return list, err
}

// FindClient returns the client hosted by the Host whose name is given
func (m *Nas) FindClient(hostName string) (*api.Nas, error) {
	var client *api.Nas
	err := m.item.BrowseInto(m.id, func(buf *bytes.Buffer) error {
		var nas api.Nas
		err := gob.NewDecoder(buf).Decode(&nas)
		if err != nil {
			return err
		}
		if nas.Host == hostName {
			client = &nas
			return nil
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("No client found for nas '%s' on host '%s'", m.name, hostName)
	}
	return client, nil
}

// Acquire waits until the write lock is available, then locks the metadata
func (m *Nas) Acquire() {
	m.item.Acquire()
}

// Release unlocks the metadata
func (m *Nas) Release() {
	m.item.Release()
}

// SaveNas saves the Nas definition in Object Storage
func SaveNas(svc *providers.Service, nas *api.Nas) error {
	err := NewNas(svc).Carry(nas).Write()
	if err != nil {
		return err
	}
	return nil
}

// RemoveNas removes the Nas definition from Object Storage
func RemoveNas(svc *providers.Service, nas *api.Nas) error {
	return NewNas(svc).Carry(nas).Delete()
}

// LoadNas gets the Nas definition from Object Storage
func LoadNas(svc *providers.Service, ref string) (*Nas, error) {
	m := NewNas(svc)
	found, err := m.ReadByID(ref)
	if err != nil {
		return nil, err
	}
	if !found {
		found, err := m.ReadByName(ref)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, nil
		}
		return m, nil
	}
	return m, nil
}

// MountNas add the client nas to the Nas definition from Object Storage
func MountNas(svc *providers.Service, client *api.Nas, nas *api.Nas) error {
	return NewNas(svc).Carry(nas).AddClient(client)
}

// UmountNas remove the client nas to the Nas definition from Object Storage
func UmountNas(svc *providers.Service, client *api.Nas, nas *api.Nas) error {
	return NewNas(svc).Carry(nas).RemoveClient(client)
}
