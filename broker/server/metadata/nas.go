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

	pb "github.com/CS-SI/SafeScale/broker"

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
	name *string
	id   *string
}

// NewNas creates an instance of metadata.Nas
func NewNas(svc *provider.Service) *Nas {
	return &Nas{
		item: metadata.NewItem(svc, nasFolderName),
	}
}

// Carry links a Nas instance to the Metadata instance
func (mn *Nas) Carry(pbn *pb.Nas) *Nas {
	if pbn == nil {
		panic("pbn is nil!")
	}
	if mn.item == nil {
		panic("mn.item is nil!")
	}
	mn.item.Carry(pbn)
	mn.name = &pbn.Name
	mn.id = &pbn.ID
	return mn
}

// Get returns the Nas instance linked to metadata
func (mn *Nas) Get() *pb.Nas {
	if mn.item == nil {
		panic("mn.item is nil!")
	}
	if pbn, ok := mn.item.Get().(*pb.Nas); ok {
		return pbn
	}
	panic("invalid content in Nas metadata!")
}

// Write updates the metadata corresponding to the nas in the Object Storage
func (mn *Nas) Write() error {
	if mn.item == nil {
		panic("mn.item is nil!")
	}
	err := mn.item.WriteInto(ByIDFolderName, mn.id)
	if err != nil {
		return err
	}
	return mn.item.WriteInto(ByNameFolderName, mn.name)
}

// ReadByID reads the metadata of a nas identified by ID from Object Storage
func (mn *Nas) ReadByID(id string) (bool, error) {
	if mn.item == nil {
		panic("mn.item is nil!")
	}
	var pbn api.Nas
	found, err := mn.item.ReadFrom(ByIDFolderName, id, func(buf *bytes.Buffer) (interface{}, error) {
		err := gob.NewDecoder(buf).Decode(&pbn)
		if err != nil {
			return nil, err
		}
		return &pbn, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	mn.id = id
	mn.name = pbn.Name
	return true, nil
}

// ReadByName reads the metadata of a nas identified by name
func (mn *Nas) ReadByName(name string) (bool, error) {
	if mn.item == nil {
		panic("mn.name is nil!")
	}
	var pbn pb.Nas
	found, err := mn.item.ReadFrom(ByNameFolderName, name, func(buf *bytes.Buffer) (interface{}, error) {
		err := gob.NewDecoder(buf).Decode(&pbn)
		if err != nil {
			return nil, err
		}
		return &pbn, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	mn.name = name
	mn.id = data.ID
	return true, nil
}

// Delete updates the metadata corresponding to the nas
func (mn *Nas) Delete() error {
	err := mn.item.DeleteFrom(ByIDFolderName, mn.id)
	if err != nil {
		return err
	}
	return mn.item.DeleteFrom(ByNameFolderName, mn.name)
}

// Browse walks through nas folder and executes a callback for each entries
func (mn *Nas) Browse(callback func(*pb.Nas) error) error {
	return mn.item.BrowseInto(ByNameFolderName, func(buf *bytes.Buffer) error {
		var pbn pb.Nas
		err := gob.NewDecoder(buf).Decode(&pbn)
		if err != nil {
			return err
		}
		return callback(&pbn)
	})
}

// AddClient adds a client to the Nas definition in Object Storage
func (mn *Nas) AddClient(pbn *pb.Host) error {
	return NewNas(mn.item.GetService()).Carry(pbn).item.WriteInto(mn.id, pbn.ID)
	// return m.item.WriteInto(m.id, nas.ID)
}

// RemoveClient removes a client to the Nas definition in Object Storage
func (mn *Nas) RemoveClient(pbh *pb.Host) error {
	return mn.item.DeleteFrom(mn.id, pbh.ID)
}

// Listclients returns the list of ID of hosts clients of the NAS server
func (mn *Nas) Listclients() ([]*pb.Host, error) {
	var list []*pb.Host
	err := mn.item.BrowseInto(mn.id, func(buf *bytes.Buffer) error {
		var pbh pb.Host
		err := gob.NewDecoder(buf).Decode(&pbh)
		if err != nil {
			return err
		}
		list = append(list, &pbh)
		return nil
	})
	return list, err
}

// FindClient returns the client hosted by the Host whose name is given
func (mn *Nas) FindClient(hostName string) (*pb.Host, error) {
	var client *pb.Host
	err := mn.item.BrowseInto(mn.id, func(buf *bytes.Buffer) error {
		var pbh pb.Host
		err := gob.NewDecoder(buf).Decode(&pbh)
		if err != nil {
			return err
		}
		if pbh.Host == hostName {
			client = &pbh
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
func (mn *Nas) Acquire() {
	if mn.item == nil {
		panic("mn.item is nil!")
	}
	mn.item.Acquire()
}

// Release unlocks the metadata
func (mn *Nas) Release() {
	if mn.item == nil {
		panic("mn.item is nil!")
	}
	mn.item.Release()
}

// SaveNas saves the Nas definition in Object Storage
func SaveNas(svc *providers.Service, pbn *pb.Nas) error {
	err := NewNas(svc).Carry(pbn).Write()
	if err != nil {
		return err
	}
	return nil
}

// RemoveNas removes the Nas definition from Object Storage
func RemoveNas(svc *providers.Service, pbn *pb.Nas) error {
	return NewNas(svc).Carry(pbn).Delete()
}

// LoadNas gets the Nas definition from Object Storage
func LoadNas(svc *providers.Service, ref string) (*Nas, error) {
	mn := NewNas(svc)
	found, err := mn.ReadByID(ref)
	if err != nil {
		return nil, err
	}
	if !found {
		found, err := mn.ReadByName(ref)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, nil
		}
		return mn, nil
	}
	return mn, nil
}

// MountNas add the client nas to the Nas definition from Object Storage
func MountNas(svc *providers.Service, client *pb.Nas, pbn *pb.Nas) error {
	return NewNas(svc).Carry(pbn).AddClient(client)
}

// UmountNas remove the client nas to the Nas definition from Object Storage
func UmountNas(svc *providers.Service, client *pb.Nas, pbn *pb.Nas) error {
	return NewNas(svc).Carry(pbn).RemoveClient(client)
}
