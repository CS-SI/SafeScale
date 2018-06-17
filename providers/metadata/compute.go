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

	"github.com/CS-SI/SafeScale/metadata"
	"github.com/CS-SI/SafeScale/providers/api"
)

const (
	//NetworkFolderName is the technical name of the container used to store networks info
	hostFolderName = "host"
)

//Host links Object Storage folder and Network
type Host struct {
	folder *metadata.Folder
	host   *api.VM
}

//NewHost creates an instance of api.VM
func NewHost(svc *providers.Service) (*Host, error) {
	f, err := metadata.NewFolder(svc, hostFolderName)
	if err != nil {
		return nil, err
	}
	return &Host{
		folder: f,
		host:   nil,
	}, nil
}

//Carry links a VM instance to the Metadata instance
func (m *Host) Carry(host *api.VM) *Host {
	if host == nil {
		panic("host parameter is nil!")
	}
	m.host = host
	return m
}

//Get returns the Network instance linked to metadata
func (m *Host) Get() *api.VM {
	return m.host
}

//Write updates the metadata corresponding to the host in the Object Storage
func (m *Host) Write() error {
	if m.host == nil {
		panic("m.host is nil!")
	}

	err := m.folder.Write(ByIDFolderName, m.host.ID, m.host)
	if err != nil {
		return err
	}
	return m.folder.Write(ByNameFolderName, m.host.Name, m.host)
}

//Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (m *Host) Reload() error {
	if m.host == nil {
		panic("Metadata isn't linked with a host!")
	}
	hostName := m.host.Name
	found, err := m.ReadByID(m.host.ID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("metadata of host '%s' doesn't exist anymore", hostName)
	}
	return nil
}

//ReadByID reads the metadata of a network identified by ID from Object Storage
func (m *Host) ReadByID(id string) (bool, error) {

	var host api.VM
	found, err := m.folder.Read(ByIDFolderName, id, func(buf *bytes.Buffer) error {
		return gob.NewDecoder(buf).Decode(&host)
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.host = &host
	return true, nil
}

//ReadByName reads the metadata of a network identified by name
func (m *Host) ReadByName(name string) (bool, error) {
	var host api.VM
	found, err := m.folder.Read(ByNameFolderName, name, func(buf *bytes.Buffer) error {
		return gob.NewDecoder(buf).Decode(&host)
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.host = &host
	return true, nil
}

//Delete updates the metadata corresponding to the network
func (m *Host) Delete() error {
	err := m.folder.Delete(ByIDFolderName, m.host.ID)
	if err != nil {
		return err
	}
	err = m.folder.Delete(ByNameFolderName, m.host.Name)
	if err != nil {
		return err
	}
	m.host = nil
	return nil
}

//Browse walks through vm folder and executes a callback for each entries
func (m *Host) Browse(callback func(*api.VM) error) error {
	return m.folder.Browse(ByIDFolderName, func(buf *bytes.Buffer) error {
		var vm api.VM
		err := gob.NewDecoder(buf).Decode(&vm)
		if err != nil {
			return err
		}
		return callback(&vm)
	})
}

//SaveHost saves the VM definition in Object Storage
func SaveHost(svc *providers.Service, vm *api.VM, netID string) error {
	mh, err := NewHost(svc)
	if err != nil {
		return err
	}
	err = mh.Carry(vm).Write()
	if err != nil {
		return err
	}
	mn, err := NewNetwork(svc)
	if err != nil {
		return err
	}
	found, err := mn.ReadByID(netID)
	if err != nil {
		return err
	}
	if found {
		return mn.AttachHost(vm)
	}
	return nil
}

//RemoveHost removes the VM definition from Object Storage
func RemoveHost(svc *providers.Service, vm *api.VM) error {
	// First, browse networks to delete links on the deleted host
	mn, err := NewNetwork(svc)
	if err != nil {
		return err
	}
	mnb, err := NewNetwork(svc)
	if err != nil {
		return err
	}
	err = mn.Browse(func(net *api.Network) error {
		mnb.Carry(net).DetachHost(vm.ID)
		return nil
	})
	if err != nil {
		return err
	}

	// Second deletes host metadata
	mh, err := NewHost(svc)
	if err != nil {
		return err
	}
	return mh.Carry(vm).Delete()
}

//LoadHost gets the VM definition from Object Storage
func LoadHost(svc *providers.Service, vmID string) (*Host, error) {
	m, err := NewHost(svc)
	if err != nil {
		return nil, err
	}
	found, err := m.ReadByID(vmID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return m, nil
}
