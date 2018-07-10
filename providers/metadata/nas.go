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
	//nasFolderName is the technical name of the container used to store nas info
	nasFolderName = "nas"
)

//Nas links Object Storage folder and Network
type Nas struct {
	folder *metadata.Folder
	nas    *api.Nas
}

//NewNas creates an instance of metadata.Nas
func NewNas(svc *providers.Service) (*Nas, error) {
	f, err := metadata.NewFolder(svc, nasFolderName)
	if err != nil {
		return nil, err
	}
	return &Nas{
		folder: f,
		nas:    nil,
	}, nil
}

//Carry links a Nas instance to the Metadata instance
func (m *Nas) Carry(nas *api.Nas) *Nas {
	if nas == nil {
		panic("nas parameter is nil!")
	}
	m.nas = nas
	return m
}

//Get returns the Nas instance linked to metadata
func (m *Nas) Get() *api.Nas {
	return m.nas
}

//Write updates the metadata corresponding to the nas in the Object Storage
func (m *Nas) Write() error {
	if m.nas == nil {
		panic("m.nas is nil!")
	}

	err := m.folder.Write(ByIDFolderName, m.nas.ServerID, m.nas)
	if err != nil {
		return err
	}
	return m.folder.Write(ByNameFolderName, m.nas.Name, m.nas)
}

//Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (m *Nas) Reload() error {
	if m.nas == nil {
		panic("Metadata isn't linked with a nas!")
	}
	nasName := m.nas.Name
	found, err := m.ReadByID(m.nas.ServerID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("metadata of nas '%s' doesn't exist anymore", nasName)
	}
	return nil
}

//ReadByID reads the metadata of a nas identified by ID from Object Storage
func (m *Nas) ReadByID(id string) (bool, error) {

	var nas api.Nas
	found, err := m.folder.Read(ByIDFolderName, id, func(buf *bytes.Buffer) error {
		return gob.NewDecoder(buf).Decode(&nas)
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.nas = &nas
	return true, nil
}

//ReadByName reads the metadata of a nas identified by name
func (m *Nas) ReadByName(name string) (bool, error) {
	var nas api.Nas
	found, err := m.folder.Read(ByNameFolderName, name, func(buf *bytes.Buffer) error {
		return gob.NewDecoder(buf).Decode(&nas)
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.nas = &nas
	return true, nil
}

//Delete updates the metadata corresponding to the nas
func (m *Nas) Delete() error {
	err := m.folder.Delete(ByIDFolderName, m.nas.ServerID)
	if err != nil {
		return err
	}
	err = m.folder.Delete(ByNameFolderName, m.nas.Name)
	if err != nil {
		return err
	}
	m.nas = nil
	return nil
}

//Browse walks through nas folder and executes a callback for each entries
func (m *Nas) Browse(callback func(*api.Nas) error) error {
	return m.folder.Browse(ByIDFolderName, func(buf *bytes.Buffer) error {
		var nas api.Nas
		err := gob.NewDecoder(buf).Decode(&nas)
		if err != nil {
			return err
		}
		return callback(&nas)
	})
}

//SaveNas saves the Nas definition in Object Storage
func SaveNas(svc *providers.Service, nas *api.Nas) error {
	mn, err := NewNas(svc)
	if err != nil {
		return err
	}
	err = mn.Carry(nas).Write()
	if err != nil {
		return err
	}
	return nil
}

//RemoveNas removes the Nas definition from Object Storage
func RemoveNas(svc *providers.Service, nas *api.Nas) error {
	mn, err := NewNas(svc)
	if err != nil {
		return err
	}

	err = mn.Carry(nas).Delete()
	if err != nil {
		return err
	}
	return nil
}

//LoadNas gets the Nas definition from Object Storage
func LoadNas(svc *providers.Service, nasID string) (*Nas, error) {
	m, err := NewNas(svc)
	if err != nil {
		return nil, err
	}
	found, err := m.ReadByID(nasID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return m, nil
}
