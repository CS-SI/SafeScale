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
	//volumeFolderName is the technical name of the container used to store volume info
	volumeFolderName = "vol"
)

//Volume links Object Storage folder and Volumes
type Volume struct {
	folder *metadata.Folder
	volume *api.Volume
}

//NewVolume creates an instance of metadata.Volume
func NewVolume(svc *providers.Service) (*Volume, error) {
	f, err := metadata.NewFolder(svc, volumeFolderName)
	if err != nil {
		return nil, err
	}
	return &Volume{
		folder: f,
		volume: nil,
	}, nil
}

//Carry links a Volume instance to the Metadata instance
func (m *Volume) Carry(volume *api.Volume) *Volume {
	if volume == nil {
		panic("volume parameter is nil!")
	}
	m.volume = volume
	return m
}

//Get returns the Volume instance linked to metadata
func (m *Volume) Get() *api.Volume {
	return m.volume
}

//Write updates the metadata corresponding to the volume in the Object Storage
func (m *Volume) Write() error {
	if m.volume == nil {
		panic("m.volume is nil!")
	}

	err := m.folder.Write(ByIDFolderName, m.volume.ID, m.volume)
	if err != nil {
		return err
	}
	return m.folder.Write(ByNameFolderName, m.volume.Name, m.volume)
}

//Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (m *Volume) Reload() error {
	if m.volume == nil {
		panic("Metadata isn't linked with a volume!")
	}
	volumeName := m.volume.Name
	found, err := m.ReadByID(m.volume.ID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("metadata of volume '%s' doesn't exist anymore", volumeName)
	}
	return nil
}

//ReadByID reads the metadata of a volume identified by ID from Object Storage
func (m *Volume) ReadByID(id string) (bool, error) {

	var volume api.Volume
	found, err := m.folder.Read(ByIDFolderName, id, func(buf *bytes.Buffer) error {
		return gob.NewDecoder(buf).Decode(&volume)
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.volume = &volume
	return true, nil
}

//ReadByName reads the metadata of a volume identified by name
func (m *Volume) ReadByName(name string) (bool, error) {
	var volume api.Volume
	found, err := m.folder.Read(ByNameFolderName, name, func(buf *bytes.Buffer) error {
		return gob.NewDecoder(buf).Decode(&volume)
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.volume = &volume
	return true, nil
}

//Delete delete the metadata corresponding to the volume
func (m *Volume) Delete() error {
	err := m.folder.Delete(ByIDFolderName, m.volume.ID)
	if err != nil {
		return err
	}
	err = m.folder.Delete(ByNameFolderName, m.volume.Name)
	if err != nil {
		return err
	}
	m.volume = nil
	return nil
}

//Browse walks through volume folder and executes a callback for each entries
func (m *Volume) Browse(callback func(*api.Volume) error) error {
	return m.folder.Browse(ByIDFolderName, func(buf *bytes.Buffer) error {
		var volume api.Volume
		err := gob.NewDecoder(buf).Decode(&volume)
		if err != nil {
			return err
		}
		return callback(&volume)
	})
}

//Attach add a volume attachment to the volume definition in Object Storage
func (m *Volume) Attach(va *api.VolumeAttachment) error {
	if m.volume == nil {
		panic("m.volume is nil!")
	}

	return m.folder.Write(m.volume.ID, va.ServerID, va)
}

//Detach remove a volume attachment from the volume definition in Object Storage
func (m *Volume) Detach(va *api.VolumeAttachment) error {
	if m.volume == nil {
		panic("m.volume is nil!")
	}

	return m.folder.Delete(m.volume.ID, va.ServerID)
}

//GetAttachment return associated attachment (if any) to this volume
func (m *Volume) GetAttachment() (*api.VolumeAttachment, error) {
	if m.volume == nil {
		panic("m.volume is nil!")
	}

	var rv *api.VolumeAttachment
	err := m.folder.Browse(m.volume.ID, func(buf *bytes.Buffer) error {
		err := gob.NewDecoder(buf).Decode(&rv)
		if err != nil {
			return err
		}
		return nil
	})

	return rv, err
}

//SaveVolume saves the Volume definition in Object Storage
func SaveVolume(svc *providers.Service, volume *api.Volume) error {
	m, err := NewVolume(svc)
	if err != nil {
		return err
	}
	err = m.Carry(volume).Write()
	if err != nil {
		return err
	}
	return nil
}

//RemoveVolume removes the Volume definition from Object Storage
func RemoveVolume(svc *providers.Service, volumeID string) error {
	m, err := LoadVolume(svc, volumeID)
	if err != nil {
		return err
	}

	return m.Delete()
}

//LoadVolume gets the Volume definition from Object Storage
func LoadVolume(svc *providers.Service, ref string) (*Volume, error) {
	m, err := NewVolume(svc)
	if err != nil {
		return nil, err
	}
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
