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
	"fmt"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/utils/metadata"
)

const (
	// volumesFolderName is the technical name of the container used to store volume info
	volumesFolderName = "volumes"
)

// Volume links Object Storage folder and Volumes
type Volume struct {
	item *metadata.Item
	name *string
	id   *string
}

// NewVolume creates an instance of metadata.Volume
func NewVolume(svc api.ClientAPI) *Volume {
	return &Volume{
		item: metadata.NewItem(svc, volumesFolderName),
		name: nil,
		id:   nil,
	}
}

// Carry links a Volume instance to the Metadata instance
func (m *Volume) Carry(volume *model.Volume) *Volume {
	if volume == nil {
		panic("volume is nil!")
	}
	m.item.Carry(volume)
	m.name = &volume.Name
	m.id = &volume.ID
	return m
}

// Get returns the Volume instance linked to metadata
func (m *Volume) Get() *model.Volume {
	if volume, ok := m.item.Get().(*model.Volume); ok {
		return volume
	}
	panic("invalid content in volume metadata")
}

// Write updates the metadata corresponding to the volume in the Object Storage
func (m *Volume) Write() error {
	if m.item == nil {
		panic("m.item is nil!")
	}

	err := m.item.WriteInto(ByIDFolderName, *m.id)
	if err != nil {
		return err
	}
	return m.item.WriteInto(ByNameFolderName, *m.name)
}

// Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (m *Volume) Reload() error {
	if m.item == nil {
		panic("item is nil!")
	}
	found, err := m.ReadByID(*m.id)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("metadata of volume '%s' vanished", *m.name)
	}
	return nil
}

// ReadByID reads the metadata of a volume identified by ID from Object Storage
func (m *Volume) ReadByID(id string) (bool, error) {
	var volume model.Volume
	found, err := m.item.ReadFrom(ByIDFolderName, id, func(buf []byte) (model.Serializable, error) {
		err := (&volume).Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return &volume, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.Carry(&volume)
	return true, nil
}

// ReadByName reads the metadata of a volume identified by name
func (m *Volume) ReadByName(name string) (bool, error) {
	var volume model.Volume
	found, err := m.item.ReadFrom(ByNameFolderName, name, func(buf []byte) (model.Serializable, error) {
		err := (&volume).Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return &volume, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.Carry(&volume)
	return true, nil
}

// Delete delete the metadata corresponding to the volume
func (m *Volume) Delete() error {
	err := m.item.DeleteFrom(ByIDFolderName, *m.id)
	if err != nil {
		return err
	}
	err = m.item.DeleteFrom(ByNameFolderName, *m.name)
	if err != nil {
		return err
	}
	m.item = nil
	m.name = nil
	m.id = nil
	return nil
}

// Browse walks through volume folder and executes a callback for each entries
func (m *Volume) Browse(callback func(*model.Volume) error) error {
	return m.item.BrowseInto(ByIDFolderName, func(buf []byte) error {
		volume := model.Volume{}
		err := (&volume).Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(&volume)
	})
}

// Attach add a volume attachment to the volume definition in Object Storage
func (m *Volume) Attach(va *model.VolumeAttachment) error {
	if m.item == nil {
		panic("m.item is nil!")
	}
	data, err := va.Serialize()
	if err != nil {
		return err
	}
	return metadata.NewFolder(m.item.GetService(), m.item.GetPath()).Write(*m.id, va.ServerID, data)
}

// Detach remove a volume attachment from the volume definition in Object Storage
func (m *Volume) Detach(va *model.VolumeAttachment) error {
	if m.item == nil {
		panic("m.item is nil!")
	}
	return metadata.NewFolder(m.item.GetService(), m.item.GetPath()).Delete(*m.id, va.ServerID)
}

// GetAttachment return associated attachment (if any) to this volume
func (m *Volume) GetAttachment() (*model.VolumeAttachment, error) {
	if m.item == nil {
		panic("m.item is nil!")
	}

	var va model.VolumeAttachment
	err := metadata.NewFolder(m.item.GetService(), m.item.GetPath()).Browse(*m.id, func(buf []byte) error {
		return (&va).Deserialize(buf)
	})

	return &va, err
}

// SaveVolume saves the Volume definition in Object Storage
func SaveVolume(svc api.ClientAPI, volume *model.Volume) error {
	return NewVolume(svc).Carry(volume).Write()
}

// RemoveVolume removes the Volume definition from Object Storage
func RemoveVolume(svc api.ClientAPI, volumeID string) error {
	m, err := LoadVolume(svc, volumeID)
	if err != nil {
		return err
	}
	return m.Delete()
}

// LoadVolume gets the Volume definition from Object Storage
func LoadVolume(svc api.ClientAPI, ref string) (*Volume, error) {
	m := NewVolume(svc)
	found, err := m.ReadByID(ref)
	if err != nil {
		return nil, err
	}
	if !found {
		found, err = m.ReadByName(ref)
		if err != nil {
			return nil, err
		}
	}
	if !found {
		return nil, nil
	}
	return m, nil
}

// VolumeAttachment links Object Storage folder and VolumeAttachments
type VolumeAttachment struct {
	item     *metadata.Item
	serverID *string
	name     *string
	id       *string
}

// NewVolumeAttachment creates an instance of metadata.Volume
func NewVolumeAttachment(svc api.ClientAPI, vID string) *VolumeAttachment {
	return &VolumeAttachment{
		item:     metadata.NewItem(svc, fmt.Sprintf("%s/%s", volumesFolderName, vID)),
		serverID: nil,
		name:     nil,
		id:       nil,
	}
}

// Carry links a Volume instance to the Metadata instance
func (m *VolumeAttachment) Carry(va *model.VolumeAttachment) *VolumeAttachment {
	if va == nil {
		panic("volume is nil!")
	}
	m.item.Carry(va)
	m.serverID = &va.ServerID
	m.name = &va.Name
	m.id = &va.ID
	return m
}

// Get returns the Volume instance linked to metadata
func (m *VolumeAttachment) Get() *model.VolumeAttachment {
	if va, ok := m.item.Get().(*model.VolumeAttachment); ok {
		return va
	}
	panic("invalid content in volume attachment metadata")
}

// Write updates the metadata corresponding to the volume in the Object Storage
func (m *VolumeAttachment) Write() error {
	if m.item == nil {
		panic("m.item is nil!")
	}

	return m.item.WriteInto(".", *m.serverID)
}

// Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (m *VolumeAttachment) Reload() error {
	if m.item == nil {
		panic("item is nil!")
	}
	found, err := m.Read(*m.serverID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("metadata of volume attachment '%s' vanished", *m.name)
	}
	return nil
}

// Read reads the metadata of a volume attachment identified by ID from Object Storage
func (m *VolumeAttachment) Read(id string) (bool, error) {
	var va model.VolumeAttachment
	found, err := m.item.ReadFrom(".", id, func(buf []byte) (model.Serializable, error) {
		err := (&va).Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return &va, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.Carry(&va)
	return true, nil
}

// Delete delete the metadata corresponding to the volume
func (m *VolumeAttachment) Delete() error {
	err := m.item.DeleteFrom(".", *m.serverID)
	if err != nil {
		return err
	}
	m.item = nil
	m.name = nil
	m.id = nil
	return nil
}

// Browse walks through volume attachment folder and executes a callback for each entry
func (m *VolumeAttachment) Browse(callback func(*model.VolumeAttachment) error) error {
	return m.item.BrowseInto(".", func(buf []byte) error {
		va := model.VolumeAttachment{}
		err := (&va).Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(&va)
	})
}

// SaveVolumeAttachment saves the Volume Attachment definition in Object Storage
func SaveVolumeAttachment(svc *providers.Service, va *model.VolumeAttachment) error {
	return NewVolumeAttachment(svc, va.VolumeID).Carry(va).Write()
}

// RemoveVolumeAttachment removes the Volume Attachment definition from Object Storage
func RemoveVolumeAttachment(svc *providers.Service, hostID, volID string) error {
	m, err := LoadVolumeAttachment(svc, hostID, volID)
	if err != nil {
		return err
	}
	return m.Delete()
}

// LoadVolumeAttachment gets the Volume attachment definition from Object Storage
func LoadVolumeAttachment(svc *providers.Service, hostID, volID string) (*VolumeAttachment, error) {
	m := NewVolumeAttachment(svc, volID)
	found, err := m.Read(hostID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return m, nil
}
