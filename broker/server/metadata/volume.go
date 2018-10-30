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

	"github.com/CS-SI/SafeScale/utils/metadata"

	"github.com/CS-SI/SafeScale/providers"
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
func NewVolume(svc *provider.Service) *Volume {
	return &Volume{
		item: metadata.NewItem(svc, volumesFolderName),
		name: nil,
		id:   nil,
	}
}

// Carry links a Volume instance to the Metadata instance
func (mv *Volume) Carry(pbv *pb.Volume) *Volume {
	if pbv == nil {
		panic("pbv is nil!")
	}
	mv.item.Carry(pbv)
	mv.name = &pbv.Name
	mv.id = &pbv.ID
	return mv
}

// Get returns the Volume instance linked to metadata
func (mv *Volume) Get() *pb.Volume {
	if pbv, ok := mv.item.Get().(*pb.Volume); ok {
		return pbv
	}
	panic("invalid content in volume metadata")
}

// Write updates the metadata corresponding to the volume in the Object Storage
func (mv *Volume) Write() error {
	if mv.item == nil {
		panic("mv.item is nil!")
	}

	err := mv.item.WriteInto(ByIDFolderName, *mv.id)
	if err != nil {
		return err
	}
	return mv.item.WriteInto(ByNameFolderName, *mv.name)
}

// Reload reloads the content of the volume, overriding what is in the metadata instance
func (mv *Volume) Reload() error {
	if mv.item == nil {
		panic("mv.item is nil!")
	}
	found, err := mv.ReadByID(*mv.id)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("metadata of volume '%s' vanished", *mv.name)
	}
	return nil
}

// ReadByID reads the metadata of a volume identified by ID from Object Storage
func (mv *Volume) ReadByID(id string) (bool, error) {
	var data pb.Volume
	found, err := mv.item.ReadFrom(ByIDFolderName, id, func(buf *bytes.Buffer) (interface{}, error) {
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
	mv.id = &data.ID
	mv.name = &data.Name
	return true, nil
}

// ReadByName reads the metadata of a volume identified by name
func (mv *Volume) ReadByName(name string) (bool, error) {
	var data pb.Volume
	found, err := mv.item.ReadFrom(ByNameFolderName, name, func(buf *bytes.Buffer) (interface{}, error) {
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
	mv.id = &data.ID
	mv.name = &data.Name
	return true, nil
}

// Delete delete the metadata corresponding to the volume
func (mv *Volume) Delete() error {
	err := mv.item.DeleteFrom(ByIDFolderName, *mv.id)
	if err != nil {
		return err
	}
	err = mv.item.DeleteFrom(ByNameFolderName, *mv.name)
	if err != nil {
		return err
	}
	mv.item = nil
	mv.name = nil
	mv.id = nil
	return nil
}

// Browse walks through volume folder and executes a callback for each entries
func (mv *Volume) Browse(callback func(*pb.Volume) error) error {
	return mv.item.BrowseInto(ByIDFolderName, func(buf *bytes.Buffer) error {
		var data pb.Volume
		err := gob.NewDecoder(buf).Decode(&data)
		if err != nil {
			return err
		}
		return callback(&data)
	})
}

// Attach add a volume attachment to the volume definition in Object Storage
func (mv *Volume) Attach(pbva *pb.VolumeAttachment) error {
	if mv.item == nil {
		panic("mv.item is nil!")
	}
	return metadata.NewFolder(mv.item.GetService(), mv.item.GetPath()).Write(*mv.id, pbva.ServerID, pbva)
}

// Detach remove a volume attachment from the volume definition in Object Storage
func (mv *Volume) Detach(pbva *pb.VolumeAttachment) error {
	if mv.item == nil {
		panic("mv.item is nil!")
	}
	return metadata.NewFolder(mv.item.GetService(), mv.item.GetPath()).Delete(*mv.id, pbva.ServerID)
}

// GetAttachment return associated attachment (if any) to this volume
func (mv *Volume) GetAttachment() (*pb.VolumeAttachment, error) {
	if mv.item == nil {
		panic("mv.item is nil!")
	}

	var data pb.VolumeAttachment
	err := metadata.NewFolder(mv.item.GetService(), mv.item.GetPath()).Browse(*mv.id, func(buf *bytes.Buffer) error {
		return gob.NewDecoder(buf).Decode(&data)
	})

	return &data, err
}

// SaveVolume saves the Volume definition in Object Storage
func SaveVolume(svc *provider.Service, volume *pb.Volume) error {
	return NewVolume(svc).Carry(volume).Write()
}

// RemoveVolume removes the Volume definition from Object Storage
func RemoveVolume(svc *provider.Service, volumeID string) error {
	mv, err := LoadVolume(svc, volumeID)
	if err != nil {
		return err
	}
	return mv.Delete()
}

// LoadVolume gets the Volume definition from Object Storage
func LoadVolume(svc *provider.Service, ref string) (*Volume, error) {
	mv := NewVolume(svc)
	found, err := mv.ReadByID(ref)
	if err != nil {
		return nil, err
	}
	if !found {
		found, err = mv.ReadByName(ref)
		if err != nil {
			return nil, err
		}
	}
	if !found {
		return nil, nil
	}
	return mv, nil
}

// VolumeAttachment links Object Storage folder and VolumeAttachments
type VolumeAttachment struct {
	item     *metadata.Item
	serverID *string
	name     *string
	id       *string
}

// NewVolumeAttachment creates an instance of metadata.VolumeAttachment
func NewVolumeAttachment(svc *providers.Service, volumeID string) *VolumeAttachment {
	return &VolumeAttachment{
		item:     metadata.NewItem(svc, fmt.Sprintf("%s/%s", volumesFolderName, volumeID)),
		serverID: nil,
		name:     nil,
		id:       nil,
	}
}

// Carry links a Volume instance to the Metadata instance
func (mva *VolumeAttachment) Carry(pbva *pb.VolumeAttachment) *VolumeAttachment {
	if pbva == nil {
		panic("pbva is nil!")
	}
	mva.item.Carry(pbva)
	mva.serverID = &pbva.ServerID
	mva.name = &pbva.Name
	mva.id = &pbva.ID
	return mva
}

// Get returns the Volume instance linked to metadata
func (mva *VolumeAttachment) Get() *pb.VolumeAttachment {
	if pbva, ok := mva.item.Get().(*pb.VolumeAttachment); ok {
		return pbva
	}
	panic("invalid content in volume attachment metadata")
}

// Write updates the metadata corresponding to the volume in the Object Storage
func (mva *VolumeAttachment) Write() error {
	if mva.item == nil {
		panic("mva.item is nil!")
	}
	return mva.item.WriteInto(".", *mva.serverID)
}

// Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (mva *VolumeAttachment) Reload() error {
	if mva.item == nil {
		panic("mva.item is nil!")
	}
	found, err := mva.Read(*mva.serverID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("metadata of volume attachment '%s' vanished", *mva.name)
	}
	return nil
}

// Read reads the metadata of a volume attachment identified by ID from Object Storage
func (mva *VolumeAttachment) Read(id string) (bool, error) {
	var pbva pb.VolumeAttachment
	found, err := mva.item.ReadFrom(".", id, func(buf *bytes.Buffer) (interface{}, error) {
		err := gob.NewDecoder(buf).Decode(&pbva)
		if err != nil {
			return nil, err
		}
		return &pbva, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	mva.id = &pbva.ID
	mva.name = &pbva.Name
	return true, nil
}

// Delete delete the metadata corresponding to the volume
func (mva *VolumeAttachment) Delete() error {
	if mva.item == nil {
		panic("mva.item is nil!")
	}
	err := mva.item.DeleteFrom(".", *mva.serverID)
	if err != nil {
		return err
	}
	mva.item = nil
	mva.name = nil
	mva.id = nil
	return nil
}

// Browse walks through volume attachment folder and executes a callback for each entry
func (mva *VolumeAttachment) Browse(callback func(*pb.VolumeAttachment) error) error {
	return mva.item.BrowseInto(".", func(buf *bytes.Buffer) error {
		var pbva pb.VolumeAttachment
		err := gob.NewDecoder(buf).Decode(&pbva)
		if err != nil {
			return err
		}
		return callback(&pbva)
	})
}

// SaveVolumeAttachment saves the Volume Attachment definition in Object Storage
func SaveVolumeAttachment(svc provider.Service, pbva *pb.VolumeAttachment) error {
	return NewVolumeAttachment(svc, pbva.VolumeID).Carry(pbva).Write()
}

// RemoveVolumeAttachment removes the Volume Attachment definition from Object Storage
func RemoveVolumeAttachment(svc provider.Service, hostID, volID string) error {
	mva, err := LoadVolumeAttachment(svc, hostID, volID)
	if err != nil {
		return err
	}
	return mva.Delete()
}

// LoadVolumeAttachment gets the Volume attachment definition from Object Storage
func LoadVolumeAttachment(svc provider.Service, hostID, volID string) (*VolumeAttachment, error) {
	mva := NewVolumeAttachment(svc, volID)
	found, err := mva.Read(hostID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return m, nil
}
