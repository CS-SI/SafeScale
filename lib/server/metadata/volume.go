/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/loghelpers"
	"github.com/CS-SI/SafeScale/lib/utils/metadata"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
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
func NewVolume(svc iaas.Service) *Volume {
	return &Volume{
		item: metadata.NewItem(svc, volumesFolderName),
		name: nil,
		id:   nil,
	}
}

// Carry links a Volume instance to the Metadata instance
func (mv *Volume) Carry(volume *resources.Volume) *Volume {
	if volume == nil {
		panic("volume is nil!")
	}
	if volume.Properties == nil {
		volume.Properties = serialize.NewJSONProperties("resources")
	}
	mv.item.Carry(volume)
	mv.name = &volume.Name
	mv.id = &volume.ID
	return mv
}

// Get returns the Volume instance linked to metadata
func (mv *Volume) Get() *resources.Volume {
	if mv.item == nil {
		panic("mv.item is nil!")
	}
	if volume, ok := mv.item.Get().(*resources.Volume); ok {
		return volume
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

// Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (mv *Volume) Reload() error {
	if mv.item == nil {
		panic("mv.item is nil!")
	}
	err := mv.ReadByID(*mv.id)
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); ok {
			return utils.NotFoundError(fmt.Sprintf("metadata of volume '%s' vanished", *mv.name))
		}
		return err
	}
	return nil
}

// ReadByReference tries to read with 'ref' as id, then if not found as name
func (mv *Volume) ReadByReference(ref string) (err error) {
	errID := mv.ReadByID(ref)
	if errID != nil {
		errName := mv.ReadByName(ref)
		if errName != nil {
			return errName
		}
	}
	return nil
}

// ReadByID reads the metadata of a volume identified by ID from Object Storage
func (mv *Volume) ReadByID(id string) error {
	volume := resources.NewVolume()
	err := mv.item.ReadFrom(ByIDFolderName, id, func(buf []byte) (serialize.Serializable, error) {
		err := volume.Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return volume, nil
	})
	if err != nil {
		return err
	}

	mv.Carry(volume)
	return nil
}

// ReadByName reads the metadata of a volume identified by name
func (mv *Volume) ReadByName(name string) error {
	volume := resources.NewVolume()
	err := mv.item.ReadFrom(ByNameFolderName, name, func(buf []byte) (serialize.Serializable, error) {
		err := volume.Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return volume, nil
	})
	if err != nil {
		return err
	}

	mv.Carry(volume)
	return nil
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
	mv.item.Reset()
	mv.name = nil
	mv.id = nil
	return nil
}

// Browse walks through volume folder and executes a callback for each entries
func (mv *Volume) Browse(callback func(*resources.Volume) error) error {
	return mv.item.BrowseInto(ByIDFolderName, func(buf []byte) error {
		volume := resources.NewVolume()
		err := volume.Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(volume)
	})
}

// SaveVolume saves the Volume definition in Object Storage
func SaveVolume(svc iaas.Service, volume *resources.Volume) (*Volume, error) {
	mv := NewVolume(svc)
	return mv, mv.Carry(volume).Write()
}

// RemoveVolume removes the Volume definition from Object Storage
func RemoveVolume(svc iaas.Service, volumeID string) error {
	m, err := LoadVolume(svc, volumeID)
	if err != nil {
		return err
	}
	return m.Delete()
}

// LoadVolume gets the Volume definition from Object Storage
// logic: Read by ID; if error is ErrNotFound then read by name; if error is ErrNotFound return this error
//        In case of any other error, abort the retry to propagate the error
//        If retry times out, return errNotFound
func LoadVolume(svc iaas.Service, ref string) (mv *Volume, err error) {
	defer loghelpers.LogErrorCallback("", concurrency.NewTracer(nil, "("+ref+")"), &err)()

	if svc == nil {
		return nil, utils.InvalidParameterError("svc", "can't be nil")
	}
	if ref == "" {
		return nil, utils.InvalidParameterError("ref", "can't be empty string")
	}

	mv = NewVolume(svc)

	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr := mv.ReadByReference(ref)
			if innerErr != nil {
				if _, ok := innerErr.(utils.ErrNotFound); ok {
					return retry.StopRetryError("no metadata found", innerErr)
				}
				return innerErr
			}

			return nil
		},
		2*utils.GetDefaultDelay(),
	)
	if retryErr != nil {
		// If it's not a timeout is something we don't know how to handle yet
		if _, ok := retryErr.(utils.ErrTimeout); !ok {
			return nil, utils.Cause(retryErr)
		}
		return nil, retryErr
	}

	return mv, nil
}
