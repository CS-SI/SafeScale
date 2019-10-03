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
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/metadata"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
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
func NewVolume(svc iaas.Service) (*Volume, error) {
	aVol, err := metadata.NewItem(svc, volumesFolderName)
	if err != nil {
		return nil, err
	}
	return &Volume{
		item: aVol,
		name: nil,
		id:   nil,
	}, nil
}

// Carry links a Volume instance to the Metadata instance
func (mv *Volume) Carry(volume *resources.Volume) (*Volume, error) {
	if volume == nil {
		return nil, scerr.InvalidParameterError("volume", "cannot be nil!")
	}
	if volume.Properties == nil {
		volume.Properties = serialize.NewJSONProperties("resources")
	}
	mv.item.Carry(volume)
	mv.name = &volume.Name
	mv.id = &volume.ID
	return mv, nil
}

// Get returns the Volume instance linked to metadata
func (mv *Volume) Get() (*resources.Volume, error) {
	if mv.item == nil {
		return nil, scerr.InvalidInstanceErrorWithMessage("mv.item is nil!")
	}
	if volume, ok := mv.item.Get().(*resources.Volume); ok {
		return volume, nil
	}
	return nil, scerr.InvalidInstanceErrorWithMessage("invalid content in volume metadata")
}

// Write updates the metadata corresponding to the volume in the Object Storage
func (mv *Volume) Write() error {
	if mv.item == nil {
		return scerr.InvalidInstanceErrorWithMessage("mv.item cannot be nil!")
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
		return scerr.InvalidInstanceErrorWithMessage("mv.item cannot be nil!")
	}
	err := mv.ReadByID(*mv.id)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			return scerr.NotFoundError(fmt.Sprintf("metadata of volume '%s' vanished", *mv.name))
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

	_, err = mv.Carry(volume)
	if err != nil {
		return err
	}

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

	_, err = mv.Carry(volume)
	if err != nil {
		return err
	}

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
func SaveVolume(svc iaas.Service, volume *resources.Volume) (mv *Volume, err error) {
	mv, err = NewVolume(svc)
	if err != nil {
		return nil, err
	}

	vo, err := mv.Carry(volume)
	if err != nil {
		return nil, err
	}

	err = vo.Write()
	if err != nil {
		return nil, err
	}

	return mv, nil
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
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "can't be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "can't be empty string")
	}

	tracer := concurrency.NewTracer(nil, "("+ref+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mv, err = NewVolume(svc)
	if err != nil {
		return nil, err
	}

	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr := mv.ReadByReference(ref)
			if innerErr != nil {
				if _, ok := innerErr.(scerr.ErrNotFound); ok {
					return retry.StopRetryError("no metadata found", innerErr)
				}
				return innerErr
			}

			return nil
		},
		2*temporal.GetDefaultDelay(),
	)
	if retryErr != nil {
		// If it's not a timeout is something we don't know how to handle yet
		if _, ok := retryErr.(scerr.ErrTimeout); !ok {
			return nil, scerr.Cause(retryErr)
		}
		return nil, retryErr
	}

	return mv, nil
}
