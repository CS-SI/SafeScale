/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/graymeta/stow"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
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
	if svc == nil {
		return nil, scerr.InvalidInstanceError()
	}

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
	if mv == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if mv.item == nil {
		return nil, scerr.InvalidInstanceContentError("mv.item", "cannot be nil")
	}
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
	if mv == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if mv.item == nil {
		return nil, scerr.InvalidInstanceContentError("mv.item", "cannot be nil")
	}
	if volume, ok := mv.item.Get().(*resources.Volume); ok {
		return volume, nil
	}
	return nil, scerr.InconsistentError("invalid content in volume metadata")
}

// Write updates the metadata corresponding to the volume in the Object Storage
func (mv *Volume) Write() error {
	if mv == nil {
		return scerr.InvalidInstanceError()
	}
	if mv.item == nil {
		return scerr.InvalidInstanceContentError("mv.item", "cannot be nil!")
	}

	err := mv.item.WriteInto(ByIDFolderName, *mv.id)
	if err != nil {
		return err
	}
	return mv.item.WriteInto(ByNameFolderName, *mv.name)
}

// Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (mv *Volume) Reload() error {
	if mv == nil {
		return scerr.InvalidInstanceError()
	}
	if mv.item == nil {
		return scerr.InvalidInstanceContentError("mv.item", "cannot be nil")
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
	if mv == nil {
		return scerr.InvalidInstanceError()
	}
	if mv.item == nil {
		return scerr.InvalidInstanceContentError("mv.item", "cannot be nil")
	}
	if ref == "" {
		return scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "('"+ref+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogErrorWithLevel(tracer.TraceMessage(""), &err, logrus.TraceLevel)()

	var errors []error
	err1 := mv.mayReadByID(ref) // First read by ID ...
	if err1 != nil {
		errors = append(errors, err1)
	}

	err2 := mv.mayReadByName(ref) // ... then read by name only if by id failed (no need to read twice if the 2 exist)
	if err2 != nil {
		errors = append(errors, err2)
	}

	if len(errors) == 2 {
		if err1 == stow.ErrNotFound && err2 == stow.ErrNotFound { // FIXME: Remove stow dependency
			return scerr.NotFoundErrorWithCause(fmt.Sprintf("reference %s not found", ref), scerr.ErrListError(errors))
		}

		if _, ok := err1.(scerr.ErrNotFound); ok {
			if _, ok := err2.(scerr.ErrNotFound); ok {
				return scerr.NotFoundErrorWithCause(
					fmt.Sprintf("reference %s not found", ref), scerr.ErrListError(errors),
				)
			}
		}

		return scerr.ErrListError(errors)
	}

	return nil
}

// mayReadByID reads the metadata of a volume identified by ID from Object Storage
// Doesn't log error or validate parameters by design; caller does that
func (mv *Volume) mayReadByID(id string) error {
	volume := resources.NewVolume()
	err := mv.item.ReadFrom(
		ByIDFolderName, id, func(buf []byte) (serialize.Serializable, error) {
			err := volume.Deserialize(buf)
			if err != nil {
				return nil, err
			}
			return volume, nil
		},
	)
	if err != nil {
		return err
	}

	_, err = mv.Carry(volume)
	if err != nil {
		return err
	}

	return nil
}

// mayReadByName reads the metadata of a volume identified by name
// Doesn't log error or validate parameters by design; caller does that
func (mv *Volume) mayReadByName(name string) error {
	volume := resources.NewVolume()
	err := mv.item.ReadFrom(
		ByNameFolderName, name, func(buf []byte) (serialize.Serializable, error) {
			err := volume.Deserialize(buf)
			if err != nil {
				return nil, err
			}
			return volume, nil
		},
	)
	if err != nil {
		return err
	}

	_, err = mv.Carry(volume)
	if err != nil {
		return err
	}
	return nil
}

// ReadByID reads the metadata of a volume identified by ID from Object Storage
func (mv *Volume) ReadByID(id string) (err error) {
	if mv == nil {
		return scerr.InvalidInstanceError()
	}
	if mv.item == nil {
		return scerr.InvalidInstanceContentError("mv.item", "cannot be nil")
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "("+id+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	return mv.mayReadByID(id)
}

// ReadByName reads the metadata of a volume identified by name
func (mv *Volume) ReadByName(name string) (err error) {
	if mv == nil {
		return scerr.InvalidInstanceError()
	}
	if mv.item == nil {
		return scerr.InvalidInstanceContentError("mv.item", "cannot be nil")
	}
	if name == "" {
		return scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "('"+name+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	return mv.mayReadByName(name)
}

// Delete delete the metadata corresponding to the volume
func (mv *Volume) Delete() (err error) {
	if mv == nil {
		return scerr.InvalidInstanceError()
	}
	if mv.item == nil {
		return scerr.InvalidInstanceContentError("mv.item", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = mv.item.DeleteFrom(ByIDFolderName, *mv.id)
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
func (mv *Volume) Browse(callback func(*resources.Volume) error) (err error) {
	if mv == nil {
		return scerr.InvalidInstanceError()
	}
	if mv.item == nil {
		return scerr.InvalidInstanceContentError("mv.item", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	return mv.item.BrowseInto(
		ByIDFolderName, func(buf []byte) error {
			volume := resources.NewVolume()
			err := volume.Deserialize(buf)
			if err != nil {
				return err
			}
			return callback(volume)
		},
	)
}

// SaveVolume saves the Volume definition in Object Storage
func SaveVolume(svc iaas.Service, volume *resources.Volume) (mv *Volume, err error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if volume == nil {
		return nil, scerr.InvalidParameterError("volume", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "("+volume.Name+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

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
func RemoveVolume(svc iaas.Service, volumeID string) (err error) {
	if svc == nil {
		return scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if volumeID == "" {
		return scerr.InvalidParameterError("volumeID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "("+volumeID+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

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
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "("+ref+")", true).GoingIn()
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
					return retry.AbortedError("no metadata found", innerErr)
				}

				if innerErr == stow.ErrNotFound { // FIXME: Remove stow dependency
					return retry.AbortedError("no metadata found", innerErr)
				}

				return innerErr
			}
			return nil
		},
		2*temporal.GetDefaultDelay(),
	)
	if retryErr != nil {
		switch err := retryErr.(type) {
		case retry.ErrAborted:
			return nil, err.Cause()
		case scerr.ErrTimeout:
			return nil, err
		default:
			return nil, scerr.Cause(err)
		}
	}

	return mv, nil
}
