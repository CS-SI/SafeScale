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

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/debug"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/utils/metadata"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// hostsFolderName is the technical name of the container used to store networks info
	hostsFolderName = "hosts"
)

// Host links Object Storage folder and Network
type Host struct {
	item *metadata.Item
	name *string
	id   *string
}

// NewHost creates an instance of api.Host
func NewHost(svc iaas.Service) (*Host, error) {
	aHost, err := metadata.NewItem(svc, hostsFolderName)
	if err != nil {
		return nil, err
	}

	return &Host{
		item: aHost,
	}, nil
}

func (mh *Host) OK() (bool, error) {
	if mh == nil {
		return false, scerr.InvalidInstanceError()
	}

	if mh.id == nil && mh.name == nil {
		if mh.item == nil {
			return false, nil
		}

		if ok, err := mh.item.OK(); err != nil || !ok {
			return false, nil
		}
	}

	return true, nil
}

// Carry links an host instance to the Metadata instance
func (mh *Host) Carry(host *resources.Host) (*Host, error) {
	if host == nil {
		return nil, scerr.InvalidParameterError("host", "cannot be nil!")
	}
	if host.Properties == nil {
		host.Properties = serialize.NewJSONProperties("resources")
	}
	mh.item.Carry(host)
	mh.name = &host.Name
	mh.id = &host.ID
	return mh, nil
}

// Get returns the Network instance linked to metadata
func (mh *Host) Get() (*resources.Host, error) {
	if mh == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if mh.item == nil {
		return nil, scerr.InvalidParameterError("mh.item", "cannot be nil")
	}

	gh := mh.item.Get().(*resources.Host)
	return gh, nil
}

// Write updates the metadata corresponding to the host in the Object Storage
func (mh *Host) Write() (err error) {
	if mh == nil {
		return scerr.InvalidInstanceError()
	}
	if mh.item == nil {
		return scerr.InvalidParameterError("m.item", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "('"+*mh.id+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = mh.item.WriteInto(ByNameFolderName, *mh.name)
	if err != nil {
		return err
	}
	return mh.item.WriteInto(ByIDFolderName, *mh.id)
}

// ReadByReference ...
func (mh *Host) ReadByReference(ref string) (err error) {
	if mh == nil {
		return scerr.InvalidInstanceError()
	}
	if mh.item == nil {
		return scerr.InvalidInstanceContentError("mh.item", "cannot be nil")
	}
	if ref == "" {
		return scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "("+ref+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogErrorWithLevel(tracer.TraceMessage(""), &err, logrus.TraceLevel)()

	var errors []error
	err = mh.mayReadByID(ref) // First read by ID ...
	if err != nil {
		errors = append(errors, err)
		err = mh.mayReadByName(ref) // ... then read by name if by id failed (no need to read twice if the 2 exist)
		if err != nil {
			errors = append(errors, err)
		}
	}
	if err != nil {
		return scerr.NotFoundErrorWithCause(fmt.Sprintf("reference %s not found", ref), scerr.ErrListError(errors))
	}

	return nil
}

// mayReadByID reads the metadata of a network identified by ID from Object Storage
// Doesn't log error or validate parameter by design; caller does that
func (mh *Host) mayReadByID(id string) (err error) {
	host := resources.NewHost()
	err = mh.item.ReadFrom(
		ByIDFolderName, id, func(buf []byte) (serialize.Serializable, error) {
			err := host.Deserialize(buf)
			if err != nil {
				return nil, err
			}
			return host, nil
		},
	)
	if err != nil {
		return err
	}
	mh.id = &(host.ID)
	mh.name = &(host.Name)
	return nil
}

// mayReadByName reads the metadata of a host identified by name
// Doesn't log error or validate parameter by design; caller does that
func (mh *Host) mayReadByName(name string) (err error) {
	host := resources.NewHost()
	err = mh.item.ReadFrom(
		ByNameFolderName, name, func(buf []byte) (serialize.Serializable, error) {
			err := host.Deserialize(buf)
			if err != nil {
				return nil, err
			}
			return host, nil
		},
	)
	if err != nil {
		return err
	}
	mh.name = &(host.Name)
	mh.id = &(host.ID)
	return nil
}

// ReadByID reads the metadata of a network identified by ID from Object Storage
func (mh *Host) ReadByID(id string) (err error) {
	if mh == nil {
		return scerr.InvalidInstanceError()
	}
	if mh.item == nil {
		return scerr.InvalidInstanceContentError("mh.item", "cannot be nil")
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "("+id+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogErrorWithLevel(tracer.TraceMessage(""), &err, logrus.TraceLevel)()

	return mh.mayReadByID(id)
}

// ReadByName reads the metadata of a host identified by name
func (mh *Host) ReadByName(name string) (err error) {
	if mh == nil {
		return scerr.InvalidInstanceError()
	}
	if mh.item == nil {
		return scerr.InvalidParameterError("mh.item", "cannot be nil")
	}
	if name == "" {
		return scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "('"+name+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogErrorWithLevel(tracer.TraceMessage(""), &err, logrus.TraceLevel)()

	return mh.mayReadByName(name)
}

// Delete updates the metadata corresponding to the host
func (mh *Host) Delete() (err error) {
	if mh == nil {
		return scerr.InvalidInstanceError()
	}
	if mh.item == nil {
		return scerr.InvalidParameterError("mh.item", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogErrorWithLevel(tracer.TraceMessage(""), &err, logrus.TraceLevel)()

	err1 := mh.item.DeleteFrom(ByIDFolderName, *mh.id)
	err2 := mh.item.DeleteFrom(ByNameFolderName, *mh.name)

	if err1 != nil && err2 != nil {
		return scerr.ErrListError([]error{err1, err2})
	}

	return nil
}

// Browse walks through host folder and executes a callback for each entries
func (mh *Host) Browse(callback func(*resources.Host) error) (err error) {
	if mh == nil {
		return scerr.InvalidInstanceError()
	}
	if mh.item == nil {
		return scerr.InvalidParameterError("mh.item", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogErrorWithLevel(tracer.TraceMessage(""), &err, logrus.TraceLevel)()

	return mh.item.BrowseInto(
		ByIDFolderName, func(buf []byte) error {
			host := resources.NewHost()
			err := host.Deserialize(buf)
			if err != nil {
				return err
			}
			return callback(host)
		},
	)
}

// SaveHost saves the Host definition in Object Storage
func SaveHost(svc iaas.Service, host *resources.Host) (mh *Host, err error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if host == nil {
		return nil, scerr.InvalidParameterError("host", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogErrorWithLevel(tracer.TraceMessage(""), &err, logrus.TraceLevel)()

	mh, err = NewHost(svc)
	if err != nil {
		return nil, err
	}

	ch, err := mh.Carry(host)
	if err != nil {
		return nil, err
	}

	err = ch.Write()
	if err != nil {
		return nil, err
	}
	// mn := NewNetwork(svc)
	// err = host.Properties.LockForRead(hostproperty.NetworkV1).ThenUse(func(v interface{}) error {
	// 	hostNetworkV1 := v.(*propsv1.HostNetwork)
	// 	for netID := range hostNetworkV1.NetworksByID {
	// 		err := mn.ReadByID(netID)
	// 		if err != nil {
	// 			return err
	// 		}
	// 		err = mn.AttachHost(host)
	// 		if err != nil {
	// 			return err
	// 		}
	// 	}
	// 	return nil
	// })
	// if err != nil {
	// 	return nil, err
	// }
	return mh, nil
}

// RemoveHost removes the host definition from Object Storage
func RemoveHost(svc iaas.Service, host *resources.Host) (err error) {
	if svc == nil {
		return scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if host == nil {
		return scerr.InvalidParameterError("host", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogErrorWithLevel(tracer.TraceMessage(""), &err, logrus.TraceLevel)()

	mh, err := NewHost(svc)
	if err != nil {
		return err
	}

	ch, err := mh.Carry(host)
	if err != nil {
		return err
	}

	return ch.Delete()
}

// LoadHost gets the host definition from Object Storage
// logic: Read by ID; if error is ErrNotFound then read by name; if error is ErrNotFound return this error
//        In case of any other error, abort the retry to propagate the error
//        If retry times out, return errNotFound
func LoadHost(svc iaas.Service, ref string) (mh *Host, err error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "("+ref+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogErrorWithLevel(tracer.TraceMessage(""), &err, logrus.TraceLevel)()

	// We first try looking for host by ID from metadata
	mh, err = NewHost(svc)
	if err != nil {
		return nil, err
	}

	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr := mh.ReadByReference(ref)
			if innerErr != nil {
				// If error is ErrNotFound, instructs retry to stop without delay
				if _, ok := innerErr.(scerr.ErrNotFound); ok {
					return retry.AbortedError("no metadata found", innerErr)
				}
				return innerErr
			}
			return nil
		},
		2*temporal.GetDefaultDelay(),
	)
	if retryErr != nil {
		switch realErr := retryErr.(type) {
		case retry.ErrAborted:
			return nil, realErr.Cause()
		case scerr.ErrTimeout:
			return nil, realErr
		default:
			return nil, scerr.Cause(realErr)
		}
	}

	return mh, nil
}

// Acquire waits until the write lock is available, then locks the metadata
func (mh *Host) Acquire() {
	mh.item.Acquire()
}

// Release unlocks the metadata
func (mh *Host) Release() {
	mh.item.Release()
}
