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
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/metadata"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// nasFolderName is the technical name of the container used to store nas info
	shareFolderName = "shares"
)

// Share contains information to maintain in Object Storage a list of shared folders
type Share struct {
	item *metadata.Item
	name *string
	id   *string
}

// NewShare creates an instance of metadata.Nas
func NewShare(svc iaas.Service) (*Share, error) {
	aShare, err := metadata.NewItem(svc, shareFolderName)
	if err != nil {
		return nil, err
	}
	return &Share{
		item: aShare,
	}, nil
}

type shareItem struct {
	HostID    string `json:"host_id"`    // contains the ID of the host serving the share
	HostName  string `json:"host_name"`  // contains the Name of the host serving the share
	ShareID   string `json:"share_id"`   // contains the ID of the share
	ShareName string `json:"share_name"` // contains the name of the share
}

// Serialize ...
func (n *shareItem) Serialize() ([]byte, error) {
	return serialize.ToJSON(n)
}

// Deserialize ...
func (n *shareItem) Deserialize(buf []byte) error {
	return serialize.FromJSON(buf, n)
}

// Carry links an export instance to the Metadata instance
func (ms *Share) Carry(hostID, hostName, shareID, shareName string) (*Share, error) {
	if ms == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ms.item == nil {
		return nil, fail.InvalidInstanceContentError("ms.item", "cannot be nil")
	}
	if hostID == "" {
		return nil, fail.InvalidParameterError("hostID", "cannot be empty string")
	}
	if hostName == "" {
		return nil, fail.InvalidParameterError("hostName", "cannot be empty string")
	}
	if shareID == "" {
		return nil, fail.InvalidParameterError("shareID", "cannot be empty string")
	}
	if shareName == "" {
		return nil, fail.InvalidParameterError("shareName", "cannot be empty string")
	}

	ni := shareItem{
		HostID:    hostID,
		HostName:  hostName,
		ShareID:   shareID,
		ShareName: shareName,
	}
	ms.item.Carry(&ni)
	ms.name = &ni.ShareName
	ms.id = &ni.ShareID
	return ms, nil
}

// Get returns the ID of the host owning the share
func (ms *Share) Get() (string, error) {
	if ms == nil {
		return "", fail.InvalidInstanceError()
	}
	if ms.item == nil {
		return "", fail.InvalidInstanceContentError("ms.item", "cannot be nil")
	}
	if ei, ok := ms.item.Get().(*shareItem); ok {
		return ei.HostName, nil
	}

	return "", fail.InconsistentError("share metadata content must be a *shareItem")
}

// Write updates the metadata corresponding to the share in the Object Storage
func (ms *Share) Write() error {
	if ms == nil {
		return fail.InvalidInstanceError()
	}
	if ms.item == nil {
		return fail.InvalidInstanceContentError("ms.item", "cannot be nil")
	}
	err := ms.item.WriteInto(ByIDFolderName, *ms.id)
	if err != nil {
		return err
	}
	return ms.item.WriteInto(ByNameFolderName, *ms.name)
}

// ReadByReference tries to read 'ref' as an ID, and if not found as a name
func (ms *Share) ReadByReference(ref string) (err error) {
	if ms == nil {
		return fail.InvalidInstanceError()
	}
	if ms.item == nil {
		return fail.InvalidInstanceContentError("ms.item", "cannot be nil")
	}
	if ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "('"+ref+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogErrorWithLevel(tracer.TraceMessage(""), &err, logrus.TraceLevel)()

	var errors []error
	err1 := ms.mayReadByID(ref) // First read by id ...
	if err1 != nil {
		errors = append(errors, err1)
	}

	err2 := ms.mayReadByName(ref) // ... then read by name if by id failed (no need to read twice)
	if err2 != nil {
		errors = append(errors, err2)
	}

	if len(errors) == 2 {
		if err1 == stow.ErrNotFound && err2 == stow.ErrNotFound { // FIXME: Remove stow dependency
			return fail.NotFoundErrorWithCause(fmt.Sprintf("reference %s not found", ref), fail.ErrListError(errors))
		}

		if _, ok := err1.(fail.ErrNotFound); ok {
			if _, ok := err2.(fail.ErrNotFound); ok {
				return fail.NotFoundErrorWithCause(
					fmt.Sprintf("reference %s not found", ref), fail.ErrListError(errors),
				)
			}
		}

		return fail.ErrListError(errors)
	}

	return nil
}

// mayReadByID reads the metadata of an export identified by ID from Object Storage
// Doesn't log error or validate parameters by design; caller does that
func (ms *Share) mayReadByID(id string) error {
	var si shareItem
	err := ms.item.ReadFrom(
		ByIDFolderName, id, func(buf []byte) (serialize.Serializable, error) {
			err := (&si).Deserialize(buf)
			if err != nil {
				return nil, err
			}
			return &si, nil
		},
	)
	if err != nil {
		return err
	}
	if _, err := ms.Carry(si.HostID, si.HostName, si.ShareID, si.ShareName); err != nil {
		return err
	}
	return nil
}

// mayReadByName reads the metadata of a nas identified by name
// Doesn't log or validate parameters by design; caller does that
func (ms *Share) mayReadByName(name string) error {
	var si shareItem
	err := ms.item.ReadFrom(
		ByNameFolderName, name, func(buf []byte) (serialize.Serializable, error) {
			err := (&si).Deserialize(buf)
			if err != nil {
				return nil, err
			}
			return &si, nil
		},
	)
	if err != nil {
		return err
	}
	if _, err := ms.Carry(si.HostID, si.HostName, si.ShareID, si.ShareName); err != nil {
		return err
	}
	return nil
}

// ReadByID reads the metadata of an export identified by ID from Object Storage
func (ms *Share) ReadByID(id string) (err error) {
	if ms == nil {
		return fail.InvalidInstanceError()
	}
	if ms.item == nil {
		return fail.InvalidInstanceContentError("ms.item", "cannot be nil")
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "("+id+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	return ms.mayReadByID(id)
}

// ReadByName reads the metadata of a nas identified by name
func (ms *Share) ReadByName(name string) (err error) {
	if ms == nil {
		return fail.InvalidInstanceError()
	}
	if ms.item == nil {
		return fail.InvalidInstanceContentError("ms.item", "cannot be nil")
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "('"+name+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	return ms.mayReadByName(name)
}

// Delete updates the metadata corresponding to the share
func (ms *Share) Delete() error {
	if ms == nil {
		return fail.InvalidInstanceError()
	}
	if ms.item == nil {
		return fail.InvalidInstanceContentError("ms.item", "cannot be nil")
	}
	err := ms.item.DeleteFrom(ByIDFolderName, *ms.id)
	if err != nil {
		return err
	}
	return ms.item.DeleteFrom(ByNameFolderName, *ms.name)
}

// Browse walks through shares folder and executes a callback for each entry
func (ms *Share) Browse(callback func(string, string) error) error {
	if ms == nil {
		return fail.InvalidInstanceError()
	}
	if ms.item == nil {
		return fail.InvalidInstanceContentError("ms.item", "cannot be nil")
	}
	return ms.item.BrowseInto(
		ByNameFolderName, func(buf []byte) error {
			si := shareItem{}
			err := (&si).Deserialize(buf)
			if err != nil {
				return err
			}
			return callback(si.HostName, si.ShareID)
		},
	)
}

// // AddClient adds a client to the Nas definition in Object Storage
// func (m *Nas) AddClient(nas *abstract.Nas) error {
// 	return NewNas(m.item.GetService()).Carry(nas).item.WriteInto(*m.id, nas.ID)
// 	// return m.item.WriteInto(m.id, nas.ID)
// }

// // RemoveClient removes a client to the Nas definition in Object Storage
// func (m *Nas) RemoveClient(nas *abstract.Nas) error {
// 	return m.item.DeleteFrom(*m.id, nas.ID)
// }

// // Listclients returns the list of ID of hosts clients of the NAS server
// func (m *Nas) Listclients() ([]*abstract.Nas, error) {
// 	var list []*abstract.Nas
// 	err := m.item.BrowseInto(*m.id, func(buf []byte) error {
// 		nas := abstract.Nas{}
// 		err := (&nas).Deserialize(buf)
// 		if err != nil {
// 			return err
// 		}
// 		list = append(list, &nas)
// 		return nil
// 	})
// 	return list, err
// }

// // FindClient returns the client hosted by the Host whose name is given
// func (m *Nas) FindClient(hostName string) (*abstract.Nas, error) {
// 	var client *abstract.Nas
// 	err := m.item.BrowseInto(*m.id, func(buf []byte) error {
// 		nas := abstract.Nas{}
// 		err := (&nas).Deserialize(buf)
// 		if err != nil {
// 			return err
// 		}
// 		if nas.Host == hostName {
// 			client = &nas
// 			return nil
// 		}
// 		return nil
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	if client == nil {
// 		return nil, fmt.Errorf("no client found for nas '%s' on host '%s'", *m.name, hostName)
// 	}
// 	return client, nil
// }

// Acquire waits until the write lock is available, then locks the metadata.
//
// May panic (see fail.OnPanic() usage to intercept and translate it to an error)
func (ms *Share) Acquire() {
	if ms == nil {
		panic("invalid instance")
	}
	if ms.item == nil {
		panic("invalid instance content: ms.item cannot be nil")
	}
	ms.item.Acquire()
}

// Release unlocks the metadata
//
// May panic (see fail.OnPanic() usage to intercept and translate it to an error)
func (ms *Share) Release() {
	if ms == nil {
		panic("invalid instance")
	}
	if ms.item == nil {
		panic("invalid instance content: ms.item cannot be nil")
	}
	ms.item.Release()
}

// SaveShare saves the Nas definition in Object Storage
func SaveShare(svc iaas.Service, hostID, hostName, shareID, shareName string) (*Share, error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if hostID == "" {
		return nil, fail.InvalidParameterError("hostID", "cannot be empty string")
	}
	if hostName == "" {
		return nil, fail.InvalidParameterError("hostName", "cannot be empty string")
	}
	if shareID == "" {
		return nil, fail.InvalidParameterError("shareID", "cannot be empty string")
	}
	if shareName == "" {
		return nil, fail.InvalidParameterError("shareName", "cannot be empty string")
	}

	aShare, err := NewShare(svc)
	if err != nil {
		return nil, err
	}
	ms, err := aShare.Carry(hostID, hostName, shareID, shareName)
	if err != nil {
		return nil, err
	}
	return ms, ms.Write()
}

// RemoveShare removes the share definition from Object Storage
func RemoveShare(svc iaas.Service, hostID, hostName, shareID, shareName string) error {
	if svc == nil {
		return fail.InvalidParameterError("svc", "cannot be nil")
	}
	if hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}
	if hostName == "" {
		return fail.InvalidParameterError("hostName", "cannot be empty string")
	}
	if shareID == "" {
		return fail.InvalidParameterError("shareID", "cannot be empty string")
	}
	if shareName == "" {
		return fail.InvalidParameterError("shareName", "cannot be empty string")
	}

	aShare, err := NewShare(svc)
	if err != nil {
		return err
	}

	aShare, err = aShare.Carry(hostID, hostName, shareID, shareName)
	if err != nil {
		return err
	}

	return aShare.Delete()
}

// LoadShare returns the name of the host owing the share 'ref', read from Object Storage
// logic: Read by ID; if error is ErrNotFound then read by name; if error is ErrNotFound return this error
//        In case of any other error, abort the retry to propagate the error
//        If retry times out, return errNotFound
func LoadShare(svc iaas.Service, ref string) (share string, err error) {
	if svc == nil {
		return "", fail.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return "", fail.InvalidParameterError("ref", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "(<svc>, '"+ref+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	ms, err := NewShare(svc)
	if err != nil {
		return "", err
	}

	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr := ms.ReadByReference(ref)
			if innerErr != nil {
				if _, ok := innerErr.(fail.ErrNotFound); ok {
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
	// If retry timed out, log it and return error ErrNotFound
	if retryErr != nil {
		switch realErr := retryErr.(type) {
		case retry.ErrAborted:
			return "", realErr.Cause()
		case fail.ErrTimeout:
			return "", realErr
		default:
			return "", fail.Cause(realErr)
		}
	}

	return ms.Get()
}

// // MountNas add the client nas to the Nas definition from Object Storage
// func MountNas(svc *providers.Service, client *abstract.Nas, server *abstract.Nas) error {
// 	return NewNas(svc).Carry(server).AddClient(client)
// }

// // UmountNas remove the client nas to the Nas definition from Object Storage
// func UmountNas(svc *providers.Service, client *abstract.Nas, server *abstract.Nas) error {
// 	return NewNas(svc).Carry(server).RemoveClient(client)
// }
