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
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/metadata"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
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
		return nil, scerr.InvalidInstanceError()
	}
	if ms.item == nil {
		return nil, scerr.InvalidInstanceContentError("ms.item", "cannot be nil")
	}
	if hostID == "" {
		return nil, scerr.InvalidParameterError("hostID", "cannot be empty string")
	}
	if hostName == "" {
		return nil, scerr.InvalidParameterError("hostName", "cannot be empty string")
	}
	if shareID == "" {
		return nil, scerr.InvalidParameterError("shareID", "cannot be empty string")
	}
	if shareName == "" {
		return nil, scerr.InvalidParameterError("shareName", "cannot be empty string")
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
		return "", scerr.InvalidInstanceError()
	}
	if ms.item == nil {
		return "", scerr.InvalidInstanceContentError("ms.item", "cannot be nil")
	}
	if ei, ok := ms.item.Get().(*shareItem); ok {
		return ei.HostName, nil
	}

	return "", scerr.InconsistentError("share metadata content must be a *shareItem")
}

// Write updates the metadata corresponding to the share in the Object Storage
func (ms *Share) Write() error {
	if ms == nil {
		return scerr.InvalidInstanceError()
	}
	if ms.item == nil {
		return scerr.InvalidInstanceContentError("ms.item", "cannot be nil")
	}
	err := ms.item.WriteInto(ByIDFolderName, *ms.id)
	if err != nil {
		return err
	}
	return ms.item.WriteInto(ByNameFolderName, *ms.name)
}

// ReadByReference tries to read 'ref' as an ID, and if not found as a name
func (ms *Share) ReadByReference(id string) (err error) {
	if ms == nil {
		return scerr.InvalidInstanceError()
	}
	errID := ms.ReadByID(id)
	if errID != nil {
		errName := ms.ReadByName(id)
		if errName != nil {
			return errName
		}
	}
	return nil
}

// ReadByID reads the metadata of an export identified by ID from Object Storage
func (ms *Share) ReadByID(id string) (err error) {
	if ms == nil {
		return scerr.InvalidInstanceError()
	}
	if ms.item == nil {
		return scerr.InvalidInstanceContentError("ms.item", "cannot be nil")
	}
	var si shareItem
	err = ms.item.ReadFrom(ByIDFolderName, id, func(buf []byte) (serialize.Serializable, error) {
		err := (&si).Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return &si, nil
	})
	if err != nil {
		return err
	}
	if _, err := ms.Carry(si.HostID, si.HostName, si.ShareID, si.ShareName); err != nil {
		return err
	}
	return nil
}

// ReadByName reads the metadata of a nas identified by name
func (ms *Share) ReadByName(name string) (err error) {
	if ms == nil {
		return scerr.InvalidInstanceError()
	}
	if ms.item == nil {
		return scerr.InvalidInstanceContentError("ms.item", "cannot be nil")
	}
	var si shareItem
	err = ms.item.ReadFrom(ByNameFolderName, name, func(buf []byte) (serialize.Serializable, error) {
		err := (&si).Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return &si, nil
	})
	if err != nil {
		return err
	}
	if _, err := ms.Carry(si.HostID, si.HostName, si.ShareID, si.ShareName); err != nil {
		return err
	}
	return nil
}

// Delete updates the metadata corresponding to the share
func (ms *Share) Delete() error {
	if ms == nil {
		return scerr.InvalidInstanceError()
	}
	if ms.item == nil {
		return scerr.InvalidInstanceContentError("ms.item", "cannot be nil")
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
		return scerr.InvalidInstanceError()
	}
	if ms.item == nil {
		return scerr.InvalidInstanceContentError("ms.item", "cannot be nil")
	}
	return ms.item.BrowseInto(ByNameFolderName, func(buf []byte) error {
		si := shareItem{}
		err := (&si).Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(si.HostName, si.ShareID)
	})
}

// // AddClient adds a client to the Nas definition in Object Storage
// func (m *Nas) AddClient(nas *resources.Nas) error {
// 	return NewNas(m.item.GetService()).Carry(nas).item.WriteInto(*m.id, nas.ID)
// 	// return m.item.WriteInto(m.id, nas.ID)
// }

// // RemoveClient removes a client to the Nas definition in Object Storage
// func (m *Nas) RemoveClient(nas *resources.Nas) error {
// 	return m.item.DeleteFrom(*m.id, nas.ID)
// }

// // Listclients returns the list of ID of hosts clients of the NAS server
// func (m *Nas) Listclients() ([]*resources.Nas, error) {
// 	var list []*resources.Nas
// 	err := m.item.BrowseInto(*m.id, func(buf []byte) error {
// 		nas := resources.Nas{}
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
// func (m *Nas) FindClient(hostName string) (*resources.Nas, error) {
// 	var client *resources.Nas
// 	err := m.item.BrowseInto(*m.id, func(buf []byte) error {
// 		nas := resources.Nas{}
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
// May panic (see scerr.OnPanic() usage to intercept and translate it to an error)
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
// May panic (see scerr.OnPanic() usage to intercept and translate it to an error)
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
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if hostID == "" {
		return nil, scerr.InvalidParameterError("hostID", "cannot be empty string")
	}
	if hostName == "" {
		return nil, scerr.InvalidParameterError("hostName", "cannot be empty string")
	}
	if shareID == "" {
		return nil, scerr.InvalidParameterError("shareID", "cannot be empty string")
	}
	if shareName == "" {
		return nil, scerr.InvalidParameterError("shareName", "cannot be empty string")
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
		return scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if hostID == "" {
		return scerr.InvalidParameterError("hostID", "cannot be empty string")
	}
	if hostName == "" {
		return scerr.InvalidParameterError("hostName", "cannot be empty string")
	}
	if shareID == "" {
		return scerr.InvalidParameterError("shareID", "cannot be empty string")
	}
	if shareName == "" {
		return scerr.InvalidParameterError("shareName", "cannot be empty string")
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
		return "", scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return "", scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, "(<svc>, '"+ref+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ms, err := NewShare(svc)
	if err != nil {
		return "", err
	}

	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr := ms.ReadByReference(ref)
			if innerErr != nil {
				if _, ok := innerErr.(*scerr.ErrNotFound); ok {
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
		// If it's not a timeout is something we don't know how to handle yet
		if _, ok := retryErr.(*scerr.ErrTimeout); !ok {
			return "", scerr.Cause(retryErr)
		}
		return "", retryErr
	}

	return ms.Get()
}

// // MountNas add the client nas to the Nas definition from Object Storage
// func MountNas(svc *providers.Service, client *resources.Nas, server *resources.Nas) error {
// 	return NewNas(svc).Carry(server).AddClient(client)
// }

// // UmountNas remove the client nas to the Nas definition from Object Storage
// func UmountNas(svc *providers.Service, client *resources.Nas, server *resources.Nas) error {
// 	return NewNas(svc).Carry(server).RemoveClient(client)
// }
