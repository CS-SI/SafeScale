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
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/loghelpers"
	"github.com/CS-SI/SafeScale/lib/utils/metadata"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
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
func NewShare(svc iaas.Service) *Share {
	return &Share{
		item: metadata.NewItem(svc, shareFolderName),
	}
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
func (ms *Share) Carry(hostID, hostName, shareID, shareName string) *Share {
	if hostID == "" {
		panic("hostID is empty!")
	}
	if hostName == "" {
		panic("hostName is empty!")
	}
	if shareID == "" {
		panic("shareID is empty!")
	}
	if shareName == "" {
		panic("shareName is empty!")
	}
	if ms.item == nil {
		panic("ms.item is nil!")
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
	return ms
}

// Get returns the ID of the host owning the share
func (ms *Share) Get() string {
	if ms.item == nil {
		panic("ms.item is nil!")
	}
	if ei, ok := ms.item.Get().(*shareItem); ok {
		return ei.HostName
	}
	panic("invalid content in metadata!")
}

// Write updates the metadata corresponding to the share in the Object Storage
func (ms *Share) Write() error {
	if ms.item == nil {
		panic("ms.item is nil!")
	}
	err := ms.item.WriteInto(ByIDFolderName, *ms.id)
	if err != nil {
		return err
	}
	return ms.item.WriteInto(ByNameFolderName, *ms.name)
}

// ReadByReference tries to read 'ref' as an ID, and if not found as a name
func (ms *Share) ReadByReference(id string) (err error) {
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
func (ms *Share) ReadByID(id string) error {
	if ms.item == nil {
		panic("ms.item is nil!")
	}
	var si shareItem
	err := ms.item.ReadFrom(ByIDFolderName, id, func(buf []byte) (serialize.Serializable, error) {
		err := (&si).Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return &si, nil
	})
	if err != nil {
		return err
	}
	ms.Carry(si.HostID, si.HostName, si.ShareID, si.ShareName)
	return nil
}

// ReadByName reads the metadata of a nas identified by name
func (ms *Share) ReadByName(name string) error {
	if ms.item == nil {
		panic("ms.name is nil!")
	}
	var si shareItem
	err := ms.item.ReadFrom(ByNameFolderName, name, func(buf []byte) (serialize.Serializable, error) {
		err := (&si).Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return &si, nil
	})
	if err != nil {
		return err
	}
	ms.Carry(si.HostID, si.HostName, si.ShareID, si.ShareName)
	return nil
}

// Delete updates the metadata corresponding to the share
func (ms *Share) Delete() error {
	err := ms.item.DeleteFrom(ByIDFolderName, *ms.id)
	if err != nil {
		return err
	}
	return ms.item.DeleteFrom(ByNameFolderName, *ms.name)
}

// Browse walks through shares folder and executes a callback for each entry
func (ms *Share) Browse(callback func(string, string) error) error {
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

// Acquire waits until the write lock is available, then locks the metadata
func (ms *Share) Acquire() {
	ms.item.Acquire()
}

// Release unlocks the metadata
func (ms *Share) Release() {
	ms.item.Release()
}

// SaveShare saves the Nas definition in Object Storage
func SaveShare(svc iaas.Service, hostID, hostName, shareID, shareName string) (*Share, error) {
	ms := NewShare(svc).Carry(hostID, hostName, shareID, shareName)
	return ms, ms.Write()
}

// RemoveShare removes the share definition from Object Storage
func RemoveShare(svc iaas.Service, hostID, hostName, shareID, shareName string) error {
	return NewShare(svc).Carry(hostID, hostName, shareID, shareName).Delete()
}

// LoadShare returns the name of the host owing the share 'ref', read from Object Storage
// logic: Read by ID; if error is ErrNotFound then read by name; if error is ErrNotFound return this error
//        In case of any other error, abort the retry to propagate the error
//        If retry times out, return errNotFound
func LoadShare(svc iaas.Service, ref string) (share string, err error) {
	defer loghelpers.LogErrorCallback(
		"",
		concurrency.NewTracer(nil, "").Enable(true),
		&err,
	)()

	if svc == nil {
		return "", utils.InvalidParameterError("svc", "can't be nil")
	}
	if ref == "" {
		return "", utils.InvalidParameterError("ref", "can't be empty string")
	}

	ms := NewShare(svc)

	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr := ms.ReadByReference(ref)
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
	// If retry timed out, log it and return error ErrNotFound
	if retryErr != nil {
		// If it's not a timeout is something we don't know how to handle yet
		if _, ok := retryErr.(utils.ErrTimeout); !ok {
			return "", utils.Cause(retryErr)
		}
		return "", retryErr
	}

	return ms.Get(), nil
}

// // MountNas add the client nas to the Nas definition from Object Storage
// func MountNas(svc *providers.Service, client *resources.Nas, server *resources.Nas) error {
// 	return NewNas(svc).Carry(server).AddClient(client)
// }

// // UmountNas remove the client nas to the Nas definition from Object Storage
// func UmountNas(svc *providers.Service, client *resources.Nas, server *resources.Nas) error {
// 	return NewNas(svc).Carry(server).RemoveClient(client)
// }
