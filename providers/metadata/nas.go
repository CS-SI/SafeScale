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
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/model"

	"github.com/CS-SI/SafeScale/utils/metadata"
)

const (
	// nasFolderName is the technical name of the container used to store nas info
	nasFolderName = "nas"
)

// Nas links Object Storage folder and Network
type Nas struct {
	item *metadata.Item
	name *string
	id   *string
}

// NewNas creates an instance of metadata.Nas
func NewNas(svc api.ClientAPI) *Nas {
	return &Nas{
		item: metadata.NewItem(svc, nasFolderName),
	}
}

type exportItem struct {
	HostID     string `json:"id"`          // contains the ID of the host serving the export
	ExportID   string `json:"export_id"`   // contains the ID of the export
	ExportName string `json:"export_name"` // contains the name of the export
}

// Serialize ...
func (n *exportItem) Serialize() ([]byte, error) {
	return model.SerializeToJSON(n)
}

// Deserialize ...
func (n *exportItem) Deserialize(buf []byte) error {
	return model.DeserializeFromJSON(buf, n)
}

// Carry links an export instance to the Metadata instance
func (mn *Nas) Carry(hostID, exportID, exportName string) *Nas {
	if hostID == "" {
		panic("hostID is empty!")
	}
	if exportID == "" {
		panic("exportID is empty!")
	}
	if exportName == "" {
		panic("exportName is empty!")
	}
	if mn.item == nil {
		panic("mn.item is nil!")
	}
	ni := exportItem{
		HostID:     hostID,
		ExportID:   exportID,
		ExportName: exportName,
	}
	mn.item.Carry(&ni)
	mn.name = &ni.ExportName
	mn.id = &ni.ExportID
	return mn
}

// Get returns the ID of the host the exporting
func (mn *Nas) Get() string {
	if mn.item == nil {
		panic("mn.item is nil!")
	}
	if ei, ok := mn.item.Get().(*exportItem); ok {
		return ei.HostID
	}
	panic("invalid content in metadata!")
}

// Write updates the metadata corresponding to the nas in the Object Storage
func (mn *Nas) Write() error {
	if mn.item == nil {
		panic("mn.item is nil!")
	}
	err := mn.item.WriteInto(ByIDFolderName, *mn.id)
	if err != nil {
		return err
	}
	return mn.item.WriteInto(ByNameFolderName, *mn.name)
}

// ReadByID reads the metadata of an export identified by ID from Object Storage
func (mn *Nas) ReadByID(id string) (bool, error) {
	if mn.item == nil {
		panic("mn.item is nil!")
	}
	var ei exportItem
	found, err := mn.item.ReadFrom(ByIDFolderName, id, func(buf []byte) (model.Serializable, error) {
		err := (&ei).Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return &ei, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	mn.Carry(ei.HostID, ei.ExportID, ei.ExportName)
	return true, nil
}

// ReadByName reads the metadata of a nas identified by name
func (mn *Nas) ReadByName(name string) (bool, error) {
	if mn.item == nil {
		panic("mn.name is nil!")
	}
	var ei exportItem
	found, err := mn.item.ReadFrom(ByNameFolderName, name, func(buf []byte) (model.Serializable, error) {
		err := (&ei).Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return &ei, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	mn.Carry(ei.HostID, ei.ExportID, ei.ExportName)
	return true, nil
}

// Delete updates the metadata corresponding to the nas
func (mn *Nas) Delete() error {
	err := mn.item.DeleteFrom(ByIDFolderName, *mn.id)
	if err != nil {
		return err
	}
	return mn.item.DeleteFrom(ByNameFolderName, *mn.name)
}

// Browse walks through nas folder and executes a callback for each entries
func (mn *Nas) Browse(callback func(string, string) error) error {
	return mn.item.BrowseInto(ByNameFolderName, func(buf []byte) error {
		ei := exportItem{}
		err := (&ei).Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(ei.HostID, ei.ExportID)
	})
}

// // AddClient adds a client to the Nas definition in Object Storage
// func (m *Nas) AddClient(nas *model.Nas) error {
// 	return NewNas(m.item.GetService()).Carry(nas).item.WriteInto(*m.id, nas.ID)
// 	// return m.item.WriteInto(m.id, nas.ID)
// }

// // RemoveClient removes a client to the Nas definition in Object Storage
// func (m *Nas) RemoveClient(nas *model.Nas) error {
// 	return m.item.DeleteFrom(*m.id, nas.ID)
// }

// // Listclients returns the list of ID of hosts clients of the NAS server
// func (m *Nas) Listclients() ([]*model.Nas, error) {
// 	var list []*model.Nas
// 	err := m.item.BrowseInto(*m.id, func(buf []byte) error {
// 		nas := model.Nas{}
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
// func (m *Nas) FindClient(hostName string) (*model.Nas, error) {
// 	var client *model.Nas
// 	err := m.item.BrowseInto(*m.id, func(buf []byte) error {
// 		nas := model.Nas{}
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
func (mn *Nas) Acquire() {
	mn.item.Acquire()
}

// Release unlocks the metadata
func (mn *Nas) Release() {
	mn.item.Release()
}

// // SaveNas saves the Nas definition in Object Storage
// func SaveNas(svc *providers.Service, nas *model.Nas) error {
// 	err := NewNas(svc).Carry(nas).Write()
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

// // RemoveNas removes the Nas definition from Object Storage
// func RemoveNas(svc *providers.Service, nas *model.Nas) error {
// 	return NewNas(svc).Carry(nas).Delete()
// }

// LoadNas returns the host ID hosting export 'ref' read from Object Storage
func LoadNas(svc *providers.Service, ref string) (string, error) {
	mn := NewNas(svc)
	found, err := mn.ReadByID(ref)
	if err != nil {
		return "", err
	}
	if !found {
		found, err := mn.ReadByName(ref)
		if err != nil {
			return "", err
		}
		if !found {
			return "", nil
		}
	}
	return mn.Get(), nil
}

// // MountNas add the client nas to the Nas definition from Object Storage
// func MountNas(svc *providers.Service, client *model.Nas, server *model.Nas) error {
// 	return NewNas(svc).Carry(server).AddClient(client)
// }

// // UmountNas remove the client nas to the Nas definition from Object Storage
// func UmountNas(svc *providers.Service, client *model.Nas, server *model.Nas) error {
// 	return NewNas(svc).Carry(server).RemoveClient(client)
// }
