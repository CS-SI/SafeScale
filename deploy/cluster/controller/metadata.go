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

package controller

import (
	"fmt"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/utils/metadata"
	"github.com/CS-SI/SafeScale/utils/serialize"
)

const (
	//Path is the path to use to reach Cluster Definitions/Metadata
	clusterFolderName = "clusters"
)

// Metadata is the cluster definition stored in ObjectStorage
type Metadata struct {
	item *metadata.Item
	name string
}

// NewMetadata creates a new Cluster Controller metadata
func NewMetadata(svc *providers.Service) (*Metadata, error) {
	return &Metadata{
		item: metadata.NewItem(svc, clusterFolderName),
	}, nil
}

// GetService returns the service used by metadata
func (m *Metadata) GetService() *providers.Service {
	return m.item.GetService()
}

// Carry links metadata with cluster struct
func (m *Metadata) Carry(cluster *Controller) *Metadata {
	if m.item == nil {
		panic("m.item is nil!")
	}
	if cluster == nil {
		panic("cluster is nil!")
	}
	m.item.Carry(cluster)
	m.name = cluster.GetIdentity().Name
	return m
}

// Delete removes a cluster metadata
func (m *Metadata) Delete() error {
	if m.item == nil {
		panic("m.item is nil!")
	}
	return m.item.Delete(m.name)
}

// Read reads metadata of cluster named 'name' from Object Storage
func (m *Metadata) Read(name string) (bool, error) {
	var (
		ptr *Controller
		ok  bool
	)
	// If m.item is already carrying data, overwrites it
	// Otherwise, allocates new one
	anon := m.item.Get()
	if anon == nil {
		ptr = NewController(m.GetService())
	} else {
		ptr, ok = anon.(*Controller)
		if !ok {
			ptr = &Controller{}
		}
	}
	found, err := m.item.Read(name, func(buf []byte) (serialize.Serializable, error) {
		err := ptr.Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return ptr, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.name = ptr.GetIdentity().Name
	return true, nil
}

// Write saves the content of m to the Object Storage
func (m *Metadata) Write() error {
	return m.item.Write(m.name)
}

// Reload reloads the metadata from ObjectStorage
// It's a good idea to do that just after a Acquire() to be sure to have the latest data
func (m *Metadata) Reload() error {
	if m.item == nil {
		panic("m.item is nil!")
	}
	found, err := m.Read(m.name)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("metadata of cluster '%s' vanished", m.name)
	}
	return nil
}

// Get returns the content of the metadata
func (m *Metadata) Get() *Controller {
	if m.item == nil {
		panic("m.item is nil!")
	}
	if p, ok := m.item.Get().(*Controller); ok {
		p.service = m.GetService()
		p.metadata = m
		return p
	}
	panic("invalid cluster content in metadata")
}

// Browse walks through cluster folder and executes a callback for each entry
func (m *Metadata) Browse(callback func(*Controller) error) error {
	return m.item.Browse(func(buf []byte) error {
		cc := NewController(m.GetService())
		err := cc.Deserialize(buf)
		if err != nil {
			return err
		}
		cm, err := NewMetadata(m.GetService())
		if err != nil {
			return err
		}
		cm.Carry(cc)
		return callback(cc)
	})
}

// Acquire waits until the write lock is available, then locks the metadata
func (m *Metadata) Acquire() {
	m.item.Acquire()
}

// Release unlocks the metadata
func (m *Metadata) Release() {
	m.item.Release()
}
