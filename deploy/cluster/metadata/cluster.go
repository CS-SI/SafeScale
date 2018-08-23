package metadata

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

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/CS-SI/SafeScale/utils/metadata"
	"github.com/CS-SI/SafeScale/utils/provideruse"

	"github.com/CS-SI/SafeScale/deploy/cluster/api"
)

const (
	//Path is the path to use to reach Cluster Definitions/Metadata
	clusterFolderName = "cluster"
)

// Cluster is the cluster definition stored in ObjectStorage
type Cluster struct {
	item *metadata.Item
	name string
}

// NewCluster creates a new Cluster metadata
func NewCluster() (*Cluster, error) {
	svc, err := provideruse.GetProviderService()
	if err != nil {
		return nil, err
	}
	return &Cluster{
		item: metadata.NewItem(svc, clusterFolderName),
	}, nil
}

// Carry links metadata with cluster struct
func (m *Cluster) Carry(cluster *api.Cluster) *Cluster {
	if m.item == nil {
		panic("m.item is nil!")
	}
	m.item.Carry(cluster)
	m.name = cluster.GetName()
	return m
}

// Delete removes a cluster metadata
func (m *Cluster) Delete() error {
	if m.item == nil {
		panic("m.item is nil!")
	}
	return m.item.Delete(m.name)
}

// Read reads metadata of cluster named 'name' from Object Storage
func (m *Cluster) Read(name string) (bool, error) {
	var (
		target api.Cluster
		ptr    *api.Cluster
		ok     bool
	)
	// If m.item is already carrying data, overwrites it
	// Otherwise, allocates new memory
	anon := m.item.Get()
	if anon == nil {
		ptr = &target
	} else {
		ptr, ok = anon.(*api.Cluster)
		if !ok {
			ptr = &target
		}
	}
	found, err := m.item.Read(name, func(buf *bytes.Buffer) (interface{}, error) {
		err := gob.NewDecoder(buf).Decode(ptr)
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
	m.name = ptr.Name
	return true, nil
}

// Write saves the content of m to the Object Storage
func (m *Cluster) Write() error {
	return m.item.Write(m.name)
}

// Reload reloads the metadata from ObjectStorage
// It's a good idea to do that just after a Acquire() to be sure to have the latest data
func (m *Cluster) Reload() error {
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
func (m *Cluster) Get() *api.Cluster {
	if m.item == nil {
		panic("m.item is nil!")
	}
	if p, ok := m.item.Get().(*api.Cluster); ok {
		return p
	}
	panic("invalid cluster content in metadata")
}

// Browse walks through cluster folder and executes a callback for each entries
func (m *Cluster) Browse(callback func(c *api.Cluster) error) error {
	return m.item.Browse(func(buf *bytes.Buffer) error {
		var data api.Cluster
		err := gob.NewDecoder(buf).Decode(&data)
		if err != nil {
			return err
		}
		return callback(&data)
	})
}

// Acquire waits until the write lock is available, then locks the metadata
func (m *Cluster) Acquire() {
	m.item.Acquire()
}

// Release unlocks the metadata
func (m *Cluster) Release() {
	m.item.Release()
}
