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

	"github.com/CS-SI/SafeScale/metadata"
	"github.com/CS-SI/SafeScale/perform/cluster/api"
	"github.com/CS-SI/SafeScale/utils/provideruse"
)

const (
	//Path is the path to use to reach Cluster Definitions/Metadata
	clusterFolderName = "cluster"
)

type empty struct{}
type semaphore chan empty

// acquire n resources
func (s semaphore) P(n int) {
	e := empty{}
	for i := 0; i < n; i++ {
		s <- e
	}
}

// release n resources
func (s semaphore) V(n int) {
	for i := 0; i < n; i++ {
		<-s
	}
}

/* mutexes */
func (s semaphore) Lock() {
	s.P(1)
}

func (s semaphore) Unlock() {
	s.V(1)
}

/* signal-wait */

func (s semaphore) Signal() {
	s.V(1)
}

func (s semaphore) Wait(n int) {
	s.P(n)
}

type record struct {
	Common   *api.Cluster
	Specific interface{}
}

//Cluster is the cluster definition stored in ObjectStorage
type Cluster struct {
	folder *metadata.Folder
	data   *record
	lock   semaphore
}

//NewCluster creates a new Cluster metadata
func NewCluster() (*Cluster, error) {
	svc, err := provideruse.GetProviderService()
	if err != nil {
		return nil, err
	}
	f, err := metadata.NewFolder(svc, clusterFolderName)
	if err != nil {
		return nil, err
	}
	return &Cluster{
		folder: f,
		data:   nil,
		lock:   make(semaphore, 1),
	}, nil
}

//Carry links metadata with cluster struct
func (m *Cluster) Carry(common *api.Cluster, specific interface{}) *Cluster {
	m.data = &record{
		Common:   common,
		Specific: specific,
	}
	return m
}

//Delete removes a cluster metadata
func (m *Cluster) Delete() error {
	if m.data == nil {
		panic("m.data is nil!")
	}
	err := m.folder.Delete(".", m.data.Common.Name)
	if err != nil {
		return err
	}
	return nil
}

//Read reads metadata of cluster named 'name' from Object Storage
func (m *Cluster) Read(name string) (bool, error) {
	var data record
	found, err := m.folder.Read(".", name, func(buf *bytes.Buffer) error {
		err := gob.NewDecoder(buf).Decode(&data)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.data = &data
	return true, nil
}

//Write saves the content of m to the Object Storage
func (m *Cluster) Write() error {
	return m.folder.Write("/", m.data.Common.Name, m.data)
}

//Get returns the content of the metadata
func (m *Cluster) Get() (*api.Cluster, interface{}) {
	if m.data == nil {
		panic("m.data is nil!")
	}
	return m.data.Common, m.data.Specific
}

//Browse walks through cluster folder and executes a callback for each entries
func (m *Cluster) Browse(callback func(c *api.Cluster) error) error {
	return m.folder.Browse(".", func(buf *bytes.Buffer) error {
		var data record
		err := gob.NewDecoder(buf).Decode(&data)
		if err != nil {
			return err
		}
		return callback(data.Common)
	})
}

//Acquire waits until the write lock is available, then locks the metadata
func (m *Cluster) Acquire() {
	m.lock.Lock()
}

//Release unlocks the metadata
func (m *Cluster) Release() {
	m.lock.Unlock()
}

func init() {
	gob.Register(record{})
}
