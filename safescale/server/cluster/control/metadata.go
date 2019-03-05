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

package control

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/concurrency"
	"github.com/CS-SI/SafeScale/utils/metadata"
	"github.com/CS-SI/SafeScale/utils/retry"
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
	// lock *sync.Mutex
}

// NewMetadata creates a new Cluster Controller metadata
func NewMetadata(svc *iaas.Service) (*Metadata, error) {
	return &Metadata{
		item: metadata.NewItem(svc, clusterFolderName),
		// lock: &sync.Mutex{},
	}, nil
}

// GetService returns the service used by metadata
func (m *Metadata) GetService() *iaas.Service {
	return m.item.GetService()
}

// Written tells if the metadata has already been written to ObjectStorage
func (m *Metadata) Written() bool {
	return m.item.Written()
}

// Carry links metadata with cluster struct
func (m *Metadata) Carry(task concurrency.Task, cluster *Controller) *Metadata {
	if m.item == nil {
		panic("m.item is nil!")
	}
	if cluster == nil {
		panic("Invalid parameter 'cluster': can't be nil!")
	}
	m.item.Carry(cluster)
	m.name = cluster.GetIdentity(task).Name
	return m
}

// Delete removes a cluster metadata
func (m *Metadata) Delete() error {
	if m.item == nil {
		panic("m.item is nil!")
	}
	err := m.item.Delete(m.name)
	if err != nil {
		return err
	}
	m.item.Reset()
	return nil
}

// Read reads metadata of cluster named 'name' from Object Storage
func (m *Metadata) Read(task concurrency.Task, name string) error {
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
	err := m.item.Read(name, func(buf []byte) (serialize.Serializable, error) {
		err := ptr.Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return ptr, nil
	})
	if err != nil {
		return err
	}
	m.name = ptr.GetIdentity(task).Name
	return nil
}

// Write saves the content of m to the Object Storage
func (m *Metadata) Write() error {
	return m.item.Write(m.name)
}

// Reload reloads the metadata from ObjectStorage
// It's a good idea to do that just after an Acquire() to be sure to have the latest data
func (m *Metadata) Reload(task concurrency.Task) error {
	if m.item == nil {
		panic("m.item is nil!")
	}

	// If the metadata object has never been written yet, succeed doing nothing
	if !m.item.Written() {
		return nil
	}

	// Metadata had been written at least once, so try to reload (and propagate failure if it occurs)
	var innerErr error
	err := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr = m.Read(task, m.name)
			if innerErr != nil {
				if _, ok := innerErr.(utils.ErrNotFound); ok {
					return innerErr
				}
			}
			return nil
		},
		5*time.Second,
	)
	if err != nil {
		if _, ok := err.(retry.ErrTimeout); ok && innerErr != nil {
			if _, ok = innerErr.(utils.ErrNotFound); ok {
				// On timeout and last error was NotFound, returns that last error
				return innerErr
			}
			log.Debugf("timeout reading metadata of cluster '%s'", m.name)
			return utils.NotFoundError(fmt.Sprintf("failed to reload metadata of cluster '%s'", m.name))
		}
		return err
	}
	return nil
}

// Get returns the content of the metadata
func (m *Metadata) Get() *Controller {
	if m.item == nil {
		panic("m.item is nil!")
	}
	if p, ok := m.item.Get().(*Controller); ok {
		return p
	}
	panic("Missing cluster content in metadata!")
}

// Browse walks through cluster folder and executes a callback for each entry
func (m *Metadata) Browse(callback func(*Controller) error) error {
	if m.item == nil {
		panic("m.item is nil!")
	}
	return m.item.Browse(func(buf []byte) error {
		cc := NewController(m.GetService())
		err := cc.Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(cc)
	})
}

// Acquire waits until the write lock is available, then locks the metadata
func (m *Metadata) Acquire() {
	// m.lock.Lock()
	// defer m.lock.Unlock()
	m.item.Acquire()
}

// Release unlocks the metadata
func (m *Metadata) Release() {
	// m.lock.Lock()
	// defer m.lock.Unlock()
	m.item.Release()
}
