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
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/metadata"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// Path is the path to use to reach Cluster Definitions/Metadata
	clusterFolderName = "clusters"
)

// Metadata is the cluster definition stored in ObjectStorage
type Metadata struct {
	item *metadata.Item
	name string
	// lock *sync.Mutex
}

// NewMetadata creates a new Cluster Controller metadata
func NewMetadata(svc iaas.Service) (*Metadata, error) {
	meta, err := metadata.NewItem(svc, clusterFolderName)
	if err != nil {
		return nil, err
	}

	return &Metadata{
		item: meta,
		// lock: &sync.Mutex{},
	}, nil
}

// GetService returns the service used by metadata
func (m *Metadata) GetService() iaas.Service {
	return m.item.GetService()
}

// Written tells if the metadata has already been written to ObjectStorage
func (m *Metadata) Written() bool {
	return m.item.Written()
}

// Carry links metadata with cluster struct
func (m *Metadata) Carry(task concurrency.Task, cluster *Controller) *Metadata {
	var err error
	tracer := concurrency.NewTracer(task, "", false)
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if m == nil {
		err = scerr.InvalidInstanceError()
		return m
	}
	if m.item == nil {
		err = scerr.InvalidParameterError("m.item", "cannot be nil")
		return m
	}
	if cluster == nil {
		err = scerr.InvalidParameterError("cluster", "cannot be nil")
		return m
	}

	m.item.Carry(cluster)
	m.name = cluster.GetIdentity(task).Name
	return m
}

// Delete removes a cluster metadata
func (m *Metadata) Delete() error {
	if m == nil {
		return scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return scerr.InvalidParameterError("m.item", "cannot be nil")
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
		err error
	)
	// If m.item is already carrying data, overwrites it
	// Otherwise, allocates new one
	anon := m.item.Get()
	if anon == nil {
		ptr, err = NewController(m.GetService())
		if err != nil {
			return err
		}
	} else {
		ptr, ok = anon.(*Controller)
		if !ok {
			ptr = &Controller{}
		}
	}
	err = m.item.Read(name, func(buf []byte) (serialize.Serializable, error) {
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
	if m == nil {
		return scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return scerr.InvalidParameterError("m.item", "cannot be nil")
	}

	// If the metadata object has never been written yet, succeed doing nothing
	if !m.item.Written() {
		return nil
	}

	// Metadata had been written at least once, so try to reload (and propagate failure if it occurs)
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr := m.Read(task, m.name)
			if innerErr != nil {
				if _, ok := innerErr.(scerr.ErrNotFound); ok {
					return retry.StopRetryError("not found", innerErr)
				}
				return innerErr
			}
			return nil
		},
		temporal.GetDefaultDelay(),
	)
	if retryErr != nil {
		// If it's not a timeout is something we don't know how to handle yet
		if _, ok := retryErr.(scerr.ErrTimeout); !ok {
			return scerr.Cause(retryErr)
		}
		return retryErr
	}
	return nil
}

// Get returns the content of the metadata
func (m *Metadata) Get() (_ *Controller, err error) {
	tracer := concurrency.NewTracer(nil, "", false)
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if m == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return nil, scerr.InvalidParameterError("m.item", "cannot be nil")
	}
	if p, ok := m.item.Get().(*Controller); ok {
		return p, nil
	}
	return nil, scerr.NotFoundError("missing cluster content in metadata")
}

// OK ...
func (m *Metadata) OK() bool {
	if m == nil {
		return false
	}

	if m.item == nil {
		return false
	}

	if _, ok := m.item.Get().(*Controller); ok {
		return true
	}

	return false
}

// Browse walks through cluster folder and executes a callback for each entry
func (m *Metadata) Browse(callback func(*Controller) error) error {
	if m == nil {
		return scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return scerr.InvalidParameterError("m.item", "cannot be nil")
	}

	return m.item.Browse(func(buf []byte) error {
		cc, err := NewController(m.GetService())
		if err == nil {
			err = cc.Deserialize(buf)
		}
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
