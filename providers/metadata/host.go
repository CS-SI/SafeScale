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
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/utils/metadata"
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
func NewHost(svc *providers.Service) *Host {
	return &Host{
		item: metadata.NewItem(svc, hostsFolderName),
	}
}

// Carry links an host instance to the Metadata instance
func (m *Host) Carry(host *model.Host) *Host {
	if host == nil {
		panic("host is nil!")
	}
	if host.Properties == nil {
		host.Properties = model.NewExtensions()
	}
	m.item.Carry(host)
	m.name = &host.Name
	m.id = &host.ID
	return m
}

// Get returns the Network instance linked to metadata
func (m *Host) Get() *model.Host {
	if m.item == nil {
		panic("m.item is nil!")
	}
	return m.item.Get().(*model.Host)
}

// Write updates the metadata corresponding to the host in the Object Storage
func (m *Host) Write() error {
	if m.item == nil {
		panic("m.item is nil!")
	}

	err := m.item.WriteInto(ByNameFolderName, *m.name)
	if err != nil {
		return err
	}
	return m.item.WriteInto(ByIDFolderName, *m.id)
}

// ReadByID reads the metadata of a network identified by ID from Object Storage
func (m *Host) ReadByID(id string) (bool, error) {
	if m.item == nil {
		panic("m.item is nil!")
	}

	var host model.Host
	found, err := m.item.ReadFrom(ByIDFolderName, id, func(buf []byte) (model.Serializable, error) {
		phost := &host
		err := phost.Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return phost, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.id = &host.ID
	m.name = &host.Name
	return true, nil
}

// ReadByName reads the metadata of a network identified by name
func (m *Host) ReadByName(name string) (bool, error) {
	if m.item == nil {
		panic("m.item is nil!")
	}

	var host model.Host
	found, err := m.item.ReadFrom(ByNameFolderName, name, func(buf []byte) (model.Serializable, error) {
		phost := &host
		err := phost.Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return phost, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.name = &host.Name
	m.id = &host.ID
	return true, nil
}

// Delete updates the metadata corresponding to the network
func (m *Host) Delete() error {
	if m.item == nil {
		panic("m.item is nil!")
	}

	err := m.item.DeleteFrom(ByIDFolderName, *m.id)
	if err != nil {
		return err
	}
	err = m.item.DeleteFrom(ByNameFolderName, *m.name)
	if err != nil {
		return err
	}
	return nil
}

// Browse walks through host folder and executes a callback for each entries
func (m *Host) Browse(callback func(*model.Host) error) error {
	return m.item.BrowseInto(ByIDFolderName, func(buf []byte) error {
		host := model.Host{}
		phost := &host
		err := phost.Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(phost)
	})
}

// SaveHost saves the Host definition in Object Storage
func SaveHost(svc *providers.Service, host *model.Host) error {
	err := NewHost(svc).Carry(host).Write()
	if err != nil {
		return err
	}
	hostNetworkV1 := propsv1.NewHostNetwork()
	err = host.Properties.Get(HostProperty.NetworkV1, hostNetworkV1)
	if err != nil {
		return err
	}
	mn := NewNetwork(svc)
	for netID := range hostNetworkV1.NetworksByID {
		found, err := mn.ReadByID(netID)
		if err != nil {
			return err
		}
		if found {
			err = mn.AttachHost(host)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// RemoveHost removes the host definition from Object Storage
func RemoveHost(svc *providers.Service, host *model.Host) error {
	// First, browse networks to delete links on the deleted host
	mn := NewNetwork(svc)
	mnb := NewNetwork(svc)
	err := mn.Browse(func(network *model.Network) error {
		nerr := mnb.Carry(network).DetachHost(host.ID)
		if nerr != nil {
			if strings.Contains(nerr.Error(), "failed to remove metadata in Object Storage") {
				log.Debugf("Error while browsing network: %v", nerr)
			} else {
				log.Warnf("Error while browsing network: %v", nerr)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Second deletes host metadata
	mh := NewHost(svc)
	return mh.Carry(host).Delete()
}

// LoadHostByID gets the host definition from Object Storage
func LoadHostByID(svc *providers.Service, hostID string) (*Host, error) {
	m := NewHost(svc)
	found, err := m.ReadByID(hostID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return m, nil
}

// LoadHostByName gets the Network definition from Object Storage
func LoadHostByName(svc *providers.Service, hostName string) (*Host, error) {
	m := NewHost(svc)
	found, err := m.ReadByName(hostName)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return m, nil
}

// LoadHost gets the host definition from Object Storage
func LoadHost(svc *providers.Service, ref string) (*Host, error) {
	// We first try looking for host by ID from metadata
	m, err := LoadHostByID(svc, ref)
	if err != nil {
		return nil, err
	}
	if m != nil {
		return m, nil
	}

	// If not found, we try looking for host by name from metadata
	m, err = LoadHostByName(svc, ref)
	if err != nil {
		return nil, err
	}
	if m != nil {
		return m, nil
	}

	return nil, nil
}

// Acquire waits until the write lock is available, then locks the metadata
func (m *Host) Acquire() {
	m.item.Acquire()
}

// Release unlocks the metadata
func (m *Host) Release() {
	m.item.Release()
}
