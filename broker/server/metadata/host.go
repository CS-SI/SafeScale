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
	"bytes"
	"encoding/gob"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Extension"
	"github.com/CS-SI/SafeScale/providers"

	"github.com/CS-SI/SafeScale/utils/metadata"
)

const (
	// hostsFolderName is the technical name of the container used to store networks info
	hostsFolderName = "hosts"
)

// Host links Object Storage folder and Network
type Host struct {
	item       *metadata.Item
	name       string
	id         string
	extensions utils.Extensions
}

// NewHost creates an instance of metadata.Host
func NewHost(svc *providers.Service) *Host {
	return &Host{
		item: metadata.NewItem(svc, hostsFolderName),
	}
}

// Carry links an host instance to the Metadata instance
func (mh *Host) Carry(pbh *pb.Host) *Host {
	if pbh == nil {
		panic("pbh is nil!")
	}

	mh.item.Carry(pbh)
	mh.name = pbh.Name
	mh.id = pbh.ID
	mh.extensions = extensions.New(pbh.Extensions)
	return mh
}

// Get returns the Network instance linked to metadata
func (mh *Host) Get() *pb.Host {
	if mh.item == nil {
		panic("mh.item is nil!")
	}
	return mh.item.Get().(*pb.Host)
}

// Write updates the metadata corresponding to the host in the Object Storage
func (mh *Host) Write() error {
	if mh.item == nil {
		panic("mh.item is nil!")
	}

	err := mh.item.WriteInto(ByNameFolderName, mh.name)
	if err != nil {
		return err
	}
	return mh.item.WriteInto(ByIDFolderName, mh.id)
}

// ReadByID reads the metadata of a network identified by ID from Object Storage
func (mh *Host) ReadByID(id string) (bool, error) {
	if mh.item == nil {
		panic("mh.item is nil!")
	}

	var data pb.Host
	found, err := mh.item.ReadFrom(ByIDFolderName, id, func(buf *bytes.Buffer) (interface{}, error) {
		err := gob.NewDecoder(buf).Decode(&data)
		if err != nil {
			return nil, err
		}
		return &data, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	mh.id = id
	mh.name = data.Name
	mh.extensions = nil
	return true, nil
}

// ReadByName reads the metadata of a network identified by name
func (mh *Host) ReadByName(name string) (bool, error) {
	if mh.item == nil {
		panic("mh.item is nil!")
	}

	var data pb.Host
	found, err := mh.item.ReadFrom(ByNameFolderName, name, func(buf *bytes.Buffer) (interface{}, error) {
		err := gob.NewDecoder(buf).Decode(&data)
		if err != nil {
			return nil, err
		}
		return &data, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	mh.name = name
	mh.id = data.ID
	mh.extensions = nil
	return true, nil
}

// Delete updates the metadata corresponding to the network
func (mh *Host) Delete() error {
	if mh.item == nil {
		panic("mh.item is nil!")
	}

	err := mh.item.DeleteFrom(ByIDFolderName, mh.id)
	if err != nil {
		return err
	}
	err = mh.item.DeleteFrom(ByNameFolderName, mh.name)
	if err != nil {
		return err
	}
	mh.item = nil
	mh.name = ""
	mh.id = ""
	mh.extensions = nil
	return nil
}

// Browse walks through host folder and executes a callback for each entries
func (mh *Host) Browse(callback func(*pb.Host) error) error {
	if mh.item == nil {
		panic("mh.item is nil!")
	}
	return mh.item.BrowseInto(ByIDFolderName, func(buf *bytes.Buffer) error {
		var host pb.Host
		err := gob.NewDecoder(buf).Decode(&host)
		if err != nil {
			return err
		}
		return callback(&host)
	})
}

// SaveHost saves the Host definition in Object Storage
func SaveHost(svc *provider.Service, pbh *pb.Host, netID string) error {
	err := NewHost(svc).Carry(pbh).Write()
	if err != nil {
		return err
	}
	mn := NewNetwork(svc)
	found, err := mn.ReadByID(netID)
	if err != nil {
		return err
	}
	if found {
		return mn.AttachHost(pbh)
	}
	return nil
}

// RemoveHost removes the host definition from Object Storage
func RemoveHost(svc *providers.Service, pbh *pb.Host) error {
	// First, browse networks to delete links on the deleted host
	mn := NewNetwork(svc)
	mnb := NewNetwork(svc)
	err := mn.Browse(func(network *pb.Network) error {
		nerr := mnb.Carry(network).DetachHost(pbh.ID)
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
	return mh.Carry(pbh).Delete()
}

// LoadHostByID gets the host definition from Object Storage
func LoadHostByID(svc *provider.Service, hostID string) (*Host, error) {
	mh := NewHost(svc)
	found, err := mh.ReadByID(hostID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return mh, nil
}

// LoadHostByName gets the Network definition from Object Storage
func LoadHostByName(svc *provider.Service, hostName string) (*Host, error) {
	mh := NewHost(svc)
	found, err := mh.ReadByName(hostName)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return mh, nil
}

// LoadHost gets the host definition from Object Storage
func LoadHost(svc *provider.Service, ref string) (*Host, error) {
	// We first try looking for host by ID from metadata
	mh, err := LoadHostByID(svc, ref)
	if err != nil {
		return nil, err
	}
	if mh != nil {
		return mh, nil
	}

	// If not found, we try looking for host by name from metadata
	mh, err = LoadHostByName(svc, ref)
	if err != nil {
		return nil, err
	}
	if mh != nil {
		return mh, nil
	}

	return nil, nil
}

// Acquire waits until the write lock is available, then locks the metadata
func (mh *Host) Acquire() {
	if mh.item == nil {
		panic("mh.item is nil!")
	}
	mh.item.Acquire()
}

// Release unlocks the metadata
func (mh *Host) Release() {
	if mh.item == nil {
		panic("mh.item is nil!")
	}
	mh.item.Release()
}

// HostExtensionsMap ...
type HostExtensionsMap map[Extension.Enum]interface{}

type ExtensionsRaw []byte

// HostExtensionDescriptionV1 contains description information for the host
type HostExtensionDescriptionV1 struct {
	// Created tells when a host as been created
	Created time.Time `json:"created"`
	// Purpose contains... a description of the use of a host
	Purpose string
	// Creator contains an information about the creator of a host
	Creator string
	// Free contains anything
	Free string
}

// HostExtensionNetworkV1 contains network information related to Host
type HostExtensionNetworkV1 struct {
	Networks     []string `json:"networks,omitempty"`
	PrivateIPsV4 []string `json:"private_ips_v4,omitempty"`
	PrivateIPsV6 []string `json:"private_ips_v6,omitempty"`
	GatewayID    string   `json:"gateway_id,omitempty"`
}
