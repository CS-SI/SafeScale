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
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/metadata"
	"github.com/CS-SI/SafeScale/utils/retry"
	"github.com/CS-SI/SafeScale/utils/serialize"
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
func (mh *Host) Carry(host *model.Host) *Host {
	if host == nil {
		panic("host is nil!")
	}
	if host.Properties == nil {
		host.Properties = serialize.NewJSONProperties("resources")
	}
	mh.item.Carry(host)
	mh.name = &host.Name
	mh.id = &host.ID
	return mh
}

// Get returns the Network instance linked to metadata
func (mh *Host) Get() *model.Host {
	if mh.item == nil {
		panic("m.item is nil!")
	}
	return mh.item.Get().(*model.Host)
}

// Write updates the metadata corresponding to the host in the Object Storage
func (mh *Host) Write() error {
	if mh.item == nil {
		panic("m.item is nil!")
	}

	err := mh.item.WriteInto(ByNameFolderName, *mh.name)
	if err != nil {
		return err
	}
	return mh.item.WriteInto(ByIDFolderName, *mh.id)
}

// ReadByID reads the metadata of a network identified by ID from Object Storage
func (mh *Host) ReadByID(id string) error {
	if mh.item == nil {
		panic("m.item is nil!")
	}

	host := model.NewHost()
	err := mh.item.ReadFrom(ByIDFolderName, id, func(buf []byte) (serialize.Serializable, error) {
		err := host.Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return host, nil
	})
	if err != nil {
		return err
	}
	mh.id = &(host.ID)
	mh.name = &(host.Name)
	return nil
}

// ReadByName reads the metadata of a network identified by name
func (mh *Host) ReadByName(name string) error {
	if mh.item == nil {
		panic("m.item is nil!")
	}

	host := model.NewHost()
	err := mh.item.ReadFrom(ByNameFolderName, name, func(buf []byte) (serialize.Serializable, error) {
		err := host.Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return host, nil
	})
	if err != nil {
		return err
	}
	mh.name = &(host.Name)
	mh.id = &(host.ID)
	return nil
}

// Delete updates the metadata corresponding to the network
func (mh *Host) Delete() error {
	if mh.item == nil {
		panic("mh.item is nil!")
	}

	err := mh.item.DeleteFrom(ByIDFolderName, *mh.id)
	if err != nil {
		return err
	}
	err = mh.item.DeleteFrom(ByNameFolderName, *mh.name)
	if err != nil {
		return err
	}
	return nil
}

// Browse walks through host folder and executes a callback for each entries
func (mh *Host) Browse(callback func(*model.Host) error) error {
	return mh.item.BrowseInto(ByIDFolderName, func(buf []byte) error {
		host := model.NewHost()
		err := host.Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(host)
	})
}

// SaveHost saves the Host definition in Object Storage
func SaveHost(svc *providers.Service, host *model.Host) error {
	err := NewHost(svc).Carry(host).Write()
	if err != nil {
		return err
	}
	mn := NewNetwork(svc)
	err = host.Properties.LockForRead(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
		hostNetworkV1 := v.(*propsv1.HostNetwork)
		for netID := range hostNetworkV1.NetworksByID {
			err := mn.ReadByID(netID)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
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

// LoadHost gets the host definition from Object Storage
// logic: Read by ID; if error is ErrNotFound then read by name; if error is ErrNotFound return this error
//        In case of any other error, abort the retry to propagate the error
//        If retry times out, return errNotFound
func LoadHost(svc *providers.Service, ref string) (*Host, error) {
	// We first try looking for host by ID from metadata
	mh := NewHost(svc)
	var innerErr error
	err := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr = mh.ReadByID(ref)
			if innerErr != nil {
				if _, ok := innerErr.(utils.ErrNotFound); ok {
					innerErr = mh.ReadByName(ref)
					if innerErr != nil {
						if _, ok := innerErr.(utils.ErrNotFound); ok {
							log.Debugf("LoadHost(): %v", innerErr)
							log.Debugf("LoadHost(): retrying in 1 second")
							return innerErr
						}
					}
				}
			}
			// // In case of inconsistency in Object Storage (had happened in the past...)
			// host := mh.Get()
			// ip := host.GetAccessIP()
			// if ip == "" {
			// 	log.Warnf("Host metadata inconsistent, AccessIP is empty. Retrying")
			// 	return fmt.Errorf("host metadata inconsistent, AccessIP is empty")
			// }
			return nil
		},
		10*time.Second,
	)
	// If retry timed out, log it and return error ErrNotFound
	if err != nil {
		if _, ok := err.(retry.ErrTimeout); ok {
			log.Debugf("timeout reading metadata of host '%s'", ref)
			return nil, utils.NotFoundError(fmt.Sprintf("failed to load metadata of host '%s'", ref))
		}
		return nil, err
	}
	// Returns the error different than ErrNotFound to caller
	if innerErr != nil {
		return nil, innerErr
	}
	return mh, nil
}

// Acquire waits until the write lock is available, then locks the metadata
func (mh *Host) Acquire() {
	mh.item.Acquire()
}

// Release unlocks the metadata
func (mh *Host) Release() {
	mh.item.Release()
}
