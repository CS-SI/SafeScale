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
	"fmt"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/loghelpers"
	"github.com/CS-SI/SafeScale/lib/utils/metadata"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
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
func NewHost(svc iaas.Service) *Host {
	return &Host{
		item: metadata.NewItem(svc, hostsFolderName),
	}
}

// Carry links an host instance to the Metadata instance
func (mh *Host) Carry(host *resources.Host) *Host {
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
func (mh *Host) Get() *resources.Host {
	if mh.item == nil {
		panic("m.item is nil!")
	}
	return mh.item.Get().(*resources.Host)
}

// Write updates the metadata corresponding to the host in the Object Storage
func (mh *Host) Write() (err error) {
	if mh.item == nil {
		panic("m.item is nil!")
	}

	defer loghelpers.LogTraceErrorCallback(fmt.Sprintf("Writing host metadata: %s", *mh.id), nil, &err)()

	err = mh.item.WriteInto(ByNameFolderName, *mh.name)
	if err != nil {
		return err
	}
	return mh.item.WriteInto(ByIDFolderName, *mh.id)
}

// ReadByIDOrName ...
func (mh *Host) ReadByIDOrName(id string) (err error) {
	errID := mh.ReadByID(id)
	if errID != nil {
		errName := mh.ReadByName(id)
		if errName != nil {
			return errName
		}
	}
	return nil
}

// ReadByID reads the metadata of a network identified by ID from Object Storage
func (mh *Host) ReadByID(id string) (err error) {
	defer loghelpers.LogTraceErrorCallback("", concurrency.NewTracer(nil, "("+id+")").Enable(true), &err)()

	if mh.item == nil {
		return utils.InvalidInstanceError()
	}
	if id == "" {
		return utils.InvalidParameterError("id", "can't be nil")
	}

	host := resources.NewHost()
	err = mh.item.ReadFrom(ByIDFolderName, id, func(buf []byte) (serialize.Serializable, error) {
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

// ReadByName reads the metadata of a host identified by name
func (mh *Host) ReadByName(name string) (err error) {
	defer loghelpers.LogTraceErrorCallback("", concurrency.NewTracer(nil, "("+name+")").Enable(true), &err)()

	if mh.item == nil {
		return utils.InvalidInstanceError()
	}
	if name == "" {
		return utils.InvalidParameterError("name", "can't be empty string")
	}

	host := resources.NewHost()
	err = mh.item.ReadFrom(ByNameFolderName, name, func(buf []byte) (serialize.Serializable, error) {
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

// Delete updates the metadata corresponding to the host
func (mh *Host) Delete() (err error) {
	defer loghelpers.LogTraceErrorCallback("", concurrency.NewTracer(nil, "").Enable(true), &err)()

	if mh.item == nil {
		return utils.InvalidInstanceError()
	}

	// FIXME Merge errors
	err1 := mh.item.DeleteFrom(ByIDFolderName, *mh.id)
	err2 := mh.item.DeleteFrom(ByNameFolderName, *mh.name)

	if err1 != nil {
		return err1
	}
	if err != nil {
		return err2
	}

	return nil
}

// Browse walks through host folder and executes a callback for each entries
func (mh *Host) Browse(callback func(*resources.Host) error) (err error) {
	defer loghelpers.LogTraceErrorCallback("", concurrency.NewTracer(nil, "").Enable(true), &err)()

	return mh.item.BrowseInto(ByIDFolderName, func(buf []byte) error {
		host := resources.NewHost()
		err := host.Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(host)
	})
}

// SaveHost saves the Host definition in Object Storage
func SaveHost(svc iaas.Service, host *resources.Host) (mh *Host, err error) {
	defer loghelpers.LogTraceErrorCallback("", concurrency.NewTracer(nil, "").Enable(true), &err)()

	if svc == nil {
		return nil, utils.InvalidParameterError("svc", "can't be nil")
	}
	if host == nil {
		return nil, utils.InvalidParameterError("host", "can't be nil")
	}
	mh = NewHost(svc)
	err = mh.Carry(host).Write()
	if err != nil {
		return nil, err
	}
	// mn := NewNetwork(svc)
	// err = host.Properties.LockForRead(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
	// 	hostNetworkV1 := v.(*propsv1.HostNetwork)
	// 	for netID := range hostNetworkV1.NetworksByID {
	// 		err := mn.ReadByID(netID)
	// 		if err != nil {
	// 			return err
	// 		}
	// 		err = mn.AttachHost(host)
	// 		if err != nil {
	// 			return err
	// 		}
	// 	}
	// 	return nil
	// })
	// if err != nil {
	// 	return nil, err
	// }
	return mh, nil
}

// RemoveHost removes the host definition from Object Storage
func RemoveHost(svc iaas.Service, host *resources.Host) error {
	// // First, browse networks to delete links on the deleted host
	// mn := NewNetwork(svc)
	// mnb := NewNetwork(svc)
	// err := mn.Browse(func(network *resources.Network) error {
	// 	nerr := mnb.Carry(network).DetachHost(host.ID)
	// 	if nerr != nil {
	// 		if strings.Contains(nerr.Error(), "failed to remove metadata in Object Storage") {
	// 			log.Debugf("Error while browsing network: %v", nerr)
	// 		} else {
	// 			log.Warnf("Error while browsing network: %v", nerr)
	// 		}
	// 	}
	// 	return nil
	// })
	// if err != nil {
	// 	return err
	// }

	// Second deletes host metadata
	mh := NewHost(svc)
	return mh.Carry(host).Delete()
}

// LoadHost gets the host definition from Object Storage
// logic: Read by ID; if error is ErrNotFound then read by name; if error is ErrNotFound return this error
//        In case of any other error, abort the retry to propagate the error
//        If retry times out, return errNotFound
func LoadHost(svc iaas.Service, ref string) (mh *Host, err error) {
	defer loghelpers.LogTraceErrorCallback("", concurrency.NewTracer(nil, "("+ref+")").Enable(true), &err)()

	if svc == nil {
		return nil, utils.InvalidParameterError("svc", "can't be nil")
	}
	if ref == "" {
		return nil, utils.InvalidParameterError("ref", "can't be empty string")
	}

	// We first try looking for host by ID from metadata
	mh = NewHost(svc)

	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr := mh.ReadByIDOrName(ref)
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
	if retryErr != nil {
		// If it's not a timeout is something we don't know how to handle yet
		if _, ok := retryErr.(utils.ErrTimeout); !ok {
			return nil, utils.Cause(retryErr)
		}

		return nil, retryErr
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
