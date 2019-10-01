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

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/NetworkProperty"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/metadata"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

const (
	//NetworkFolderName is the technical name of the container used to store networks info
	networksFolderName = "networks"
	// //GatewayObjectName is the name of the object containing the id of the host acting as a default gateway for a network
	// gatewayObjectName = "gw"
)

// Network links Object Storage folder and Network
type Network struct {
	item *metadata.Item
	//inside *metadata.Folder
	name *string
	id   *string
}

// NewNetwork creates an instance of network.Metadata
func NewNetwork(svc iaas.Service) *Network {
	return &Network{
		item: metadata.NewItem(svc, networksFolderName),
	}
}

// GetService returns the provider service used
func (m *Network) GetService() iaas.Service {
	return m.item.GetService()
}

// GetPath returns the path in Object Storage where the item is stored
func (m *Network) GetPath() string {
	if m.item == nil {
		panic("m.item is nil!")
	}
	return m.item.GetPath()
}

// Carry links a Network instance to the Metadata instance
func (m *Network) Carry(network *resources.Network) *Network {
	if network == nil {
		panic("network parameter is nil!")
	}
	if m.item == nil {
		panic("m.item is nil!")
	}
	if network.Properties == nil {
		network.Properties = serialize.NewJSONProperties("resources")
	}
	m.item.Carry(network)
	m.id = &network.ID
	m.name = &network.Name
	//m.inside = metadata.NewFolder(m.item.GetService(), strings.Trim(m.item.GetPath()+"/"+*m.id, "/"))
	return m
}

// Get returns the resources.Network instance linked to metadata
func (m *Network) Get() *resources.Network {
	if m.item == nil {
		panic("m.item is nil!")
	}
	return m.item.Get().(*resources.Network)
}

// Write updates the metadata corresponding to the network in the Object Storage
func (m *Network) Write() (err error) {
	if m == nil {
		return utils.InvalidInstanceError()
	}
	if m.item == nil {
		return utils.InvalidParameterError("m.item", "can't be nil")
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	err1 := m.item.WriteInto(ByIDFolderName, *m.id)
	err2 := m.item.WriteInto(ByNameFolderName, *m.name)

	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return nil
}

// Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (m *Network) Reload() (err error) {
	if m == nil {
		return utils.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	err = m.ReadByID(*m.id)
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); ok {
			return utils.NotFoundError(fmt.Sprintf("the metadata of Network '%s' vanished", *m.name))
		}
		return err
	}
	return nil
}

// ReadByReference tries to read first using 'ref' as an ID then as a name
func (m *Network) ReadByReference(ref string) (err error) {
	errID := m.ReadByID(ref)
	if errID != nil {
		errName := m.ReadByName(ref)
		if errName != nil {
			return errName
		}
	}
	return nil
}

// ReadByID reads the metadata of a network identified by ID from Object Storage
func (m *Network) ReadByID(id string) (err error) {
	if m == nil {
		return utils.InvalidInstanceError()
	}
	if m.item == nil {
		return utils.InvalidParameterError("m.item", "can't be nil")
	}

	tracer := concurrency.NewTracer(nil, "("+id+")", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	network := resources.NewNetwork()
	err = m.item.ReadFrom(ByIDFolderName, id, func(buf []byte) (serialize.Serializable, error) {
		err := network.Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return network, nil
	})
	if err != nil {
		return err
	}
	m.id = &(network.ID)
	m.name = &(network.Name)
	// m.inside = metadata.NewFolder(m.item.GetService(), strings.Trim(m.item.GetPath()+"/"+id, "/"))
	return nil
}

// ReadByName reads the metadata of a network identified by name
func (m *Network) ReadByName(name string) (err error) {
	if m == nil {
		return utils.InvalidInstanceError()
	}
	if m.item == nil {
		return utils.InvalidParameterError("m.item", "can't be nil")
	}
	if name == "" {
		return utils.InvalidParameterError("name", "can't be empty string")
	}

	tracer := concurrency.NewTracer(nil, "("+name+")", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	network := resources.NewNetwork()
	err = m.item.ReadFrom(ByNameFolderName, name, func(buf []byte) (serialize.Serializable, error) {
		err := network.Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return network, nil
	})
	if err != nil {
		return err
	}
	m.name = &(network.Name)
	m.id = &(network.ID)
	//	m.inside = metadata.NewFolder(m.item.GetService(), strings.Trim(m.item.GetPath()+"/"+*m.id, "/"))
	return nil
}

// Delete deletes the metadata corresponding to the network
func (m *Network) Delete() (err error) {
	if m == nil {
		return utils.InvalidInstanceError()
	}
	if m.item == nil {
		return utils.InvalidParameterError("m.item", "can't be nil")
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	// Delete the entry in 'ByIDFolderName' folder
	err1 := m.item.DeleteFrom(ByIDFolderName, *m.id)
	// Delete the entry in 'ByNameFolderName' folder
	err2 := m.item.DeleteFrom(ByNameFolderName, *m.name)

	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}

	return nil
}

// Browse walks through all the metadata objects in network
func (m *Network) Browse(callback func(*resources.Network) error) (err error) {
	if m == nil {
		return utils.InvalidInstanceError()
	}
	if m.item == nil {
		return utils.InvalidParameterError("m.item", "can't be nil")
	}
	if callback == nil {
		return utils.InvalidParameterError("callback", "can't be nil")
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	return m.item.BrowseInto(ByIDFolderName, func(buf []byte) error {
		network := resources.Network{}
		err := (&network).Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(&network)
	})
}

// AttachHost links host ID to the network
func (m *Network) AttachHost(host *resources.Host) (err error) {
	if m == nil {
		return utils.InvalidInstanceError()
	}
	if host == nil {
		return utils.InvalidParameterError("host", "can't be nil")
	}

	tracer := concurrency.NewTracer(nil, "("+host.Name+")", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	network := m.Get()
	return network.Properties.LockForWrite(NetworkProperty.HostsV1).ThenUse(func(v interface{}) error {
		networkHostsV1 := v.(*propsv1.NetworkHosts)
		networkHostsV1.ByID[host.ID] = host.Name
		networkHostsV1.ByName[host.Name] = host.ID
		return nil
	})
}

// DetachHost unlinks host ID from network
func (m *Network) DetachHost(hostID string) (err error) {
	if m == nil {
		return utils.InvalidInstanceError()
	}
	if hostID == "" {
		return utils.InvalidParameterError("hostID", "can't be empty string")
	}

	tracer := concurrency.NewTracer(nil, "('"+hostID+"')", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	network := m.Get()
	err = network.Properties.LockForWrite(NetworkProperty.HostsV1).ThenUse(func(v interface{}) error {
		networkHostsV1 := v.(*propsv1.NetworkHosts)
		hostName, found := networkHostsV1.ByID[hostID]
		if found {
			delete(networkHostsV1.ByName, hostName)
			delete(networkHostsV1.ByID, hostID)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

// ListHosts returns the list of resources.Host attached to the network (excluding gateway)
func (m *Network) ListHosts() (list []*resources.Host, err error) {
	if m == nil {
		return nil, utils.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	network := m.Get()
	err = network.Properties.LockForRead(NetworkProperty.HostsV1).ThenUse(func(v interface{}) error {
		networkHostsV1 := v.(*propsv1.NetworkHosts)
		for id := range networkHostsV1.ByID {
			mh, err := LoadHost(m.item.GetService(), id)
			if err != nil {
				return err
			}
			if mh != nil {
				list = append(list, mh.Get())
			} else {
				log.Warnf("Host metadata for '%s' not found!", id)
			}
		}
		return nil
	})
	if err != nil {
		log.Errorf("Error listing hosts: %+v", err)
	}
	return list, nil
}

// Acquire waits until the write lock is available, then locks the metadata
func (m *Network) Acquire() {
	m.item.Acquire()
}

// Release unlocks the metadata
func (m *Network) Release() {
	m.item.Release()
}

// SaveNetwork saves the Network definition in Object Storage
func SaveNetwork(svc iaas.Service, net *resources.Network) (mn *Network, err error) {
	if svc == nil {
		return nil, utils.InvalidParameterError("svc", "can't be nil")
	}
	if net == nil {
		return nil, utils.InvalidParameterError("net", "can't be nil")
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	mn = NewNetwork(svc)
	return mn, mn.Carry(net).Write()
}

// RemoveNetwork removes the Network definition from Object Storage
func RemoveNetwork(svc iaas.Service, net *resources.Network) (err error) {
	if svc == nil {
		return utils.InvalidParameterError("svc", "can't be nil")
	}
	if net == nil {
		return utils.InvalidParameterError("net", "can't be nil")
	}

	tracer := concurrency.NewTracer(nil, "(<iaas.Service>, "+net.Name+")", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	return NewNetwork(svc).Carry(net).Delete()
}

// LoadNetwork gets the Network definition from Object Storage
// logic: Read by ID; if error is ErrNotFound then read by name; if error is ErrNotFound return this error
//        In case of any other error, abort the retry to propagate the error
//        If retry times out, return errNotFound
func LoadNetwork(svc iaas.Service, ref string) (mn *Network, err error) {
	if svc == nil {
		return nil, utils.InvalidParameterError("svc", "can't be nil")
	}
	if ref == "" {
		return nil, utils.InvalidParameterError("ref", "can't be empty string")
	}

	tracer := concurrency.NewTracer(nil, "(<iaas.Service>, '"+ref+"')", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	mn = NewNetwork(svc)
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr := mn.ReadByReference(ref)
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
		return nil, retryErr
	}

	return mn, nil
}

// Gateway links Object Storage folder and Network
type Gateway struct {
	host      *Host
	network   *Network
	networkID string
}

// NewGateway creates an instance of metadata.Gateway
func NewGateway(svc iaas.Service, networkID string) (gw *Gateway, err error) {
	if svc == nil {
		return nil, utils.InvalidParameterError("svc", "can't be nil")
	}
	if networkID == "" {
		return nil, utils.InvalidParameterError("networkID", "can't be empty string")
	}

	tracer := concurrency.NewTracer(nil, "(<iaas.Service>, '"+networkID+"')", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	network := NewNetwork(svc)
	err = network.ReadByID(networkID)
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); ok {
			return nil, utils.NotFoundError("failed to find metadata of network using gateway")
		}
		return nil, err
	}
	return &Gateway{
		network:   network,
		networkID: networkID,
	}, nil
}

// Carry links a Network instance to the Metadata instance
func (mg *Gateway) Carry(host *resources.Host) *Gateway {
	if mg.host == nil {
		mg.host = NewHost(mg.network.GetService())
	}
	mg.host.Carry(host)
	return mg
}

// Get returns the *resources.Host linked to the metadata
func (mg *Gateway) Get() *resources.Host {
	if mg.host == nil {
		panic("mg.host is nil!")
	}
	return mg.host.Get()
}

// Write updates the metadata corresponding to the network in the Object Storage
// A Gateway is a particular host : we want it listed in hosts, but not listed as attached to the network
func (mg *Gateway) Write() error {
	if mg.host == nil {
		panic("mg.host is nil!")
	}
	return mg.host.Write()
}

// Read reads the metadata of a gateway of a network identified by ID from Object Storage
func (mg *Gateway) Read() (err error) {
	if mg == nil {
		return utils.InvalidInstanceError()
	}
	if mg.network == nil {
		return utils.InvalidParameterError("mg.network", "can't be nil")
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	err = mg.network.Reload()
	if err != nil {
		return err
	}
	if mg.host == nil {
		mg.host = NewHost(mg.network.GetService())
	}
	err = mg.host.ReadByID(mg.network.Get().GatewayID)
	if err != nil {
		return err
	}
	return nil
}

// Reload reloads the content of the Object Storage, overriding what is in the metadata instance
// It's advised to Acquire/Release around Reload()...
func (mg *Gateway) Reload() (err error) {
	if mg == nil {
		return utils.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	err = mg.Read()
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); ok {
			return utils.NotFoundError(fmt.Sprintf("metadata about the gateway of network '%s' doesn't exist anymore", mg.networkID))
		}
		return err
	}
	return nil
}

// Delete updates the metadata of the network concerning the gateway
func (mg *Gateway) Delete() (err error) {
	if mg == nil {
		return utils.InvalidInstanceError()
	}
	if mg.network == nil {
		return utils.InvalidParameterError("mg.network", "can't be nil")
	}
	if mg.host == nil {
		return utils.InvalidParameterError("mg.host", "can't be nil")
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	mg.network.Acquire()
	mg.network.Get().GatewayID = ""
	err = mg.network.Write()
	mg.network.Release()
	if err != nil {
		return err
	}
	mg.host.Acquire()
	defer mg.host.Release()
	return mg.host.Delete()
}

// Acquire waits until the write lock is available, then locks the metadata
func (mg *Gateway) Acquire() {
	mg.host.Acquire()
}

// Release unlocks the metadata
func (mg *Gateway) Release() {
	mg.host.Release()
}

// LoadGateway returns the metadata of the Gateway of a network
func LoadGateway(svc iaas.Service, networkID string) (mg *Gateway, err error) {
	if svc == nil {
		return nil, utils.InvalidParameterError("svc", "can't be nil")
	}
	if networkID == "" {
		return nil, utils.InvalidParameterError("networkID", "can't be empty string")
	}

	tracer := concurrency.NewTracer(nil, "(<iaas.Service>, '"+networkID+"')", true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	mg, err = NewGateway(svc, networkID)
	if err != nil {
		return nil, err
	}

	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr := mg.Read()
			if innerErr != nil {
				if _, ok := innerErr.(utils.ErrNotFound); ok {
					return retry.StopRetryError("", innerErr)
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

	return mg, nil
}

// SaveGateway saves the metadata of a gateway
func SaveGateway(svc iaas.Service, host *resources.Host, networkID string) (mg *Gateway, err error) {
	if svc == nil {
		return nil, utils.InvalidParameterError("svc", "can't be nil")
	}
	if host == nil {
		return nil, utils.InvalidParameterError("host", "can't be nil")
	}
	if networkID == "" {
		return nil, utils.InvalidParameterError("networkID", "can't be empty string")
	}

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("(<iaas.Service>, %s, '%s'", host.Name, networkID), true).GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	mg, err = NewGateway(svc, networkID)
	if err != nil {
		return nil, err
	}

	// Update network with gateway info
	mn := NewNetwork(svc)
	err = mn.ReadByID(networkID)
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); ok {
			return nil, utils.NotFoundError(fmt.Sprintf("metadata about the network '%s' doesn't exist anymore", networkID))
		}
		return nil, err
	}
	mn.Get().GatewayID = host.ID
	err = mn.Write()
	if err != nil {
		return nil, err
	}

	// write gateway
	return mg, mg.Carry(host).Write()
}
