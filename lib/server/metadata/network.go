/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/networkproperty"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/metadata"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// NetworksFolderName is the technical name of the container used to store networks info
	networksFolderName = "networks"
)

// Network links Object Storage folder and Network resource
type Network struct {
	item *metadata.Item
	//inside *metadata.Folder
	name *string
	id   *string
}

// NewNetwork creates an instance of Network
func NewNetwork(svc iaas.Service) (*Network, error) {
	aNet, err := metadata.NewItem(svc, networksFolderName)
	if err != nil {
		return nil, err
	}
	return &Network{
		item: aNet,
	}, nil
}

// GetService returns the provider service used
func (m *Network) GetService() iaas.Service {
	return m.item.GetService()
}

// GetPath returns the path in Object Storage where the item is stored
func (m *Network) GetPath() (string, error) {
	if m == nil {
		return "", scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return "", scerr.InvalidInstanceContentError("m.item", "cannot be nil")
	}

	return m.item.GetPath(), nil
}

// Carry links a Network instance to the Metadata instance
func (m *Network) Carry(network *resources.Network) (*Network, error) {
	if m == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return nil, scerr.InvalidInstanceContentError("m.item", "m.item cannot be nil")
	}
	if network == nil {
		return nil, scerr.InvalidParameterError("network", "cannot be nil")
	}

	if network.Properties == nil {
		network.Properties = serialize.NewJSONProperties("resources")
	}

	m.item.Carry(network)
	m.id = &network.ID
	m.name = &network.Name
	//m.inside = metadata.NewFolder(m.item.GetService(), strings.Trim(m.item.GetPath()+"/"+*m.id, "/"))
	return m, nil
}

// Get returns the resources.Network instance linked to metadata
func (m *Network) Get() (*resources.Network, error) {
	if m == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return nil, scerr.InvalidInstanceContentError("m.item", "cannot be nil")
	}
	return m.item.Get().(*resources.Network), nil
}

// Write updates the metadata corresponding to the network in the Object Storage
func (m *Network) Write() (err error) {
	if m == nil {
		return scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return scerr.InvalidInstanceContentError("m.item", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

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
		return scerr.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = m.ReadByID(*m.id)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			return scerr.NotFoundError(fmt.Sprintf("the metadata of Network '%s' vanished", *m.name))
		}
		return err
	}
	return nil
}

// ReadByReference tries to read first using 'ref' as an ID then as a name
func (m *Network) ReadByReference(ref string) (err error) {
	if m == nil {
		return scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return scerr.InvalidInstanceContentError("m.item", "cannot be nil")
	}
	if ref == "" {
		return scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, "('"+ref+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	errID := m.mayReadByID(ref)
	if errID != nil {
		errName := m.mayReadByName(ref)
		if errName != nil {
			return errName
		}
	}
	return nil
}

// mayReadByID reads the metadata of a network identified by ID from Object Storage
// Doesn't log error or validate parameter by design; caller does that
func (m *Network) mayReadByID(id string) (err error) {
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

// mayReadByName reads the metadata of a network identified by name
// Doesn't log error or validate parameter by design; caller does that
func (m *Network) mayReadByName(name string) (err error) {
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
	return nil
}

// ReadByID reads the metadata of a network identified by ID from Object Storage
func (m *Network) ReadByID(id string) (err error) {
	if m == nil {
		return scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return scerr.InvalidInstanceContentError("m.item", "cannot be nil")
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, "("+id+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	return m.mayReadByID(id)
}

// ReadByName reads the metadata of a network identified by name
func (m *Network) ReadByName(name string) (err error) {
	if m == nil {
		return scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return scerr.InvalidInstanceContentError("m.item", "cannot be nil")
	}
	if name == "" {
		return scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, "('"+name+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	return m.mayReadByName(name)
}

// Delete deletes the metadata corresponding to the network
func (m *Network) Delete() (err error) {
	if m == nil {
		return scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return scerr.InvalidInstanceContentError("m.item", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

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
		return scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return scerr.InvalidInstanceContentError("m.item", "cannot be nil")
	}
	if callback == nil {
		return scerr.InvalidParameterError("callback", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

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
		return scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return scerr.InvalidInstanceContentError("m.item", "cannot be nil")
	}
	if host == nil {
		return scerr.InvalidParameterError("host", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "("+host.Name+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	network, err := m.Get()
	if err != nil {
		return err
	}
	return network.Properties.LockForWrite(networkproperty.HostsV1).ThenUse(func(v interface{}) error {
		networkHostsV1 := v.(*propsv1.NetworkHosts)
		networkHostsV1.ByID[host.ID] = host.Name
		networkHostsV1.ByName[host.Name] = host.ID
		return nil
	})
}

// DetachHost unlinks host ID from network
func (m *Network) DetachHost(hostID string) (err error) {
	if m == nil {
		return scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return scerr.InvalidInstanceContentError("m.item", "cannot be nil")
	}
	if hostID == "" {
		return scerr.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, "('"+hostID+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	network, err := m.Get()
	if err != nil {
		return err
	}
	err = network.Properties.LockForWrite(networkproperty.HostsV1).ThenUse(func(v interface{}) error {
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
		return nil, scerr.InvalidInstanceError()
	}
	if m.item == nil {
		return nil, scerr.InvalidInstanceContentError("m.item", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	network, err := m.Get()
	if err != nil {
		return nil, err
	}
	err = network.Properties.LockForRead(networkproperty.HostsV1).ThenUse(func(v interface{}) error {
		networkHostsV1 := v.(*propsv1.NetworkHosts)
		for id := range networkHostsV1.ByID {
			mh, err := LoadHost(m.item.GetService(), id)
			if err != nil {
				return err
			}
			if mh != nil {
				mhm, merr := mh.Get()
				if merr != nil {
					return merr
				}
				list = append(list, mhm)
			} else {
				logrus.Warnf("Host metadata for '%s' not found!", id)
			}
		}
		return nil
	})
	if err != nil {
		logrus.Errorf("Error listing hosts: %+v", err)
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
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if net == nil {
		return nil, scerr.InvalidParameterError("net", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mn, err = NewNetwork(svc)
	if err != nil {
		return nil, err
	}

	mnm, err := mn.Carry(net)
	if err != nil {
		return nil, err
	}

	return mn, mnm.Write()
}

// RemoveNetwork removes the Network definition from Object Storage
func RemoveNetwork(svc iaas.Service, net *resources.Network) (err error) {
	if svc == nil {
		return scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if net == nil {
		return scerr.InvalidParameterError("net", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "(<iaas.Service>, "+net.Name+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	aNet, err := NewNetwork(svc)
	if err != nil {
		return err
	}

	aNetm, err := aNet.Carry(net)
	if err != nil {
		return err
	}

	return aNetm.Delete()
}

// LoadNetwork gets the Network definition from Object Storage
// logic: Read by ID; if error is ErrNotFound then read by name; if error is ErrNotFound return this error
//        In case of any other error, abort the retry to propagate the error
//        If retry times out, return errNotFound
func LoadNetwork(svc iaas.Service, ref string) (mn *Network, err error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, "(<iaas.Service>, '"+ref+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mn, err = NewNetwork(svc)
	if err != nil {
		return nil, err
	}
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr := mn.ReadByReference(ref)
			if innerErr != nil {
				if _, ok := innerErr.(scerr.ErrNotFound); ok {
					return retry.StopRetryError("no metadata found", innerErr)
				}
				return innerErr
			}

			return nil
		},
		2*temporal.GetDefaultDelay(),
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
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if networkID == "" {
		return nil, scerr.InvalidParameterError("networkID", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, "(<iaas.Service>, '"+networkID+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	network, err := NewNetwork(svc)
	if err != nil {
		return nil, err
	}
	err = network.ReadByID(networkID)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			return nil, scerr.NotFoundError("failed to find metadata of network using gateway")
		}
		return nil, err
	}
	return &Gateway{
		network:   network,
		networkID: networkID,
	}, nil
}

// Carry links a Network instance to the Metadata instance
func (mg *Gateway) Carry(host *resources.Host) (gw *Gateway, err error) {
	if mg.host == nil {
		mg.host, err = NewHost(mg.network.GetService())
		if err != nil {
			return nil, err
		}
	}

	_, err = mg.host.Carry(host)
	if err != nil {
		return nil, err
	}

	return mg, nil
}

// Get returns the *resources.Host linked to the metadata
func (mg *Gateway) Get() (*resources.Host, error) {
	if mg == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if mg.host == nil {
		return nil, scerr.InvalidInstanceContentError("mg.host", "cannot be nil")
	}

	mgm, err := mg.host.Get()
	if err != nil {
		return nil, err
	}

	return mgm, nil
}

// Write updates the metadata corresponding to the network in the Object Storage
// A Gateway is a particular host : we want it listed in hosts, but not listed as attached to the network
func (mg *Gateway) Write() error {
	if mg.host == nil {
		return scerr.InvalidInstanceContentError("mg.host", "cannot be nil")
	}
	return mg.host.Write()
}

// Read reads the metadata of a gateway of a network identified by ID from Object Storage
func (mg *Gateway) Read() (err error) {
	if mg == nil {
		return scerr.InvalidInstanceError()
	}
	if mg.network == nil {
		return scerr.InvalidParameterError("mg.network", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = mg.network.Reload()
	if err != nil {
		return err
	}
	if mg.host == nil {
		mg.host, err = NewHost(mg.network.GetService())
		if err != nil {
			return err
		}
	}

	mgm, err := mg.network.Get()
	if err != nil {
		return err
	}

	err = mg.host.ReadByID(mgm.GatewayID)
	if err != nil {
		return err
	}
	return nil
}

// Reload reloads the content of the Object Storage, overriding what is in the metadata instance
// It's advised to Acquire/Release around Reload()...
func (mg *Gateway) Reload() (err error) {
	if mg == nil {
		return scerr.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = mg.Read()
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			return scerr.NotFoundError(fmt.Sprintf("metadata about the gateway of network '%s' doesn't exist anymore", mg.networkID))
		}
		return err
	}
	return nil
}

// Delete updates the metadata of the network concerning the gateway
func (mg *Gateway) Delete() (err error) {
	if mg == nil {
		return scerr.InvalidInstanceError()
	}
	if mg.network == nil {
		return scerr.InvalidParameterError("mg.network", "cannot be nil")
	}
	if mg.host == nil {
		return scerr.InvalidParameterError("mg.host", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mg.network.Acquire()

	mgm, err := mg.network.Get()
	if err != nil {
		return err
	}

	mgm.GatewayID = ""
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
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if networkID == "" {
		return nil, scerr.InvalidParameterError("networkID", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, "(<iaas.Service>, '"+networkID+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mg, err = NewGateway(svc, networkID)
	if err != nil {
		return nil, err
	}

	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr := mg.Read()
			if innerErr != nil {
				if _, ok := innerErr.(scerr.ErrNotFound); ok {
					return retry.StopRetryError("", innerErr)
				}
				return innerErr
			}
			return nil
		},
		2*temporal.GetDefaultDelay(),
	)
	if retryErr != nil {
		// If it's not a timeout is something we don't know how to handle yet
		if _, ok := retryErr.(scerr.ErrTimeout); !ok {
			return nil, scerr.Cause(retryErr)
		}
		return nil, retryErr
	}

	return mg, nil
}

// SaveGateway saves the metadata of a gateway
func SaveGateway(svc iaas.Service, host *resources.Host, networkID string) (mg *Gateway, err error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if host == nil {
		return nil, scerr.InvalidParameterError("host", "cannot be nil")
	}
	if networkID == "" {
		return nil, scerr.InvalidParameterError("networkID", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("(<iaas.Service>, %s, '%s'", host.Name, networkID), true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mg, err = NewGateway(svc, networkID)
	if err != nil {
		return nil, err
	}

	// Update network with gateway info
	mn, err := NewNetwork(svc)
	if err != nil {
		return nil, err
	}

	err = mn.ReadByID(networkID)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			return nil, scerr.NotFoundError(fmt.Sprintf("metadata about the network '%s' doesn't exist anymore", networkID))
		}
		return nil, err
	}

	mnm, err := mn.Get()
	if err != nil {
		return nil, err
	}

	mnm.GatewayID = host.ID
	err = mn.Write()
	if err != nil {
		return nil, err
	}

	// write gateway
	aGw, err := mg.Carry(host)
	if err != nil {
		return nil, err
	}
	return mg, aGw.Write()
}
