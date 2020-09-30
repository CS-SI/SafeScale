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

	"github.com/graymeta/stow"

	"github.com/CS-SI/SafeScale/lib/utils/debug"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/networkproperty"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/abstract/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/metadata"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
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
	// inside *metadata.Folder
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
		return "", fail.InvalidInstanceError()
	}
	if m.item == nil {
		return "", fail.InvalidInstanceContentError("m.item", "cannot be nil")
	}

	return m.item.GetPath(), nil
}

func (m *Network) OK() (bool, error) {
	if m == nil {
		return false, fail.InvalidInstanceError()
	}

	if m.id == nil && m.name == nil {
		if m.item == nil {
			return false, nil
		}

		if ok, err := m.item.OK(); err != nil || !ok {
			return false, nil
		}
	}

	return true, nil
}

// Carry links a Network instance to the Metadata instance
func (m *Network) Carry(network *abstract.Network) (*Network, error) {
	if m == nil {
		return nil, fail.InvalidInstanceError()
	}
	if m.item == nil {
		return nil, fail.InvalidInstanceContentError("m.item", "m.item cannot be nil")
	}
	if network == nil {
		return nil, fail.InvalidParameterError("network", "cannot be nil")
	}

	if network.Properties == nil {
		network.Properties = serialize.NewJSONProperties("abstract")
	}

	m.item.Carry(network)
	m.id = &network.ID
	m.name = &network.Name
	// m.inside = metadata.NewFolder(m.item.GetService(), strings.Trim(m.item.GetPath()+"/"+*m.id, "/"))
	return m, nil
}

// Get returns the abstract.Network instance linked to metadata
func (m *Network) Get() (*abstract.Network, error) {
	if m == nil {
		return nil, fail.InvalidInstanceError()
	}
	if m.item == nil {
		return nil, fail.InvalidInstanceContentError("m.item", "cannot be nil")
	}
	return m.item.Get().(*abstract.Network), nil
}

// Write updates the metadata corresponding to the network in the Object Storage
func (m *Network) Write() (err error) {
	if m == nil {
		return fail.InvalidInstanceError()
	}
	if m.item == nil {
		return fail.InvalidInstanceContentError("m.item", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

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
		return fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = m.ReadByID(*m.id)
	if err != nil {
		if _, ok := err.(fail.ErrNotFound); ok {
			return fail.NotFoundError(fmt.Sprintf("the metadata of Network '%s' vanished", *m.name))
		}
		return err
	}
	return nil
}

// ReadByReference tries to read first using 'ref' as an ID then as a name
func (m *Network) ReadByReference(ref string) (err error) {
	if m == nil {
		return fail.InvalidInstanceError()
	}
	if m.item == nil {
		return fail.InvalidInstanceContentError("m.item", "cannot be nil")
	}
	if ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "('"+ref+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogErrorWithLevel(tracer.TraceMessage(""), &err, logrus.TraceLevel)()

	var errors []error
	err1 := m.mayReadByID(ref) // First read by id...
	if err1 != nil {
		errors = append(errors, err1)
	}

	err2 := m.mayReadByName(ref) // ... then read by name if by id failed (no need to read twice if the 2 exist)
	if err2 != nil {
		errors = append(errors, err2)
	}

	if len(errors) == 2 {
		if err1 == stow.ErrNotFound && err2 == stow.ErrNotFound { // FIXME: Remove stow dependency
			return fail.NotFoundErrorWithCause(fmt.Sprintf("reference %s not found", ref), fail.ErrListError(errors))
		}

		if _, ok := err1.(fail.ErrNotFound); ok {
			if _, ok := err2.(fail.ErrNotFound); ok {
				return fail.NotFoundErrorWithCause(
					fmt.Sprintf("reference %s not found", ref), fail.ErrListError(errors),
				)
			}
		}

		return fail.ErrListError(errors)
	}
	return nil
}

// mayReadByID reads the metadata of a network identified by ID from Object Storage
// Doesn't log error or validate parameter by design; caller does that
func (m *Network) mayReadByID(id string) (err error) {
	network := abstract.NewNetwork()
	err = m.item.ReadFrom(
		ByIDFolderName, id, func(buf []byte) (serialize.Serializable, error) {
			ierr := network.Deserialize(buf)
			if ierr != nil {
				return nil, ierr
			}
			return network, nil
		},
	)
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
	network := abstract.NewNetwork()
	err = m.item.ReadFrom(
		ByNameFolderName, name, func(buf []byte) (serialize.Serializable, error) {
			ierr := network.Deserialize(buf)
			if ierr != nil {
				return nil, ierr
			}
			return network, nil
		},
	)
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
		return fail.InvalidInstanceError()
	}
	if m.item == nil {
		return fail.InvalidInstanceContentError("m.item", "cannot be nil")
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "("+id+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	return m.mayReadByID(id)
}

// ReadByName reads the metadata of a network identified by name
func (m *Network) ReadByName(name string) (err error) {
	if m == nil {
		return fail.InvalidInstanceError()
	}
	if m.item == nil {
		return fail.InvalidInstanceContentError("m.item", "cannot be nil")
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "('"+name+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	return m.mayReadByName(name)
}

// Delete deletes the metadata corresponding to the network
func (m *Network) Delete() (err error) {
	if m == nil {
		return fail.InvalidInstanceError()
	}
	if m.item == nil {
		return fail.InvalidInstanceContentError("m.item", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

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
func (m *Network) Browse(callback func(*abstract.Network) error) (err error) {
	if m == nil {
		return fail.InvalidInstanceError()
	}
	if m.item == nil {
		return fail.InvalidInstanceContentError("m.item", "cannot be nil")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	return m.item.BrowseInto(
		ByIDFolderName, func(buf []byte) error {
			network := abstract.Network{}
			err := (&network).Deserialize(buf)
			if err != nil {
				return err
			}
			return callback(&network)
		},
	)
}

// AttachHost links host ID to the network
func (m *Network) AttachHost(host *abstract.Host) (err error) {
	if m == nil {
		return fail.InvalidInstanceError()
	}
	if m.item == nil {
		return fail.InvalidInstanceContentError("m.item", "cannot be nil")
	}
	if host == nil {
		return fail.InvalidParameterError("host", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "("+host.Name+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	network, err := m.Get()
	if err != nil {
		return err
	}
	return network.Properties.LockForWrite(networkproperty.HostsV1).ThenUse(
		func(clonable data.Clonable) error {
			networkHostsV1 := clonable.(*propsv1.NetworkHosts)
			networkHostsV1.ByID[host.ID] = host.Name
			networkHostsV1.ByName[host.Name] = host.ID
			return nil
		},
	)
}

// DetachHost unlinks host ID from network
func (m *Network) DetachHost(hostID string) (err error) {
	if m == nil {
		return fail.InvalidInstanceError()
	}
	if m.item == nil {
		return fail.InvalidInstanceContentError("m.item", "cannot be nil")
	}
	if hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "('"+hostID+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	network, err := m.Get()
	if err != nil {
		return err
	}
	err = network.Properties.LockForWrite(networkproperty.HostsV1).ThenUse(
		func(clonable data.Clonable) error {
			networkHostsV1 := clonable.(*propsv1.NetworkHosts)
			hostName, found := networkHostsV1.ByID[hostID]
			if found {
				delete(networkHostsV1.ByName, hostName)
				delete(networkHostsV1.ByID, hostID)
			}
			return nil
		},
	)
	if err != nil {
		return err
	}
	return nil
}

// ListHosts returns the list of abstract.Host attached to the network (excluding gateway)
func (m *Network) ListHosts() (list []*abstract.Host, err error) {
	if m == nil {
		return nil, fail.InvalidInstanceError()
	}
	if m.item == nil {
		return nil, fail.InvalidInstanceContentError("m.item", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	network, err := m.Get()
	if err != nil {
		return nil, err
	}
	err = network.Properties.LockForRead(networkproperty.HostsV1).ThenUse(
		func(clonable data.Clonable) error {
			networkHostsV1 := clonable.(*propsv1.NetworkHosts)
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
		},
	)
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
func SaveNetwork(svc iaas.Service, net *abstract.Network) (mn *Network, err error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if net == nil {
		return nil, fail.InvalidParameterError("net", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

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
func RemoveNetwork(svc iaas.Service, net *abstract.Network) (err error) {
	if svc == nil {
		return fail.InvalidParameterError("svc", "cannot be nil")
	}
	if net == nil {
		return fail.InvalidParameterError("net", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "(<iaas.Service>, "+net.Name+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

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
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "(<iaas.Service>, '"+ref+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogErrorWithLevel(tracer.TraceMessage(""), &err, logrus.TraceLevel)()

	mn, err = NewNetwork(svc)
	if err != nil {
		return nil, err
	}
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr := mn.ReadByReference(ref)
			if innerErr != nil {
				if _, ok := innerErr.(fail.ErrNotFound); ok {
					return retry.AbortedError("no metadata found", innerErr)
				}

				if innerErr == stow.ErrNotFound { // FIXME: Remove stow dependency
					return retry.AbortedError("no metadata found", innerErr)
				}

				return innerErr
			}

			return nil
		},
		2*temporal.GetDefaultDelay(),
	)
	if retryErr != nil {
		switch realErr := retryErr.(type) {
		case retry.ErrAborted:
			return nil, realErr.Cause()
		case fail.ErrTimeout:
			return nil, realErr
		default:
			return nil, fail.Cause(realErr)
		}
	}

	ok, err := mn.OK()
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fail.NotFoundError(fmt.Sprintf("reference %s not found", ref))
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
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if networkID == "" {
		return nil, fail.InvalidParameterError("networkID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "(<iaas.Service>, '"+networkID+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	network, err := NewNetwork(svc)
	if err != nil {
		return nil, err
	}
	err = network.ReadByID(networkID)
	if err != nil {
		if _, ok := err.(fail.ErrNotFound); ok {
			return nil, fail.NotFoundError("failed to find metadata of network using gateway")
		}
		return nil, err
	}
	return &Gateway{
		network:   network,
		networkID: networkID,
	}, nil
}

// Carry links a Network instance to the Metadata instance
func (mg *Gateway) Carry(host *abstract.Host) (gw *Gateway, err error) {
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

// Get returns the *abstract.Host linked to the metadata
func (mg *Gateway) Get() (*abstract.Host, error) {
	if mg == nil {
		return nil, fail.InvalidInstanceError()
	}
	if mg.host == nil {
		return nil, fail.InvalidInstanceContentError("mg.host", "cannot be nil")
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
		return fail.InvalidInstanceContentError("mg.host", "cannot be nil")
	}
	return mg.host.Write()
}

// Read reads the metadata of a gateway of a network identified by ID from Object Storage
func (mg *Gateway) Read() (err error) {
	if mg == nil {
		return fail.InvalidInstanceError()
	}
	if mg.network == nil {
		return fail.InvalidParameterError("mg.network", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

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
		return fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = mg.Read()
	if err != nil {
		if _, ok := err.(fail.ErrNotFound); ok {
			return fail.NotFoundError(
				fmt.Sprintf(
					"metadata about the gateway of network '%s' doesn't exist anymore", mg.networkID,
				),
			)
		}
		return err
	}
	return nil
}

// Delete updates the metadata of the network concerning the gateway
func (mg *Gateway) Delete() (err error) {
	if mg == nil {
		return fail.InvalidInstanceError()
	}
	if mg.network == nil {
		return fail.InvalidParameterError("mg.network", "cannot be nil")
	}
	if mg.host == nil {
		return fail.InvalidParameterError("mg.host", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

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
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if networkID == "" {
		return nil, fail.InvalidParameterError("networkID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "(<iaas.Service>, '"+networkID+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	mg, err = NewGateway(svc, networkID)
	if err != nil {
		return nil, err
	}

	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			innerErr := mg.Read()
			if innerErr != nil {
				if _, ok := innerErr.(fail.ErrNotFound); ok {
					return retry.AbortedError("", innerErr)
				}
				return innerErr
			}
			return nil
		},
		2*temporal.GetDefaultDelay(),
	)
	if retryErr != nil {
		switch realErr := retryErr.(type) {
		case retry.ErrAborted:
			return nil, realErr.Cause()
		case fail.ErrTimeout:
			return nil, realErr
		default:
			return nil, fail.Cause(realErr)
		}
	}

	return mg, nil
}

// SaveGateway saves the metadata of a gateway
func SaveGateway(svc iaas.Service, host *abstract.Host, networkID string) (mg *Gateway, err error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if host == nil {
		return nil, fail.InvalidParameterError("host", "cannot be nil")
	}
	if networkID == "" {
		return nil, fail.InvalidParameterError("networkID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, fmt.Sprintf("(<iaas.Service>, %s, '%s'", host.Name, networkID), true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

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
		if _, ok := err.(fail.ErrNotFound); ok {
			return nil, fail.NotFoundError(
				fmt.Sprintf(
					"metadata about the network '%s' doesn't exist anymore", networkID,
				),
			)
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
