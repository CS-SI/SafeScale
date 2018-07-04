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
	"fmt"

	"github.com/CS-SI/SafeScale/metadata"
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
)

const (
	//NetworkFolderName is the technical name of the container used to store networks info
	networkFolderName = "network"
	//GatewayObjectName is the name of the object containing the id of the VM acting as a default gateway for a network
	gatewayObjectName = "gw"
)

//Network links Object Storage folder and Network
type Network struct {
	folder  *metadata.Folder
	network *api.Network
}

//NewNetwork creates an instance of network.Metadata
func NewNetwork(svc *providers.Service) (*Network, error) {
	f, err := metadata.NewFolder(svc, networkFolderName)
	if err != nil {
		return nil, err
	}
	return &Network{
		folder:  f,
		network: nil,
	}, nil
}

//Carry links a Network instance to the Metadata instance
func (m *Network) Carry(network *api.Network) *Network {
	if network == nil {
		panic("network parameter is nil!")
	}
	m.network = network
	return m
}

//Get returns the Network instance linked to metadata
func (m *Network) Get() *api.Network {
	return m.network
}

//Write updates the metadata corresponding to the network in the Object Storage
func (m *Network) Write() error {
	if m.network == nil {
		panic("m.network is nil!")
	}

	err := m.folder.Write(ByIDFolderName, m.network.ID, m.network)
	if err != nil {
		return err
	}
	return m.folder.Write(ByNameFolderName, m.network.Name, m.network)
}

//Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (m *Network) Reload() error {
	if m.network == nil {
		panic("m.network is nil!")
	}
	netName := m.network.Name
	found, err := m.ReadByID(m.network.ID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("The metadata of Network '%s' doesn't exist anymore", netName)
	}
	return nil
}

//ReadByID reads the metadata of a network identified by ID from Object Storage
func (m *Network) ReadByID(id string) (bool, error) {
	var network api.Network
	found, err := m.folder.Read(ByIDFolderName, id, func(buf *bytes.Buffer) error {
		return gob.NewDecoder(buf).Decode(&network)
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.network = &network
	return true, nil
}

//ReadByName reads the metadata of a network identified by name
func (m *Network) ReadByName(name string) (bool, error) {
	var network api.Network
	found, err := m.folder.Read(ByNameFolderName, name, func(buf *bytes.Buffer) error {
		return gob.NewDecoder(buf).Decode(&network)
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.network = &network
	return true, nil
}

//Delete updates the metadata corresponding to the network
func (m *Network) Delete() error {
	if m.network == nil {
		panic("m.network is nil!")
	}
	err := m.folder.Delete(ByIDFolderName, m.network.ID)
	if err != nil {
		return err
	}
	return m.folder.Delete(ByNameFolderName, m.network.Name)
}

//Browse walks through all the metadata objects in network
func (m *Network) Browse(callback func(*api.Network) error) error {
	return m.folder.Browse(ByIDFolderName, func(buf *bytes.Buffer) error {
		var net api.Network
		err := gob.NewDecoder(buf).Decode(&net)
		if err != nil {
			return nil
		}
		return callback(&net)
	})
}

//AttachHost links host ID to the network
func (m *Network) AttachHost(vm *api.VM) error {
	if m.network == nil {
		panic("m.network is nil!")
	}
	return m.folder.Write(m.network.ID+"/host", vm.ID, vm)
}

//DetachHost unlinks host ID to network
func (m *Network) DetachHost(vmID string) error {
	if m.network == nil {
		panic("m.network is nil!")
	}
	return m.folder.Delete(m.network.ID+"/host", vmID)
}

//ListHosts returns the list of ID of hosts attached to the network (be careful: including gateway)
func (m *Network) ListHosts() ([]*api.VM, error) {
	if m.network == nil {
		panic("m.network is nil!")
	}

	var list []*api.VM
	err := m.folder.Browse(m.network.ID+"/host", func(buf *bytes.Buffer) error {
		var vm api.VM
		err := gob.NewDecoder(buf).Decode(&vm)
		if err != nil {
			return err
		}
		list = append(list, &vm)
		return nil
	})
	return list, err
}

//SaveNetwork saves the Network definition in Object Storage
func SaveNetwork(svc *providers.Service, net *api.Network) error {
	m, err := NewNetwork(svc)
	if err != nil {
		return err
	}
	return m.Carry(net).Write()
}

//RemoveNetwork removes the VM definition from Object Storage
func RemoveNetwork(svc *providers.Service, net *api.Network) error {
	// First, browse networks to delete links on the deleted host
	m, err := NewNetwork(svc)
	if err != nil {
		return err
	}
	return m.Carry(net).Delete()
}

//LoadNetwork gets the VM definition from Object Storage
func LoadNetwork(svc *providers.Service, networkID string) (*Network, error) {
	m, err := NewNetwork(svc)
	if err != nil {
		return nil, err
	}
	found, err := m.ReadByID(networkID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return m, nil
}

//LoadNetworkByName gets the VM definition from Object Storage
func LoadNetworkByName(svc *providers.Service, networkname string) (*Network, error) {
	m, err := NewNetwork(svc)
	if err != nil {
		return nil, err
	}
	found, err := m.ReadByName(networkname)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return m, nil
}

//Gateway links Object Storage folder and Network
type Gateway struct {
	folder    *metadata.Folder
	networkID string
	host      *api.VM
}

//NewGateway creates an instance of metadata.Gateway
func NewGateway(svc *providers.Service, networkID string) (*Gateway, error) {
	f, err := metadata.NewFolder(svc, networkFolderName)
	if err != nil {
		return nil, err
	}
	return &Gateway{
		folder:    f,
		host:      nil,
		networkID: networkID,
	}, nil
}

//Carry links a Network instance to the Metadata instance
func (m *Gateway) Carry(vm *api.VM) *Gateway {
	m.host = vm
	return m
}

//Get returns the *api.VM linked to the metadata
func (m *Gateway) Get() *api.VM {
	return m.host
}

//Write updates the metadata corresponding to the network in the Object Storage
func (m *Gateway) Write(svc *providers.Service) error {
	// A Gateway is a particular host : we want it listed in hosts, but not listed as attached to the network...
	mh, err := NewHost(svc)
	if err != nil {
		return err
	}
	err = mh.Carry(m.host).Write()
	if err != nil {
		return err
	}
	// ... with a reference as gw in network metadata
	return m.folder.Write(m.networkID, gatewayObjectName, m.host)
}

//Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (m *Gateway) Reload() error {
	if m.host == nil {
		panic("m.host is nil!")
	}
	found, err := m.Read()
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("metadata about the gateway of network '%s' doesn't exist anymore", m.networkID)
	}
	return nil
}

//Read reads the metadata of a gateway of a network identified by ID from Object Storage
func (m *Gateway) Read() (bool, error) {
	var host api.VM
	found, err := m.folder.Read(m.networkID, gatewayObjectName, func(buf *bytes.Buffer) error {
		return gob.NewDecoder(buf).Decode(&host)
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.host = &host
	return true, nil
}

//Delete updates the metadata corresponding to the network
func (m *Gateway) Delete() error {
	return m.folder.Delete(m.networkID, gatewayObjectName)
}

//LoadGateway returns the metadata of the Gateway of a network
func LoadGateway(svc *providers.Service, networkID string) (*Gateway, error) {
	m, err := NewGateway(svc, networkID)
	if err != nil {
		return nil, err
	}
	found, err := m.Read()
	if err != nil {
		return nil, err
	}
	if found {
		return m, nil
	}
	return nil, nil
}

//SaveGateway saves the metadata of a gateway
func SaveGateway(svc *providers.Service, vm *api.VM, networkID string) error {
	m, err := NewGateway(svc, networkID)
	if err != nil {
		return err
	}
	// Update network
	n, err := NewNetwork(svc)
	if err != nil {
		return err
	}
	ok, err := n.ReadByID(networkID)
	if !ok || err != nil {
		return fmt.Errorf("metadata about the  '%s' doesn't exist anymore", networkID)
	}
	net := n.Get()
	net.GatewayID = vm.ID
	err = n.Write()
	if err != nil {
		return err
	}

	return m.Carry(vm).Write(svc)
}
