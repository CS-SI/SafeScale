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

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/NetworkExtension"
	"github.com/CS-SI/SafeScale/utils/metadata"
)

const (
	//NetworkFolderName is the technical name of the container used to store networks info
	networksFolderName = "networks"
	//GatewayObjectName is the name of the object containing the id of the host acting as a default gateway for a network
	gatewayObjectName = "gw"
)

// Network links Object Storage folder and Network
type Network struct {
	item   *metadata.Item
	inside *metadata.Folder
	name   *string
	id     *string
}

// NewNetwork creates an instance of network.Metadata
func NewNetwork(svc api.ClientAPI) *Network {
	return &Network{
		item: metadata.NewItem(svc, networksFolderName),
	}
}

// GetPath returns the path in Object Storage where the item is stored
func (m *Network) GetPath() string {
	if m.item == nil {
		panic("m.item is nil!")
	}
	return m.item.GetPath()
}

// Carry links a Network instance to the Metadata instance
func (m *Network) Carry(network *model.Network) *Network {
	if network == nil {
		panic("network parameter is nil!")
	}
	if m.item == nil {
		panic("m.item is nil!")
	}

	m.item.Carry(network)
	m.id = &network.ID
	m.name = &network.Name
	m.inside = metadata.NewFolder(m.item.GetService(), strings.Trim(m.item.GetPath()+"/"+*m.id, "/"))
	return m
}

// Get returns the model.Network instance linked to metadata
func (m *Network) Get() *model.Network {
	if m.item == nil {
		panic("m.item is nil!")
	}
	return m.item.Get().(*model.Network)
}

// Write updates the metadata corresponding to the network in the Object Storage
func (m *Network) Write() error {
	if m.item == nil {
		panic("m.item is nil!")
	}
	err := m.item.WriteInto(ByIDFolderName, *m.id)
	if err != nil {
		return err
	}
	return m.item.WriteInto(ByNameFolderName, *m.name)
}

// Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (m *Network) Reload() error {
	found, err := m.ReadByID(*m.id)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("the metadata of Network '%s' vanished", *m.name)
	}
	return nil
}

// ReadByID reads the metadata of a network identified by ID from Object Storage
func (m *Network) ReadByID(id string) (bool, error) {
	if m.item == nil {
		panic("m.item is nil!")
	}

	var network model.Network
	found, err := m.item.ReadFrom(ByIDFolderName, id, func(buf []byte) (model.Serializable, error) {
		err := (&network).Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return &network, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.id = &network.ID
	m.name = &network.Name
	m.inside = metadata.NewFolder(m.item.GetService(), strings.Trim(m.item.GetPath()+"/"+id, "/"))
	return true, nil
}

// ReadByName reads the metadata of a network identified by name
func (m *Network) ReadByName(name string) (bool, error) {
	if m.item == nil {
		panic("m.item is nil!")
	}

	var network model.Network
	found, err := m.item.ReadFrom(ByNameFolderName, name, func(buf []byte) (model.Serializable, error) {
		err := (&network).Deserialize(buf)
		if err != nil {
			return nil, err
		}
		return &network, nil
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.name = &network.Name
	m.id = &network.ID
	m.inside = metadata.NewFolder(m.item.GetService(), strings.Trim(m.item.GetPath()+"/"+*m.id, "/"))
	return true, nil
}

// Delete deletes the metadata corresponding to the network
func (m *Network) Delete() error {
	if m.item == nil {
		panic("m.item is nil!")
	}

	// First delete network/<id> folder if it exists
	nerr := m.item.Delete(*m.id)
	if nerr != nil {
		log.Warnf("Error deleting network: %v", nerr)
	}

	// then delete the entry in 'ByIDFolderName' folder
	err := m.item.DeleteFrom(ByIDFolderName, *m.id)
	if err != nil {
		return err
	}
	// at last delete the entry in 'ByNameFolderName' folder
	err = m.item.DeleteFrom(ByNameFolderName, *m.name)
	if err != nil {
		return err
	}
	return nil
}

// Browse walks through all the metadata objects in network
func (m *Network) Browse(callback func(*model.Network) error) error {
	if m.item == nil {
		panic("m.item is nil!")
	}

	return m.item.BrowseInto(ByIDFolderName, func(buf []byte) error {
		network := model.Network{}
		err := (&network).Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(&network)
	})
}

// attachGateway register an host metadata as the Gateway for the network
func (m *Network) attachGateway(mh *Host) error {
	if m.inside == nil {
		panic("m.inside is nil!")
	}
	data, err := mh.Get().Serialize()
	if err != nil {
		return err
	}
	return m.inside.Write(".", gatewayObjectName, data)
}

// getGateway returns the host acting as a gateway for the network
func (m *Network) getGateway() (bool, *model.Host, error) {
	if m.inside == nil {
		panic("m.inside is nil!")
	}
	var host model.Host
	found, err := m.inside.Read(".", gatewayObjectName, func(buf []byte) error {
		return (&host).Deserialize(buf)
	})
	if err != nil {
		return false, nil, err
	}
	if !found {
		return false, nil, fmt.Errorf("failed to find gateway metadata")
	}
	return true, &host, nil
}

// detachGateway detaches the host used as gateway of the network
func (m *Network) detachGateway() error {
	if m.inside == nil {
		panic("m.inside is nil")
	}

	err := m.inside.Delete(".", gatewayObjectName)

	if err != nil {
		log.Errorf("Error detaching gateway: deleting host folder: %+v", err)
	}

	return err
}

// AttachHost links host ID to the network
func (m *Network) AttachHost(host *model.Host) error {
	if m.inside == nil {
		panic("m.inside is nil!")
	}
	data, err := host.Serialize()
	if err != nil {
		return err
	}
	return m.inside.Write(hostsFolderName, host.ID, data)
}

// DetachHost unlinks host ID to network
func (m *Network) DetachHost(hostID string) error {
	if m.inside == nil {
		panic("m.inside is nil!")
	}

	err := m.inside.Delete(hostsFolderName, hostID)
	if err != nil {
		log.Errorf("Error detaching host metadata: deleting host folder: %+v", err)
	}
	return err
}

// ListHosts returns the list of ID of hosts attached to the network (be careful: including gateway)
func (m *Network) ListHosts() ([]*model.Host, error) {
	if m.inside == nil {
		panic("m.inside is nil!")
	}
	var list []*model.Host
	err := m.inside.Browse(hostsFolderName, func(buf []byte) error {
		host := model.Host{}
		err := (&host).Deserialize(buf)
		if err != nil {
			return err
		}
		list = append(list, &host)
		return nil
	})

	if err != nil {
		log.Errorf("Error listing hosts: browsing hosts: %+v", err)
	}
	return list, err
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
func SaveNetwork(svc api.ClientAPI, net *model.Network) error {
	return NewNetwork(svc).Carry(net).Write()
}

// RemoveNetwork removes the Network definition from Object Storage
func RemoveNetwork(svc api.ClientAPI, net *model.Network) error {
	return NewNetwork(svc).Carry(net).Delete()
}

// LoadNetworkByID gets the Network definition from Object Storage
func LoadNetworkByID(svc api.ClientAPI, networkID string) (*Network, error) {
	m := NewNetwork(svc)
	found, err := m.ReadByID(networkID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return m, nil
}

// LoadNetworkByName gets the Network definition from Object Storage
func LoadNetworkByName(svc api.ClientAPI, networkname string) (*Network, error) {
	m := NewNetwork(svc)
	found, err := m.ReadByName(networkname)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return m, nil
}

// LoadNetwork gets the Network definition from Object Storage
func LoadNetwork(svc api.ClientAPI, ref string) (*Network, error) {
	m, err := LoadNetworkByID(svc, ref)
	if err != nil {
		return nil, err
	}
	if m != nil {
		return m, nil
	}

	m, err = LoadNetworkByName(svc, ref)
	if err != nil {
		return nil, err
	}
	if m != nil {
		return m, nil
	}
	return nil, nil
}

// Gateway links Object Storage folder and Network
type Gateway struct {
	host      *Host
	network   *Network
	networkID string
}

// NewGateway creates an instance of metadata.Gateway
func NewGateway(svc api.ClientAPI, networkID string) (*Gateway, error) {
	network := NewNetwork(svc)
	found, err := network.ReadByID(networkID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("failed to find metadata of network using gateway")
	}
	return &Gateway{
		host:      NewHost(svc),
		network:   network,
		networkID: networkID,
	}, nil
}

// Carry links a Network instance to the Metadata instance
func (m *Gateway) Carry(host *model.Host) *Gateway {
	m.host.Carry(host)
	return m
}

// Get returns the *model.Host linked to the metadata
func (m *Gateway) Get() *model.Host {
	if m.host == nil {
		panic("m.host is nil!")
	}
	return m.host.Get()
}

// Write updates the metadata corresponding to the network in the Object Storage
// A Gateway is a particular host : we want it listed in hosts, but not listed as attached to the network
// with a reference as gw in network metadata
func (m *Gateway) Write() error {
	if m.host == nil {
		panic("m.item is nil!")
	}
	if m.network == nil {
		panic("m.network is nil!")
	}
	err := m.host.Write()
	if err != nil {
		return err
	}
	return m.network.attachGateway(m.host)
}

// Read reads the metadata of a gateway of a network identified by ID from Object Storage
func (m *Gateway) Read() (bool, error) {
	if m.network == nil {
		panic("m.network is nil!")
	}
	if m.host == nil {
		panic("m.host is nil!")
	}
	found, host, err := m.network.getGateway()
	if !found {
		return false, err
	}
	m.host.Carry(host)
	return true, nil
}

// Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (m *Gateway) Reload() error {
	found, err := m.Read()
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("metadata about the gateway of network '%s' doesn't exist anymore", m.networkID)
	}
	return nil
}

// Delete updates the metadata corresponding to the gateway
func (m *Gateway) Delete() error {
	if m.network == nil {
		panic("m.network is nil!")
	}
	if m.host == nil {
		panic("m.host is nil!")
	}
	err := m.network.detachGateway()
	if err != nil {
		return err
	}
	return m.host.Delete()
}

// Acquire waits until the write lock is available, then locks the metadata
func (m *Gateway) Acquire() {
	m.host.Acquire()
}

// Release unlocks the metadata
func (m *Gateway) Release() {
	m.host.Release()
}

// LoadGateway returns the metadata of the Gateway of a network
func LoadGateway(svc api.ClientAPI, networkID string) (*Gateway, error) {
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

// SaveGateway saves the metadata of a gateway
func SaveGateway(svc api.ClientAPI, host *model.Host, networkID string) error {
	m, err := NewGateway(svc, networkID)
	if err != nil {
		return err
	}
	// Update network
	n := NewNetwork(svc)
	ok, err := n.ReadByID(networkID)
	if !ok || err != nil {
		return fmt.Errorf("metadata about the network '%s' doesn't exist anymore", networkID)
	}
	network := n.Get()
	networkV1 := model.NetworkExtensionNetworkV1{}
	err = network.Extensions.Get(NetworkExtension.NetworkV1, &networkV1)
	if err != nil {
		return err
	}
	networkV1.GatewayID = host.ID
	err = network.Extensions.Set(NetworkExtension.NetworkV1, &networkV1)
	if err != nil {
		return err
	}
	err = n.Write()
	if err != nil {
		return err
	}

	return m.Carry(host).Write()
}
