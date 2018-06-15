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
func NewNetwork() (*Network, error) {
	f, err := metadata.NewFolder(networkFolderName)
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
		panic("Metadata isn't linked with a Network!")
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
	err := m.folder.Delete(ByIDFolderName, m.network.ID)
	if err != nil {
		return err
	}
	err = m.folder.Delete(ByNameFolderName, m.network.Name)
	if err != nil {
		return err
	}
	return nil
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
func (m *Network) AttachHost(vmID string) error {
	if m.network == nil {
		panic("m.network is nil!")
	}

	return m.folder.Write(m.network.ID+"/host", vmID, vmID)
}

//DetachHost unlinks host ID to network
func (m *Network) DetachHost(vmID string) error {
	if m.network == nil {
		panic("m.network is nil!")
	}
	return m.folder.Delete(m.network.ID+"/host", vmID)
}

//ListHosts returns the list of ID of hosts attached to the network
func (m *Network) ListHosts() ([]string, error) {
	if m.network == nil {
		panic("m.network is nil!")
	}

	var list []string
	err := m.folder.Browse(m.network.ID+"/host", func(buf *bytes.Buffer) error {
		var vmID string
		err := gob.NewDecoder(buf).Decode(&vmID)
		if err != nil {
			return err
		}
		list = append(list, vmID)
		return nil
	})
	return list, err
}

//Gateway links Object Storage folder and Network
type Gateway struct {
	folder    *metadata.Folder
	networkID string
	hostID    string
}

//NewGateway creates an instance of metadata.Gateway
func NewGateway(networkID string) (*Gateway, error) {
	f, err := metadata.NewFolder(networkFolderName)
	if err != nil {
		return nil, err
	}
	return &Gateway{
		folder:    f,
		hostID:    "",
		networkID: networkID,
	}, nil
}

//Carry links a Network instance to the Metadata instance
func (m *Gateway) Carry(id string) *Gateway {
	m.hostID = id
	return m
}

//Get returns the vmID linked to the metadata
func (m *Gateway) Get() string {
	return m.hostID
}

//Write updates the metadata corresponding to the network in the Object Storage
func (m *Gateway) Write() error {
	return m.folder.Write(m.networkID, gatewayObjectName, m.hostID)
}

//Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (m *Gateway) Reload() error {
	if m.hostID == "" {
		panic("Metadata isn't linked with a host!")
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
	var hostID string
	found, err := m.folder.Read(m.networkID, gatewayObjectName, func(buf *bytes.Buffer) error {
		return gob.NewDecoder(buf).Decode(&hostID)
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	m.hostID = hostID
	return true, nil
}

//Delete updates the metadata corresponding to the network
func (m *Gateway) Delete() error {
	return m.folder.Delete(m.networkID, "gw")
}
