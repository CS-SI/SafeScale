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
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Extension"
	"github.com/CS-SI/SafeScale/utils/metadata"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
)

const (
	//NetworkFolderName is the technical name of the container used to store networks info
	networksFolderName = "networks"
	//GatewayObjectName is the name of the object containing the id of the host acting as a default gateway for a network
	gatewayObjectName = "gw"
)

type NetworkExtensionsMap map[Extension.Enum]interface{}

//Network links Object Storage folder and Network
type Network struct {
	name       string
	id         string
	item       *metadata.Item
	inside     *metadata.Folder
	extensions NetworkExtensionsMap
}

// NewNetwork creates an instance of network.Metadata
func NewNetwork(svc *provider.Service) *Network {
	return &Network{
		item: metadata.NewItem(svc, networksFolderName),
	}
}

// GetPath returns the path in Object Storage where the item is stored
func (mn *Network) GetPath() string {
	if mn.item == nil {
		panic("mn.item is nil!")
	}
	return mn.item.GetPath()
}

// Carry links a Network instance to the Metadata instance
func (mn *Network) Carry(pbn *pb.Network) *Network {
	if pbn == nil {
		panic("pbn is nil!")
	}
	if mn.item == nil {
		panic("mn.item is nil!")
	}

	mn.item.Carry(pbn)
	mn.id = network.ID
	mn.name = network.Name
	insidePath := strings.Trim(mn.item.GetPath()+"/"+mn.id, "/")
	mn.inside = metadata.NewFolder(m.item.GetService(), insidePath)
	mn.extensions = nil
	return m
}

// Get returns the Network instance linked to metadata
func (mn *Network) Get() *api.Network {
	if mn.item == nil {
		panic("mn.item is nil!")
	}
	pbn, ok := mn.item.Get().(*pb.Network)
	if ok {
		return pbn
	}
	panic(fmt.Sprintf("invalid content in metadata of network '%s'", mn.name))
}

// Write updates the metadata corresponding to the network in the Object Storage
func (mn *Network) Write() error {
	if mn.item == nil {
		panic("mn.item is nil!")
	}
	_, err := mn.encodeExtensions()
	if err != nil {
		return err
	}
	err = mn.item.WriteInto(ByIDFolderName, mn.id)
	if err != nil {
		return err
	}
	return mn.item.WriteInto(ByNameFolderName, mn.name)
}

// Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (mn *Network) Reload() error {
	found, err := mn.ReadByID(mn.id)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("the metadata of Network '%s' vanished", mn.name)
	}
	return nil
}

// ReadByID reads the metadata of a network identified by ID from Object Storage
func (mn *Network) ReadByID(id string) (bool, error) {
	if mn.item == nil {
		panic("mn.item is nil!")
	}

	var data pb.Network
	found, err := mn.item.ReadFrom(ByIDFolderName, id, func(buf *bytes.Buffer) (interface{}, error) {
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
	mn.id = id
	mn.name = data.Name
	mn.inside = metadata.NewFolder(mn.item.GetService(), strings.Trim(mn.item.GetPath()+"/"+id, "/"))
	mn.extensions = nil
	return true, nil
}

// ReadByName reads the metadata of a network identified by name
func (mn *Network) ReadByName(name string) (bool, error) {
	if mn.item == nil {
		panic("mn.item is nil!")
	}

	var data api.Network
	found, err := m.item.ReadFrom(ByNameFolderName, name, func(buf *bytes.Buffer) (interface{}, error) {
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
	mn.name = name
	mn.id = data.ID
	mn.inside = metadata.NewFolder(mn.item.GetService(), strings.Trim(mn.item.GetPath()+"/"+mn.id, "/"))
	mn.extensions = nil
	return true, nil
}

// Delete deletes the metadata corresponding to the network
func (mn *Network) Delete() error {
	if mn.item == nil {
		panic("mn.item is nil!")
	}

	// First delete network/<id> folder if it exists
	nerr := mn.item.Delete(mn.id)
	if nerr != nil {
		log.Warnf("Error deleting network: %v", nerr)
	}

	// then delete the entry in 'ByIDFolderName' folder
	err := mn.item.DeleteFrom(ByIDFolderName, mn.id)
	if err != nil {
		return err
	}
	// at last delete the entry in 'ByNameFolderName' folder
	err = mn.item.DeleteFrom(ByNameFolderName, mn.name)
	if err != nil {
		return err
	}
	return nil
}

// Browse walks through all the metadata objects in network
func (mn *Network) Browse(callback func(*api.Network) error) error {
	if mn.item == nil {
		panic("mn.item is nil!")
	}

	return mn.item.BrowseInto(ByIDFolderName, func(buf *bytes.Buffer) error {
		var pbn pb.Network
		err := gob.NewDecoder(buf).Decode(&pbn)
		if err != nil {
			return err
		}
		return callback(&pbn)
	})
}

// attachGateway register an host metadata as the Gateway for the network
func (mn *Network) attachGateway(mh *Host) error {
	if mn.inside == nil {
		panic("mn.inside is nil!")
	}
	return mn.inside.Write(".", gatewayObjectName, mh.Get())
}

// getGateway returns the host acting as a gateway for the network
func (mn *Network) getGateway() (bool, *pb.Host, error) {
	if mn.inside == nil {
		panic("mn.inside is nil!")
	}
	var pbh pb.Host
	found, err := mn.inside.Read(".", gatewayObjectName, func(buf *bytes.Buffer) error {
		return gob.NewDecoder(buf).Decode(&pbh)
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
func (mn *Network) detachGateway() error {
	if mn.inside == nil {
		panic("mn.inside is nil")
	}

	// TODO Check this
	return mn.inside.Delete(".", gatewayObjectName)
}

// AttachHost links host ID to the network
func (mn *Network) AttachHost(pbh *pb.Host) error {
	if mn.inside == nil {
		panic("mn.inside is nil!")
	}
	return mn.inside.Write(hostsFolderName, pbh.ID, pbh)
}

// DetachHost unlinks host ID to network
func (mn *Network) DetachHost(hostID string) error {
	if mn.inside == nil {
		panic("mn.inside is nil!")
	}

	// TODO Check this
	return mn.inside.Delete(hostsFolderName, hostID)
}

// ListHosts returns the list of ID of hosts attached to the network (be careful: including gateway)
func (mn *Network) ListHosts() ([]*pb.Host, error) {
	if mn.inside == nil {
		panic("mn.inside is nil!")
	}
	var list []*pb.Host
	err := mn.inside.Browse(hostsFolderName, func(buf *bytes.Buffer) error {
		var pbh pb.Host
		err := gob.NewDecoder(buf).Decode(&pbh)
		if err != nil {
			return err
		}
		list = append(list, &pbh)
		return nil
	})
	return list, err
}

// Acquire waits until the write lock is available, then locks the metadata
func (mn *Network) Acquire() {
	if mn.item == nil {
		panic("mn.item is nil")
	}
	mn.item.Acquire()
}

// Release unlocks the metadata
func (mn *Network) Release() {
	if mn.item == nil {
		panic("mn.item is nil")
	}
	mn.item.Release()
}

// SaveNetwork saves the Network definition in Object Storage
func SaveNetwork(svc *providers.Service, pbn *pb.Network) error {
	return NewNetwork(svc).Carry(pbn).Write()
}

// RemoveNetwork removes the Network definition from Object Storage
func RemoveNetwork(svc *providers.Service, pbn *pb.Network) error {
	return NewNetwork(svc).Carry(pbn).Delete()
}

// LoadNetworkById gets the Network definition from Object Storage
func LoadNetworkByID(svc *providers.Service, networkID string) (*Network, error) {
	mn := NewNetwork(svc)
	found, err := mn.ReadByID(networkID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return mn, nil
}

// LoadNetworkByName gets the Network definition from Object Storage
func LoadNetworkByName(svc *providers.Service, networkname string) (*Network, error) {
	mn := NewNetwork(svc)
	found, err := mn.ReadByName(networkname)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return mn, nil
}

// LoadNetwork gets the Network definition from Object Storage
func LoadNetwork(svc *providers.Service, ref string) (*Network, error) {
	mn, err := LoadNetworkByID(svc, ref)
	if err != nil {
		return nil, err
	}
	if mn != nil {
		return mn, nil
	}

	mn, err = LoadNetworkByName(svc, ref)
	if err != nil {
		return nil, err
	}
	if mn != nil {
		return mn, nil
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
func NewGateway(svc *providers.Service, networkID string) (*Gateway, error) {
	mn := NewNetwork(svc)
	found, err := mn.ReadByID(networkID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("failed to find metadata of network using gateway")
	}
	return &Gateway{
		host:      NewHost(svc),
		network:   mn,
		networkID: networkID,
	}, nil
}

// Carry links a Network instance to the Metadata instance
func (mg *Gateway) Carry(pbh *pb.Host) *Gateway {
	mg.host.Carry(pbh)
	return m
}

// Get returns the *api.Host linked to the metadata
func (mg *Gateway) Get() *pb.Host {
	if mg.host == nil {
		panic("mg.host is nil!")
	}
	return mg.host.Get()
}

// Write updates the metadata corresponding to the network in the Object Storage
// A Gateway is a particular host : we want it listed in hosts, but not listed as attached to the network
// with a reference as gw in network metadata
func (mg *Gateway) Write() error {
	if mg.host == nil {
		panic("mg.item is nil!")
	}
	if mg.network == nil {
		panic("mg.network is nil!")
	}
	err := mg.host.Write()
	if err != nil {
		return err
	}
	return mg.network.attachGateway(mg.host)
}

// Read reads the metadata of a gateway of a network identified by ID from Object Storage
func (mg *Gateway) Read() (bool, error) {
	if mg.network == nil {
		panic("mg.network is nil!")
	}
	if mg.host == nil {
		panic("mg.host is nil!")
	}
	found, host, err := mg.network.getGateway()
	if !found {
		return false, err
	}
	mg.host.Carry(host)
	return true, nil
}

// Reload reloads the content of the Object Storage, overriding what is in the metadata instance
func (mg *Gateway) Reload() error {
	found, err := mg.Read()
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("metadata about the gateway of network '%s' doesn't exist anymore", mg.networkID)
	}
	return nil
}

// Delete updates the metadata corresponding to the gateway
func (mg *Gateway) Delete() error {
	if mg.network == nil {
		panic("mg.network is nil!")
	}
	if mg.host == nil {
		panic("mg.host is nil!")
	}
	err := mg.network.detachGateway()
	if err != nil {
		return err
	}
	return mg.host.Delete()
}

// Acquire waits until the write lock is available, then locks the metadata
func (mg *Gateway) Acquire() {
	if mg.host == nil {
		panic("mg.host is nil")
	}
	mg.host.Acquire()
}

// Release unlocks the metadata
func (mg *Gateway) Release() {
	if mg.host == nil {
		panic("mg.host is nil")
	}
	mg.host.Release()
}

// LoadGateway returns the metadata of the Gateway of a network
func LoadGateway(svc *providers.Service, networkID string) (*Gateway, error) {
	mg, err := NewGateway(svc, networkID)
	if err != nil {
		return nil, err
	}
	found, err := mg.Read()
	if err != nil {
		return nil, err
	}
	if found {
		return m, nil
	}
	return nil, nil
}

// SaveGateway saves the metadata of a gateway
func SaveGateway(svc *providers.Service, pbh *pb.Host, networkID string) error {
	mg, err := NewGateway(svc, networkID)
	if err != nil {
		return err
	}
	// Update network
	mn := NewNetwork(svc)
	ok, err := mn.ReadByID(networkID)
	if !ok || err != nil {
		return fmt.Errorf("metadata about the  '%s' doesn't exist anymore", networkID)
	}
	pbn := mn.Get()
	pbn.GatewayID = pbh.ID
	err = mn.Write()
	if err != nil {
		return err
	}

	return mg.Carry(pbh).Write()
}

// NetworkExtensionsMap ...
type NetworkExtensionsMap map[Extension.Enum]interface{}

// NetworkExtensionDescriptionV1 contains description information for the network
type NetworkExtensionDescriptionV1 struct {
	// Created tells when a host as been created
	Created time.Time `json:"created"`
	// Purpose contains... a description of the use of a host
	Purpose string
	// Creator contains an information about the creator of a host
	Creator string
	// Free contains anything
	Free string
}

// NetworkExtensionNetworkV1 contains network information related to Host
type NetworkExtensionNetworkV1 struct {
	GatewayID string `json:"gateway_id,omitempty"`
}

// decodeExtensions returns an ExtensionsMap from the field host.extensionsRaw
func (mn *Network) decodeExtensions() (NetworkExtensionsMap, error) {
	if mn.extensions == nil {
		var data HostExtensionsMap
		pbn := mn.Get()
		r := bytes.NewReader(pbn.Extensions)
		err := gob.NewDecoder(r).Decode(&data)
		if err != nil {
			return nil, err
		}
		mn.extensions = data
	}
	return mn.extensions, nil
}

// encodeExtensions encodes Hosts.extensions into Hosts.extensionsRaw (into []byte)
func (mn *Network) encodeExtensions() ([]byte, error) {
	pbn := mnGet()
	if mn.extensions != nil {
		var buffer bytes.Buffer
		err := gob.NewEncoder(&buffer).Encode(mn.extensions)
		if err != nil {
			return []byte{}, err
		}
		pbn.Extensions = buffer.Bytes()
	}
	return pbn.Extensions, nil
}

// GetExtension gets the content of an extension
// When the extension is not found, returns (nil,nil)
func (mn *Network) GetExtension(ex NetworkExtension.Enum) (interface{}, error) {
	exMap, err := mn.decodeExtensions()
	if err != nil {
		return nil, err
	}
	if anon, ok := (*exMap)[ex]; ok {
		return anon, nil
	}
	return nil, fmt.Errorf("not found")
}

// SetExtension sets the value of an extension of the host
func (mn *Network) SetExtension(ex NetworkExtension.Enum, data interface{}) error {
	exMap, err := mn.decodeExtensions()
	if err != nil {
		return err
	}
	(*exMap)[ex] = data
	return nil
}
