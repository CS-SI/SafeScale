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

package services

import (
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/api/enums/IPVersion"
	"github.com/CS-SI/SafeScale/providers/metadata"
)

//NetworkAPI defines API to manage networks
type NetworkAPI interface {
	Create(net string, cidr string, ipVersion IPVersion.Enum, cpu int, ram float32, disk int, os string, gwname string) (*api.Network, error)
	List(all bool) ([]api.Network, error)
	Get(ref string) (*api.Network, error)
	Delete(ref string) error
}

// NetworkService an instance of NetworkAPI
type NetworkService struct {
	provider  *providers.Service
	ipVersion IPVersion.Enum
}

// NewNetworkService Creates new Network service
func NewNetworkService(api api.ClientAPI) NetworkAPI {
	return &NetworkService{
		provider: providers.FromClient(api),
	}
}

// Create creates a network
func (svc *NetworkService) Create(net string, cidr string, ipVersion IPVersion.Enum, cpu int, ram float32, disk int, os string, gwname string) (apinetwork *api.Network, err error) {
	// Check that no network with same name already exists
	_net, err := svc.Get(net)
	if err != nil && !strings.Contains(err.Error(), "does not exist") {
		return nil, fmt.Errorf("Network %s already exists", net)
	}
	if _net != nil {
		return nil, fmt.Errorf("Network %s already exists", net)
	}

	// Create the network
	network, err := svc.provider.CreateNetwork(api.NetworkRequest{
		Name:      net,
		IPVersion: ipVersion,
		CIDR:      cidr,
	})
	if err != nil {
		return nil, err
	}

	defer func() {
		if r := recover(); r != nil {
			svc.provider.DeleteNetwork(network.ID)
			switch t := r.(type) {
			case string:
				err = fmt.Errorf("%q", t)
			case error:
				err = t
			}
		}
	}()

	// Create a gateway
	tpls, err := svc.provider.SelectTemplatesBySize(api.SizingRequirements{
		MinCores:    cpu,
		MinRAMSize:  ram,
		MinDiskSize: disk,
	})
	if err != nil {
		panic(err)
	}
	if len(tpls) < 1 {
		panic(fmt.Sprintf("No template found for %v cpu, %v ram, %v disk", cpu, ram, disk))
	}
	img, err := svc.provider.SearchImage(os)
	if err != nil {
		panic(err)
	}

	keypairName := "kp_" + network.Name
	// Makes sure keypair doesn't exist
	svc.provider.DeleteKeyPair(keypairName)
	keypair, err := svc.provider.CreateKeyPair(keypairName)
	if err != nil {
		panic(err)
	}

	gwRequest := api.GWRequest{
		ImageID:    img.ID,
		NetworkID:  network.ID,
		KeyPair:    keypair,
		TemplateID: tpls[0].ID,
		GWName:     gwname,
	}

	err = svc.provider.CreateGateway(gwRequest)
	if err != nil {
		panic(err)
	}

	rv, err := svc.Get(net)
	return rv, err
}

//List returns the network list
func (svc *NetworkService) List(all bool) ([]api.Network, error) {

	return svc.provider.ListNetworks(all)
}

//Get returns the network identified by ref, ref can be the name or the id
func (svc *NetworkService) Get(ref string) (*api.Network, error) {

	// We first try looking for network by ID
	m, err := metadata.LoadNetwork(svc.provider, ref)
	if err != nil {
		return nil, err
	}
	if m != nil {
		return m.Get(), nil
	}

	// If not found, we try looking for network by name
	m, err = metadata.LoadNetworkByName(svc.provider, ref)
	if err != nil {
		return nil, err
	}
	if m != nil {
		return m.Get(), nil
	}

	// If not found, we look for network any network from provider
	nets, err := svc.List(true)
	if err != nil {
		return nil, err
	}
	for _, n := range nets {
		if n.ID == ref || n.Name == ref {
			return &n, err
		}
	}
	return nil, fmt.Errorf("Network '%s' does not exist", ref)
}

//Delete deletes network referenced by ref
func (svc *NetworkService) Delete(ref string) error {
	n, err := svc.Get(ref)
	if err != nil {
		return fmt.Errorf("Network %s does not exist", ref)
	}
	return svc.provider.DeleteNetwork(n.ID)
}
