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
	"log"

	"github.com/CS-SI/SafeScale/broker/utils"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/enums/IPVersion"
	"github.com/CS-SI/SafeScale/providers/metadata"
)

//go:generate mockgen -destination=../mocks/mock_networkapi.go -package=mocks github.com/CS-SI/SafeScale/broker/daemon/services NetworkAPI

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
		panic(fmt.Sprintf("No template found for %v cpu, %v GB of ram, %v GB of system disk", cpu, ram, disk))
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

	gw, err := svc.provider.CreateGateway(gwRequest)
	if err != nil {
		panic(err)
	}

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	log.Println("Waiting start of SSH service on gateway...")
	ssh, err := svc.provider.GetSSHConfig(gw.ID)
	if err != nil {
		svc.provider.DeleteHost(gw.ID)
		return nil, err
	}
	err = ssh.WaitServerReady(utils.TimeoutCtxHost)
	if err != nil {
		log.Println("failed to reach SSH service")
		return nil, err
	}
	log.Println("SSH service started.")

	// Gateway is ready to work, update Network metadata
	rv, err := svc.Get(net)
	if rv != nil {
		rv.GatewayID = gw.ID
	}
	err = metadata.SaveNetwork(svc.provider, rv)
	if err != nil {
		return nil, err
	}

	return rv, err
}

// List returns the network list
func (svc *NetworkService) List(all bool) ([]api.Network, error) {
	return svc.provider.ListNetworks(all)
}

// Get returns the network identified by ref, ref can be the name or the id
func (svc *NetworkService) Get(ref string) (*api.Network, error) {
	return svc.provider.GetNetwork(ref)
}

// Delete deletes network referenced by ref
func (svc *NetworkService) Delete(ref string) error {
	return svc.provider.DeleteNetwork(ref)
}
