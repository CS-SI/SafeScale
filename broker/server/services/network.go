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

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	"github.com/CS-SI/SafeScale/providers/model/enums/IPVersion"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
)

//go:generate mockgen -destination=../mocks/mock_networkapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/services NetworkAPI

// NetworkAPI defines API to manage networks
type NetworkAPI interface {
	Create(net string, cidr string, ipVersion IPVersion.Enum, cpu int, ram float32, disk int, os string, gwname string) (*model.Network, error)
	List(all bool) ([]*model.Network, error)
	Get(ref string) (*model.Network, error)
	Delete(ref string) error
}

// NetworkService an implementation of NetworkAPI
type NetworkService struct {
	provider  *providers.Service
	ipVersion IPVersion.Enum
}

// NewNetworkService Creates new Network service
func NewNetworkService(api *providers.Service) NetworkAPI {
	return &NetworkService{
		provider: api,
	}
}

// Create creates a network
func (svc *NetworkService) Create(
	net string, cidr string, ipVersion IPVersion.Enum, cpu int, ram float32, disk int, os string, gwname string,
) (*model.Network, error) {

	// Verify that the network doesn't exist first
	if exists, err := svc.provider.GetNetwork(net); exists != nil && err == nil {
		tbr := errors.Errorf("A network already exists with name '%s'", net)
		log.Errorf("%v", tbr)
		return nil, tbr
	}

	// Create the network
	network, err := svc.provider.CreateNetwork(model.NetworkRequest{
		Name:      net,
		IPVersion: ipVersion,
		CIDR:      cidr,
	})
	if err != nil {
		//tbr := errors.Wrap(err, "Error creating network: ")
		//log.Errorf("%+v", tbr)
		//return nil, tbr
		log.Errorf("%+v", err)
		return nil, err
	}

	// Starting from here, delete network if exiting with err
	defer func() {
		// r := recover()
		// if r != nil {
		// 	derr := svc.provider.DeleteNetwork(network.ID)
		// 	if derr != nil {
		// 		log.Errorf("%+v", derr)
		// 	}

		// 	switch t := r.(type) {
		// 	case string:
		// 		err = fmt.Errorf("%q", t)
		// 	case error:
		// 		err = t
		// 	}
		// 	tbr := errors.Wrap(err, "panic occured during network creation")
		// 	log.Errorf("%+v", tbr)
		// } else
		if err != nil {
			derr := svc.provider.DeleteNetwork(network.ID)
			if derr != nil {
				log.Errorf("Failed to delete network: %+v", derr)
			}
		}
	}()

	// TODO GITHUB Look at selection...
	// Create a gateway
	tpls, err := svc.provider.SelectTemplatesBySize(model.SizingRequirements{
		MinCores:    cpu,
		MinRAMSize:  ram,
		MinDiskSize: disk,
	})
	if err != nil {
		tbr := errors.Wrap(err, "Error creating network: Error selecting template")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	if len(tpls) < 1 {
		tbr := errors.New(fmt.Sprintf("Error creating network: No template found for %v cpu, %v GB of ram, %v GB of system disk", cpu, ram, disk))
		log.Errorf("%+v", tbr)
		return nil, tbr
	} else {
		for pos, atempl := range(tpls) {
			log.Debugf("Alternative [%d]: Template '%s' with %d cores, %f RAM, and %d GB Disk", pos, atempl.Name, atempl.Cores, atempl.RAMSize, atempl.DiskSize)
		}
	}

	img, err := svc.provider.SearchImage(os)
	if err != nil {
		tbr := errors.Wrap(err, "Error creating network: Error searching image")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	keypairName := "kp_" + network.Name
	keypair, err := svc.provider.CreateKeyPair(keypairName)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	log.Printf("Selected Template '%s' with %d cores, %f RAM, and %d GB Disk", tpls[0].Name, tpls[0].Cores, tpls[0].RAMSize, tpls[0].DiskSize)
	gwRequest := api.GWRequest{
		ImageID:    img.ID,
		NetworkID:  network.ID,
		KeyPair:    keypair,
		TemplateID: tpls[0].ID,
		GWName:     gwname,
	}

	log.Infof("Waiting until gateway '%s' is finished provisioning and is available through SSH ...", gwname)

	log.Infof("Requesting the creation of a gateway '%s' with image '%s'", gwname, img.ID)
	gw, err := svc.provider.CreateGateway(gwRequest)
	if err != nil {
		//defer svc.provider.DeleteNetwork(network.ID)
		tbr := errors.Wrapf(err, "Error creating network: Gateway creation with name '%s' failed", gwname)
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	// Starting from here, deletes the gateway if exiting with error
	defer func() {
		if err != nil {
			err := svc.provider.DeleteGateway(network.ID)
			if err != nil {
				log.Errorf("failed to delete gateway '%s': %v", gw.Name, err)
			}
		}
	}()

	// Updates gw requested sizing
	hpSizingV1 := propsv1.BlankHostSizing
	err = gw.Properties.Get(HostProperty.SizingV1, &hpSizingV1)
	if err != nil {
		return nil, errors.Wrapf(err, "Error creating network")
	}
	hpSizingV1.RequestedSize = propsv1.HostSize{
		Cores:    cpu,
		RAMSize:  ram,
		DiskSize: disk,
	}
	if err != nil {
		return nil, errors.Wrapf(err, "Error creating network")
	}

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	sshSvc := NewSSHService(svc.provider)
	ssh, err := sshSvc.GetConfig(gw.ID)
	if err != nil {
		//defer svc.provider.DeleteHost(gw.ID)
		tbr := errors.Wrapf(err, "Error creating network: Error retrieving SSH config of gateway '%s'", gw.Name)
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	// TODO Test for failure with 15s !!!
	err = ssh.WaitServerReady(utils.TimeoutCtxHost)
	// err = ssh.WaitServerReady(time.Second * 3)
	if err != nil {
		tbr := errors.Wrapf(err, "Error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", gw.Name)
		log.Errorf("%+v", tbr)

		// Simplified error message
		return nil, fmt.Errorf("Error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", gw.Name)
	}
	log.Infof("SSH service of gateway '%s' started.", gw.Name)

	// Gateway is ready to work, update Network metadata
	// rv, err := svc.Get(net)
	// if err != nil {
	// 	tbr := errors.Wrap(err, "Error getting network before metadata update")
	// 	log.Errorf("%+v", tbr)
	// 	return nil, tbr
	// }
	// if rv != nil {
	// 	rv.GatewayID = gw.ID
	// }
	network.GatewayID = gw.ID

	//	err = metadata.SaveNetwork(svc.provider, rv)
	err = metadata.SaveNetwork(svc.provider, network)
	if err != nil {
		tbr := errors.Wrap(err, "Error creating network: Error saving network metadata")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	return network, nil
}

// List returns the network list
func (svc *NetworkService) List(all bool) ([]*model.Network, error) {
	return svc.provider.ListNetworks(all)
}

// Get returns the network identified by ref, ref can be the name or the id
func (svc *NetworkService) Get(ref string) (*model.Network, error) {
	return svc.provider.GetNetwork(ref)
}

// Delete deletes network referenced by ref
func (svc *NetworkService) Delete(ref string) error {
	return svc.provider.DeleteNetwork(ref)
}
