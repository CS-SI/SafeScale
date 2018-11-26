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

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"

	brokerutils "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	"github.com/CS-SI/SafeScale/providers/model/enums/IPVersion"
	"github.com/CS-SI/SafeScale/providers/model/enums/NetworkProperty"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/providers/openstack"
	"github.com/CS-SI/SafeScale/utils"
)

//go:generate mockgen -destination=../mocks/mock_networkapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/services NetworkAPI

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

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
	name string, cidr string, ipVersion IPVersion.Enum, cpu int, ram float32, disk int, os string, gwname string,
) (*model.Network, error) {

	// Verify that the network doesn't exist first
	_, err := svc.provider.GetNetworkByName(name)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
		default:
			err = srvLog(errors.Errorf("failed to check if a network already exists with name '%s'", name))
			return nil, err
		}
	}

	// Create the network
	network, err := svc.provider.CreateNetwork(model.NetworkRequest{
		Name:      name,
		IPVersion: ipVersion,
		CIDR:      cidr,
	})
	if err != nil {
		err = srvLog(err)
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
				spew.Dump(derr)
				log.Errorf("Failed to delete network: %+v", derr)
			}
		}
	}()

	err = metadata.SaveNetwork(svc.provider, network)
	if err != nil {
		return nil, err
	}

	if gwname == "" {
		gwname = "gw-" + network.Name
	}

	log.Debugf("Creating compute resource '%s' ...", gwname)

	// Create a gateway
	tpls, err := svc.provider.SelectTemplatesBySize(model.SizingRequirements{
		MinCores:    cpu,
		MinRAMSize:  ram,
		MinDiskSize: disk,
	}, false)
	if err != nil {
		err := srvLog(errors.Wrap(err, "Error creating network: Error selecting template"))
		return nil, err
	}
	if len(tpls) < 1 {
		err := srvLog(errors.New(fmt.Sprintf("Error creating network: No template found for %v cpu, %v GB of ram, %v GB of system disk", cpu, ram, disk)))
		return nil, err
	}
	img, err := svc.provider.SearchImage(os)
	if err != nil {
		err := srvLog(errors.Wrap(err, "Error creating network: Error searching image"))
		return nil, err
	}

	keypairName := "kp_" + network.Name
	keypair, err := svc.provider.CreateKeyPair(keypairName)
	if err != nil {
		err = srvLog(err)
		return nil, err
	}

	gwRequest := model.GatewayRequest{
		ImageID:    img.ID,
		Network:    network,
		KeyPair:    keypair,
		TemplateID: tpls[0].ID,
		Name:       gwname,
		CIDR:       network.CIDR,
	}

	log.Infof("Requesting the creation of a gateway '%s' with image '%s'", gwname, img.ID)
	gw, err := svc.provider.CreateGateway(gwRequest)
	if err != nil {
		//defer svc.provider.DeleteNetwork(network.ID)
		err := srvLog(errors.Wrapf(err, "Error creating network: Gateway creation with name '%s' failed", gwname))
		return nil, err
	}

	// Starting from here, deletes the gateway if exiting with error
	defer func() {
		if err != nil {
			derr := svc.provider.DeleteHost(gw.ID)
			if derr != nil {
				spew.Dump(derr)
				log.Errorf("failed to delete gateway '%s': %v", gw.Name, derr)
			}
		}
	}()

	// Reloads the host to be sure all the properties are updated
	gw, err = svc.provider.GetHost(gw)
	if err != nil {
		return nil, err
	}

	// Updates requested sizing in gateway property propsv1.HostSizing
	gwSizingV1 := propsv1.NewHostSizing()
	err = gw.Properties.Get(HostProperty.SizingV1, gwSizingV1)
	if err != nil {
		return nil, srvLog(errors.Wrapf(err, "Error creating network"))
	}
	gwSizingV1.RequestedSize = &propsv1.HostSize{
		Cores:    cpu,
		RAMSize:  ram,
		DiskSize: disk,
	}
	err = gw.Properties.Set(HostProperty.SizingV1, gwSizingV1)
	if err != nil {
		return nil, srvLog(errors.Wrapf(err, "Error creating network"))
	}

	// Writes Gateway metadata
	err = metadata.SaveGateway(svc.provider, gw, network.ID)
	if err != nil {
		msg := fmt.Sprintf("failed to create gateway: failed to save metadata: %s", err.Error())
		log.Debugf(utils.TitleFirst(msg))
		return nil, errors.Wrap(err, msg)
	}

	log.Debugf("Waiting until gateway '%s' is available through SSH ...", gwname)

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	sshSvc := NewSSHService(svc.provider)
	ssh, err := sshSvc.GetConfig(gw.ID)
	if err != nil {
		//defer svc.provider.DeleteHost(gw.ID)
		tbr := srvLog(errors.Wrapf(err, "Error creating network: Error retrieving SSH config of gateway '%s'", gw.Name))
		return nil, tbr
	}

	// TODO Test for failure with 15s !!!
	err = ssh.WaitServerReady(brokerutils.TimeoutCtxHost)
	// err = ssh.WaitServerReady(time.Second * 3)
	if err != nil {
		return nil, srvLogNew(fmt.Errorf("Error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", gw.Name))
	}
	log.Infof("SSH service of gateway '%s' started.", gw.Name)

	network.GatewayID = gw.ID

	//	err = metadata.SaveNetwork(svc.provider, rv)
	err = metadata.SaveNetwork(svc.provider, network)
	if err != nil {
		return nil, srvLog(errors.Wrap(err, "Error creating network: Error saving network metadata"))
	}

	return network, nil
}

// List returns the network list
func (svc *NetworkService) List(all bool) ([]*model.Network, error) {
	if all {
		return svc.provider.ListNetworks()
	}

	var netList []*model.Network

	mn := metadata.NewNetwork(svc.provider)
	err := mn.Browse(func(network *model.Network) error {
		netList = append(netList, network)
		return nil
	})

	if err != nil {
		log.Debugf("Error listing monitored networks: pagination error: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error listing monitored networks: %s", err.Error()))
	}

	return netList, err
}

// Get returns the network identified by ref, ref can be the name or the id
func (svc *NetworkService) Get(ref string) (*model.Network, error) {
	mn, err := metadata.LoadNetwork(svc.provider, ref)
	if err != nil {
		msg := fmt.Sprintf("failed to load metadata of network '%s'", ref)
		log.Debugf(utils.TitleFirst(msg))
		return nil, fmt.Errorf(msg)
	}
	if mn == nil {
		return nil, model.ResourceNotFoundError("network(service)", ref)
	}
	return mn.Get(), err
}

// Delete deletes network referenced by ref
func (svc *NetworkService) Delete(ref string) error {
	mn, err := metadata.LoadNetwork(svc.provider, ref)
	if err != nil {
		msg := fmt.Sprintf("failed to load metadata of network '%s'", ref)
		log.Debugf(utils.TitleFirst(msg))
		return fmt.Errorf(msg)
	}
	if mn == nil {
		return fmt.Errorf("network '%s' not found", ref)
	}
	network := mn.Get()
	gwID := network.GatewayID

	// Check if hosts are still attached to network according to metadata
	networkHostsV1 := propsv1.NewNetworkHosts()
	err = network.Properties.Get(NetworkProperty.HostsV1, networkHostsV1)
	if err != nil {
		return errors.Wrap(err, "")
	}
	if len(networkHostsV1.ByID) > 0 {
		return fmt.Errorf("can't delete network '%s': at least one host is still attached to it", ref)
	}

	// 1st delete gateway
	if gwID != "" {
		mh, err := metadata.LoadHost(svc.provider, gwID)
		if err != nil {
			return errors.Wrap(err, "")
		}
		// allow no metadata, but log it
		if mh == nil {
			log.Warnf("Failed to find metadata of gateway; continuing assuming gateway is gone")
		} else {
			err = svc.provider.DeleteGateway(gwID)
			// allow no gateway, but log it
			if err != nil {
				spew.Dump(err)
				log.Warnf("Failed to delete gateway: %s", openstack.ProviderErrorToString(err))
			}
			err = mh.Delete()
			if err != nil {
				return err
			}
		}
	}

	// 2nd delete network, with no tolerance
	err = svc.provider.DeleteNetwork(network.ID)
	if err != nil {
		return err
	}
	return mn.Delete()
}
