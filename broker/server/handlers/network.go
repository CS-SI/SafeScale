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

package handlers

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

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

//go:generate mockgen -destination=../mocks/mock_networkapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/handlers NetworkAPI

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// NetworkAPI defines API to manage networks
type NetworkAPI interface {
	Create(ctx context.Context, net string, cidr string, ipVersion IPVersion.Enum, cpu int, ram float32, disk int, os string, gwname string) (*model.Network, error)
	List(ctx context.Context, all bool) ([]*model.Network, error)
	Inspect(ctx context.Context, ref string) (*model.Network, error)
	Delete(ctx context.Context, ref string) error
}

// NetworkHandler an implementation of NetworkAPI
type NetworkHandler struct {
	provider  *providers.Service
	ipVersion IPVersion.Enum
}

// NewNetworkHandler Creates new Network service
func NewNetworkHandler(api *providers.Service) NetworkAPI {
	return &NetworkHandler{
		provider: api,
	}
}

// Create creates a network
func (svc *NetworkHandler) Create(
	ctx context.Context, name string, cidr string, ipVersion IPVersion.Enum, cpu int, ram float32, disk int, theos string, gwname string,
) (*model.Network, error) {

	log.Debugf(">>> broker.server.handlers.NetworkHandler::Create()")
	defer log.Debugf("<<< broker.server.handlers.NetworkHandler::Create()")

	// Verify that the network doesn't exist first
	_, err := svc.provider.GetNetworkByName(name)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
		default:
			return nil, infraErrf(err, "failed to check if a network already exists with name '%s'", name)
		}
	} else {
		return nil, logicErr(fmt.Errorf("network '%s' already exists", name))
	}

	// Create the network
	log.Debugf("Creating network '%s' ...", name)
	network, err := svc.provider.CreateNetwork(model.NetworkRequest{
		Name:      name,
		IPVersion: ipVersion,
		CIDR:      cidr,
	})
	if err != nil {
		err = infraErr(err)
		return nil, err
	}

	// Starting from here, delete network if exiting with error
	defer func() {
		if err != nil {
			derr := svc.provider.DeleteNetwork(network.ID)
			if derr != nil {
				log.Errorf("Failed to delete network: %+v", derr)
			}
		}
	}()

	log.Debugf("Saving network metadata '%s' ...", network.Name)
	mn, err := metadata.SaveNetwork(svc.provider, network)
	if err != nil {
		return nil, infraErr(err)
	}

	// Starting from here, delete network metadata if exits with error
	defer func() {
		if err != nil {
			derr := mn.Delete()
			if derr != nil {
				log.Errorf("Failed to delete network metadata: %+v", derr)
			}
		}
	}()

	if gwname == "" {
		gwname = "gw-" + network.Name
	}

	log.Debugf("Creating compute resource '%s' ...", gwname)

	// Create a gateway

	var template model.HostTemplate
	tpls, err := svc.provider.SelectTemplatesBySize(model.SizingRequirements{
		MinCores:    cpu,
		MinRAMSize:  ram,
		MinDiskSize: disk,
	}, false)
	if err != nil {
		return nil, infraErrf(err, "Error creating network: Error selecting template")
	}
	if len(tpls) > 0 {
		template = tpls[0]
		msg := fmt.Sprintf("Selected host template: '%s' (%d core%s", template.Name, template.Cores, utils.Plural(template.Cores))
		if template.CPUFreq > 0 {
			msg += fmt.Sprintf(" at %.01f GHz", template.CPUFreq)
		}
		msg += fmt.Sprintf(", %.01f GB RAM, %d GB disk", template.RAMSize, template.DiskSize)
		if template.GPUNumber > 0 {
			msg += fmt.Sprintf(", %d GPU%s", template.GPUNumber, utils.Plural(template.GPUNumber))
			if template.GPUType != "" {
				msg += fmt.Sprintf(" %s", template.GPUType)
			}
		}
		msg += ")"
		log.Infof(msg)
	} else {
		return nil, logicErr(fmt.Errorf("Error creating network: No template found for %v cpu, %v GB of ram, %v GB of system disk", cpu, ram, disk))
	}
	img, err := svc.provider.SearchImage(theos)
	if err != nil {
		err := infraErrf(err, "Error creating network: Error searching image '%s'", theos)
		return nil, err
	}

	keypairName := "kp_" + network.Name
	keypair, err := svc.provider.CreateKeyPair(keypairName)
	if err != nil {
		return nil, infraErr(err)
	}

	gwRequest := model.GatewayRequest{
		ImageID:    img.ID,
		Network:    network,
		KeyPair:    keypair,
		TemplateID: template.ID,
		Name:       gwname,
		CIDR:       network.CIDR,
	}

	log.Infof("Requesting the creation of a gateway '%s' using template '%s' with image '%s'", gwname, template.Name, img.Name)
	gw, err := svc.provider.CreateGateway(gwRequest)
	if err != nil {
		//defer svc.provider.DeleteNetwork(network.ID)
		return nil, infraErrf(err, "Error creating network: Gateway creation with name '%s' failed", gwname)
	}

	// Starting from here, deletes the gateway if exiting with error
	defer func() {
		if err != nil {
			log.Warnf("Cleaning up on failure, deleting gateway '%s' host resource...", gw.Name)
			derr := svc.provider.DeleteHost(gw.ID)
			if derr != nil {
				log.Errorf("failed to delete gateway '%s': %v", gw.Name, derr)
			}
			log.Infof("Gateway '%s' deleted", gw.Name)
		}
	}()

	// Reloads the host to be sure all the properties are updated
	gw, err = svc.provider.GetHost(gw)
	if err != nil {
		return nil, infraErr(err)
	}

	// Updates requested sizing in gateway property propsv1.HostSizing
	err = gw.Properties.LockForWrite(HostProperty.SizingV1).ThenUse(func(v interface{}) error {
		gwSizingV1 := v.(*propsv1.HostSizing)
		gwSizingV1.RequestedSize = &propsv1.HostSize{
			Cores:    cpu,
			RAMSize:  ram,
			DiskSize: disk,
		}
		return nil
	})
	if err != nil {
		return nil, infraErrf(err, "error creating network")
	}

	// Writes Gateway metadata
	mg, err := metadata.SaveGateway(svc.provider, gw, network.ID)
	if err != nil {
		return nil, infraErrf(err, "failed to create gateway: failed to save metadata: %s", err.Error())
	}

	// Starting from here, delete network metadata if exits with error
	defer func() {
		if err != nil {
			log.Warnf("Cleaning up on failure, deleting gateway '%s' metadata", gw.Name)
			derr := mg.Delete()
			if derr != nil {
				log.Errorf("Failed to delete gateway '%s' metadata: %+v", gw.Name, derr)
			}
		}
	}()

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	log.Infof("Waiting until gateway '%s' is available through SSH ...", gwname)
	sshHandler := NewSSHHandler(svc.provider)
	ssh, err := sshHandler.GetConfig(ctx, gw.ID)
	if err != nil {
		//defer svc.provider.DeleteHost(gw.ID)
		return nil, infraErrf(err, "error creating network: Error retrieving SSH config of gateway '%s'", gw.Name)
	}

	sshDefaultTimeout := int(brokerutils.GetTimeoutCtxHost().Minutes())
	if sshDefaultTimeoutCandidate := os.Getenv("SSH_TIMEOUT"); sshDefaultTimeoutCandidate != "" {
		num, err := strconv.Atoi(sshDefaultTimeoutCandidate)
		if err == nil {
			log.Debugf("Using custom timeout of %d minutes", num)
			sshDefaultTimeout = num
		}
	}

	// TODO Test for failure with 15s !!!
	err = ssh.WaitServerReady(time.Duration(sshDefaultTimeout) * time.Minute)
	// err = ssh.WaitServerReady(time.Second * 3)
	if err != nil {
		return nil, logicErrf(err, "error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", gw.Name)
	}
	log.Infof("SSH service of gateway '%s' started.", gw.Name)

	select {
	case <-ctx.Done():
		log.Warnf("Network creation canceled by broker")
		err = fmt.Errorf("Network creation canceld by broker")
		return nil, err
	default:
	}
	return network, nil
}

// List returns the network list
func (svc *NetworkHandler) List(ctx context.Context, all bool) ([]*model.Network, error) {
	log.Debugf(">>> broker.server.handlers.NetworkHandler::List(%v)", all)
	defer log.Debugf("<<< broker.server.handlers.NetworkHandler::List(%v)", all)

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
		return nil, infraErrf(err, "Error listing monitored networks: %s", err.Error())
	}

	return netList, infraErr(err)
}

// Inspect returns the network identified by ref, ref can be the name or the id
func (svc *NetworkHandler) Inspect(ctx context.Context, ref string) (*model.Network, error) {
	defer log.Debugf("<<< broker.server.handlers.NetworkHandler::Inspect(%s)", ref)
	log.Debugf(">>> broker.server.handlers.NetworkHandler::Inspect(%s)", ref)

	mn, err := metadata.LoadNetwork(svc.provider, ref)
	if err != nil {
		return nil, err
	}
	return mn.Get(), nil
}

// Delete deletes network referenced by ref
func (svc *NetworkHandler) Delete(ctx context.Context, ref string) error {
	log.Debugf(">>> broker.server.handlers.NetworkHandler::Delete(%s)", ref)
	defer log.Debugf("<<< broker.server.handlers.NetworkHandler::Delete(%s)", ref)

	mn, err := metadata.LoadNetwork(svc.provider, ref)
	if err != nil {
		if _, ok := err.(model.ErrResourceNotFound); !ok {
			return infraErrf(err, "failed to load metadata of network '%s'", ref)
		}
		return err
	}
	network := mn.Get()
	gwID := network.GatewayID

	// Check if hosts are still attached to network according to metadata
	var errorMsg string
	err = network.Properties.LockForRead(NetworkProperty.HostsV1).ThenUse(func(v interface{}) error {
		networkHostsV1 := v.(*propsv1.NetworkHosts)
		hostsLen := len(networkHostsV1.ByName)
		if hostsLen > 0 {
			list := make([]string, 0, hostsLen)
			for k := range networkHostsV1.ByName {
				list = append(list, k)
			}
			verb := "are"
			if hostsLen == 1 {
				verb = "is"
			}
			errorMsg = fmt.Sprintf("can't delete network '%s': %d host%s %s still attached to it: %s",
				network.Name, hostsLen, utils.Plural(hostsLen), verb, strings.Join(list, ", "))
			return model.ResourceNotAvailableError("network", network.Name)
		}
		return nil
	})
	if err != nil {
		if _, ok := err.(model.ErrResourceNotAvailable); ok {
			return logicErr(fmt.Errorf(errorMsg))
		}
		return infraErr(err)
	}

	// 1st delete gateway
	var metadataHost *model.Host
	if gwID != "" {
		mh, err := metadata.LoadHost(svc.provider, gwID)
		if err != nil {
			return infraErr(err)
		}
		metadataHost = mh.Get()

		err = svc.provider.DeleteGateway(gwID)
		// allow no gateway, but log it
		if err != nil {
			log.Warnf("Failed to delete gateway: %s", openstack.ProviderErrorToString(err))
		}
		err = mh.Delete()
		if err != nil {
			return infraErr(err)
		}
	}

	// 2nd delete network, with no tolerance
	var deleteMatadataOnly bool
	err = svc.provider.DeleteNetwork(network.ID)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
			deleteMatadataOnly = true
		default:
			return infraErrf(err, "can't delete network")
		}
	}

	err = mn.Delete()
	if err != nil {
		return infraErr(err)
	}

	if deleteMatadataOnly {
		return fmt.Errorf("Unable to find the network even if it is described by metadatas\nInchoerent metadatas have been supressed")
	}

	select {
	case <-ctx.Done():
		log.Warnf("Network delete canceled by broker")
		hostSizing := propsv1.NewHostSizing()
		err := metadataHost.Properties.Get(HostProperty.SizingV1, hostSizing)
		if err != nil {
			return fmt.Errorf("Failed to get gateway sizingV1")
		}
		//os name of the gw is not stored in metadatas so we used ubuntu 16.04 by default
		networkBis, err := svc.Create(context.Background(), network.Name, network.CIDR, network.IPVersion, hostSizing.AllocatedSize.Cores, hostSizing.AllocatedSize.RAMSize, hostSizing.AllocatedSize.DiskSize, "Ubuntu 16.04", metadataHost.Name)
		if err != nil {
			return fmt.Errorf("Failed to stop network deletion")
		}
		buf, err := networkBis.Serialize()
		if err != nil {
			return fmt.Errorf("Deleted Network recreated by broker")
		}
		return fmt.Errorf("Deleted Network recreated by broker : %s", buf)
	default:
	}

	return nil
}
