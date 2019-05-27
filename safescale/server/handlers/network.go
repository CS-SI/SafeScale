/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/CS-SI/SafeScale/safescale/client"
	srvutils "github.com/CS-SI/SafeScale/safescale/utils"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/iaas/resources/enums/HostProperty"
	"github.com/CS-SI/SafeScale/iaas/resources/enums/IPVersion"
	"github.com/CS-SI/SafeScale/iaas/resources/enums/NetworkProperty"
	propsv1 "github.com/CS-SI/SafeScale/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/safescale/server/install"
	"github.com/CS-SI/SafeScale/safescale/server/metadata"
	safescaleutils "github.com/CS-SI/SafeScale/safescale/utils"
	"github.com/CS-SI/SafeScale/utils"
)

//go:generate mockgen -destination=../mocks/mock_networkapi.go -package=mocks github.com/CS-SI/SafeScale/safescale/server/handlers NetworkAPI

// TODO At service level, we need to log before returning, because it's the last chance to track the real issue in server side

// NetworkAPI defines API to manage networks
type NetworkAPI interface {
	Create(context.Context, string, string, IPVersion.Enum, int, float32, int, string, string) (*resources.Network, error)
	List(context.Context, bool) ([]*resources.Network, error)
	Inspect(context.Context, string) (*resources.Network, error)
	Delete(context.Context, string) error
}

// NetworkHandler an implementation of NetworkAPI
type NetworkHandler struct {
	service   *iaas.Service
	ipVersion IPVersion.Enum
}

// NewNetworkHandler Creates new Network service
func NewNetworkHandler(svc *iaas.Service) NetworkAPI {
	return &NetworkHandler{
		service: svc,
	}
}

// Create creates a network
func (handler *NetworkHandler) Create(
	ctx context.Context,
	name string, cidr string, ipVersion IPVersion.Enum,
	cpu int, ram float32, disk int, theos string, gwname string,
) (*resources.Network, error) {

	log.Debugf(">>> safescale.server.handlers.NetworkHandler::Create()")
	defer log.Debugf("<<< safescale.server.handlers.NetworkHandler::Create()")

	// Verify that the network doesn't exist first
	_, err := handler.service.GetNetworkByName(name)
	if err != nil {
		switch err.(type) {
		case resources.ErrResourceNotFound:
		default:
			return nil, infraErrf(err, "failed to check if a network already exists with name '%s'", name)
		}
	} else {
		return nil, logicErr(fmt.Errorf("network '%s' already exists", name))
	}

	// Create the network
	log.Debugf("Creating network '%s' ...", name)
	network, err := handler.service.CreateNetwork(resources.NetworkRequest{
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
			derr := handler.service.DeleteNetwork(network.ID)
			if derr != nil {
				log.Errorf("Failed to delete network: %+v", derr)
			}
		}
	}()

	log.Debugf("Saving network metadata '%s' ...", network.Name)
	mn, err := metadata.SaveNetwork(handler.service, network)
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

	var template resources.HostTemplate
	tpls, err := handler.service.SelectTemplatesBySize(resources.SizingRequirements{
		MinCores:    cpu,
		MinRAMSize:  ram,
		MinDiskSize: disk,
		MinGPU:      -1,
		MinFreq:     0,
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
	img, err := handler.service.SearchImage(theos)
	if err != nil {
		err := infraErrf(err, "Error creating network: Error searching image '%s'", theos)
		return nil, err
	}

	keypairName := "kp_" + network.Name
	keypair, err := handler.service.CreateKeyPair(keypairName)
	if err != nil {
		return nil, infraErr(err)
	}

	gwRequest := resources.GatewayRequest{
		ImageID:    img.ID,
		Network:    network,
		KeyPair:    keypair,
		TemplateID: template.ID,
		Name:       gwname,
		CIDR:       network.CIDR,
	}

	log.Infof("Requesting the creation of a gateway '%s' using template '%s' with image '%s'", gwname, template.Name, img.Name)
	gw, userData, err := handler.service.CreateGateway(gwRequest)
	if err != nil {
		//defer handler.service.DeleteNetwork(network.ID)
		return nil, infraErrf(err, "Error creating network: Gateway creation with name '%s' failed", gwname)
	}

	// Reloads the host to be sure all the properties are updated
	gw, err = handler.service.InspectHost(gw)
	if err != nil {
		return nil, infraErr(err)
	}

	// Starting from here, deletes the gateway if exiting with error
	defer func() {
		if err != nil {
			log.Warnf("Cleaning up on failure, deleting gateway '%s' host resource...", gw.Name)
			derr := handler.service.DeleteHost(gw.ID)
			if derr != nil {
				log.Errorf("failed to delete gateway '%s': %v", gw.Name, derr)
			}
			log.Infof("Gateway '%s' deleted", gw.Name)
		}
	}()

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
	mg, err := metadata.SaveGateway(handler.service, gw, network.ID)
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
	log.Infof("Waiting until gateway '%s' is available by SSH ...", gwname)
	sshHandler := NewSSHHandler(handler.service)
	ssh, err := sshHandler.GetConfig(ctx, gw.ID)
	if err != nil {
		//defer handler.service.DeleteHost(gw.ID)
		return nil, infraErrf(err, "error creating network: Error retrieving SSH config of gateway '%s'", gw.Name)
	}

	sshDefaultTimeout := int(safescaleutils.GetTimeoutCtxHost().Minutes())
	if sshDefaultTimeoutCandidate := os.Getenv("SSH_TIMEOUT"); sshDefaultTimeoutCandidate != "" {
		num, err := strconv.Atoi(sshDefaultTimeoutCandidate)
		if err == nil {
			log.Debugf("Using custom timeout of %d minutes", num)
			sshDefaultTimeout = num
		}
	}

	// TODO Test for failure with 15s !!!
	_, err = ssh.WaitServerReady("phase1", time.Duration(sshDefaultTimeout)*time.Minute)
	// err = ssh.WaitServerReady("phase1", time.Second * 3)
	if err != nil {
		if client.IsTimeoutError(err) {
			return nil, infraErrf(err, "Timeout creating a gateway")
		}

		if client.IsProvisioningError(err) {
			log.Errorf("%+v", err)
			return nil, logicErr(fmt.Errorf("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", gw.Name))
		}

		return nil, infraErr(err)
	}
	log.Infof("SSH service of gateway '%s' started.", gw.Name)

	// Executes userdata phase2 script to finalize host installation
	log.Infof("Starting initial configuration of the gateway '%s'", gw.Name)
	userDataPhase2, err := userData.Generate("phase2")
	if err != nil {
		return nil, err
	}
	err = install.UploadStringToRemoteFile(string(userDataPhase2), safescaleutils.ToPBHost(gw), srvutils.TempFolder+"/user_data.phase2.sh", "", "", "")
	if err != nil {
		return nil, err
	}
	command := fmt.Sprintf("sudo bash %s/%s; exit $?", srvutils.TempFolder, "user_data.phase2.sh")
	retcode, _, stderr, err := sshHandler.Run(ctx, gw.Name, command)
	if err != nil {
		return nil, err
	}
	if retcode != 0 {
		return nil, fmt.Errorf("failed to finalize host installation: %s", stderr)
	}
	log.Infof("Gateway '%s' successfully configured.", gw.Name)

	// Reboot gateway
	log.Debugf("Rebooting gateway '%s'", gw.Name)
	command = "sudo systemctl reboot"
	retcode, _, stderr, err = sshHandler.Run(ctx, gw.Name, command)
	if err != nil {
		return nil, err
	}

	// TODO Test for failure with 15s !!!
	_, err = ssh.WaitServerReady("ready", time.Duration(sshDefaultTimeout)*time.Minute)
	// err = ssh.WaitServerReady("ready", time.Second * 3)
	if err != nil {
		if client.IsTimeoutError(err) {
			return nil, infraErrf(err, "Timeout creating a gateway")
		}

		if client.IsProvisioningError(err) {
			log.Errorf("%+v", err)
			return nil, logicErr(fmt.Errorf("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", gw.Name))
		}

		return nil, infraErr(err)
	}

	select {
	case <-ctx.Done():
		log.Warnf("Network creation cancelled by user")
		err = fmt.Errorf("network creation cancelled by user")
		return nil, err
	default:
	}

	return network, nil
}

// List returns the network list
func (handler *NetworkHandler) List(ctx context.Context, all bool) ([]*resources.Network, error) {
	log.Debugf(">>> safescale.server.handlers.NetworkHandler::List(%v)", all)
	defer log.Debugf("<<< safescale.server.handlers.NetworkHandler::List(%v)", all)

	if all {
		return handler.service.ListNetworks()
	}

	var netList []*resources.Network

	mn := metadata.NewNetwork(handler.service)
	err := mn.Browse(func(network *resources.Network) error {
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
func (handler *NetworkHandler) Inspect(ctx context.Context, ref string) (*resources.Network, error) {
	defer log.Debugf("<<< safescale.server.handlers.NetworkHandler::Inspect(%s)", ref)
	log.Debugf(">>> safescale.server.handlers.NetworkHandler::Inspect(%s)", ref)

	mn, err := metadata.LoadNetwork(handler.service, ref)
	if err != nil {
		return nil, err
	}
	return mn.Get(), nil
}

// Delete deletes network referenced by ref
func (handler *NetworkHandler) Delete(ctx context.Context, ref string) error {
	log.Debugf(">>> safescale.server.handlers.NetworkHandler::Delete(%s)", ref)
	defer log.Debugf("<<< safescale.server.handlers.NetworkHandler::Delete(%s)", ref)

	mn, err := metadata.LoadNetwork(handler.service, ref)
	if err != nil {
		if _, ok := err.(resources.ErrResourceNotFound); !ok {
			err = infraErrf(err, "failed to load metadata of network '%s', trying to delete network anyway", ref)
			cleanErr := handler.service.DeleteNetwork(ref)
			if cleanErr != nil {
				_ = infraErrf(cleanErr, "error deleting network on cleanup after failure to load metadata '%s'", ref)
			}
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
				_, err = handler.service.GetHostByName(k)
				if err == nil {
					list = append(list, k)
				}

			}
			if len(list) == 0 {
				return nil
			}
			verb := "are"
			if hostsLen == 1 {
				verb = "is"
			}
			errorMsg = fmt.Sprintf("can't delete network '%s': %d host%s %s still attached to it: %s",
				network.Name, hostsLen, utils.Plural(hostsLen), verb, strings.Join(list, ", "))
			return resources.ResourceNotAvailableError("network", network.Name)
		}
		return nil
	})
	if err != nil {
		if _, ok := err.(resources.ErrResourceNotAvailable); ok {
			return logicErr(fmt.Errorf(errorMsg))
		}
		return infraErr(err)
	}

	// 1st delete gateway
	var metadataHost *resources.Host
	if gwID != "" {
		mh, err := metadata.LoadHost(handler.service, gwID)
		if err != nil {
			_ = infraErr(err)
		} else {
			metadataHost = mh.Get()

			err = handler.service.DeleteGateway(gwID)
			// allow no gateway, but log it
			if err != nil {
				log.Warnf("Failed to delete gateway: %s", openstack.ProviderErrorToString(err))
			}
			err = mh.Delete()
			if err != nil {
				return infraErr(err)
			}
		}

	}

	// 2nd delete network, with tolerance
	err = handler.service.DeleteNetwork(network.ID)
	if err != nil {
		if _, ok := err.(resources.ErrResourceNotFound); !ok {
			// Delete metadata,
			log.Error("can't delete network")
			err = mn.Delete()
			if err != nil {
				log.Errorf("can't delete network metadata: %s", err)
			}
		}
		// If network doesn't exist anymore on the provider infrastructure, don't fail
		// to cleanup the metadata
		log.Warnf("network not found on provider side, cleaning up metadata.")
	}

	// Delete metadata,
	err = mn.Delete()
	if err != nil {
		return infraErr(err)
	}

	select {
	case <-ctx.Done():
		log.Warnf("Network delete cancelled by user")
		hostSizing := propsv1.NewHostSizing()
		err := metadataHost.Properties.LockForRead(HostProperty.SizingV1).ThenUse(func(v interface{}) error {
			hostSizing = v.(*propsv1.HostSizing)
			return nil
		})
		if err != nil {
			return fmt.Errorf("Failed to get gateway sizingV1")
		}
		//os name of the gw is not stored in metadatas so we used ubuntu 16.04 by default
		networkBis, err := handler.Create(context.Background(), network.Name, network.CIDR, network.IPVersion, hostSizing.AllocatedSize.Cores, hostSizing.AllocatedSize.RAMSize, hostSizing.AllocatedSize.DiskSize, "Ubuntu 16.04", metadataHost.Name)
		if err != nil {
			return fmt.Errorf("Failed to stop network deletion")
		}
		buf, err := networkBis.Serialize()
		if err != nil {
			return fmt.Errorf("Deleted Network recreated by safescale")
		}
		return fmt.Errorf("Deleted Network recreated by safescale : %s", buf)
	default:
	}

	return nil
}
