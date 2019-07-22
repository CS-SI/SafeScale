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
	"strings"

	"github.com/CS-SI/SafeScale/lib/client"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostProperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/IPVersion"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/NetworkProperty"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/lib/server/install"
	"github.com/CS-SI/SafeScale/lib/server/metadata"
	safescaleutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils"
)

//go:generate mockgen -destination=../mocks/mock_networkapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers NetworkAPI

// TODO At service level, we need to log before returning, because it's the last chance to track the real issue in server side

// NetworkAPI defines API to manage networks
type NetworkAPI interface {
	Create(context.Context, string, string, IPVersion.Enum, resources.SizingRequirements, string, string, bool) (*resources.Network, error)
	List(context.Context, bool) ([]*resources.Network, error)
	Inspect(context.Context, string) (*resources.Network, error)
	Delete(context.Context, string) error
}

// NetworkHandler an implementation of NetworkAPI
type NetworkHandler struct {
	service   iaas.Service
	ipVersion IPVersion.Enum
}

// NewNetworkHandler Creates new Network service
func NewNetworkHandler(svc iaas.Service) NetworkAPI {
	return &NetworkHandler{
		service: svc,
	}
}

// Create creates a network
func (handler *NetworkHandler) Create(
	ctx context.Context,
	name string, cidr string, ipVersion IPVersion.Enum,
	sizing resources.SizingRequirements, theos string, gwname string,
	ha bool,
) (*resources.Network, error) {

	log.Debugf(">>> lib.server.handlers.NetworkHandler::Create()")
	defer log.Debugf("<<< lib.server.handlers.NetworkHandler::Create()")

	if gwname != "" && ha {
		return nil, fmt.Errorf("can't name gateway when HA is requested")
	}

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

	// Verify the CIDR is not routable
	routable, err := utils.IsCIDRRoutable(cidr)
	if err != nil {
		return nil, logicErr(fmt.Errorf("failed to determine if CIDR is not routable: %v", err))
	}
	if routable {
		return nil, logicErr(fmt.Errorf("can't create such a network, CIDR must be not routable; please choose an appropriate CIDR (RFC1918)"))
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

	// Creates VIP for gateways
	if ha {
		network.VIP, err = handler.service.CreateVIP(network.ID, fmt.Sprintf("for gateways of network %s", network.Name))
		if err != nil {
			return nil, infraErrf(err, "failed to create VIP")
		}

		// Starting from here, delete VIP if exists with error
		defer func() {
			if err != nil {
				derr := handler.service.DeleteVIP(network.VIP)
				if derr != nil {
					log.Errorf("Failed to delete VIP: %+v", derr)
				}
			}
		}()
	}

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

	log.Debugf("Creating compute resource '%s' ...", gwname)

	// Create a gateway (if ha is true, it will be the Master gateway)
	var template resources.HostTemplate
	tpls, err := handler.service.SelectTemplatesBySize(sizing, false)
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
		err = logicErr(fmt.Errorf("Error creating network: no host template matching requirements for gateway"))
		return nil, err
	}
	img, err := handler.service.SearchImage(theos)
	if err != nil {
		err := infraErrf(err, "Error creating network: Error searching image '%s'", theos)
		return nil, err
	}

	var (
		primaryGatewayName, secondaryGatewayName string
		secondaryGateway                         *resources.Host
		secondaryUserdata                        *userdata.Content
	)

	if ha || gwname == "" {
		primaryGatewayName = "gw-" + network.Name
	}
	if ha {
		secondaryGatewayName = "gw2-" + network.Name
	}

	keypairName := "kp_" + network.Name
	keypair, err := handler.service.CreateKeyPair(keypairName)
	if err != nil {
		return nil, infraErr(err)
	}

	// Primary gateway
	gwRequest := resources.GatewayRequest{
		ImageID:    img.ID,
		Network:    network,
		KeyPair:    keypair,
		TemplateID: template.ID,
		Name:       gwname,
		CIDR:       network.CIDR,
	}

	log.Infof("Requesting the creation of gateway '%s' using template '%s' with image '%s'", primaryGatewayName, template.Name, img.Name)
	primaryGateway, primaryUserdata, err := handler.service.CreateGateway(gwRequest)
	if err != nil {
		return nil, infraErrf(err, "Error creating network: Gateway creation with name '%s' failed", primaryGatewayName)
	}

	// Reloads the host to be sure all the properties are updated
	primaryGateway, err = handler.service.InspectHost(primaryGateway)
	if err != nil {
		return nil, infraErr(err)
	}

	// Starting from here, deletes the gateway if exiting with error
	defer func() {
		if err != nil {
			log.Warnf("Cleaning up on failure, deleting gateway '%s' host resource...", primaryGatewayName)
			derr := handler.service.DeleteHost(primaryGateway.ID)
			if derr != nil {
				log.Errorf("failed to delete gateway '%s': %v", primaryGatewayName, derr)
			}
			log.Infof("Cleaning up on failure, gateway '%s' deleted", primaryGatewayName)
		}
	}()

	// Binds gateway to VIP
	if network.VIP != nil {
		err = handler.service.BindHostToVIP(network.VIP, primaryGateway)
		if err != nil {
			return nil, infraErrf(err, "failed to bind host '%s' to VIP", primaryGatewayName)
		}
		primaryUserdata.PrivateVIP = network.VIP.PrivateIP
		// primaryUserdata.DefaultRouteIP = network.VIP.PrivateIP
		primaryUserdata.DefaultRouteIP = primaryGateway.GetPrivateIP()
		// primaryUserdata.EndpointIP = network.VIP.PublicIP
	} else {
		primaryUserdata.DefaultRouteIP = primaryGateway.GetPrivateIP()
	}
	primaryUserdata.IsPrimaryGateway = true

	defer func() {
		if err != nil {
			derr := handler.service.UnbindHostFromVIP(network.VIP, primaryGateway)
			if derr != nil {
				log.Debugf("Cleaning up on failure, failed to remove gateway bind from VIP: %v", derr)
			} else {
				log.Infof("Cleaning up on failure, gateway bind removed from VIP")
			}
		}
	}()

	// Updates requested sizing in gateway property propsv1.HostSizing
	err = primaryGateway.Properties.LockForWrite(HostProperty.SizingV1).ThenUse(func(v interface{}) error {
		gwSizingV1 := v.(*propsv1.HostSizing)
		gwSizingV1.RequestedSize = &propsv1.HostSize{
			Cores:     sizing.MinCores,
			RAMSize:   sizing.MinRAMSize,
			DiskSize:  sizing.MinDiskSize,
			GPUNumber: sizing.MinGPU,
			CPUFreq:   sizing.MinFreq,
		}
		return nil
	})
	if err != nil {
		return nil, infraErrf(err, "error creating network")
	}

	// Writes Gateway metadata
	primaryGatewayMetadata, err := metadata.SaveGateway(handler.service, primaryGateway, network.ID)
	if err != nil {
		return nil, infraErrf(err, "failed to create gateway: failed to save metadata: %s", err.Error())
	}

	// Starting from here, delete primary gateway metadata if exits with error
	defer func() {
		if err != nil {
			log.Warnf("Cleaning up on failure, deleting gateway '%s' metadata", primaryGatewayName)
			derr := primaryGatewayMetadata.Delete()
			if derr != nil {
				log.Errorf("Cleaning up on failure, failed to delete gateway '%s' metadata: %+v", primaryGatewayName, derr)
			}
		}
	}()

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	log.Infof("Waiting until gateway '%s' is available by SSH ...", primaryGatewayName)
	sshHandler := NewSSHHandler(handler.service)
	ssh, err := sshHandler.GetConfig(ctx, primaryGateway.ID)
	if err != nil {
		return nil, infraErrf(err, "error creating network: Error retrieving SSH config of gateway '%s'", primaryGatewayName)
	}

	sshDefaultTimeout := utils.GetHostTimeout()
	_, err = ssh.WaitServerReady("phase1", sshDefaultTimeout) // FIXME Phase1
	if err != nil {
		if client.IsTimeoutError(err) {
			return nil, infraErrf(err, "Timeout creating a gateway")
		}
		if client.IsProvisioningError(err) {
			log.Errorf("%+v", err)
			return nil, logicErr(fmt.Errorf("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", primaryGatewayName))
		}
		return nil, infraErr(err)
	}
	log.Infof("SSH service of gateway '%s' started.", primaryGatewayName)

	// Secondary gateway if needed
	if ha {
		gwRequest.Name = secondaryGatewayName

		log.Infof("Requesting the creation of the gateway '%s' using template '%s' with image '%s'", gwname, template.Name, img.Name)
		secondaryGateway, secondaryUserdata, err = handler.service.CreateGateway(gwRequest)
		if err != nil {
			return nil, infraErrf(err, "Error creating network: Gateway creation with name '%s' failed", gwname)
		}

		// Reloads the host to be sure all the properties are updated
		secondaryGateway, err = handler.service.InspectHost(secondaryGateway)
		if err != nil {
			return nil, infraErr(err)
		}

		// Starting from here, deletes the gateway if exiting with error
		defer func() {
			if err != nil {
				log.Warnf("Cleaning up on failure, deleting gateway '%s' host resource...", secondaryGatewayName)
				derr := handler.service.DeleteHost(secondaryGateway.ID)
				if derr != nil {
					log.Errorf("failed to delete gateway '%s': %v", secondaryGatewayName, derr)
				}
				log.Infof("Cleaning up on failure, gateway '%s' deleted", secondaryGatewayName)
			}
		}()

		// Binds gateway to VIP
		if network.VIP != nil {
			err = handler.service.BindHostToVIP(network.VIP, secondaryGateway)
			if err != nil {
				return nil, infraErrf(err, "failed to bind host '%s' to VIP", secondaryGatewayName)
			}
			secondaryUserdata.PrivateVIP = network.VIP.PrivateIP
			// secondaryUserdata.PublicVIP = network.VIP.PublicIP
			secondaryUserdata.DefaultRouteIP = network.VIP.PrivateIP
			// secondaryUserdata.EndpointIP = network.VIP.PublicIP
		} else {
			secondaryUserdata.DefaultRouteIP = secondaryGateway.GetPrivateIP()
		}
		secondaryUserdata.IsPrimaryGateway = false

		defer func() {
			if err != nil {
				derr := handler.service.UnbindHostFromVIP(network.VIP, secondaryGateway)
				if derr != nil {
					log.Debugf("Cleaning up on failure, failed to remove gateway bind from VIP: %v", derr)
				} else {
					log.Infof("Cleaning up on failure, gateway bind removed from VIP")
				}
			}
		}()

		// Updates requested sizing in gateway property propsv1.HostSizing
		err = secondaryGateway.Properties.LockForWrite(HostProperty.SizingV1).ThenUse(func(v interface{}) error {
			gwSizingV1 := v.(*propsv1.HostSizing)
			gwSizingV1.RequestedSize = &propsv1.HostSize{
				Cores:     sizing.MinCores,
				RAMSize:   sizing.MinRAMSize,
				DiskSize:  sizing.MinDiskSize,
				GPUNumber: sizing.MinGPU,
				CPUFreq:   sizing.MinFreq,
			}
			return nil
		})
		if err != nil {
			return nil, infraErrf(err, "error creating network")
		}

		// Writes Gateway metadata
		secondaryGatewayMetadata, err := metadata.SaveGateway(handler.service, secondaryGateway, network.ID)
		if err != nil {
			return nil, infraErrf(err, "failed to create gateway: failed to save metadata: %s", err.Error())
		}

		// Starting from here, delete gateway metadata if exits with error
		defer func() {
			if err != nil {
				log.Warnf("Cleaning up on failure, deleting gateway '%s' metadata", secondaryGatewayName)
				derr := secondaryGatewayMetadata.Delete()
				if derr != nil {
					log.Errorf("Failed to delete gateway '%s' metadata: %+v", secondaryGatewayName, derr)
				}
			}
		}()

		// A host claimed ready by a Cloud provider is not necessarily ready
		// to be used until ssh service is up and running. So we wait for it before
		// claiming host is created
		log.Infof("Waiting until gateway '%s' is available by SSH ...", secondaryGatewayName)
		sshHandler := NewSSHHandler(handler.service)
		ssh, err := sshHandler.GetConfig(ctx, secondaryGateway.ID)
		if err != nil {
			return nil, infraErrf(err, "error creating network: Error retrieving SSH config of gateway '%s'", secondaryGatewayName)
		}

		sshDefaultTimeout := utils.GetHostTimeout()
		_, err = ssh.WaitServerReady("phase1", sshDefaultTimeout) // FIXME Phase1
		if err != nil {
			if client.IsTimeoutError(err) {
				return nil, infraErrf(err, "Timeout creating a gateway")
			}
			if client.IsProvisioningError(err) {
				log.Errorf("%+v", err)
				return nil, logicErr(fmt.Errorf("error creating network: failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", secondaryGatewayName))
			}
			return nil, infraErr(err)
		}
		log.Infof("SSH service of gateway '%s' started.", secondaryGatewayName)
	}

	primaryUserdata.PrimaryGatewayPrivateIP = primaryGateway.GetPrivateIP()
	primaryUserdata.PrimaryGatewayPublicIP = primaryGateway.GetPublicIP()
	if ha {
		primaryUserdata.SecondaryGatewayPrivateIP = secondaryGateway.GetPrivateIP()
		primaryUserdata.SecondaryGatewayPublicIP = secondaryGateway.GetPublicIP()
		secondaryUserdata.PrimaryGatewayPrivateIP = primaryUserdata.PrimaryGatewayPrivateIP
		secondaryUserdata.PrimaryGatewayPublicIP = primaryUserdata.PrimaryGatewayPublicIP
		secondaryUserdata.SecondaryGatewayPrivateIP = primaryUserdata.SecondaryGatewayPrivateIP
		secondaryUserdata.SecondaryGatewayPublicIP = primaryUserdata.SecondaryGatewayPublicIP
	}

	// Executes userdata phase2 script to finalize host installation
	log.Infof("Starting initial configuration of the gateway '%s'", primaryGatewayName)
	primaryUserdataPhase2, err := primaryUserdata.Generate("phase2")
	if err != nil {
		return nil, err
	}
	err = install.UploadStringToRemoteFile(string(primaryUserdataPhase2), safescaleutils.ToPBHost(primaryGateway), srvutils.TempFolder+"/user_data.phase2.sh", "", "", "")
	if err != nil {
		return nil, err
	}
	command := fmt.Sprintf("sudo bash %s/%s; exit $?", srvutils.TempFolder, "user_data.phase2.sh")
	retcode, _, stderr, err := sshHandler.Run(ctx, primaryGatewayName, command)
	if err != nil {
		return nil, err
	}
	if retcode != 0 {
		return nil, fmt.Errorf("failed to finalize host installation: %s", stderr)
	}
	log.Infof("Gateway '%s' successfully configured.", primaryGatewayName)

	// Reboot gateway
	log.Debugf("Rebooting gateway '%s'", primaryGatewayName)
	command = "sudo systemctl reboot"
	retcode, _, stderr, err = sshHandler.Run(ctx, primaryGatewayName, command)
	if err != nil {
		return nil, err
	}

	network.GatewayID = primaryGateway.ID
	err = mn.Write()
	if err != nil {
		return nil, infraErr(err)
	}

	// TODO Test for failure with 15s !!!
	_, err = ssh.WaitServerReady("ready", sshDefaultTimeout)
	if err != nil {
		if client.IsTimeoutError(err) {
			return nil, infraErrf(err, "Timeout creating a gateway")
		}
		if client.IsProvisioningError(err) {
			log.Errorf("%+v", err)
			return nil, logicErr(fmt.Errorf("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", primaryGatewayName))
		}
		return nil, infraErr(err)
	}

	if ha {
		// Executes userdata phase2 script to finalize host installation
		log.Infof("Starting initial configuration of the gateway '%s'", secondaryGatewayName)
		secondaryUserdataPhase2, err := secondaryUserdata.Generate("phase2")
		if err != nil {
			return nil, err
		}
		err = install.UploadStringToRemoteFile(string(secondaryUserdataPhase2), safescaleutils.ToPBHost(secondaryGateway), srvutils.TempFolder+"/user_data.phase2.sh", "", "", "")
		if err != nil {
			return nil, err
		}
		command := fmt.Sprintf("sudo bash %s/%s; exit $?", srvutils.TempFolder, "user_data.phase2.sh")
		retcode, _, stderr, err := sshHandler.Run(ctx, secondaryGatewayName, command)
		if err != nil {
			return nil, err
		}
		if retcode != 0 {
			return nil, fmt.Errorf("failed to finalize host installation: %s", stderr)
		}
		log.Infof("Gateway '%s' successfully configured.", secondaryGatewayName)

		// Reboot gateway
		log.Debugf("Rebooting gateway '%s'", secondaryGatewayName)
		command = "sudo systemctl reboot"
		retcode, _, stderr, err = sshHandler.Run(ctx, secondaryGatewayName, command)
		if err != nil {
			return nil, err
		}

		// TODO Test for failure with 15s !!!
		_, err = ssh.WaitServerReady("ready", sshDefaultTimeout)
		if err != nil {
			if client.IsTimeoutError(err) {
				return nil, infraErrf(err, "Timeout creating a gateway")
			}
			if client.IsProvisioningError(err) {
				log.Errorf("%+v", err)
				return nil, logicErr(fmt.Errorf("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", secondaryGatewayName))
			}
			return nil, infraErr(err)
		}

		network.SecondaryGatewayID = secondaryGateway.ID
		err = mn.Write()
		if err != nil {
			return nil, infraErr(err)
		}
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
	log.Debugf(">>> lib.server.handlers.NetworkHandler::List(%v)", all)
	defer log.Debugf("<<< lib.server.handlers.NetworkHandler::List(%v)", all)

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
	defer log.Debugf("<<< lib.server.handlers.NetworkHandler::Inspect(%s)", ref)
	log.Debugf(">>> lib.server.handlers.NetworkHandler::Inspect(%s)", ref)

	mn, err := metadata.LoadNetwork(handler.service, ref)
	if err != nil {
		return nil, err
	}
	return mn.Get(), nil
}

// Delete deletes network referenced by ref
func (handler *NetworkHandler) Delete(ctx context.Context, ref string) error {
	log.Debugf(">>> lib.server.handlers.NetworkHandler::Delete(%s)", ref)
	defer log.Debugf("<<< lib.server.handlers.NetworkHandler::Delete(%s)", ref)

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

	// Delete gateway(s)
	if network.GatewayID != "" {
		mh, err := metadata.LoadHost(handler.service, network.GatewayID)
		if err != nil {
			_ = infraErr(err)
		} else {
			if network.VIP != nil {
				err = handler.service.UnbindHostFromVIP(network.VIP, mh.Get())
				if err != nil {
					log.Errorf("failed to unbind host to VIP: %v", err)
				}
			}

			err = handler.service.DeleteGateway(network.GatewayID)
			// allow no gateway, but log it
			if err != nil {
				log.Errorf("Failed to delete gateway: %s", openstack.ProviderErrorToString(err))
			}
			err = mh.Delete()
			if err != nil {
				return infraErr(err)
			}
		}
	}
	if network.SecondaryGatewayID != "" {
		mh, err := metadata.LoadHost(handler.service, network.SecondaryGatewayID)
		if err != nil {
			_ = infraErr(err)
		} else {
			if network.VIP != nil {
				err = handler.service.UnbindHostFromVIP(network.VIP, mh.Get())
				if err != nil {
					log.Errorf("failed to unbind host to VIP: %v", err)
				}
			}

			err = handler.service.DeleteGateway(network.GatewayID)
			// allow no gateway, but log it
			if err != nil {
				log.Errorf("Failed to delete gateway: %s", openstack.ProviderErrorToString(err))
			}
			err = mh.Delete()
			if err != nil {
				return infraErr(err)
			}
		}
	}

	// Delete VIP if needed
	if network.VIP != nil {
		err = handler.service.DeleteVIP(network.VIP)
		if err != nil {
			log.Errorf("Failed to delete VIP: %v", err)
		}
	}

	// delete network, with tolerance
	err = handler.service.DeleteNetwork(network.ID)
	if err != nil {
		if _, ok := err.(resources.ErrResourceNotFound); !ok {
			// Delete metadata,
			log.Error("Can't delete network")
		} else {
			// If network doesn't exist anymore on the provider infrastructure, don't fail
			// to cleanup the metadata
			log.Warnf("network not found on provider side, cleaning up metadata.")
		}
	}

	// Delete metadata,
	err = mn.Delete()
	if err != nil {
		return infraErr(err)
	}

	// select {
	// case <-ctx.Done():
	// 	log.Warnf("Network delete cancelled by user")
	// 	hostSizingV1 := propsv1.NewHostSizing()
	// 	err := metadataHost.Properties.LockForRead(HostProperty.SizingV1).ThenUse(func(v interface{}) error {
	// 		hostSizingV1 = v.(*propsv1.HostSizing)
	// 		return nil
	// 	})
	// 	if err != nil {
	// 		return fmt.Errorf("Failed to get gateway sizingV1")
	// 	}

	// 	//os name of the gw is not stored in metadatas so we used ubuntu 16.04 by default
	// 	sizing := resources.SizingRequirements{
	// 		MinCores:    hostSizingV1.AllocatedSize.Cores,
	// 		MaxCores:    hostSizingV1.AllocatedSize.Cores,
	// 		MinFreq:     hostSizingV1.AllocatedSize.CPUFreq,
	// 		MinGPU:      hostSizingV1.AllocatedSize.GPUNumber,
	// 		MinRAMSize:  hostSizingV1.AllocatedSize.RAMSize,
	// 		MaxRAMSize:  hostSizingV1.AllocatedSize.RAMSize,
	// 		MinDiskSize: hostSizingV1.AllocatedSize.DiskSize,
	// 	}
	// 	networkBis, err := handler.Create(context.Background(), network.Name, network.CIDR, network.IPVersion, sizing, "Ubuntu 18.04", metadataHost.Name)
	// 	if err != nil {
	// 		return fmt.Errorf("Failed to stop network deletion")
	// 	}
	// 	buf, err := networkBis.Serialize()
	// 	if err != nil {
	// 		return fmt.Errorf("Deleted Network recreated by safescale")
	// 	}
	// 	return fmt.Errorf("Deleted Network recreated by safescale : %s", buf)
	// default:
	// }

	return nil
}
