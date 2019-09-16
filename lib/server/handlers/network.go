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
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/client"
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
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
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
	failover bool,
) (network *resources.Network, err error) {
	defer utils.TimerWithLevel(fmt.Sprintf("lib.server.handlers.NetworkHandler::Create() called"), log.TraceLevel)()

	if gwname != "" && failover {
		return nil, fmt.Errorf("can't name gateway when failover is requested")
	}

	// Verify that the network doesn't exist first
	_, err = handler.service.GetNetworkByName(name)
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
	network, err = handler.service.CreateNetwork(resources.NetworkRequest{
		Name:      name,
		IPVersion: ipVersion,
		CIDR:      cidr,
	})
	if err != nil {
		return nil, infraErr(err)
	}

	newNetwork := network
	// Starting from here, delete network if exiting with error
	defer func() {
		if err != nil {
			if newNetwork != nil {
				derr := handler.service.DeleteNetwork(newNetwork.ID)
				if derr != nil {
					log.Errorf("Failed to delete network: %+v", derr)
				}
			}
		}
	}()

	// Creates VIP for gateways if asked for
	if failover {
		network.VIP, err = handler.service.CreateVIP(network.ID, fmt.Sprintf("for gateways of network %s", network.Name))
		if err != nil {
			return nil, infraErrf(err, "failed to create VIP")
		}

		// Starting from here, delete VIP if exists with error
		defer func() {
			if err != nil {
				if newNetwork != nil {
					derr := handler.service.DeleteVIP(newNetwork.VIP)
					if derr != nil {
						log.Errorf("Failed to delete VIP: %+v", derr)
					}
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
			if mn != nil {
				derr := mn.Delete()
				if derr != nil {
					log.Errorf("Failed to delete network metadata: %+v", derr)
				}
			}
		}
	}()

	var template *resources.HostTemplate
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
		return nil, logicErr(fmt.Errorf("error creating network: no host template matching requirements for gateway"))
	}
	img, err := handler.service.SearchImage(theos)
	if err != nil {
		return nil, infraErrf(err, "error creating network: Error searching image '%s'", theos)
	}

	var primaryGatewayName, secondaryGatewayName string
	if failover || gwname == "" {
		primaryGatewayName = "gw-" + network.Name
	} else {
		primaryGatewayName = gwname
	}
	if failover {
		secondaryGatewayName = "gw2-" + network.Name
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
		CIDR:       network.CIDR,
	}

	var (
		primaryGateway, secondaryGateway   *resources.Host
		primaryUserdata, secondaryUserdata *userdata.Content
		secondaryTask                      concurrency.Task
		primaryMetadata, secondaryMetadata *metadata.Gateway
		secondaryErr                       error
		secondaryResult                    concurrency.TaskResult
	)

	// Starts primary gateway creation
	primaryRequest := gwRequest
	primaryRequest.Name = primaryGatewayName
	primaryTask := concurrency.NewTaskWithContext(ctx).Start(handler.createGateway, data.Map{
		"request": primaryRequest,
		"sizing":  sizing,
	})

	// Starts secondary gateway creation if asked for
	if failover {
		secondaryRequest := gwRequest
		secondaryRequest.Name = secondaryGatewayName
		secondaryTask = concurrency.NewTaskWithContext(ctx).Start(handler.createGateway, data.Map{
			"request": secondaryRequest,
			"sizing":  sizing,
		})
	}

	primaryResult, primaryErr := primaryTask.Wait()
	if primaryErr == nil {
		primaryGateway = primaryResult.(data.Map)["host"].(*resources.Host)
		primaryUserdata = primaryResult.(data.Map)["userdata"].(*userdata.Content)
		primaryMetadata = primaryResult.(data.Map)["metadata"].(*metadata.Gateway)

		// Starting from here, deletes the primary gateway if exiting with error
		defer func() {
			if err != nil {
				handler.deleteGateway(primaryGateway)
				handler.deleteGatewayMetadata(primaryMetadata)
				if failover {
					handler.unbindHostFromVIP(newNetwork.VIP, primaryGateway)
				}
			}
		}()
	}
	if failover && secondaryTask != nil {
		secondaryResult, secondaryErr = secondaryTask.Wait()
		if secondaryErr == nil {
			secondaryGateway = secondaryResult.(data.Map)["host"].(*resources.Host)
			secondaryUserdata = secondaryResult.(data.Map)["userdata"].(*userdata.Content)
			secondaryMetadata = secondaryResult.(data.Map)["metadata"].(*metadata.Gateway)

			// Starting from here, deletes the secondary gateway if exiting with error
			defer func() {
				if err != nil {
					handler.deleteGateway(secondaryGateway)
					handler.deleteGatewayMetadata(secondaryMetadata)
					handler.unbindHostFromVIP(newNetwork.VIP, secondaryGateway)
				}
			}()
		}
	}
	if primaryErr != nil {
		return nil, primaryErr
	}
	if secondaryErr != nil {
		return nil, secondaryErr
	}

	network.GatewayID = primaryGateway.ID
	if secondaryGateway != nil {
		network.SecondaryGatewayID = secondaryGateway.ID
	}
	err = mn.Write()
	if err != nil {
		return nil, infraErr(err)
	}

	// Starts gateway(s) installation
	primaryTask = primaryTask.Reset().Start(handler.waitForInstallPhase1OnGateway, primaryGateway)
	if failover && secondaryTask != nil {
		secondaryTask = secondaryTask.Reset().Start(handler.waitForInstallPhase1OnGateway, secondaryGateway)
	}
	_, primaryErr = primaryTask.Wait()
	if primaryErr != nil {
		return nil, primaryErr
	}
	if failover && secondaryTask != nil {
		_, secondaryErr = secondaryTask.Wait()
		if secondaryErr != nil {
			return nil, secondaryErr
		}
	}

	if primaryUserdata == nil {
		return nil, logicErr(fmt.Errorf("error creating network: primaryUserdata is nil"))
	}

	// Complement userdata for gateway(s) with allocated IP
	primaryUserdata.PrimaryGatewayPrivateIP = primaryGateway.GetPrivateIP()
	primaryUserdata.PrimaryGatewayPublicIP = primaryGateway.GetPublicIP()
	if failover {
		primaryUserdata.SecondaryGatewayPrivateIP = secondaryGateway.GetPrivateIP()
		primaryUserdata.SecondaryGatewayPublicIP = secondaryGateway.GetPublicIP()

		if secondaryUserdata == nil {
			return nil, logicErr(fmt.Errorf("error creating network: secondaryUserdata is nil"))
		}

		secondaryUserdata.PrimaryGatewayPrivateIP = primaryUserdata.PrimaryGatewayPrivateIP
		secondaryUserdata.PrimaryGatewayPublicIP = primaryUserdata.PrimaryGatewayPublicIP
		secondaryUserdata.SecondaryGatewayPrivateIP = primaryUserdata.SecondaryGatewayPrivateIP
		secondaryUserdata.SecondaryGatewayPublicIP = primaryUserdata.SecondaryGatewayPublicIP
	}

	// Starts gateway(s) installation
	primaryTask = primaryTask.Reset().Start(handler.installPhase2OnGateway, data.Map{
		"host":     primaryGateway,
		"userdata": primaryUserdata,
	})
	if failover && secondaryTask != nil {
		secondaryTask = secondaryTask.Reset().Start(handler.installPhase2OnGateway, data.Map{
			"host":     secondaryGateway,
			"userdata": secondaryUserdata,
		})
	}
	_, primaryErr = primaryTask.Wait()
	if primaryErr != nil {
		return nil, primaryErr
	}
	if failover && secondaryTask != nil {
		_, secondaryErr = secondaryTask.Wait()
		if secondaryErr != nil {
			return nil, secondaryErr
		}
	}

	select {
	case <-ctx.Done():
		log.Warnf("Network creation cancelled by user")
		return nil, fmt.Errorf("network creation cancelled by user")
	default:
	}

	return network, nil
}

func (handler *NetworkHandler) createGateway(t concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	var (
		inputs data.Map
		ok     bool
	)
	if inputs, ok = params.(data.Map); !ok {
		return nil, utils.InvalidParameterError("params", "must be a data.Map")
	}
	// name := inputs["name"].(string)
	request := inputs["request"].(resources.GatewayRequest)
	sizing := inputs["sizing"].(resources.SizingRequirements)

	log.Infof("Requesting the creation of gateway '%s' using template '%s' with image '%s'", request.Name, request.TemplateID, request.ImageID)
	gw, userData, err := handler.service.CreateGateway(request)
	if err != nil {
		return nil, infraErrf(err, "Error creating network: Gateway creation with name '%s' failed", request.Name)
	}

	// Starting from here, deletes the primary gateway if exiting with error
	defer func() {
		if err != nil {
			log.Warnf("Cleaning up on failure, deleting gateway '%s' host resource...", request.Name)
			derr := handler.service.DeleteHost(gw.ID)
			if derr != nil {
				log.Errorf("Cleaning up on failure, failed to delete gateway '%s': %v", request.Name, derr)
			}
			log.Infof("Cleaning up on failure, gateway '%s' deleted", request.Name)
		}
	}()

	// Reloads the host to be sure all the properties are updated
	gw, err = handler.service.InspectHost(gw)
	if err != nil {
		return nil, infraErr(err)
	}

	// Binds gateway to VIP
	if request.Network.VIP != nil {
		err = handler.service.BindHostToVIP(request.Network.VIP, gw)
		if err != nil {
			return nil, infraErrf(err, "failed to bind host '%s' to VIP", gw.Name)
		}
		userData.PrivateVIP = request.Network.VIP.PrivateIP
		// userData.DefaultRouteIP = request.Network.VIP.PrivateIP
		userData.DefaultRouteIP = gw.GetPrivateIP()
		// userData.EndpointIP = request.Network.VIP.PublicIP
	} else {
		userData.DefaultRouteIP = gw.GetPrivateIP()
	}
	userData.IsPrimaryGateway = true

	// Updates requested sizing in gateway property propsv1.HostSizing
	err = gw.Properties.LockForWrite(HostProperty.SizingV1).ThenUse(func(v interface{}) error {
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
		return nil, infraErr(err)
	}

	// Writes Gateway metadata
	m, err := metadata.SaveGateway(handler.service, gw, request.Network.ID)
	if err != nil {
		return nil, infraErrf(err, "failed to create gateway '%s': failed to save metadata: %s", gw.Name, err.Error())
	}
	result = data.Map{
		"host":     gw,
		"userdata": userData,
		"metadata": m,
	}
	return result, nil
}

func (handler *NetworkHandler) waitForInstallPhase1OnGateway(
	task concurrency.Task, params concurrency.TaskParameters,
) (result concurrency.TaskResult, err error) {

	gw := params.(*resources.Host)

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	log.Infof("Waiting until gateway '%s' is available by SSH ...", gw.Name)
	sshHandler := NewSSHHandler(handler.service)
	ssh, err := sshHandler.GetConfig(task.GetContext(), gw.ID)
	if err != nil {
		return nil, infraErrf(err, "error creating network: Error retrieving SSH config of gateway '%s'", gw.Name)
	}

	log.Debugf("Provisioning gateway '%s', phase 1", gw.Name)
	_, err = ssh.WaitServerReady("phase1", utils.GetHostCreationTimeout())
	if err != nil {
		if client.IsTimeoutError(err) {
			return nil, infraErrf(err, "Timeout waiting gateway '%s' to become ready", gw.Name)
		}
		if client.IsProvisioningError(err) {
			log.Errorf("%+v", err)

			if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
				_ = os.MkdirAll(utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s", gw.Name)), 0777)
				dumpName := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/userdata-%s.", gw.Name, "phase2"))
				_, _, _, _ = sshHandler.Copy(task.GetContext(), gw.Name+":/opt/safescale/var/tmp/user_data.phase2.sh", dumpName+"sh")
				_, _, _, _ = sshHandler.Copy(task.GetContext(), gw.Name+":/opt/safescale/var/log/user_data.phase2.log", dumpName+"log")
			}

			return nil, logicErr(fmt.Errorf("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", gw.Name))
		}
		return nil, infraErrf(err, "failed to wait gateway '%s' to become ready", gw.Name)
	}
	log.Infof("SSH service of gateway '%s' started.", gw.Name)

	return nil, nil
}

func (handler *NetworkHandler) installPhase2OnGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	var (
		gw       *resources.Host
		userData *userdata.Content
		ok       bool
	)
	if gw, ok = params.(data.Map)["host"].(*resources.Host); !ok {
		return nil, utils.InvalidParameterError("params", "missing field 'host'")
	}
	if userData, ok = params.(data.Map)["userdata"].(*userdata.Content); !ok {
		return nil, utils.InvalidParameterError("params", "missing field 'userdata'")
	}

	// Executes userdata phase2 script to finalize host installation
	defer utils.TimerErrWithLevel(fmt.Sprintf("Starting configuration of the gateway '%s'", gw.Name), err, log.InfoLevel)()
	content, err := userData.Generate("phase2")
	if err != nil {
		return nil, err
	}
	err = install.UploadStringToRemoteFile(string(content), safescaleutils.ToPBHost(gw), srvutils.TempFolder+"/user_data.phase2.sh", "", "", "")
	if err != nil {
		return nil, err
	}
	command := fmt.Sprintf("sudo bash %s/%s; exit $?", srvutils.TempFolder, "user_data.phase2.sh")
	sshHandler := NewSSHHandler(handler.service)

	log.Debugf("Provisioning gateway '%s', phase 2", gw.Name)
	returnCode, _, stderr, err := sshHandler.Run(task.GetContext(), gw.Name, command)
	if err != nil {
		return nil, err
	}
	if returnCode != 0 {
		if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
			_ = os.MkdirAll(utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s", gw.Name)), 0777)
			dumpName := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/userdata-%s.", gw.Name, "phase2"))
			_, _, _, _ = sshHandler.Copy(task.GetContext(), gw.Name+":/opt/safescale/var/tmp/user_data.phase2.sh", dumpName+"sh")
			_, _, _, _ = sshHandler.Copy(task.GetContext(), gw.Name+":/opt/safescale/var/log/user_data.phase2.log", dumpName+"log")
		}

		return nil, fmt.Errorf("failed to finalize gateway '%s' installation: %s", gw.Name, stderr)
	}
	log.Infof("Gateway '%s' successfully configured.", gw.Name)

	// Reboot gateway
	log.Debugf("Rebooting gateway '%s'", gw.Name)
	command = "sudo systemctl reboot"
	returnCode, _, stderr, err = sshHandler.Run(task.GetContext(), gw.Name, command)
	if err != nil {
		return nil, err
	}

	ssh, err := sshHandler.GetConfig(task.GetContext(), gw.ID)
	if err != nil {
		return nil, err
	}

	sshDefaultTimeout := utils.GetHostTimeout()
	_, err = ssh.WaitServerReady("ready", sshDefaultTimeout)
	if err != nil {
		if client.IsTimeoutError(err) {
			return nil, infraErrf(err, "Timeout waiting gateway '%s' to become ready", gw.Name)
		}
		if client.IsProvisioningError(err) {
			log.Errorf("%+v", err)
			return nil, logicErr(fmt.Errorf("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", gw.Name))
		}
		return nil, infraErrf(err, "failed to wait gateway '%s' to become ready", gw.Name)
	}
	return nil, nil
}

func (handler *NetworkHandler) deleteGateway(gw *resources.Host) {
	log.Warnf("Cleaning up on failure, deleting gateway '%s'...", gw.Name)
	derr := handler.service.DeleteHost(gw.ID)
	if derr != nil {
		log.Errorf("Cleaning up on failure, failed to delete gateway '%s': %v", gw.Name, derr)
	}
	log.Infof("Cleaning up on failure, gateway '%s' deleted", gw.Name)
}

func (handler *NetworkHandler) deleteGatewayMetadata(m *metadata.Gateway) {
	name := m.Get().Name
	log.Warnf("Cleaning up on failure, deleting gateway '%s' metadata", name)
	derr := m.Delete()
	if derr != nil {
		log.Errorf("Cleaning up on failure, failed to delete gateway '%s' metadata: %+v", name, derr)
	}
}

func (handler *NetworkHandler) unbindHostFromVIP(vip *resources.VIP, host *resources.Host) {
	derr := handler.service.UnbindHostFromVIP(vip, host)
	if derr != nil {
		log.Debugf("Cleaning up on failure, failed to remove gateway bind from VIP: %v", derr)
	} else {
		log.Infof("Cleaning up on failure, host '%s' bind removed from VIP", host.Name)
	}
}

// List returns the network list
func (handler *NetworkHandler) List(ctx context.Context, all bool) (netList []*resources.Network, err error) {
	defer utils.TimerWithLevel(fmt.Sprintf("lib.server.handlers.NetworkHandler::List(%v) called", all), log.TraceLevel)()

	if all {
		return handler.service.ListNetworks()
	}

	mn := metadata.NewNetwork(handler.service)
	err = mn.Browse(func(network *resources.Network) error {
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
func (handler *NetworkHandler) Inspect(ctx context.Context, ref string) (network *resources.Network, err error) {
	defer utils.TimerWithLevel(fmt.Sprintf("lib.server.handlers.NetworkHandler::Inspect(%s) called", ref), log.TraceLevel)()

	mn, err := metadata.LoadNetwork(handler.service, ref)
	if err != nil {
		return nil, err
	}
	return mn.Get(), nil
}

// Delete deletes network referenced by ref
func (handler *NetworkHandler) Delete(ctx context.Context, ref string) (err error) {
	defer utils.TimerWithLevel(fmt.Sprintf("lib.server.handlers.NetworkHandler::Delete(%s) called", ref), log.TraceLevel)()

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
					log.Errorf("failed to unbind primary gateway from VIP: %v", err)
				}
			}

			err = handler.service.DeleteGateway(network.GatewayID)
			// allow no gateway, but log it
			if err != nil {
				log.Errorf("Failed to delete primary gateway: %s", openstack.ProviderErrorToString(err))
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
					log.Errorf("failed to unbind secondary gateway from VIP: %v", err)
				}
			}

			err = handler.service.DeleteGateway(network.SecondaryGatewayID)
			// allow no gateway, but log it
			if err != nil {
				log.Errorf("Failed to delete secondary gateway: %s", openstack.ProviderErrorToString(err))
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
