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
	"github.com/CS-SI/SafeScale/lib/utils/retry"
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
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.NetworkHandler::Create() called"), &err, log.TraceLevel)()

	if gwname != "" && failover {
		return nil, fmt.Errorf("can't name gateway when failover is requested")
	}

	// Verify that the network doesn't exist first
	_, err = handler.service.GetNetworkByName(name)
	if err != nil {
		switch err.(type) {
		case utils.ErrNotFound:
		case utils.ErrInvalidRequest, utils.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("network '%s' already exists", name)
	}

	// Verify the CIDR is not routable
	routable, err := utils.IsCIDRRoutable(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to determine if CIDR is not routable: %v", err)
	}
	if routable {
		return nil, fmt.Errorf("can't create such a network, CIDR must be not routable; please choose an appropriate CIDR (RFC1918)")
	}

	// Create the network
	log.Debugf("Creating network '%s' ...", name)
	network, err = handler.service.CreateNetwork(resources.NetworkRequest{
		Name:      name,
		IPVersion: ipVersion,
		CIDR:      cidr,
	})
	if err != nil {
		switch err.(type) {
		case utils.ErrNotFound, utils.ErrInvalidRequest, utils.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	}

	newNetwork := network
	// Starting from here, delete network if exiting with error
	defer func() {
		if err != nil {
			if newNetwork != nil {
				derr := handler.service.DeleteNetwork(newNetwork.ID)
				if derr != nil {
					switch derr.(type) {
					case utils.ErrNotFound:
						log.Errorf("Failed to delete network, resource not found: %+v", derr)
					case utils.ErrTimeout:
						log.Errorf("Failed to delete network, timeout: %+v", derr)
					default:
						log.Errorf("Failed to delete network, other reason: %+v", derr)
					}
					err = retry.AddConsequence(err, derr)
				}
			}
		}
	}()

	// Creates VIP for gateways if asked for
	if failover {
		network.VIP, err = handler.service.CreateVIP(network.ID, fmt.Sprintf("for gateways of network %s", network.Name))
		if err != nil {
			switch err.(type) {
			case utils.ErrNotFound, utils.ErrTimeout:
				return nil, err
			default:
				return nil, err
			}
		}

		// Starting from here, delete VIP if exists with error
		defer func() {
			if err != nil {
				if newNetwork != nil {
					derr := handler.service.DeleteVIP(newNetwork.VIP)
					if derr != nil {
						log.Errorf("Failed to delete VIP: %+v", derr)
						err = retry.AddConsequence(err, derr)
					}
				}
			}
		}()
	}

	log.Debugf("Saving network metadata '%s' ...", network.Name)
	mn, err := metadata.SaveNetwork(handler.service, network)
	if err != nil {
		return nil, err
	}

	// Starting from here, delete network metadata if exits with error
	defer func() {
		if err != nil {
			if mn != nil {
				derr := mn.Delete()
				if derr != nil {
					log.Errorf("Failed to delete network metadata: %+v", derr)
					err = retry.AddConsequence(err, derr)
				}
			}
		}
	}()

	var template *resources.HostTemplate
	tpls, err := handler.service.SelectTemplatesBySize(sizing, false)
	if err != nil {
		switch err.(type) {
		case utils.ErrNotFound, utils.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
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
		return nil, fmt.Errorf("error creating network: no host template matching requirements for gateway")
	}
	img, err := handler.service.SearchImage(theos)
	if err != nil {
		switch err.(type) {
		case utils.ErrNotFound, utils.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
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
		return nil, err
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
				derr := handler.deleteGateway(primaryGateway)
				if derr != nil {
					switch derr.(type) {
					case utils.ErrTimeout:
						log.Warnf("We should wait") // FIXME Wait until gateway no longer exists
					default:
					}
					err = retry.AddConsequence(err, derr)
				}
				dmerr := handler.deleteGatewayMetadata(primaryMetadata)
				if dmerr != nil {
					switch dmerr.(type) {
					case utils.ErrTimeout:
						log.Warnf("We should wait") // FIXME Wait until gateway no longer exists
					default:
					}
					err = retry.AddConsequence(err, dmerr)
				}
				if failover {
					failErr := handler.unbindHostFromVIP(newNetwork.VIP, primaryGateway)
					err = retry.AddConsequence(err, failErr)
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
					derr := handler.deleteGateway(secondaryGateway)
					if derr != nil {
						switch derr.(type) {
						case utils.ErrTimeout:
							log.Warnf("We should wait") // FIXME Wait until gateway no longer exists
						default:
						}
						err = retry.AddConsequence(err, derr)
					}
					dmerr := handler.deleteGatewayMetadata(secondaryMetadata)
					if dmerr != nil {
						switch dmerr.(type) {
						case utils.ErrTimeout:
							log.Warnf("We should wait") // FIXME Wait until gateway no longer exists
						default:
						}
						err = retry.AddConsequence(err, dmerr)
					}
					failErr := handler.unbindHostFromVIP(newNetwork.VIP, secondaryGateway)
					err = retry.AddConsequence(err, failErr)
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
		return nil, err
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
		return nil, fmt.Errorf("error creating network: primaryUserdata is nil")
	}

	// Complement userdata for gateway(s) with allocated IP
	primaryUserdata.PrimaryGatewayPrivateIP = primaryGateway.GetPrivateIP()
	primaryUserdata.PrimaryGatewayPublicIP = primaryGateway.GetPublicIP()
	if failover {
		primaryUserdata.SecondaryGatewayPrivateIP = secondaryGateway.GetPrivateIP()
		primaryUserdata.SecondaryGatewayPublicIP = secondaryGateway.GetPublicIP()

		if secondaryUserdata == nil {
			return nil, fmt.Errorf("error creating network: secondaryUserdata is nil")
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
		switch err.(type) {
		case utils.ErrNotFound, utils.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	}

	// Starting from here, deletes the primary gateway if exiting with error
	defer func() {
		if err != nil {
			log.Warnf("Cleaning up on failure, deleting gateway '%s' host resource...", request.Name)
			derr := handler.service.DeleteHost(gw.ID)
			if derr != nil {
				switch derr.(type) {
				case utils.ErrNotFound:
					log.Errorf("Cleaning up on failure, failed to delete gateway '%s', resource not found: %v", request.Name, derr)
				case utils.ErrTimeout:
					log.Errorf("Cleaning up on failure, failed to delete gateway '%s', timeout: %v", request.Name, derr)
				default:
					log.Errorf("Cleaning up on failure, failed to delete gateway '%s': %v", request.Name, derr)
				}
				err = retry.AddConsequence(err, derr)
			} else {
				log.Infof("Cleaning up on failure, gateway '%s' deleted", request.Name)
			}
			err = retry.AddConsequence(err, derr)
		}
	}()

	// Reloads the host to be sure all the properties are updated
	gw, err = handler.service.InspectHost(gw)
	if err != nil {
		switch err.(type) {
		case utils.ErrNotFound, utils.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	}

	// Binds gateway to VIP
	if request.Network.VIP != nil {
		err = handler.service.BindHostToVIP(request.Network.VIP, gw)
		if err != nil {
			return nil, err
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
		return nil, err
	}

	// Writes Gateway metadata
	m, err := metadata.SaveGateway(handler.service, gw, request.Network.ID)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	log.Debugf("Provisioning gateway '%s', phase 1", gw.Name)
	_, err = ssh.WaitServerReady("phase1", utils.GetHostCreationTimeout())
	if err != nil {
		if client.IsTimeoutError(err) {
			return nil, err
		}
		if client.IsProvisioningError(err) {
			return nil, fmt.Errorf("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH: [%+v]", gw.Name, err)
		}
		return nil, err
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
	defer utils.TimerErrWithLevel(fmt.Sprintf("Starting configuration of the gateway '%s'", gw.Name), &err, log.InfoLevel)()
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
	returnCode, _, _, err := sshHandler.Run(task.GetContext(), gw.Name, command)
	if err != nil {
		retrieveForensicsData(task.GetContext(), sshHandler, gw)

		return nil, err
	}
	if returnCode != 0 {
		retrieveForensicsData(task.GetContext(), sshHandler, gw)

		warnings, errs := getPhaseWarningsAndErrors(task.GetContext(), sshHandler, gw)

		return nil, fmt.Errorf("failed to finalize gateway '%s' installation: errorcode '%d', warnings '%s', errors '%s'", gw.Name, returnCode, warnings, errs)
	}
	log.Infof("Gateway '%s' successfully configured.", gw.Name)

	// Reboot gateway
	log.Debugf("Rebooting gateway '%s'", gw.Name)
	command = "sudo systemctl reboot"
	returnCode, _, _, err = sshHandler.Run(task.GetContext(), gw.Name, command)
	if err != nil {
		return nil, err
	}
	if returnCode != 0 {
		log.Warnf("Unexpected problem rebooting...")
	}

	ssh, err := sshHandler.GetConfig(task.GetContext(), gw.ID)
	if err != nil {
		return nil, err
	}

	sshDefaultTimeout := utils.GetHostTimeout()
	_, err = ssh.WaitServerReady("ready", sshDefaultTimeout)
	if err != nil {
		if client.IsTimeoutError(err) {
			return nil, err
		}
		if client.IsProvisioningError(err) {
			log.Errorf("%+v", err)
			return nil, fmt.Errorf("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", gw.Name)
		}
		return nil, err
	}
	return nil, nil
}

func (handler *NetworkHandler) deleteGateway(gw *resources.Host) (err error) {
	log.Warnf("Cleaning up on failure, deleting gateway '%s'...", gw.Name)
	err = handler.service.DeleteHost(gw.ID)
	if err != nil {
		switch err.(type) {
		case utils.ErrNotFound:
			log.Errorf("Cleaning up on failure, failed to delete gateway '%s', resource not found: %v", gw.Name, err)
		case utils.ErrTimeout:
			log.Errorf("Cleaning up on failure, failed to delete gateway '%s', timeout: %v", gw.Name, err)
		default:
			log.Errorf("Cleaning up on failure, failed to delete gateway '%s': %v", gw.Name, err)
		}
	}
	log.Infof("Cleaning up on failure, gateway '%s' deleted", gw.Name)
	return err
}

func (handler *NetworkHandler) deleteGatewayMetadata(m *metadata.Gateway) (err error) {
	name := m.Get().Name
	log.Warnf("Cleaning up on failure, deleting gateway '%s' metadata", name)
	derr := m.Delete()
	if derr != nil {
		log.Errorf("Cleaning up on failure, failed to delete gateway '%s' metadata: %+v", name, derr)
	}
	return derr
}

func (handler *NetworkHandler) unbindHostFromVIP(vip *resources.VIP, host *resources.Host) (err error) {
	err = handler.service.UnbindHostFromVIP(vip, host)
	if err != nil {
		switch err.(type) {
		case utils.ErrNotFound, utils.ErrTimeout:
			log.Debugf("Cleaning up on failure, failed to remove gateway bind from VIP: %v", err)
		default:
			log.Debugf("Cleaning up on failure, failed to remove gateway bind from VIP: %v", err)
		}
	} else {
		log.Infof("Cleaning up on failure, host '%s' bind removed from VIP", host.Name)
	}
	return err
}

// List returns the network list
func (handler *NetworkHandler) List(ctx context.Context, all bool) (netList []*resources.Network, err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.NetworkHandler::List(%v) called", all), &err, log.TraceLevel)()

	if all {
		return handler.service.ListNetworks()
	}

	mn := metadata.NewNetwork(handler.service)
	err = mn.Browse(func(network *resources.Network) error {
		netList = append(netList, network)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return netList, err
}

// Inspect returns the network identified by ref, ref can be the name or the id
func (handler *NetworkHandler) Inspect(ctx context.Context, ref string) (network *resources.Network, err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.NetworkHandler::Inspect(%s) called", ref), &err, log.TraceLevel)()

	mn, err := metadata.LoadNetwork(handler.service, ref)
	if err != nil {
		return nil, err
	}
	return mn.Get(), nil
}

// Delete deletes network referenced by ref
func (handler *NetworkHandler) Delete(ctx context.Context, ref string) (err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.NetworkHandler::Delete(%s) called", ref), &err, log.TraceLevel)()

	mn, err := metadata.LoadNetwork(handler.service, ref)
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); !ok {
			cleanErr := handler.service.DeleteNetwork(ref)
			if cleanErr != nil {
				switch cleanErr.(type) {
				case utils.ErrNotFound, utils.ErrTimeout:
					log.Warnf("error deleting network on cleanup after failure to load metadata '%s': %v", ref, cleanErr)
				default:
					log.Warnf("error deleting network on cleanup after failure to load metadata '%s': %v", ref, cleanErr)
				}
			}
			err = retry.AddConsequence(err, cleanErr)
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
		if _, ok := err.(utils.ErrNotAvailable); ok {
			return fmt.Errorf(errorMsg)
		}
		return err
	}

	// Delete gateway(s)
	if network.GatewayID != "" {
		mh, err := metadata.LoadHost(handler.service, network.GatewayID)
		if err != nil {
			log.Error(err)
		} else {
			if network.VIP != nil {
				err = handler.service.UnbindHostFromVIP(network.VIP, mh.Get())
				if err != nil {
					log.Errorf("failed to unbind primary gateway from VIP: %v", err)
				}
			}

			err = handler.service.DeleteGateway(network.GatewayID) // allow no gateway, but log it
			if err != nil {
				switch err.(type) {
				case utils.ErrNotFound:
					log.Errorf("Failed to delete primary gateway, resource not found: %s", openstack.ProviderErrorToString(err))
				case utils.ErrTimeout:
					log.Errorf("Failed to delete primary gateway, timeout: %s", openstack.ProviderErrorToString(err))
				default:
					log.Errorf("Failed to delete primary gateway: %s", openstack.ProviderErrorToString(err))
				}
			}

			err = mh.Delete()
			if err != nil {
				return err
			}
		}
	}
	if network.SecondaryGatewayID != "" {
		mh, err := metadata.LoadHost(handler.service, network.SecondaryGatewayID)
		if err != nil {
			log.Error(err)
		} else {
			if network.VIP != nil {
				err = handler.service.UnbindHostFromVIP(network.VIP, mh.Get())
				if err != nil {
					log.Errorf("failed to unbind secondary gateway from VIP: %v", err)
				}
			}

			err = handler.service.DeleteGateway(network.SecondaryGatewayID) // allow no gateway, but log it
			if err != nil {
				switch err.(type) {
				case utils.ErrNotFound:
					log.Errorf("failed to delete secondary gateway, resource not found: %s", openstack.ProviderErrorToString(err))
				case utils.ErrTimeout:
					log.Errorf("failed to delete secondary gateway, timeout: %s", openstack.ProviderErrorToString(err))
				default:
					log.Errorf("failed to delete secondary gateway: %s", openstack.ProviderErrorToString(err))
				}
			}

			err = mh.Delete()
			if err != nil {
				return err
			}
		}
	}

	// Delete VIP if needed
	if network.VIP != nil {
		err = handler.service.DeleteVIP(network.VIP)
		if err != nil {
			log.Errorf("failed to delete VIP: %v", err)
		}
	}

	defer func() {
		if err != nil {
			// Delete metadata if there
			if mn.Get() != nil {
				derr := mn.Delete()
				if derr != nil {
					err = retry.AddConsequence(err, derr)
				}
			}
		}
	}()

	waitMore := false
	// delete network, with tolerance
	err = handler.service.DeleteNetwork(network.ID)
	if err != nil {
		switch err.(type) {
		case utils.ErrNotFound:
			// If network doesn't exist anymore on the provider infrastructure, don't fail to cleanup the metadata
			log.Warnf("network not found on provider side, cleaning up metadata.")
			return err
		case utils.ErrTimeout:
			log.Error("can't delete network due to a timeout")
			waitMore = true
		default:
			log.Error("can't delete network, other reason")
		}
	}
	if waitMore {
		errWaitMore := retry.WhileUnsuccessfulDelay1Second(func() error {
			recNet, recErr := handler.service.GetNetwork(network.ID)
			if recNet != nil {
				return fmt.Errorf("still there")
			}
			if _, ok := recErr.(utils.ErrNotFound); ok {
				return nil
			}
			return fmt.Errorf("another kind of error")
		}, utils.GetContextTimeout())
		if errWaitMore != nil {
			err = retry.AddConsequence(err, errWaitMore)
		}
	}

	if err != nil {
		return err
	}

	// Delete network metadata if there
	if mn.Get() != nil {
		err = mn.Delete()
		if err != nil {
			return err
		}
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
	// 		return fmt.Errorf("failed to get gateway sizingV1")
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
	// 		return fmt.Errorf("failed to stop network deletion")
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
