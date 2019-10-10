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
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/NetworkState"
	"strings"

	"github.com/sirupsen/logrus"

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
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
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

	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be nil")
	}
	if failover && gwname != "" {
		return nil, scerr.InvalidParameterError("gwname", "cannot be set if failover is set")
	}

	tracer := concurrency.NewTracer(
		nil,
		fmt.Sprintf("('%s', '%s', %s, <sizing>, '%s', '%s', %v)", name, cidr, ipVersion.String(), theos, gwname, failover),
		true,
	).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Verify that the network doesn't exist first
	_, err = handler.service.GetNetworkByName(name)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound:
		case *scerr.ErrInvalidRequest, *scerr.ErrTimeout:
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
		return nil, fmt.Errorf("cannot create such a network, CIDR must be not routable; please choose an appropriate CIDR (RFC1918)")
	}

	// Create the network
	logrus.Debugf("Creating network '%s' ...", name)
	network, err = handler.service.CreateNetwork(resources.NetworkRequest{
		Name:      name,
		IPVersion: ipVersion,
		CIDR:      cidr,
	})
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound, *scerr.ErrInvalidRequest, *scerr.ErrTimeout:
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
					case *scerr.ErrNotFound:
						logrus.Errorf("failed to delete network, resource not found: %+v", derr)
					case *scerr.ErrTimeout:
						logrus.Errorf("failed to delete network, timeout: %+v", derr)
					default:
						logrus.Errorf("failed to delete network, other reason: %+v", derr)
					}
					err = scerr.AddConsequence(err, derr)
				}
			}
		}
	}()

	caps := handler.service.GetCapabilities()
	if failover && caps.PrivateVirtualIP {
		logrus.Infof("Provider support private Virtual IP, honoring the failover setup for gateways.")
	} else {
		logrus.Warningf("Provider doesn't support private Virtual IP, cannot set up high availability of network default route.")
		failover = false
	}

	// Creates VIP for gateways if asked for
	if failover {
		network.VIP, err = handler.service.CreateVIP(network.ID, fmt.Sprintf("for gateways of network %s", network.Name))
		if err != nil {
			switch err.(type) {
			case *scerr.ErrNotFound, *scerr.ErrTimeout:
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
						logrus.Errorf("failed to delete VIP: %+v", derr)
						err = scerr.AddConsequence(err, derr)
					}
				}
			}
		}()
	}

	logrus.Debugf("Saving network metadata '%s' ...", network.Name)
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
					logrus.Errorf("failed to delete network metadata: %+v", derr)
					err = scerr.AddConsequence(err, derr)
				}
			}
		}
	}()

	var template *resources.HostTemplate
	tpls, err := handler.service.SelectTemplatesBySize(sizing, false)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound, *scerr.ErrTimeout:
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
		logrus.Infof(msg)
	} else {
		return nil, fmt.Errorf("error creating network: no host template matching requirements for gateway")
	}
	img, err := handler.service.SearchImage(theos)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound, *scerr.ErrTimeout:
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
	primaryTask, err := concurrency.NewTaskWithContext(ctx)
	if err != nil {
		return nil, err
	}
	primaryTask, err = primaryTask.Start(handler.createGateway, data.Map{
		"request": primaryRequest,
		"sizing":  sizing,
	})
	if err != nil {
		return nil, err
	}

	// Starts secondary gateway creation if asked for
	if failover {
		secondaryRequest := gwRequest
		secondaryRequest.Name = secondaryGatewayName
		secondaryTask, err = concurrency.NewTaskWithContext(ctx)
		if err != nil {
			return nil, err
		}
		secondaryTask, err = secondaryTask.Start(handler.createGateway, data.Map{
			"request": secondaryRequest,
			"sizing":  sizing,
		})
		if err != nil {
			return nil, err
		}
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
					case *scerr.ErrTimeout:
						logrus.Warnf("We should wait") // FIXME Wait until gateway no longer exists
					default:
					}
					err = scerr.AddConsequence(err, derr)
				}
				dmerr := handler.deleteGatewayMetadata(primaryMetadata)
				if dmerr != nil {
					switch dmerr.(type) {
					case *scerr.ErrTimeout:
						logrus.Warnf("We should wait") // FIXME Wait until gateway no longer exists
					default:
					}
					err = scerr.AddConsequence(err, dmerr)
				}
				if failover {
					failErr := handler.unbindHostFromVIP(newNetwork.VIP, primaryGateway)
					err = scerr.AddConsequence(err, failErr)
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
						case *scerr.ErrTimeout:
							logrus.Warnf("We should wait") // FIXME Wait until gateway no longer exists
						default:
						}
						err = scerr.AddConsequence(err, derr)
					}
					dmerr := handler.deleteGatewayMetadata(secondaryMetadata)
					if dmerr != nil {
						switch dmerr.(type) {
						case *scerr.ErrTimeout:
							logrus.Warnf("We should wait") // FIXME Wait until gateway no longer exists
						default:
						}
						err = scerr.AddConsequence(err, dmerr)
					}
					failErr := handler.unbindHostFromVIP(newNetwork.VIP, secondaryGateway)
					err = scerr.AddConsequence(err, failErr)
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
	primaryTask, err = primaryTask.Reset()
	if err != nil {
		return nil, err
	}

	network.NetworkState = NetworkState.PHASE1
	logrus.Debugf("Updating network metadata '%s' ...", network.Name)
	mn, err = metadata.SaveNetwork(handler.service, network)
	if err != nil {
		return nil, err
	}

	primaryTask, err = primaryTask.Start(handler.waitForInstallPhase1OnGateway, primaryGateway)
	if err != nil {
		return nil, err
	}
	if failover && secondaryTask != nil {
		secondaryTask, err = secondaryTask.Reset()
		if err != nil {
			return nil, err
		}
		secondaryTask, err = secondaryTask.Start(handler.waitForInstallPhase1OnGateway, secondaryGateway)
		if err != nil {
			return nil, err
		}
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
	primaryTask, err = primaryTask.Reset()
	if err != nil {
		return nil, err
	}

	network.NetworkState = NetworkState.PHASE2
	logrus.Debugf("Updating network metadata '%s' ...", network.Name)
	mn, err = metadata.SaveNetwork(handler.service, network)
	if err != nil {
		return nil, err
	}

	// Check if hosts are still attached to network according to metadata
	primaryTask, err = primaryTask.Start(handler.installPhase2OnGateway, data.Map{
		"host":     primaryGateway,
		"userdata": primaryUserdata,
	})
	if err != nil {
		return nil, err
	}
	if failover && secondaryTask != nil {
		secondaryTask, err = secondaryTask.Reset()
		if err != nil {
			return nil, err
		}
		secondaryTask, err = secondaryTask.Start(handler.installPhase2OnGateway, data.Map{
			"host":     secondaryGateway,
			"userdata": secondaryUserdata,
		})
		if err != nil {
			return nil, err
		}
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
		logrus.Warnf("Network creation cancelled by user")
		return nil, fmt.Errorf("network creation cancelled by user")
	default:
	}

	network.NetworkState = NetworkState.READY
	logrus.Debugf("Updating network metadata '%s' ...", network.Name)
	mn, err = metadata.SaveNetwork(handler.service, network)
	if err != nil {
		return nil, err
	}

	return network, nil
}

func (handler *NetworkHandler) createGateway(t concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	var (
		inputs data.Map
		ok     bool
	)
	if inputs, ok = params.(data.Map); !ok {
		return nil, scerr.InvalidParameterError("params", "must be a data.Map")
	}
	// name := inputs["name"].(string)
	request := inputs["request"].(resources.GatewayRequest)
	sizing := inputs["sizing"].(resources.SizingRequirements)

	logrus.Infof("Requesting the creation of gateway '%s' using template '%s' with image '%s'", request.Name, request.TemplateID, request.ImageID)
	gw, userData, err := handler.service.CreateGateway(request)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound, *scerr.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	}

	// Starting from here, deletes the primary gateway if exiting with error
	defer func() {
		if err != nil {
			logrus.Warnf("Cleaning up on failure, deleting gateway '%s' host resource...", request.Name)
			derr := handler.service.DeleteHost(gw.ID)
			if derr != nil {
				msgRoot := "Cleaning up on failure, failed to delete gateway '%s'"
				switch derr.(type) {
				case *scerr.ErrNotFound:
					logrus.Errorf(msgRoot+", resource not found: %v", request.Name, derr)
				case *scerr.ErrTimeout:
					logrus.Errorf(msgRoot+", timeout: %v", request.Name, derr)
				default:
					logrus.Errorf(msgRoot+": %v", request.Name, derr)
				}
				err = scerr.AddConsequence(err, derr)
			} else {
				logrus.Infof("Cleaning up on failure, gateway '%s' deleted", request.Name)
			}
			err = scerr.AddConsequence(err, derr)
		}
	}()

	// Reloads the host to be sure all the properties are updated
	gw, err = handler.service.InspectHost(gw)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound, *scerr.ErrTimeout:
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
	logrus.Infof("Waiting until gateway '%s' is available by SSH ...", gw.Name)
	sshHandler := NewSSHHandler(handler.service)
	ct, _ := task.GetContext()
	ssh, err := sshHandler.GetConfig(ct, gw.ID)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("Provisioning gateway '%s', phase 1", gw.Name)
	_, err = ssh.WaitServerReady("phase1", temporal.GetHostCreationTimeout())
	if err != nil {
		if client.IsTimeoutError(err) {
			return nil, err
		}
		if client.IsProvisioningError(err) {
			return nil, fmt.Errorf("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH: [%+v]", gw.Name, err)
		}
		return nil, err
	}
	logrus.Infof("SSH service of gateway '%s' started.", gw.Name)

	return nil, nil
}

func (handler *NetworkHandler) installPhase2OnGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	var (
		gw       *resources.Host
		userData *userdata.Content
		ok       bool
	)
	if gw, ok = params.(data.Map)["host"].(*resources.Host); !ok {
		return nil, scerr.InvalidParameterError("params", "missing field 'host'")
	}
	if userData, ok = params.(data.Map)["userdata"].(*userdata.Content); !ok {
		return nil, scerr.InvalidParameterError("params", "missing field 'userdata'")
	}

	// Executes userdata phase2 script to finalize host installation
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("(%s)", gw.Name), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting configuration phase 2 on the gateway '%s'...", gw.Name),
		fmt.Sprintf("Ending configuration phase 2 on the gateway '%s'", gw.Name),
	)()

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

	ct, _ := task.GetContext()

	// logrus.Debugf("Configuring gateway '%s', phase 2", gw.Name)
	returnCode, _, _, err := sshHandler.Run(ct, gw.Name, command)
	if err != nil {
		retrieveForensicsData(ct, sshHandler, gw)

		return nil, err
	}
	if returnCode != 0 {
		retrieveForensicsData(ct, sshHandler, gw)

		warnings, errs := getPhaseWarningsAndErrors(ct, sshHandler, gw)

		return nil, fmt.Errorf("failed to finalize gateway '%s' installation: errorcode '%d', warnings '%s', errors '%s'", gw.Name, returnCode, warnings, errs)
	}
	logrus.Infof("Gateway '%s' successfully configured.", gw.Name)

	// Reboot gateway
	logrus.Debugf("Rebooting gateway '%s'", gw.Name)
	command = "sudo systemctl reboot"
	returnCode, _, _, err = sshHandler.Run(ct, gw.Name, command)
	if err != nil {
		return nil, err
	}
	if returnCode != 0 {
		logrus.Warnf("Unexpected problem rebooting...")
	}

	ssh, err := sshHandler.GetConfig(ct, gw.ID)
	if err != nil {
		return nil, err
	}

	sshDefaultTimeout := temporal.GetHostTimeout()
	_, err = ssh.WaitServerReady("ready", sshDefaultTimeout)
	if err != nil {
		if client.IsTimeoutError(err) {
			return nil, err
		}
		if client.IsProvisioningError(err) {
			logrus.Errorf("%+v", err)
			return nil, fmt.Errorf("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", gw.Name)
		}
		return nil, err
	}
	return nil, nil
}

func (handler *NetworkHandler) deleteGateway(gw *resources.Host) (err error) {
	logrus.Warnf("Cleaning up on failure, deleting gateway '%s'...", gw.Name)
	err = handler.service.DeleteHost(gw.ID)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound:
			logrus.Errorf("Cleaning up on failure, failed to delete gateway '%s', resource not found: %v", gw.Name, err)
		case *scerr.ErrTimeout:
			logrus.Errorf("Cleaning up on failure, failed to delete gateway '%s', timeout: %v", gw.Name, err)
		default:
			logrus.Errorf("Cleaning up on failure, failed to delete gateway '%s': %v", gw.Name, err)
		}
	}
	logrus.Infof("Cleaning up on failure, gateway '%s' deleted", gw.Name)
	return err
}

func (handler *NetworkHandler) deleteGatewayMetadata(m *metadata.Gateway) (err error) {
	mm, err := m.Get()
	if err != nil {
		return err
	}
	name := mm.Name
	logrus.Warnf("Cleaning up on failure, deleting gateway '%s' metadata", name)
	derr := m.Delete()
	if derr != nil {
		logrus.Errorf("Cleaning up on failure, failed to delete gateway '%s' metadata: %+v", name, derr)
	}
	return derr
}

func (handler *NetworkHandler) unbindHostFromVIP(vip *resources.VIP, host *resources.Host) (err error) {
	err = handler.service.UnbindHostFromVIP(vip, host)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound, *scerr.ErrTimeout:
			logrus.Debugf("Cleaning up on failure, failed to remove gateway bind from VIP: %v", err)
		default:
			logrus.Debugf("Cleaning up on failure, failed to remove gateway bind from VIP: %v", err)
		}
	} else {
		logrus.Infof("Cleaning up on failure, host '%s' bind removed from VIP", host.Name)
	}
	return err
}

// List returns the network list
func (handler *NetworkHandler) List(ctx context.Context, all bool) (netList []*resources.Network, err error) {
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("(%v)", all), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if all {
		return handler.service.ListNetworks()
	}

	mn, err := metadata.NewNetwork(handler.service)
	if err != nil {
		return nil, err
	}
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
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mn, err := metadata.LoadNetwork(handler.service, ref)
	if err != nil {
		return nil, err
	}

	return mn.Get()
}

// Delete deletes network referenced by ref
func (handler *NetworkHandler) Delete(ctx context.Context, ref string) (err error) {
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mn, err := metadata.LoadNetwork(handler.service, ref)
	if err != nil {
		if _, ok := err.(*scerr.ErrNotFound); !ok {
			cleanErr := handler.service.DeleteNetwork(ref)
			if cleanErr != nil {
				switch cleanErr.(type) {
				case *scerr.ErrNotFound, *scerr.ErrTimeout:
					logrus.Warnf("error deleting network on cleanup after failure to load metadata '%s': %v", ref, cleanErr)
				default:
					logrus.Warnf("error deleting network on cleanup after failure to load metadata '%s': %v", ref, cleanErr)
				}
			}
			err = scerr.AddConsequence(err, cleanErr)
		}
		return err
	}
	network, err := mn.Get()
	if err != nil {
		return err
	}

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
			errorMsg = fmt.Sprintf("cannot delete network '%s': %d host%s %s still attached to it: %s",
				network.Name, hostsLen, utils.Plural(hostsLen), verb, strings.Join(list, ", "))
			return resources.ResourceNotAvailableError("network", network.Name)
		}
		return nil
	})
	if err != nil {
		if _, ok := err.(*scerr.ErrNotAvailable); ok {
			return fmt.Errorf(errorMsg)
		}
		return err
	}

	// Delete gateway(s)
	if network.GatewayID != "" {
		mh, err := metadata.LoadHost(handler.service, network.GatewayID)
		if err != nil {
			logrus.Error(err)
		} else {
			if network.VIP != nil {
				mhm, merr := mh.Get()
				if merr != nil {
					return merr
				}
				err = handler.service.UnbindHostFromVIP(network.VIP, mhm)
				if err != nil {
					logrus.Errorf("failed to unbind primary gateway from VIP: %v", err)
				}
			}

			err = handler.service.DeleteGateway(network.GatewayID) // allow no gateway, but log it
			if err != nil {
				switch err.(type) {
				case *scerr.ErrNotFound:
					logrus.Errorf("failed to delete primary gateway, resource not found: %s", openstack.ProviderErrorToString(err))
				case *scerr.ErrTimeout:
					logrus.Errorf("failed to delete primary gateway, timeout: %s", openstack.ProviderErrorToString(err))
				default:
					logrus.Errorf("failed to delete primary gateway: %s", openstack.ProviderErrorToString(err))
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
			logrus.Error(err)
		} else {
			if network.VIP != nil {
				mhm, merr := mh.Get()
				if merr != nil {
					return merr
				}

				err = handler.service.UnbindHostFromVIP(network.VIP, mhm)
				if err != nil {
					logrus.Errorf("failed to unbind secondary gateway from VIP: %v", err)
				}
			}

			err = handler.service.DeleteGateway(network.SecondaryGatewayID) // allow no gateway, but log it
			if err != nil {
				switch err.(type) {
				case *scerr.ErrNotFound:
					logrus.Errorf("failed to delete secondary gateway, resource not found: %s", openstack.ProviderErrorToString(err))
				case *scerr.ErrTimeout:
					logrus.Errorf("failed to delete secondary gateway, timeout: %s", openstack.ProviderErrorToString(err))
				default:
					logrus.Errorf("failed to delete secondary gateway: %s", openstack.ProviderErrorToString(err))
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
			logrus.Errorf("failed to delete VIP: %v", err)
		}
	}

	defer func() {
		if err != nil {
			// Delete metadata if there
			mnm, nerr := mn.Get()
			if nerr != nil {
				err = scerr.AddConsequence(err, nerr)
			}
			if nerr == nil {
				if mnm != nil {
					derr := mn.Delete()
					if derr != nil {
						err = scerr.AddConsequence(err, derr)
					}
				}
			}
		}
	}()

	waitMore := false
	// delete network, with tolerance
	err = handler.service.DeleteNetwork(network.ID)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound:
			// If network doesn't exist anymore on the provider infrastructure, don't fail to cleanup the metadata
			logrus.Warnf("network not found on provider side, cleaning up metadata.")
			return err
		case *scerr.ErrTimeout:
			logrus.Error("cannot delete network due to a timeout")
			waitMore = true
		default:
			logrus.Error("cannot delete network, other reason")
		}
	}
	if waitMore {
		errWaitMore := retry.WhileUnsuccessfulDelay1Second(func() error {
			recNet, recErr := handler.service.GetNetwork(network.ID)
			if recNet != nil {
				return fmt.Errorf("still there")
			}
			if _, ok := recErr.(*scerr.ErrNotFound); ok {
				return nil
			}
			return fmt.Errorf("another kind of error")
		}, temporal.GetContextTimeout())
		if errWaitMore != nil {
			err = scerr.AddConsequence(err, errWaitMore)
		}
	}

	if err != nil {
		return err
	}

	// Delete network metadata if there
	mnm, err := mn.Get()
	if err != nil {
		return err
	}

	if mnm != nil {
		err = mn.Delete()
		if err != nil {
			return err
		}
	}

	// select {
	// case <-ctx.Done():
	// 	logrus.Warnf("Network delete cancelled by user")
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
