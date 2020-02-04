/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"fmt"
	"strings"

	// "github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/NetworkState"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/networkstate"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/lib/server/install"
	"github.com/CS-SI/SafeScale/lib/server/metadata"
	safescaleutils "github.com/CS-SI/SafeScale/lib/server/utils"
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
	Create(string, string, IPVersion.Enum, resources.SizingRequirements, string, string, bool) (*resources.Network, error)
	List(bool) ([]*resources.Network, error)
	Inspect(string) (*resources.Network, error)
	Delete(string) error
}

// FIXME ROBUSTNESS All functions MUST propagate context
// FIXME Technical debt Input verification

// NetworkHandler an implementation of NetworkAPI
type NetworkHandler struct {
	job       server.Job
	ipVersion IPVersion.Enum
}

// NewNetworkHandler Creates new Network service
func NewNetworkHandler(job server.Job) NetworkAPI {
	return &NetworkHandler{job: job}
}

// Create creates a network
func (handler *NetworkHandler) Create(
	name string, cidr string, ipVersion IPVersion.Enum,
	sizing resources.SizingRequirements, theos string, gwname string,
	failover bool,
) (network *resources.Network, err error) {

	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "canot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}
	if failover && gwname != "" {
		return nil, scerr.InvalidParameterError("gwname", "cannot be set if failover is set")
	}

	tracer := concurrency.NewTracer(
		handler.job.Task(),
		fmt.Sprintf("('%s', '%s', %s, <sizing>, '%s', '%s', %v)", name, cidr, ipVersion.String(), theos, gwname, failover),
		true,
	).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Verify that the network doesn't exist first
	_, err = handler.job.Service().GetNetworkByName(name)
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
		return nil, scerr.NewError("failed to determine if CIDR is not routable", err, nil)
	}
	if routable {
		return nil, scerr.NewError("cannot create such a network, CIDR must be not routable; please choose an appropriate CIDR (RFC1918)", nil, nil)
	}

	if handler.job.Aborted() {
		return nil, scerr.AbortedError("aborted", nil)
	}

	// Create the network
	logrus.Debugf("Creating network '%s' ...", name)
	network, err = handler.job.Service().CreateNetwork(resources.NetworkRequest{
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

	// Starting from here, delete network if exiting with error
	defer func() {
		if err != nil && network != nil {
			prefix := "cleaning up on "
			if _, ok := err.(*scerr.ErrAborted); ok {
				prefix += "abort, "
			} else {
				prefix += "failure, "
			}
			derr := handler.job.Service().DeleteNetwork(network.ID)
			if derr != nil {
				logrus.Errorf(prefix+"failed to delete network: %+v", derr)
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	if handler.job.Aborted() {
		return nil, scerr.AbortedError("aborted", nil)
	}

	caps := handler.job.Service().GetCapabilities()
	if failover && caps.PrivateVirtualIP {
		logrus.Infof("Provider support private Virtual IP, honoring the failover setup for gateways.")
	} else {
		logrus.Warningf("Provider doesn't support private Virtual IP, cannot set up high availability of network default route.")
		failover = false
	}

	// Creates VIP for gateways if asked for
	if failover {
		network.VIP, err = handler.job.Service().CreateVIP(network.ID, fmt.Sprintf("for gateways of network %s", network.Name))
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
			if err != nil && network != nil {
				prefix := "cleaning up on "
				if _, ok := err.(*scerr.ErrAborted); ok {
					prefix += "abort, "
				} else {
					prefix += "failure, "
				}
				derr := handler.job.Service().DeleteVIP(network.VIP)
				if derr != nil {
					logrus.Errorf(prefix+"failed to delete VIP: %+v", derr)
					err = scerr.AddConsequence(err, derr)
				}
			}
		}()
	}

	if handler.job.Aborted() {
		return nil, scerr.AbortedError("aborted", nil)
	}

	logrus.Debugf("Saving network metadata '%s' ...", network.Name)
	mn, err := metadata.SaveNetwork(handler.job.Service(), network)
	if err != nil {
		return nil, err
	}

	// Starting from here, delete network metadata if exits with error
	defer func() {
		if err != nil && network != nil {
			err = metadata.RemoveNetwork(handler.job.Service(), network)
		}
	}()

	if handler.job.Aborted() {
		return nil, scerr.AbortedError("aborted", nil)
	}

	var template *resources.HostTemplate
	tpls, err := handler.job.Service().SelectTemplatesBySize(sizing, false)
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
		msg := fmt.Sprintf("Selected host template: '%s' (%d core%s", template.Name, template.Cores, utils.Plural(uint(template.Cores)))
		if template.CPUFreq > 0 {
			msg += fmt.Sprintf(" at %.01f GHz", template.CPUFreq)
		}
		msg += fmt.Sprintf(", %.01f GB RAM, %d GB disk", template.RAMSize, template.DiskSize)
		if template.GPUNumber > 0 {
			msg += fmt.Sprintf(", %d GPU%s", template.GPUNumber, utils.Plural(uint(template.GPUNumber)))
			if template.GPUType != "" {
				msg += fmt.Sprintf(" %s", template.GPUType)
			}
		}
		msg += ")"
		logrus.Infof(msg)
	} else {
		return nil, fmt.Errorf("error creating network: no host template matching requirements for gateway")
	}

	if handler.job.Aborted() {
		return nil, scerr.AbortedError("aborted", nil)
	}

	img, err := handler.job.Service().SearchImage(theos)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound, *scerr.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	}

	if handler.job.Aborted() {
		return nil, scerr.AbortedError("aborted", nil)
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
	keypair, err := handler.job.Service().CreateKeyPair(keypairName)
	if err != nil {
		return nil, err
	}

	if handler.job.Aborted() {
		return nil, scerr.AbortedError("aborted", nil)
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
	primaryTask, err := concurrency.NewTaskWithParent(handler.job.Task())
	if err != nil {
		return nil, err
	}
	defer primaryTask.Close()
	primaryTask, err = primaryTask.Start(handler.taskCreateGateway, data.Map{
		"request": primaryRequest,
		"sizing":  sizing,
		"primary": true,
	})
	if err != nil {
		return nil, err
	}

	// Starts secondary gateway creation if asked for
	if failover {
		secondaryRequest := gwRequest
		secondaryRequest.Name = secondaryGatewayName
		secondaryTask, err = concurrency.NewTaskWithParent(handler.job.Task())
		if err != nil {
			return nil, err
		}
		defer secondaryTask.Close()

		secondaryTask, err = secondaryTask.Start(handler.taskCreateGateway, data.Map{
			"request": secondaryRequest,
			"sizing":  sizing,
			"primary": false,
		})
		if err != nil {
			return nil, err
		}
	}

	primaryResult, primaryErr := primaryTask.Wait()
	if primaryErr == nil {
		if _, ok := primaryResult.(data.Map); !ok {
			return nil, scerr.InvalidParameterError("primaryResult", "must be a data.Map")
		}

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
					failErr := handler.unbindHostFromVIP(network.VIP, primaryGateway)
					err = scerr.AddConsequence(err, failErr)
				}
			}
		}()
	}

	if handler.job.Aborted() {
		return nil, scerr.AbortedError("aborted", nil)
	}

	if failover && secondaryTask != nil {
		secondaryResult, secondaryErr = secondaryTask.Wait()
		if secondaryErr == nil {
			if _, ok := secondaryResult.(data.Map); !ok {
				return nil, scerr.InvalidParameterError("secondaryResult", "must be a data.Map")
			}

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
					failErr := handler.unbindHostFromVIP(network.VIP, secondaryGateway)
					err = scerr.AddConsequence(err, failErr)
				}
			}()
		}
	}

	if handler.job.Aborted() {
		return nil, scerr.AbortedError("aborted", nil)
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
	primaryTask, err = concurrency.NewTaskWithParent(handler.job.Task())
	if err != nil {
		return nil, err
	}
	defer primaryTask.Close()

	network.NetworkState = networkstate.PHASE1
	logrus.Debugf("Updating network metadata '%s' ...", network.Name)
	mn, err = metadata.SaveNetwork(handler.job.Service(), network)
	if err != nil {
		return nil, err
	}

	if handler.job.Aborted() {
		return nil, scerr.AbortedError("aborted", nil)
	}

	primaryTask, err = primaryTask.Start(handler.waitForInstallPhase1OnGateway, primaryGateway)
	if err != nil {
		return nil, err
	}
	if failover && secondaryTask != nil {
		secondaryTask, err = concurrency.NewTaskWithParent(handler.job.Task())
		if err != nil {
			return nil, err
		}
		defer secondaryTask.Close()
		_, err = secondaryTask.Start(handler.waitForInstallPhase1OnGateway, secondaryGateway)
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
	primaryTask, err = concurrency.NewTaskWithParent(handler.job.Task())
	if err != nil {
		return nil, err
	}
	defer primaryTask.Close()

	network.NetworkState = networkstate.PHASE2
	logrus.Debugf("Updating network metadata '%s' ...", network.Name)
	mn, err = metadata.SaveNetwork(handler.job.Service(), network)
	if err != nil {
		return nil, err
	}

	if handler.job.Aborted() {
		return nil, scerr.AbortedError("aborted", nil)
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
		secondaryTask, err = concurrency.NewTaskWithParent(handler.job.Task())
		if err != nil {
			return nil, err
		}
		defer secondaryTask.Close()
		_, err = secondaryTask.Start(handler.installPhase2OnGateway, data.Map{
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

	if handler.job.Aborted() {
		return nil, scerr.AbortedError("aborted", nil)
	}

	network.NetworkState = networkstate.READY
	logrus.Debugf("Updating network metadata '%s' ...", network.Name)
	mn, err = metadata.SaveNetwork(handler.job.Service(), network)
	if err != nil {
		return nil, err
	}

	return network, nil
}

func (handler *NetworkHandler) taskCreateGateway(t concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	defer scerr.OnPanic(&err)()

	var (
		inputs data.Map
		ok     bool
	)
	if inputs, ok = params.(data.Map); !ok {
		return nil, scerr.InvalidParameterError("params", "must be a data.Map")
	}

	// name := inputs["name"].(string)
	request, ok := inputs["request"].(resources.GatewayRequest)
	if !ok {
		return nil, scerr.InvalidParameterError("request", "must be a resources.GatewayRequest")
	}
	sizing, ok := inputs["sizing"].(resources.SizingRequirements)
	if !ok {
		return nil, scerr.InvalidParameterError("sizing", "must be a resources.SizingRequirements")
	}
	primary, ok := inputs["primary"].(bool)
	if !ok {
		return nil, scerr.InvalidParameterError("primary", "must be a bool")
	}

	logrus.Infof("Requesting the creation of gateway '%s' using template '%s' with image '%s'", request.Name, request.TemplateID, request.ImageID)
	gw, userData, err := handler.job.Service().CreateGateway(request)
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
			prefix := "cleaning up on "
			if _, ok := err.(*scerr.ErrAborted); ok {
				prefix += "abort, "
			} else {
				prefix += "failure, "
			}
			logrus.Infof(prefix+" deleting gateway '%s' host resource...", request.Name)
			derr := handler.job.Service().DeleteHost(gw.ID)
			if derr != nil {
				msgRoot := prefix + "failed to delete gateway '%s'"
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
				logrus.Infof(prefix+"gateway '%s' deleted", request.Name)
			}
			err = scerr.AddConsequence(err, derr)
		}
	}()

	if handler.job.Aborted() {
		return nil, scerr.AbortedError("aborted", nil)
	}

	// Reloads the host to be sure all the properties are updated
	gw, err = handler.job.Service().InspectHost(gw)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound, *scerr.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	}

	if handler.job.Aborted() {
		return nil, scerr.AbortedError("aborted", nil)
	}

	// Binds gateway to VIP
	if request.Network.VIP != nil {
		err = handler.job.Service().BindHostToVIP(request.Network.VIP, gw)
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
	userData.IsPrimaryGateway = primary

	// Updates requested sizing in gateway property propsv1.HostSizing
	err = gw.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(func(v interface{}) error {
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
	m, err := metadata.SaveGateway(handler.job.Service(), gw, request.Network.ID)
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
	sshHandler := NewSSHHandler(handler.job)
	ssh, err := sshHandler.GetConfig(gw.ID)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("Provisioning gateway '%s', phase 1", gw.Name)

	_, err = ssh.WaitServerReady(handler.job.Task(), "phase1", temporal.GetHostCreationTimeout())
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
	tracer := concurrency.NewTracer(handler.job.Task(), fmt.Sprintf("(%s)", gw.Name), true).WithStopwatch().GoingIn()
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
	err = install.UploadStringToRemoteFile(string(content), safescaleutils.ToPBHost(gw), utils.TempFolder+"/user_data.phase2.sh", "", "", "")
	if err != nil {
		return nil, err
	}

	if handler.job.Aborted() {
		return nil, scerr.AbortedError("aborted", nil)
	}

	command := fmt.Sprintf("sudo bash %s/%s; exit $?", utils.TempFolder, "user_data.phase2.sh")
	sshHandler := NewSSHHandler(handler.job)

	// logrus.Debugf("Configuring gateway '%s', phase 2", gw.Name)
	returnCode, _, _, err := sshHandler.Run(gw.Name, command)
	if err != nil {
		if _, ok := err.(*scerr.ErrAborted); !ok {
			retrieveForensicsData(sshHandler, gw)
		}
		return nil, err
	}
	if returnCode != 0 {
		retrieveForensicsData(sshHandler, gw)
		warnings, errs := getPhaseWarningsAndErrors(sshHandler, gw)
		return nil, fmt.Errorf("failed to finalize gateway '%s' installation: errorcode '%d', warnings '%s', errors '%s'", gw.Name, returnCode, warnings, errs)
	}
	logrus.Infof("Gateway '%s' successfully configured.", gw.Name)

	// Reboot gateway
	logrus.Debugf("Rebooting gateway '%s'", gw.Name)
	command = "sudo systemctl reboot"
	returnCode, _, _, err = sshHandler.Run(gw.Name, command)
	if err != nil {
		return nil, err
	}
	if returnCode != 0 {
		logrus.Warnf("Unexpected problem rebooting...")
	}

	ssh, err := sshHandler.GetConfig(gw.ID)
	if err != nil {
		return nil, err
	}

	sshDefaultTimeout := temporal.GetHostTimeout()
	_, err = ssh.WaitServerReady(handler.job.Task(), "ready", sshDefaultTimeout)
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
	err = handler.job.Service().DeleteHost(gw.ID)
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

func (handler *NetworkHandler) unbindHostFromVIP(vip *resources.VirtualIP, host *resources.Host) (err error) {
	err = handler.job.Service().UnbindHostFromVIP(vip, host)
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
func (handler *NetworkHandler) List(all bool) (netList []*resources.Network, err error) {
	tracer := concurrency.NewTracer(handler.job.Task(), fmt.Sprintf("(%v)", all), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if all {
		return handler.job.Service().ListNetworks()
	}

	mn, err := metadata.NewNetwork(handler.job.Service())
	if err != nil {
		return nil, err
	}
	err = mn.Browse(func(network *resources.Network) error {
		if handler.job.Aborted() {
			return scerr.AbortedError("aborted", nil)
		}
		netList = append(netList, network)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return netList, err
}

// Inspect returns the network identified by ref, ref can be the name or the id
func (handler *NetworkHandler) Inspect(ref string) (network *resources.Network, err error) {
	tracer := concurrency.NewTracer(handler.job.Task(), fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mn, err := metadata.LoadNetwork(handler.job.Service(), ref)
	if err != nil {
		return nil, err
	}

	return mn.Get()
}

// Delete deletes network referenced by ref
func (handler *NetworkHandler) Delete(ref string) (err error) { // FIXME Unused ctx
	tracer := concurrency.NewTracer(handler.job.Task(), fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	mn, err := metadata.LoadNetwork(handler.job.Service(), ref)
	if err != nil {
		if _, ok := err.(*scerr.ErrNotFound); !ok {
			cleanErr := handler.job.Service().DeleteNetwork(ref)
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
	err = network.Properties.LockForRead(networkproperty.HostsV1).ThenUse(func(v interface{}) error {
		networkHostsV1 := v.(*propsv1.NetworkHosts)
		hostsLen := uint(len(networkHostsV1.ByName))
		if hostsLen > 0 {
			list := make([]string, 0, hostsLen)
			for k := range networkHostsV1.ByName {
				if handler.job.Aborted() {
					return scerr.AbortedError("aborted", nil)
				}
				_, err = handler.job.Service().GetHostByName(k)
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
			errorMsg = fmt.Sprintf("%d host%s %s still attached to network '%s': %s",
				hostsLen, utils.Plural(hostsLen), verb, network.Name, strings.Join(list, ", "))
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

	if handler.job.Aborted() {
		return scerr.AbortedError("aborted", nil)
	}
	// Starting here, abort cannot be honored

	// Delete gateway(s)
	if network.GatewayID != "" {
		mh, err := metadata.LoadHost(handler.job.Service(), network.GatewayID)
		if err != nil {
			logrus.Error(err)
		} else {
			if network.VIP != nil {
				mhm, merr := mh.Get()
				if merr != nil {
					return merr
				}
				err = handler.job.Service().UnbindHostFromVIP(network.VIP, mhm)
				if err != nil {
					logrus.Errorf("failed to unbind primary gateway from VIP: %v", err)
				}
			}

			err = handler.job.Service().DeleteGateway(network.GatewayID) // allow no gateway, but log it
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
		mh, err := metadata.LoadHost(handler.job.Service(), network.SecondaryGatewayID)
		if err != nil {
			logrus.Error(err)
			return err
		}

		if network.VIP != nil {
			mhm, merr := mh.Get()
			if merr != nil {
				return merr
			}

			err = handler.job.Service().UnbindHostFromVIP(network.VIP, mhm)
			if err != nil {
				logrus.Errorf("failed to unbind secondary gateway from VIP: %v", err)
			}
		}

		err = handler.job.Service().DeleteGateway(network.SecondaryGatewayID) // allow no gateway, but log it
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

	// Delete VIP if needed
	if network.VIP != nil {
		err = handler.job.Service().DeleteVIP(network.VIP)
		if err != nil {
			// FIXME THINK Should we exit on failure ?
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
	err = handler.job.Service().DeleteNetwork(network.ID)
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
			recNet, recErr := handler.job.Service().GetNetwork(network.ID)
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

	return nil
}
