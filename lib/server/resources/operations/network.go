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

package operations

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/networkstate"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// networksFolderName is the technical name of the container used to store networks info
	networksFolderName = "networks"
)

var NullNetwork = func() *network {
	return &network{Core: NullCore}
}()

// network links Object Storage folder and Network
type network struct {
	*Core

	hasVIP bool
}

// NewNetwork creates an instance of Network
func NewNetwork(svc iaas.Service) (*network, error) {
	if svc == nil {
		return NullNetwork, scerr.InvalidParameterError("svc", "cannot be nil")
	}

	core, err := NewCore(svc, "network", networksFolderName)
	if err != nil {
		return NullNetwork, err
	}

	return &network{Core: core}, nil
}

// LoadNetwork loads the metadata of a network
func LoadNetwork(task concurrency.Task, svc iaas.Service, ref string) (*network, error) {
	if task != nil {
		return NullNetwork, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return NullNetwork, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return NullNetwork, scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	objn, err := NewNetwork(svc)
	if err != nil {
		return NullNetwork, err
	}
	err = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			return objn.Read(task, ref)
		},
		10*time.Second, // FIXME: parameterize
	)
	if err != nil {
		// If retry timed out, log it and return error ErrNotFound
		if _, ok := err.(retry.ErrTimeout); ok {
			logrus.Debugf("timeout reading metadata of network '%s'", ref)
			err = scerr.NotFoundError("failed to read metadata of network '%s': timeout", ref)
		}
		return NullNetwork, err
	}
	return objn, nil
}

// Create creates a network
//
func (objn *network) Create(task concurrency.Task, req abstract.NetworkRequest, gwname string, gwSizing *abstract.HostSizingRequirements) (err error) {
	if objn.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task != nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(
		nil,
		true,
		"('%s', '%s', %s, <sizing>, '%s', %v)", req.Name, req.CIDR, req.IPVersion.String(), req.Image, req.HA,
	).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	svc := objn.SafeGetService()

	// Verify that the network doesn't exist first
	_, err = svc.GetNetworkByName(req.Name)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound:
		case *scerr.ErrInvalidRequest, *scerr.ErrTimeout:
			return err
		default:
			return err
		}
	} else {
		return scerr.DuplicateError("network '%s' already exists", req.Name)
	}

	// Verify the CIDR is not routable
	routable, err := utils.IsCIDRRoutable(req.CIDR)
	if err != nil {
		return scerr.Wrap(err, "failed to determine if CIDR is not routable")
	}
	if routable {
		return scerr.InvalidRequestError("cannot create such a network, CIDR must be not routable; please choose an appropriate CIDR (RFC1918)")
	}

	// Create the network
	logrus.Debugf("Creating network '%s' ...", req.Name)
	rn, err := svc.CreateNetwork(req)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound, *scerr.ErrInvalidRequest, *scerr.ErrTimeout:
			return err
		default:
			return err
		}
	}

	// Starting from here, delete network if exiting with error
	defer func() {
		if err != nil && rn != nil {
			derr := svc.DeleteNetwork(rn.ID)
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
	}()

	caps := svc.GetCapabilities()
	failover := req.HA
	if failover && caps.PrivateVirtualIP {
		logrus.Infof("Provider support private Virtual IP, honoring the failover setup for gateways.")
	} else {
		logrus.Warningf("Provider doesn't support private Virtual IP, cannot set up high availability of network default route.")
		failover = false
	}

	// Creates VIP for gateways if asked for
	if failover {
		rn.VIP, err = svc.CreateVIP(rn.ID, fmt.Sprintf("for gateways of network %s", rn.Name))
		if err != nil {
			switch err.(type) {
			case *scerr.ErrNotFound, *scerr.ErrTimeout:
				return err
			default:
				return err
			}
		}

		// Starting from here, delete VIP if exists with error
		defer func() {
			if err != nil {
				if rn != nil {
					derr := svc.DeleteVIP(rn.VIP)
					if derr != nil {
						logrus.Errorf("failed to delete VIP: %+v", derr)
						err = scerr.AddConsequence(err, derr)
					}
				}
			}
		}()
	}

	// Write network object metadata
	// logrus.Debugf("Saving network metadata '%s' ...", network.Name)
	err = objn.Carry(task, rn)
	if err != nil {
		return err
	}

	// Starting from here, delete network metadata if exits with error
	defer func() {
		if err != nil {
			derr := objn.Core.Delete(task)
			if derr != nil {
				logrus.Errorf("failed to delete network metadata: %+v", derr)
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	var template *abstract.HostTemplate
	tpls, err := svc.SelectTemplatesBySize(*gwSizing, false)
	if err != nil {
		return scerr.Wrap(err, "failed to find appropriate template")
	}
	if len(tpls) > 0 {
		template = tpls[0]
		msg := fmt.Sprintf("Selected host template: '%s' (%d core%s", template.Name, template.Cores, strprocess.Plural(uint(template.Cores)))
		if template.CPUFreq > 0 {
			msg += fmt.Sprintf(" at %.01f GHz", template.CPUFreq)
		}
		msg += fmt.Sprintf(", %.01f GB RAM, %d GB disk", template.RAMSize, template.DiskSize)
		if template.GPUNumber > 0 {
			msg += fmt.Sprintf(", %d GPU%s", template.GPUNumber, strprocess.Plural(uint(template.GPUNumber)))
			if template.GPUType != "" {
				msg += fmt.Sprintf(" %s", template.GPUType)
			}
		}
		msg += ")"
		logrus.Infof(msg)
	} else {
		return scerr.NotFoundError("error creating network: no host template matching requirements for gateway")
	}
	img, err := svc.SearchImage(req.Image)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound, *scerr.ErrTimeout:
			return err
		default:
			return err
		}
	}

	networkName := objn.SafeGetName()
	var primaryGatewayName, secondaryGatewayName string
	if failover || gwname == "" {
		primaryGatewayName = "gw-" + networkName
	} else {
		primaryGatewayName = gwname
	}
	if failover {
		secondaryGatewayName = "gw2-" + networkName
	}

	keypairName := "kp_" + networkName
	keypair, err := svc.CreateKeyPair(keypairName)
	if err != nil {
		return err
	}

	gwRequest := abstract.GatewayRequest{
		ImageID:    img.ID,
		Network:    rn,
		KeyPair:    keypair,
		TemplateID: template.ID,
		CIDR:       rn.CIDR,
	}

	var (
		primaryGateway, secondaryGateway   resources.Host
		primaryUserdata, secondaryUserdata *userdata.Content
		primaryTask, secondaryTask         concurrency.Task
		secondaryErr                       error
		secondaryResult                    concurrency.TaskResult
	)

	// Starts primary gateway creation
	primaryRequest := gwRequest
	primaryRequest.Name = primaryGatewayName
	primaryTask, err = task.StartInSubtask(objn.createGateway, data.Map{
		"request": primaryRequest,
		"sizing":  gwSizing,
		"primary": true,
	})
	if err != nil {
		return err
	}

	// Starts secondary gateway creation if asked for
	if failover {
		secondaryRequest := gwRequest
		secondaryRequest.Name = secondaryGatewayName
		secondaryTask, err = task.StartInSubtask(objn.createGateway, data.Map{
			"request": secondaryRequest,
			"sizing":  gwSizing,
			"primary": false,
		})
		if err != nil {
			return err
		}
	}

	primaryResult, primaryErr := primaryTask.Wait()
	if primaryErr == nil {
		result, ok := primaryResult.(data.Map)
		if !ok {
			return scerr.InconsistentError("'data.Map' expected, '%s' provided", reflect.TypeOf(primaryResult).String())
		}
		primaryGateway = result["host"].(resources.Host)
		primaryUserdata = result["userdata"].(*userdata.Content)

		// Starting from here, deletes the primary gateway if exiting with error
		defer func() {
			if err != nil {
				derr := objn.deleteGateway(task, primaryGateway)
				if derr != nil {
					switch derr.(type) {
					case *scerr.ErrTimeout:
						logrus.Warnf("We should wait") // FIXME Wait until gateway no longer exists
					default:
					}
					err = scerr.AddConsequence(err, derr)
				}
				if failover {
					failErr := objn.unbindHostFromVIP(task, rn.VIP, primaryGateway)
					err = scerr.AddConsequence(err, failErr)
				}
			}
		}()
	}
	if failover && secondaryTask != nil {
		secondaryResult, secondaryErr = secondaryTask.Wait()
		if secondaryErr == nil {
			result, ok := secondaryResult.(data.Map)
			if !ok {
				return scerr.InconsistentError("'data.Map' expected, '%s' provided", reflect.TypeOf(secondaryResult).String())
			}

			secondaryGateway = result["host"].(resources.Host)
			secondaryUserdata = result["userdata"].(*userdata.Content)

			// Starting from here, deletes the secondary gateway if exiting with error
			defer func() {
				if err != nil {
					derr := objn.deleteGateway(task, secondaryGateway)
					if derr != nil {
						switch derr.(type) {
						case *scerr.ErrTimeout:
							logrus.Warnf("We should wait") // FIXME Wait until gateway no longer exists
						default:
						}
						err = scerr.AddConsequence(err, derr)
					}
					failErr := objn.unbindHostFromVIP(task, rn.VIP, secondaryGateway)
					err = scerr.AddConsequence(err, failErr)
				}
			}()
		}
	}
	if primaryErr != nil {
		return primaryErr
	}
	if secondaryErr != nil {
		return secondaryErr
	}

	// Update metadata of network object
	err = objn.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		an.GatewayID = primaryGateway.SafeGetID()
		if secondaryGateway != nil {
			an.SecondaryGatewayID = secondaryGateway.SafeGetID()
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Starts gateway(s) installation
	primaryTask, err = concurrency.NewTask()
	if err != nil {
		return err
	}

	primaryTask, err = primaryTask.Start(objn.waitForInstallPhase1OnGateway, primaryGateway)
	if err != nil {
		return err
	}
	if failover && secondaryTask != nil {
		secondaryTask, err = concurrency.NewTask()
		if err != nil {
			return err
		}
		secondaryTask, err = secondaryTask.Start(objn.waitForInstallPhase1OnGateway, secondaryGateway)
		if err != nil {
			return err
		}
	}
	_, primaryErr = primaryTask.Wait()
	if primaryErr != nil {
		return primaryErr
	}
	if failover && secondaryTask != nil {
		_, secondaryErr = secondaryTask.Wait()
		if secondaryErr != nil {
			return secondaryErr
		}
	}

	if primaryUserdata == nil {
		return fmt.Errorf("error creating network: primaryUserdata is nil")
	}

	// Complement userdata for gateway(s) with allocated IP
	primaryUserdata.PrimaryGatewayPrivateIP = primaryGateway.SafeGetPrivateIP(task)
	primaryUserdata.PrimaryGatewayPublicIP = primaryGateway.SafeGetPublicIP(task)

	if failover {
		primaryUserdata.SecondaryGatewayPrivateIP = secondaryGateway.SafeGetPrivateIP(task)
		primaryUserdata.SecondaryGatewayPublicIP = secondaryGateway.SafeGetPublicIP(task)

		if secondaryUserdata == nil {
			return fmt.Errorf("error creating network: secondaryUserdata is nil")
		}

		secondaryUserdata.PrimaryGatewayPrivateIP = primaryUserdata.PrimaryGatewayPrivateIP
		secondaryUserdata.PrimaryGatewayPublicIP = primaryUserdata.PrimaryGatewayPublicIP
		secondaryUserdata.SecondaryGatewayPrivateIP = primaryUserdata.SecondaryGatewayPrivateIP
		secondaryUserdata.SecondaryGatewayPublicIP = primaryUserdata.SecondaryGatewayPublicIP
	}

	// Starts gateway(s) installation
	primaryTask, err = concurrency.NewTask()
	if err != nil {
		return err
	}

	// logrus.Debugf("Updating network metadata '%s' ...", network.Name)
	err = objn.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		an.NetworkState = networkstate.PHASE2
		return nil
	})
	if err != nil {
		return err
	}

	// Check if hosts are still attached to network according to metadata
	primaryTask, err = primaryTask.Start(objn.installPhase2OnGateway, data.Map{
		"host":     primaryGateway,
		"userdata": primaryUserdata,
	})
	if err != nil {
		return err
	}
	if failover && secondaryTask != nil {
		secondaryTask, err = concurrency.NewTask()
		if err != nil {
			return err
		}
		secondaryTask, err = secondaryTask.Start(objn.installPhase2OnGateway, data.Map{
			"host":     secondaryGateway,
			"userdata": secondaryUserdata,
		})
		if err != nil {
			return err
		}
	}
	_, primaryErr = primaryTask.Wait()
	if primaryErr != nil {
		return primaryErr
	}
	if failover && secondaryTask != nil {
		_, secondaryErr = secondaryTask.Wait()
		if secondaryErr != nil {
			return secondaryErr
		}
	}

	// select {
	// case <-ctx.Done():
	// 	logrus.Warnf("Network creation cancelled by user")
	// 	return nil, fmt.Errorf("network creation cancelled by user")
	// default:
	// }

	// Updates network state in metadata
	// logrus.Debugf("Updating network metadata '%s' ...", network.Name)
	return objn.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		an.NetworkState = networkstate.READY
		return nil
	})
}

func (objn *network) createGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	defer scerr.OnPanic(&err)()

	var (
		inputs data.Map
		ok     bool
	)
	if inputs, ok = params.(data.Map); !ok {
		return nil, scerr.InvalidParameterError("params", "must be a data.Map")
	}

	// name := inputs["name"].(string)
	request, ok := inputs["request"].(abstract.GatewayRequest)
	if !ok {
		return nil, scerr.InvalidParameterError("params[request]", "must be a resources.GatewayRequest")
	}
	sizing, ok := inputs["sizing"].(abstract.HostSizingRequirements)
	if !ok {
		return nil, scerr.InvalidParameterError("params[sizing]", "must be a resources.SizingRequirements")
	}
	primary, ok := inputs["primary"].(bool)
	if !ok {
		return nil, scerr.InvalidParameterError("params[primary]", "must be a bool")
	}

	logrus.Infof("Requesting the creation of gateway '%s' using template '%s' with image '%s'", request.Name, request.TemplateID, request.ImageID)
	pgw, userData, err := objn.SafeGetService().CreateGateway(request)
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
			derr := objn.SafeGetService().DeleteHost(pgw.Core.ID)
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
	pgw, err = objn.SafeGetService().InspectHost(pgw)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound, *scerr.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	}

	objgw, err := NewHost(objn.SafeGetService())
	if err != nil {
		return nil, err
	}
	err = objgw.Carry(task, pgw.Core)
	if err != nil {
		return nil, err
	}

	// Binds gateway to VIP
	if request.Network.VIP != nil {
		err := objn.SafeGetService().BindHostToVIP(request.Network.VIP, pgw.Core.ID)
		if err != nil {
			return nil, err
		}
		userData.DefaultRouteIP = request.Network.VIP.PrivateIP
		userData.EndpointIP = request.Network.VIP.PublicIP
	} else {
		userData.DefaultRouteIP = objgw.SafeGetPrivateIP(task)
	}
	userData.IsPrimaryGateway = primary

	err = objgw.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		// Updates requested sizing in gateway property propertiesv1.HostSizing
		return props.Alter(hostproperty.SizingV2, func(clonable data.Clonable) error {
			gwSizingV2, ok := clonable.(*propertiesv2.HostSizing)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			gwSizingV2.RequestedSize = converters.HostSizingRequirementsFromAbstractToPropertyV2(sizing)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	res := data.Map{
		"host":     pgw,
		"userdata": userData,
		"object":   objgw,
	}
	return res, nil
}

func (objn *network) waitForInstallPhase1OnGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {

	objgw, ok := params.(resources.Host)
	if !ok {
		return nil, scerr.InconsistentError("'resources.Host' expected, '%s' provided", reflect.TypeOf(params).String())
	}
	gwname := objgw.SafeGetName()

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	logrus.Infof("Waiting until gateway '%s' is available by SSH ...", gwname)

	ssh, err := objgw.SSHConfig(task)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("Provisioning gateway '%s', phase 1", gwname)
	_, err = ssh.WaitServerReady(task, "phase1", temporal.GetHostCreationTimeout())
	if err != nil {
		if _, ok := err.(scerr.ErrTimeout); ok {
			return nil, err
		}
		if abstract.IsProvisioningError(err) {
			return nil, fmt.Errorf("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH: [%+v]", gwname, err)
		}
		return nil, err
	}
	logrus.Infof("SSH service of gateway '%s' started.", gwname)

	return nil, nil
}

func (objn *network) installPhase2OnGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	var (
		objgw    resources.Host
		userData *userdata.Content
		ok       bool
	)
	if objgw, ok = params.(data.Map)["host"].(resources.Host); !ok {
		return nil, scerr.InvalidParameterError("params['host']", "is missing or is not a 'resources.Host'")
	}
	if userData, ok = params.(data.Map)["userdata"].(*userdata.Content); !ok {
		return nil, scerr.InvalidParameterError("params['userdata']", "is missing or is not a '*userdata.Content'")
	}
	gwname := objgw.SafeGetName()

	// Executes userdata phase2 script to finalize host installation
	tracer := concurrency.NewTracer(nil, true, "(%s)", gwname).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting configuration phase 2 on the gateway '%s'...", gwname),
		fmt.Sprintf("Ending configuration phase 2 on the gateway '%s'", gwname),
	)()
	defer scerr.OnPanic(&err)()

	content, err := userData.Generate("phase2")
	if err != nil {
		return nil, err
	}
	err = objgw.PushStringToFile(task, string(content), utils.TempFolder+"/user_data.phase2.sh", "", "")
	if err != nil {
		return nil, err
	}
	command := fmt.Sprintf("sudo bash %s/%s; exit $?", utils.TempFolder, "user_data.phase2.sh")

	// logrus.Debugf("Configuring gateway '%s', phase 2", gw.Name)
	returnCode, _, _, err := objgw.Run(task, command, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil {
		RetrieveForensicsData(task, objgw)
		return nil, err
	}
	if returnCode != 0 {
		RetrieveForensicsData(task, objgw)
		warnings, errs := GetPhaseWarningsAndErrors(task, objgw)
		return nil, fmt.Errorf("failed to finalize gateway '%s' installation: errorcode '%d', warnings '%s', errors '%s'", gwname, returnCode, warnings, errs)
	}
	logrus.Infof("Gateway '%s' successfully configured.", gwname)

	// Reboot gateway
	logrus.Debugf("Rebooting gateway '%s'", gwname)
	command = "sudo systemctl reboot"
	returnCode, _, _, err = objgw.Run(task, command, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil {
		return nil, err
	}
	if returnCode != 0 {
		logrus.Warnf("Unexpected problem rebooting...")
	}

	ssh, err := objgw.SSHConfig(task)
	if err != nil {
		return nil, err
	}

	sshDefaultTimeout := temporal.GetHostTimeout()
	_, err = ssh.WaitServerReady(task, "ready", sshDefaultTimeout)
	if err != nil {
		if _, ok := err.(scerr.ErrTimeout); ok {
			return nil, err
		}
		if abstract.IsProvisioningError(err) {
			logrus.Errorf("%+v", err)
			return nil, fmt.Errorf("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", gwname)
		}
		return nil, err
	}
	return nil, nil

}

func (objn *network) deleteGateway(task concurrency.Task, gw resources.Host) (err error) {
	name := gw.SafeGetName()
	logrus.Warnf("Cleaning up on failure, deleting gateway '%s'...", name)
	err = gw.Delete(task)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound:
			logrus.Errorf("Cleaning up on failure, failed to delete gateway '%s', resource not found: %v", name, err)
		case *scerr.ErrTimeout:
			logrus.Errorf("Cleaning up on failure, failed to delete gateway '%s', timeout: %v", name, err)
		default:
			logrus.Errorf("Cleaning up on failure, failed to delete gateway '%s': %v", name, err)
		}
	}
	logrus.Infof("Cleaning up on failure, gateway '%s' deleted", name)
	return err
}

func (objn *network) unbindHostFromVIP(task concurrency.Task, vip *abstract.VirtualIP, host resources.Host) error {
	name := host.SafeGetName()
	err := objn.SafeGetService().UnbindHostFromVIP(vip, host.SafeGetID())
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound, *scerr.ErrTimeout:
			logrus.Debugf("Cleaning up on failure, failed to remove '%s' gateway bind from VIP: %v", name, err)
		default:
			logrus.Debugf("Cleaning up on failure, failed to remove '%s' gateway bind from VIP: %v", name, err)
		}
		return err
	}
	logrus.Infof("Cleaning up on failure, host '%s' bind removed from VIP", name)
	return nil
}

// Browse walks through all the metadata objects in network
func (objn *network) Browse(task concurrency.Task, callback func(*abstract.Network) error) error {
	if objn.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "can't be nil")
	}
	if callback == nil {
		return scerr.InvalidParameterError("callback", "can't be nil")
	}

	return objn.Browse(task, func(entry *abstract.Network) error {
		return callback(entry)
	})
}

// AttachHost links host ID to the network
func (objn *network) AttachHost(task concurrency.Task, host resources.Host) (err error) {
	if objn.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if host == nil {
		return scerr.InvalidParameterError("host", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, true, "("+host.SafeGetName()+")").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	hostID := host.SafeGetID()
	hostName := host.SafeGetName()

	return objn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(networkproperty.HostsV1, func(clonable data.Clonable) error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			networkHostsV1.ByID[hostID] = hostName
			networkHostsV1.ByName[hostName] = hostID
			return nil
		})
	})
}

// DetachHost unlinks host ID from network
func (objn *network) DetachHost(task concurrency.Task, hostID string) (err error) {
	if objn.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if hostID == "" {
		return scerr.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, true, "('"+hostID+"')").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	return objn.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(networkproperty.HostsV1, func(clonable data.Clonable) error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostName, found := networkHostsV1.ByID[hostID]
			if found {
				delete(networkHostsV1.ByName, hostName)
				delete(networkHostsV1.ByID, hostID)
			}
			return nil
		})
	})
}

// ListHosts returns the list of Host attached to the network (excluding gateway)
func (objn *network) ListHosts(task concurrency.Task) (_ []resources.Host, err error) {
	if objn.IsNull() {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, true, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	var list []resources.Host
	err = objn.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(networkproperty.HostsV1, func(clonable data.Clonable) error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			svc := objn.SafeGetService()
			for id := range networkHostsV1.ByID {
				host, err := LoadHost(task, svc, id)
				if err != nil {
					return err
				}
				list = append(list, host)
			}
			return nil
		})
	})
	if err != nil {
		logrus.Errorf("Error listing hosts: %+v", err)
	}
	return list, nil
}

// GetGateway returns the gateway related to network
func (objn *network) GetGateway(task concurrency.Task, primary bool) (_ resources.Host, err error) {
	if objn.IsNull() {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	defer scerr.OnPanic(&err)()

	tracer := concurrency.NewTracer(nil, true, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	var gatewayID string
	err = objn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if primary {
			gatewayID = an.GatewayID
		} else {
			gatewayID = an.SecondaryGatewayID
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return LoadHost(task, objn.SafeGetService(), gatewayID)
}

// SafeGetGateway returns a resources.Host corresponding to the gateway requested. May return HostNull if no gateway exists.
func (objn *network) SafeGetGateway(task concurrency.Task, primary bool) resources.Host {
	if objn.IsNull() {
		return NullHost
	}
	host, _ := objn.GetGateway(task, primary)
	return host
}

// Delete deletes network referenced by ref
func (objn *network) Delete(task concurrency.Task) (err error) {
	if objn.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, true, "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	objn.Lock(task)
	defer objn.Unlock(task)

	// var gwID string
	err = objn.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		svc := objn.SafeGetService()

		// Check if hosts are still attached to network according to metadata
		var errorMsg string
		innerErr := props.Inspect(networkproperty.HostsV1, func(clonable data.Clonable) error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostsLen := uint(len(networkHostsV1.ByName))
			if hostsLen > 0 {
				list := make([]string, 0, hostsLen)
				for k := range networkHostsV1.ByName {
					list = append(list, k)
				}
				verb := "are"
				if hostsLen == 1 {
					verb = "is"
				}
				errorMsg = fmt.Sprintf("cannot delete network '%s': %d host%s %s still attached to it: %s",
					an.Name, hostsLen, strprocess.Plural(hostsLen), verb, strings.Join(list, ", "))
				return scerr.NotAvailableError(errorMsg)
			}
			return nil
		})
		if innerErr != nil {
			return innerErr
		}

		// Leave a chance to abort
		if task.Aborted() {
			return scerr.AbortedError("", nil)
		}

		// 1st delete primary gateway
		if an.GatewayID != "" {
			stop := false
			rh, innerErr := LoadHost(task, svc, an.GatewayID)
			if err != nil {
				return err
			}
			if innerErr != nil {
				if _, ok := innerErr.(scerr.ErrNotFound); !ok {
					return innerErr
				}
				stop = true
			}
			if !stop {
				innerErr = rh.Delete(task)
				if innerErr != nil { // allow no gateway, but log it
					if _, ok := err.(scerr.ErrNotFound); ok {
						logrus.Errorf("failed to delete primary gateway: %s", innerErr.Error())
					} else {
						return innerErr
					}
				}
			} else {
				logrus.Infof("Gateway of network '%s' appears to be already deleted", an.Name)
			}
		}

		// 2nd delete secondary gateway
		if an.SecondaryGatewayID != "" {
			stop := false
			rh, innerErr := LoadHost(task, svc, an.SecondaryGatewayID)
			if innerErr != nil {
				if _, ok := innerErr.(scerr.ErrNotFound); !ok {
					return innerErr
				}
				stop = true
			}
			if !stop {
				innerErr = rh.Delete(task)
				if innerErr != nil { // allow no gateway, but log it
					if _, ok := innerErr.(scerr.ErrNotFound); ok {
						logrus.Errorf("failed to delete secondary gateway: %s", innerErr.Error())
					} else {
						return innerErr
					}
				}
			} else {
				logrus.Infof("Gateway of network '%s' appears to be already deleted", an.Name)
			}
		}

		// 3rd delete VIP if needed
		if an.VIP != nil {
			innerErr = svc.DeleteVIP(an.VIP)
			if innerErr != nil {
				// FIXME: THINK Should we exit on failure ?
				logrus.Errorf("failed to delete VIP: %v", innerErr)
			}
		}

		waitMore := false
		// delete network, with tolerance
		innerErr = svc.DeleteNetwork(an.ID)
		if innerErr != nil {
			switch innerErr.(type) {
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
			errWaitMore := retry.WhileUnsuccessfulDelay1Second(
				func() error {
					recNet, recErr := svc.GetNetwork(an.ID)
					if recNet != nil {
						return fmt.Errorf("still there")
					}
					if _, ok := recErr.(*scerr.ErrNotFound); ok {
						return nil
					}
					return fmt.Errorf("another kind of error")
				},
				temporal.GetContextTimeout(),
			)
			if errWaitMore != nil {
				innerErr = scerr.AddConsequence(err, errWaitMore)
			}
		}
		return innerErr
	})
	if err != nil {
		return err
	}

	// Delete metadata
	return objn.Core.Delete(task)
}

// GetDefaultRouteIP returns the IP of the LAN default route
func (objn *network) GetDefaultRouteIP(task concurrency.Task) (ip string, err error) {
	if objn.IsNull() {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}

	ip = ""
	err = objn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if an.VIP != nil && an.VIP.PrivateIP != "" {
			ip = an.VIP.PrivateIP
		} else {
			objpgw, innerErr := LoadHost(task, objn.SafeGetService(), an.GatewayID)
			if innerErr != nil {
				return innerErr
			}
			ip = objpgw.SafeGetPrivateIP(task)
			return nil
		}
		return nil
	})
	return ip, err
}

// SafeGetDefaultRouteIP ...
func (objn *network) SafeGetDefaultRouteIP(task concurrency.Task) string {
	if objn.IsNull() {
		return ""
	}
	ip, _ := objn.GetDefaultRouteIP(task)
	return ip
}

// GetEndpointIP returns the IP of the internet IP to reach the network
func (objn *network) GetEndpointIP(task concurrency.Task) (ip string, err error) {
	if objn.IsNull() {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}

	ip = ""
	err = objn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if an.VIP != nil && an.VIP.PublicIP != "" {
			ip = an.VIP.PublicIP
		} else {
			objpgw, inErr := LoadHost(task, objn.SafeGetService(), an.GatewayID)
			if inErr != nil {
				return inErr
			}
			ip = objpgw.SafeGetPublicIP(task)
			return nil
		}
		return nil
	})
	return ip, err
}

// SafeGetEndpointIP ...
func (objn *network) SafeGetEndpointIP(task concurrency.Task) string {
	if objn.IsNull() {
		return ""
	}
	ip, _ := objn.GetEndpointIP(task)
	return ip
}

// HasVirtualIP tells if the network uses a VIP a default route
func (objn *network) HasVirtualIP(task concurrency.Task) (vip bool) {
	if objn.IsNull() {
		logrus.Errorf(scerr.InvalidInstanceError().Error())
		return false
	}
	if task == nil {
		logrus.Errorf(scerr.InvalidParameterError("task", "cannot be nil").Error())
		return false
	}
	err := objn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		core, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		vip = core.VIP != nil
		return nil
	})
	if err != nil {
		return false
	}
	return vip
}
