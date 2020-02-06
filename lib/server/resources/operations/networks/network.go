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

package networks

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// networksFolderName is the technical name of the container used to store networks info
	networksFolderName = "networks"
)

// Network links Object Storage folder and Network
type Network struct {
	*resources.Core
	properties *serialize.JSONProperties
}

// NewNetwork creates an instance of Network
func New(svc iaas.Service) (*Network, error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}

	core, err := resources.NewCore(svc, "network", networksFolderName)
	if err != nil {
		return nil, err
	}

	props, err := serialize.NewJSONProperties("resources.network")
	if err != nil {
		return nil, err
	}

	return &Network{Core: core, properties: props}, nil
}

// Load loads the metadata of a network
func Load(task concurrency.Task, svc iaas.Service, ref string) (*Network, error) {
	if task != nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	return networks.Load(task, svc, ref)
}

// // Properties returns the extensions of the host
// func (objn *Network) Properties(task concurrency.Task) (_ *serialize.JSONProperties, err error) {
// 	if objn == nil {
// 		return nil, scerr.InvalidInstanceError()
// 	}
// 	if task == nil {
// 		return nil, scerr.InvalidParameterError("task", "cannot be nil")
// 	}

// 	tracer := concurrency.NewTracer(nil, "", false).GoingIn()
// 	defer tracer.OnExitTrace()()
// 	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

// 	objn.Core.RLock(task)
// 	defer objn.Core.RUnlock(task)

// 	if objn.properties == nil {
// 		return nil, scerr.InvalidInstanceContentError("objn.properties", "cannot be nil")
// 	}
// 	return objn.properties, nil
// }

// Create creates a network
//
func (objn *Network) Create(task concurrency.Task, req resources.NetworkRequest, gwname string, gwSizing *resources.SizingRequirements) (err error) {
	if objn == nil {
		return scerr.InvalidInstanceError()
	}
	if task != nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(
		nil,
		fmt.Sprintf("('%s', '%s', %s, <sizing>, '%s', %v)", req.Name, req.CIDR, req.IPVersion.String(), req.Image, req.HA),
		true,
	).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	svc := objn.Service()

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

	var template *resources.HostTemplate
	tpls, err := svc.SelectTemplatesBySize(*gwSizing, false)
	if err != nil {
		return scerr.Wrap(err, "failed to find appropriate template")
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

	networkName := objn.Name()
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

	gwRequest := resources.GatewayRequest{
		ImageID:    img.ID,
		Network:    rn,
		KeyPair:    keypair,
		TemplateID: template.ID,
		CIDR:       rn.CIDR,
	}

	var (
		primaryGateway, secondaryGateway   *Host
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
		secondaryTask, err = secondaryTask.StartInSubtask(objn.createGateway, data.Map{
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
		primaryGateway = result["host"].(*Host)
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

			secondaryGateway = result["host"].(*Host)
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
	err = objn.Alter(task, func(clonable data.Clonable) error {
		rn, ok := clonable.(*resources.Network)
		if !ok {
			return scerr.InconsistentError("'*resources.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		// props, err := objn.Properties(task)
		// if err != nil {
		// 	return err
		// }
		rn.GatewayID = primaryGateway.ID()
		if secondaryGateway != nil {
			rn.SecondaryGatewayID = secondaryGateway.ID()
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Starts gateway(s) installation
	err = primaryTask.Reset()
	if err != nil {
		return err
	}

	primaryTask, err = primaryTask.Start(objn.waitForInstallPhase1OnGateway, primaryGateway)
	if err != nil {
		return err
	}
	if failover && secondaryTask != nil {
		err = secondaryTask.Reset()
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
	ip, err := primaryGateway.PrivateIP(task)
	if err != nil {
		return err
	}
	primaryUserdata.PrimaryGatewayPrivateIP = ip

	ip, err = primaryGateway.PublicIP(task)
	if err != nil {
		return err
	}
	primaryUserdata.PrimaryGatewayPublicIP = ip

	if failover {
		ip, err = secondaryGateway.PrivateIP(task)
		if err != nil {
			return err
		}
		primaryUserdata.SecondaryGatewayPrivateIP = ip

		ip, err = secondaryGateway.PublicIP(task)
		if err != nil {
			return err
		}
		primaryUserdata.SecondaryGatewayPublicIP = ip

		if secondaryUserdata == nil {
			return fmt.Errorf("error creating network: secondaryUserdata is nil")
		}

		secondaryUserdata.PrimaryGatewayPrivateIP = primaryUserdata.PrimaryGatewayPrivateIP
		secondaryUserdata.PrimaryGatewayPublicIP = primaryUserdata.PrimaryGatewayPublicIP
		secondaryUserdata.SecondaryGatewayPrivateIP = primaryUserdata.SecondaryGatewayPrivateIP
		secondaryUserdata.SecondaryGatewayPublicIP = primaryUserdata.SecondaryGatewayPublicIP
	}

	// Starts gateway(s) installation
	err = primaryTask.Reset()
	if err != nil {
		return err
	}

	// logrus.Debugf("Updating network metadata '%s' ...", network.Name)
	err = objn.Alter(task, func(clonable data.Clonable) error {
		rn, ok := clonable.(*resources.Network)
		if !ok {
			return scerr.InconsistentError("'*resources.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		rn.NetworkState = NetworkState.PHASE2
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
		err = secondaryTask.Reset()
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
	return objn.Alter(task, func(clonable data.Clonable) error {
		rn, ok := clonable.(*resources.Network)
		if !ok {
			return scerr.InconsistentError("'*resources.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		rn.NetworkState = NetworkState.READY
		return nil
	})
}

func (objn *Network) createGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
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
		return nil, scerr.InvalidParameterError("params[request]", "must be a resources.GatewayRequest")
	}
	sizing, ok := inputs["sizing"].(resources.SizingRequirements)
	if !ok {
		return nil, scerr.InvalidParameterError("params[sizing]", "must be a resources.SizingRequirements")
	}
	primary, ok := inputs["primary"].(bool)
	if !ok {
		return nil, scerr.InvalidParameterError("params[primary]", "must be a bool")
	}

	logrus.Infof("Requesting the creation of gateway '%s' using template '%s' with image '%s'", request.Name, request.TemplateID, request.ImageID)
	var (
		// hsV2     *propertiesv2.HostSizing
		// hnV1     *propertiesv1.HostNetwork
		rgw      *resources.Host
		userData *userdata.Content
	)
	rgw, _, _, userData, err = objn.Service().CreateGateway(request)
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
			derr := objn.Service().DeleteHost(rgw.ID)
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
	rgw, _, _, err = objn.Service().InspectHost(rgw)
	if err != nil {
		switch err.(type) {
		case *scerr.ErrNotFound, *scerr.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	}

	svc := objn.Service()
	objgw, err := NewHost(svc)
	if err != nil {
		return nil, err
	}
	err = objgw.Carry(task, rgw)
	if err != nil {
		return nil, err
	}

	// Binds gateway to VIP
	if request.Network.VIP != nil {
		privIP, pubIP, err := objn.Service().BindHostToVIP(request.Network.VIP, rgw)
		if err != nil {
			return nil, err
		}
		userData.PrivateVIP = privIP
		// userData.DefaultRouteIP = request.Network.VIP.PrivateIP
		userData.DefaultRouteIP = pubIP
		// userData.EndpointIP = request.Network.VIP.PublicIP
	} else {
		ip, err := objgw.PrivateIP(task)
		if err != nil {
			return nil, err
		}
		userData.DefaultRouteIP = ip
	}
	userData.IsPrimaryGateway = primary

	err = objgw.Alter(task, func(clonable data.Clonable) error {
		props, inErr := objgw.Properties(task)
		if inErr != nil {
			return inErr
		}
		// Updates requested sizing in gateway property propertiesv1.HostSizing
		return props.Alter(hostproperty.SizingV2, func(clonable data.Clonable) error {
			gwSizingV2, ok := clonable.(*propertiesv2.HostSizing)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			gwSizingV2.RequestedSize = &sizing
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	result = data.Map{
		"host":     rgw,
		"userdata": userData,
		"object":   objgw,
	}
	return result, nil
}

func (objn *Network) waitForInstallPhase1OnGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {

	objgw, ok := params.(*Host)
	if !ok {
		return nil, scerr.InconsistentError(fmt.Sprintf("'*Host' expected, '%s' provided", reflect.TypeOf(params).String()))
	}
	gwname := objgw.Name()

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	logrus.Infof("Waiting until gateway '%s' is available by SSH ...", gwname)

	ssh, err := objgw.SSHConfig(task)
	if err != nil {
		return nil, err
	}
	ctx, err := task.Context()
	if err != nil {
		return nil, err
	}

	logrus.Debugf("Provisioning gateway '%s', phase 1", gwname)
	_, err = ssh.WaitServerReady(ctx, "phase1", temporal.GetHostCreationTimeout())
	if err != nil {
		if _, ok := err.(scerr.ErrTimeout); ok {
			return nil, err
		}
		if resources.IsProvisioningError(err) {
			return nil, fmt.Errorf("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH: [%+v]", gwname, err)
		}
		return nil, err
	}
	logrus.Infof("SSH service of gateway '%s' started.", gwname)

	return nil, nil
}

func (objn *Network) installPhase2OnGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	var (
		objgw    *Host
		userData *userdata.Content
		ok       bool
	)
	if objgw, ok = params.(data.Map)["host"].(*Host); !ok {
		return nil, scerr.InvalidParameterError("params", "missing field 'host'")
	}
	if userData, ok = params.(data.Map)["userdata"].(*userdata.Content); !ok {
		return nil, scerr.InvalidParameterError("params", "missing field 'userdata'")
	}
	gwname := objgw.Name()

	// Executes userdata phase2 script to finalize host installation
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("(%s)", objgw.Name()), true).WithStopwatch().GoingIn()
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
	err = objgw.PushStringToFile(task, string(content), srvutils.TempFolder+"/user_data.phase2.sh", "", "", "")
	if err != nil {
		return nil, err
	}
	command := fmt.Sprintf("sudo bash %s/%s; exit $?", srvutils.TempFolder, "user_data.phase2.sh")
	ctx, err := task.Context()
	if err != nil {
		return nil, err
	}

	// logrus.Debugf("Configuring gateway '%s', phase 2", gw.Name)
	returnCode, _, _, err := objgw.Run(task, command, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil {
		retrieveForensicsData(task, objgw)
		return nil, err
	}
	if returnCode != 0 {
		retrieveForensicsData(task, objgw)
		warnings, errs := getPhaseWarningsAndErrors(task, objgw)
		return nil, fmt.Errorf("failed to finalize gateway '%s' installation: errorcode '%d', warnings '%s', errors '%s'", gwname, returnCode, warnings, errs)
	}
	logrus.Infof("Gateway '%s' successfully configured.", gwname)

	// Reboot gateway
	logrus.Debugf("Rebooting gateway '%s'", gwname)
	command = "sudo systemctl reboot"
	returnCode, _, _, err = objgw.Run(task, command, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
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
	_, err = ssh.WaitServerReady(ctx, "ready", sshDefaultTimeout)
	if err != nil {
		if _, ok := err.(scerr.ErrTimeout); ok {
			return nil, err
		}
		if resources.IsProvisioningError(err) {
			logrus.Errorf("%+v", err)
			return nil, fmt.Errorf("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", gwname)
		}
		return nil, err
	}
	return nil, nil

}

func (objn *Network) deleteGateway(task concurrency.Task, gw *Host) (err error) {
	name := gw.Name()
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

func (objn *Network) unbindHostFromVIP(task concurrency.Task, vip *resources.VIP, host *Host) error {
	name := host.Name()
	var (
		rh *resources.Host
		ok bool
	)
	err := host.Inspect(task, func(clonable data.Clonable) error {
		rh, ok = clonable.(*resources.Host)
		if !ok {
			return scerr.InconsistentError("'*resources.host' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		return nil
	})
	if err != nil {
		return err
	}

	err = objn.Service().UnbindHostFromVIP(vip, rh)
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
func (objn *Network) Browse(task concurrency.Task, callback func(*resources.Network) error) error {
	// this function is allowed to be called from nil pointer by design
	if task == nil {
		return scerr.InvalidParameterError("task", "can't be nil")
	}
	if callback == nil {
		return scerr.InvalidParameterError("callback", "can't be nil")
	}

	return objn.Browse(task, func(entry *resources.Network) error {
		return callback(entry)
	})
}

// AttachHost links host ID to the network
func (objn *Network) AttachHost(task concurrency.Task, host resources.Host) (err error) {
	if objn == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if host == nil {
		return scerr.InvalidParameterError("host", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "("+host.Name()+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	var hostID, hostName string

	err = host.Inspect(task, func(clonable data.Clonable) error {
		h, ok := clonable.(*resources.Host)
		if !ok {
			return scerr.InconsistentError(fmt.Sprintf("'*resources.Host' expected, '%s' provided", reflect.TypeOf(clonable).String()))
		}
		hostID = h.ID
		hostName = h.Name
		return nil
	})
	if err != nil {
		return err
	}

	return objn.Alter(task, func(clonable data.Clonable) error {
		props, inErr := objn.Properties(task)
		if inErr != nil {
			return inErr
		}
		return props.Alter(NetworkProperty.HostsV1, func(clonable data.Clonable) error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			networkHostsV1.ByID[hostID] = hostName
			networkHostsV1.ByName[hostName] = hostID
			return nil
		})
	})
}

// DetachHost unlinks host ID from network
func (objn *Network) DetachHost(task concurrency.Task, hostID string) (err error) {
	if objn == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if hostID == "" {
		return scerr.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, "('"+hostID+"')", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	return objn.Alter(task, func(clonable data.Clonable) error {
		props, inErr := objn.Properties(task)
		if inErr != nil {
			return inErr
		}
		return props.Alter(NetworkProperty.HostsV1, func(clonable data.Clonable) error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String()))
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
func (objn *Network) ListHosts(task concurrency.Task) (_ []resources.Host, err error) {
	if objn == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	var list []resources.Host
	err = objn.Inspect(task, func(clonable data.Clonable) error {
		props, inErr := objn.Properties(task)
		if inErr != nil {
			return inErr
		}
		return props.Inspect(NetworkProperty.HostsV1, func(clonable data.Clonable) error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			svc := objn.Service()
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

// Gateway returns the gateway related to network
func (objn *Network) Gateway(task concurrency.Task, primary bool) (_ resources.Host, err error) {
	if objn == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	defer scerr.OnPanic(&err)()

	tracer := concurrency.NewTracer(nil, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	objn.RLock(task)
	defer objn.RUnlock(task)

	var gatewayID string
	err = objn.Inspect(task, func(clonable data.Clonable) error {
		rn, ok := clonable.(*resources.Network)
		if !ok {
			return scerr.InconsistentError("'*resources.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if primary {
			gatewayID = rn.GatewayID
		} else {
			gatewayID = rn.SecondaryGatewayID
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return LoadHost(task, objn.Service(), gatewayID)
}

// Delete deletes network referenced by ref
func (objn *Network) Delete(task concurrency.Task) (err error) {
	if objn == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	objn.Lock(task)
	defer objn.Unlock(task)

	// var gwID string
	err = objn.Alter(task, func(clonable data.Clonable) error {
		rn, ok := clonable.(*resources.Network)
		if !ok {
			return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String()))
		}

		svc := objn.Service()

		// Check if hosts are still attached to network according to metadata
		var errorMsg string
		inErr := rn.Properties.Inspect(NetworkProperty.HostsV1, func(clonable data.Clonable) error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String()))
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
					rn.Name, hostsLen, utils.Plural(hostsLen), verb, strings.Join(list, ", "))
				return scerr.NotAvailableError(errorMsg)
			}
			return nil
		})
		if inErr != nil {
			return inErr
		}

		// Leave a chance to abort
		aborted, inErr := task.Aborted()
		if aborted {
			return scerr.AbortedError("", nil)
		}

		// 1st delete primary gateway
		if rn.GatewayID != "" {
			stop := false
			oh, err := LoadHost(task, svc, rn.GatewayID)
			if err != nil {
				return err
			}
			if err != nil {
				if _, ok := err.(scerr.ErrNotFound); !ok {
					return err
				}
				stop = true
			}
			if !stop {
				err = oh.Delete(task)
				if err != nil { // allow no gateway, but log it
					if _, ok := err.(scerr.ErrNotFound); ok {
						logrus.Errorf("failed to delete primary gateway: %s", err.Error())
					} else {
						return err
					}
				}
			} else {
				logrus.Infof("Gateway of network '%s' appears to be already deleted", rn.Name)
			}
		}

		// 1st delete secondary gateway
		if rn.SecondaryGatewayID != "" {
			stop := false
			oh, err := LoadHost(task, svc, rn.SecondaryGatewayID)
			if err != nil {
				return err
			}
			if err != nil {
				if _, ok := err.(scerr.ErrNotFound); !ok {
					return err
				}
				stop = true
			}
			if !stop {
				err = oh.Delete(task)
				if err != nil { // allow no gateway, but log it
					if _, ok := err.(scerr.ErrNotFound); ok {
						logrus.Errorf("failed to delete secondary gateway: %s", err.Error())
					} else {
						return err
					}
				}
			} else {
				logrus.Infof("Gateway of network '%s' appears to be already deleted", rn.Name)
			}
		}

		// Delete VIP if needed
		if rn.VIP != nil {
			err = svc.DeleteVIP(rn.VIP)
			if err != nil {
				// FIXME THINK Should we exit on failure ?
				logrus.Errorf("failed to delete VIP: %v", err)
			}
		}

		waitMore := false
		// delete network, with tolerance
		err = svc.DeleteNetwork(rn.ID)
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
				recNet, recErr := svc.GetNetwork(rn.ID)
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
		return err
	})
	if err != nil {
		return err
	}

	// Delete metadata
	return objn.Core.Delete(task)
}

// DefaultRouteIP returns the IP of the LAN default route
func (objn *Network) DefaultRouteIP(task concurrency.Task) (ip string, err error) {
	if objn == nil {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}

	ip = ""
	err = objn.Inspect(task, func(clonable data.Clonable) error {
		rn, ok := clonable.(*resources.Network)
		if !ok {
			return scerr.InconsistentError("'*resources.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if rn.VIP != nil && rn.VIP.PrivateIP != "" {
			ip = rn.VIP.PrivateIP
		} else {
			objpgw, inErr := LoadHost(task, objn.Service(), rn.GatewayID)
			if inErr != nil {
				return inErr
			}
			ip, inErr = objpgw.PrivateIP(task)
			return inErr
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return ip, nil
}

// EndpointIP returns the IP of the internet IP to reach the network
func (objn *Network) EndpointIP(task concurrency.Task) (ip string, err error) {
	if objn == nil {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}

	ip = ""
	err = objn.Inspect(task, func(clonable data.Clonable) error {
		rn, ok := clonable.(*resources.Network)
		if !ok {
			return scerr.InconsistentError("'*resources.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if rn.VIP != nil && rn.VIP.PublicIP != "" {
			ip = rn.VIP.PublicIP
		} else {
			objpgw, inErr := LoadHost(task, objn.Service(), rn.GatewayID)
			if inErr != nil {
				return inErr
			}
			ip, inErr = objpgw.PublicIP(task)
			return inErr
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return ip, nil
}
