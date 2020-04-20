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

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

func (objn *network) taskCreateGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "failed to create gateway")
		}
	}()
	defer scerr.OnPanic(&err)()

	var (
		inputs data.Map
		ok     bool
	)
	if inputs, ok = params.(data.Map); !ok {
		return nil, scerr.InvalidParameterError("params", "must be a data.Map")
	}

	hostRequest, ok := inputs["request"].(abstract.HostRequest)
	if !ok {
		return nil, scerr.InvalidParameterError("params['request']", "must be a abstract.GatewayRequest")
	}
	if hostRequest.TemplateID == "" {
		return nil, scerr.InvalidRequestError("params['request'].TemplateID", "cannot be empty string")
	}
	if len(hostRequest.Networks) == 0 {
		return nil, scerr.InvalidRequestError("params['request'].Networks", "cannot be an empty '[]*abstract.Network'")
	}
	hostSizing, ok := inputs["sizing"].(abstract.HostSizingRequirements)
	if !ok {
		hostSizing = abstract.HostSizingRequirements{}
	}
	primary, ok := inputs["primary"].(bool)
	if !ok {
		return nil, scerr.InvalidParameterError("params['primary']", "must be a bool")
	}

	logrus.Infof("Requesting the creation of gateway '%s' using template '%s' with image '%s'", hostRequest.ResourceName, hostRequest.TemplateID, hostRequest.ImageID)
	svc := objn.SafeGetService()
	hostRequest.PublicIP = true
	hostRequest.IsGateway = true

	objgw, err := NewHost(svc)
	if err != nil {
		return nil, err
	}
	userData, err := objgw.Create(task, hostRequest, hostSizing)
	if err != nil {
		return nil, err
	}

	// Starting from here, deletes the gateway if exiting with error
	defer func() {
		if err != nil {
			logrus.Debugf("Cleaning up on failure, deleting gateway '%s' host resource...", hostRequest.ResourceName)
			derr := svc.DeleteHost(objgw.SafeGetID())
			if derr != nil {
				msgRoot := "Cleaning up on failure, failed to delete gateway '%s'"
				switch derr.(type) {
				case scerr.ErrNotFound:
					logrus.Errorf(msgRoot+", resource not found: %v", hostRequest.ResourceName, derr)
				case scerr.ErrTimeout:
					logrus.Errorf(msgRoot+", timeout: %v", hostRequest.ResourceName, derr)
				default:
					logrus.Errorf(msgRoot+": %v", hostRequest.ResourceName, derr)
				}
				err = scerr.AddConsequence(err, derr)
			} else {
				logrus.Infof("Cleaning up on failure, gateway '%s' deleted", hostRequest.ResourceName)
			}
			err = scerr.AddConsequence(err, derr)
		}
	}()

	//
	// // Updates properties in metadata
	// err = objgw.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
	// 	innerErr := props.Alter(task, hostproperty.SizingV2, func(clonable data.Clonable) error {
	// 		hostSizingV2, ok := clonable.(*propertiesv2.HostSizing)
	// 		if !ok {
	// 			return scerr.InconsistentError("'*propertiesv2.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	// 		hostSizingV2.AllocatedSize = converters.HostEffectiveSizingFromAbstractToPropertyV2(gwahf.Sizing)
	// 		return nil
	// 	})
	// 	if innerErr != nil {
	// 		return innerErr
	// 	}
	//
	// 	// Starting from here, delete host metadata if exiting with error
	// 	defer func() {
	// 		if innerErr != nil {
	// 			derr := objgw.(*host).core.Delete(task)
	// 			if derr != nil {
	// 				logrus.Errorf("After failure, failed to cleanup by removing host metadata")
	// 			}
	// 		}
	// 	}()
	//
	// 	// Sets host extension DescriptionV1
	// 	innerErr = props.Alter(task, hostproperty.DescriptionV1, func(clonable data.Clonable) error {
	// 		hostDescriptionV1, ok := clonable.(*propertiesv1.HostDescription)
	// 		if !ok {
	// 			return scerr.InconsistentError("'*propertiesv1.HostDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	// 		_ = hostDescriptionV1.Replace(converters.HostDescriptionFromAbstractToPropertyV1(*gwahf.Description))
	// 		creator := ""
	// 		hostname, _ := os.Hostname()
	// 		if curUser, err := user.Current(); err == nil {
	// 			creator = curUser.Username
	// 			if hostname != "" {
	// 				creator += "@" + hostname
	// 			}
	// 			if curUser.Name != "" {
	// 				creator += " (" + curUser.Name + ")"
	// 			}
	// 		} else {
	// 			creator = "unknown@" + hostname
	// 		}
	// 		hostDescriptionV1.Creator = creator
	// 		return nil
	// 	})
	// 	if innerErr != nil {
	// 		return innerErr
	// 	}
	//
	// 	// Updates host property propertiesv1.HostNetwork
	// 	// var (
	// 	// 	defaultNetworkID string
	// 	// 	gatewayID string
	// 	// )
	// 	innerErr = props.Alter(task, hostproperty.NetworkV1, func(clonable data.Clonable) error {
	// 		hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
	// 		if !ok {
	// 			return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	// 		_ = hostNetworkV1.Replace(converters.HostNetworkFromAbstractToPropertyV1(*gwahf.Network))
	// 		hostNetworkV1.DefaultNetworkID = objn.SafeGetID()
	// 		hostNetworkV1.IsGateway = true
	// 		return nil
	// 	})
	// 	if innerErr != nil {
	// 		return innerErr
	// 	}

	// Binds gateway to VIP if needed
	if an := hostRequest.Networks[0]; an != nil && an.VIP != nil {
		err = svc.BindHostToVIP(an.VIP, objgw.SafeGetID())
		if err != nil {
			return nil, err
		}
	}

	// 	return nil
	// })
	if err != nil {
		return nil, err
	}

	r := data.Map{
		"host":     objgw,
		"userdata": userData,
	}
	return r, nil
}

//
// func (objn *network) taskWaitForInstallPhase1OnGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
// 	objgw, ok := params.(resources.Host)
// 	if !ok {
// 		return nil, scerr.InconsistentError("'resources.Host' expected, '%s' provided", reflect.TypeOf(params).String())
// 	}
// 	gwname := objgw.SafeGetName()
//
// 	// A host claimed ready by a Cloud provider is not necessarily ready
// 	// to be used until ssh service is up and running. So we wait for it before
// 	// claiming host is created
// 	logrus.Infof("Waiting until gateway '%s' is available by SSH ...", gwname)
//
// 	ssh, err := objgw.GetSSHConfig(task)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	logrus.Debugf("Provisioning gateway '%s', phase 1", gwname)
// 	_, err = ssh.WaitServerReady(task, "phase1", temporal.GetHostCreationTimeout())
// 	if err != nil {
// 		if _, ok := err.(scerr.ErrTimeout); ok {
// 			return nil, err
// 		}
// 		if abstract.IsProvisioningError(err) {
// 			return nil, scerr.Wrap(err, "error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", gwname)
// 		}
// 		return nil, err
// 	}
// 	logrus.Infof("SSH service of gateway '%s' started.", gwname)
//
// 	return nil, nil
// }
//
// func (objn *network) taskInstallPhase2OnGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
// 	var (
// 		objgw    resources.Host
// 		userData *userdata.Content
// 		ok       bool
// 	)
// 	if objgw, ok = params.(data.Map)["host"].(resources.Host); !ok {
// 		return nil, scerr.InvalidParameterError("params['host']", "is missing or is not a 'resources.Host'")
// 	}
// 	if userData, ok = params.(data.Map)["userdata"].(*userdata.Content); !ok {
// 		return nil, scerr.InvalidParameterError("params['userdata']", "is missing or is not a '*userdata.Content'")
// 	}
// 	gwname := objgw.SafeGetName()
//
// 	// Executes userdata phase2 script to finalize host installation
// 	tracer := concurrency.NewTracer(nil, true, "(%s)", gwname).WithStopwatch().Entering()
// 	defer tracer.OnExitTrace()()
// 	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
// 	defer temporal.NewStopwatch().OnExitLogInfo(
// 		fmt.Sprintf("Starting configuration phase 2 on the gateway '%s'...", gwname),
// 		fmt.Sprintf("Ending configuration phase 2 on the gateway '%s'", gwname),
// 	)()
// 	defer scerr.OnPanic(&err)()
//
// 	content, err := userData.Generate("phase2")
// 	if err != nil {
// 		return nil, err
// 	}
// 	err = objgw.PushStringToFile(task, string(content), utils.TempFolder+"/user_data.phase2.sh", "", "")
// 	if err != nil {
// 		return nil, err
// 	}
// 	command := fmt.Sprintf("sudo bash %s/%s; exit $?", utils.TempFolder, "user_data.phase2.sh")
//
// 	// logrus.Debugf("Configuring gateway '%s', phase 2", gw.Name)
// 	returnCode, _, _, err := objgw.Run(task, command, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
// 	if err != nil {
// 		RetrieveForensicsData(task, objgw)
// 		return nil, err
// 	}
// 	if returnCode != 0 {
// 		RetrieveForensicsData(task, objgw)
// 		warnings, errs := GetPhaseWarningsAndErrors(task, objgw)
// 		return nil, scerr.NewError("failed to finalize gateway '%s' installation: phase2 returned code '%d', warnings '%s', errors '%s'", gwname, returnCode, warnings, errs)
// 	}
// 	logrus.Infof("Gateway '%s' successfully configured.", gwname)
//
// 	// Reboot gateway
// 	logrus.Debugf("Rebooting gateway '%s'", gwname)
// 	command = "sudo systemctl reboot"
// 	returnCode, _, _, err = objgw.Run(task, command, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
// 	if err != nil {
// 		return nil, err
// 	}
// 	if returnCode != 0 {
// 		logrus.Warnf("Unexpected problem rebooting...")
// 	}
//
// 	ssh, err := objgw.GetSSHConfig(task)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	sshDefaultTimeout := temporal.GetHostTimeout()
// 	_, err = ssh.WaitServerReady(task, "ready", sshDefaultTimeout)
// 	if err != nil {
// 		if _, ok := err.(scerr.ErrTimeout); ok {
// 			return nil, err
// 		}
// 		if abstract.IsProvisioningError(err) {
// 			logrus.Errorf("%+v", err)
// 			return nil, scerr.NewError("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", gwname)
// 		}
// 		return nil, err
// 	}
// 	return nil, nil
//
// }

func (objn *network) taskInstallPhase3OnGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
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
		fmt.Sprintf("Starting configuration phase 3 on the gateway '%s'...", gwname),
		fmt.Sprintf("Ending configuration phase 3 on the gateway '%s'", gwname),
	)()
	defer scerr.OnPanic(&err)()

	content, err := userData.Generate("phase3")
	if err != nil {
		return nil, err
	}
	err = objgw.PushStringToFile(task, string(content), utils.TempFolder+"/user_data.phase3.sh", "", "")
	if err != nil {
		return nil, err
	}
	command := fmt.Sprintf("sudo bash %s/%s; exit $?", utils.TempFolder, "user_data.phase3.sh")

	// logrus.Debugf("Configuring gateway '%s', phase 2", gw.Name)
	returnCode, _, _, err := objgw.Run(task, command, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil {
		RetrieveForensicsData(task, objgw)
		return nil, err
	}
	if returnCode != 0 {
		RetrieveForensicsData(task, objgw)
		warnings, errs := GetPhaseWarningsAndErrors(task, objgw)
		return nil, scerr.NewError("failed to finalize gateway '%s' installation: phase3 returned code '%d', warnings '%s', errors '%s'", gwname, returnCode, warnings, errs)
	}
	logrus.Infof("Gateway '%s' successfully configured.", gwname)
	//
	// // Reboot gateway
	// logrus.Debugf("Rebooting gateway '%s'", gwname)
	// command = "sudo systemctl reboot"
	// returnCode, _, _, err = objgw.Run(task, command, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	// if err != nil {
	// 	return nil, err
	// }
	// if returnCode != 0 {
	// 	logrus.Warnf("Unexpected problem rebooting...")
	// }
	//
	// ssh, err := objgw.GetSSHConfig(task)
	// if err != nil {
	// 	return nil, err
	// }
	//
	// sshDefaultTimeout := temporal.GetHostTimeout()
	// _, err = ssh.WaitServerReady(task, "ready", sshDefaultTimeout)
	// if err != nil {
	// 	if _, ok := err.(scerr.ErrTimeout); ok {
	// 		return nil, err
	// 	}
	// 	if abstract.IsProvisioningError(err) {
	// 		logrus.Errorf("%+v", err)
	// 		return nil, scerr.NewError("error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH", gwname)
	// 	}
	// 	return nil, err
	// }
	return nil, nil
}
