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

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

func (objn *network) taskCreateGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
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
		case scerr.ErrNotFound, scerr.ErrTimeout:
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
				case scerr.ErrNotFound:
					logrus.Errorf(msgRoot+", resource not found: %v", request.Name, derr)
				case scerr.ErrTimeout:
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
		case scerr.ErrNotFound, scerr.ErrTimeout:
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

func (objn *network) taskWaitForInstallPhase1OnGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {

	objgw, ok := params.(resources.Host)
	if !ok {
		return nil, scerr.InconsistentError("'resources.Host' expected, '%s' provided", reflect.TypeOf(params).String())
	}
	gwname := objgw.SafeGetName()

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	logrus.Infof("Waiting until gateway '%s' is available by SSH ...", gwname)

	ssh, err := objgw.GetSSHConfig(task)
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

func (objn *network) taskInstallPhase2OnGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
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

	ssh, err := objgw.GetSSHConfig(task)
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
