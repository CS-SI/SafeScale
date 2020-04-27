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
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

func (objn *network) taskCreateGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	defer scerr.OnPanic(&err)

	var (
		inputs data.Map
		ok     bool
	)
	if inputs, ok = params.(data.Map); !ok {
		return nil, scerr.InvalidParameterError("params", "must be a data.Map")
	}

	hostReq, ok := inputs["request"].(abstract.HostRequest)
	if !ok {
		return nil, scerr.InvalidParameterError("params['request']", "must be a abstract.GatewayRequest")
	}
	if hostReq.TemplateID == "" {
		return nil, scerr.InvalidRequestError("params['request'].TemplateID", "cannot be empty string")
	}
	if len(hostReq.Networks) == 0 {
		return nil, scerr.InvalidRequestError("params['request'].Networks", "cannot be an empty '[]*abstract.Network'")
	}
	hostSizing, ok := inputs["sizing"].(abstract.HostSizingRequirements)
	if !ok {
		hostSizing = abstract.HostSizingRequirements{}
	}
	primary, ok := inputs["primary"].(bool)
	if !ok {
		return nil, scerr.InvalidRequestError("params['primary']", "is mandatory")
	}

	logrus.Infof("Requesting the creation of gateway '%s' using template '%s' with image '%s'", hostReq.ResourceName, hostReq.TemplateID, hostReq.ImageID)
	svc := objn.SafeGetService()
	hostReq.PublicIP = true
	hostReq.IsGateway = true

	objgw, err := NewHost(svc)
	if err != nil {
		return nil, err
	}
	userData, err := objgw.Create(task, hostReq, hostSizing)
	if err != nil {
		return nil, err
	}

	// Starting from here, deletes the gateway if exiting with error
	defer func() {
		if err != nil && !hostReq.KeepOnFailure {
			logrus.Debugf("Cleaning up on failure, deleting gateway '%s' host resource...", hostReq.ResourceName)
			derr := objgw.Delete(task)
			if derr != nil {
				msgRoot := "Cleaning up on failure, failed to delete gateway '%s'"
				switch derr.(type) {
				case scerr.ErrNotFound:
					logrus.Errorf(msgRoot+", resource not found: %v", hostReq.ResourceName, derr)
				case scerr.ErrTimeout:
					logrus.Errorf(msgRoot+", timeout: %v", hostReq.ResourceName, derr)
				default:
					logrus.Errorf(msgRoot+": %v", hostReq.ResourceName, derr)
				}
				err = scerr.AddConsequence(err, derr)
			} else {
				logrus.Infof("Cleaning up on failure, gateway '%s' deleted", hostReq.ResourceName)
			}
			err = scerr.AddConsequence(err, derr)
		}
	}()

	// Set link to network
	err = objn.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if primary {
			an.GatewayID = objgw.SafeGetID()
		} else {
			an.SecondaryGatewayID = objgw.SafeGetID()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Binds gateway to VIP if needed
	if an := hostReq.Networks[0]; an != nil && an.VIP != nil {
		err = svc.BindHostToVIP(an.VIP, objgw.SafeGetID())
		if err != nil {
			return nil, err
		}
	}

	r := data.Map{
		"host":     objgw,
		"userdata": userData,
	}
	return r, nil
}

func (objn *network) taskFinalizeGatewayConfiguration(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	var (
		objgw    *host
		userData *userdata.Content
		ok       bool
	)
	if objgw, ok = params.(data.Map)["host"].(*host); !ok {
		return nil, scerr.InvalidParameterError("params['host']", "is missing or is not a '*operations.host'")
	}
	if userData, ok = params.(data.Map)["userdata"].(*userdata.Content); !ok {
		return nil, scerr.InvalidParameterError("params['userdata']", "is missing or is not a '*userdata.Content'")
	}
	gwname := objgw.SafeGetName()

	// Executes userdata phase2 script to finalize host installation
	tracer := concurrency.NewTracer(nil, true, "(%s)", gwname).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)
	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting configuration phase 3 on the gateway '%s'...", gwname),
		fmt.Sprintf("Ending configuration phase 3 on the gateway '%s'", gwname),
	)()
	defer scerr.OnPanic(&err)

	err = objgw.runInstallPhase(task, userdata.PHASE3_GATEWAY_HIGH_AVAILABILITY, userData)
	if err != nil {
		return nil, err
	}

	err = objgw.runInstallPhase(task, userdata.PHASE4_SYSTEM_FIXES, userData)
	if err != nil {
		return nil, err
	}

	// intermediate gateway reboot
	logrus.Debugf("Rebooting gateway '%s'", gwname)
	command := "sudo systemctl reboot"
	retcode, _, _, err := objgw.Run(task, command, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil {
		return nil, err
	}
	if retcode != 0 {
		logrus.Warnf("Unexpected problem rebooting...")
	}

	// final phase...
	err = objgw.runInstallPhase(task, userdata.PHASE5_FINAL, userData)
	if err != nil {
		return nil, err
	}

	// Final gatewqay reboot
	logrus.Debugf("Rebooting gateway '%s'", gwname)
	command = "sudo systemctl reboot"
	retcode, _, _, err = objgw.Run(task, command, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil {
		return nil, err
	}
	if retcode != 0 {
		logrus.Warnf("Unexpected problem rebooting...")
	}

	_, err = objgw.waitInstallPhase(task, "final")
	if err != nil {
		return nil, err
	}

	return nil, nil
}
