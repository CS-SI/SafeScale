/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

type taskCreateGatewayParameters struct {
	request abstract.HostRequest
	sizing  abstract.HostSizingRequirements
}

func (instance *Subnet) taskCreateGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	hostReq := params.(taskCreateGatewayParameters).request
	if hostReq.TemplateID == "" {
		return nil, fail.InvalidRequestError("params.request.TemplateID cannot be empty string")
	}
	if len(hostReq.Subnets) == 0 {
		return nil, fail.InvalidRequestError("params.request.Networks cannot be an empty '[]*abstract.Network'")
	}
	hostSizing := params.(taskCreateGatewayParameters).sizing

	logrus.Infof("Requesting the creation of gateway '%s' using template '%s' with image '%s'", hostReq.ResourceName, hostReq.TemplateID, hostReq.ImageID)
	svc := instance.GetService()
	hostReq.PublicIP = true
	hostReq.IsGateway = true

	rgw, xerr := NewHost(svc)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	userData, createXErr := rgw.Create(task.Context(), hostReq, hostSizing) // createXErr is tested later

	// Set link to Subnet before testing if Host has been successfully created;
	// in case of failure, we need to have registered the gateway ID in Subnet in case KeepOnFailure is requested, to
	// be able to delete subnet on later safescale command
	xerr = instance.Alter(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		// If Host resources has been created and error occured after (and KeepOnFailure is requested), rgw.ID() does contain the ID of the Host
		if id := rgw.GetID(); id != "" {
			as.GatewayIDs = append(as.GatewayIDs, id)
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Now test result of gateway creation
	if createXErr != nil {
		return nil, createXErr
	}

	// Starting from here, deletes the gateway if exiting with error
	defer func() {
		if xerr != nil && !hostReq.KeepOnFailure {
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

			logrus.Debugf("Cleaning up on failure, deleting gateway '%s' Host resource...", hostReq.ResourceName)
			derr := rgw.Delete(task.Context())
			if derr != nil {
				msgRoot := "Cleaning up on failure, failed to delete gateway '%s'"
				switch derr.(type) {
				case *fail.ErrNotFound:
					// missing Host is considered as a successful deletion, continue
					debug.IgnoreError(derr)
				case *fail.ErrTimeout:
					logrus.Errorf(msgRoot+", timeout: %v", hostReq.ResourceName, derr)
				default:
					logrus.Errorf(msgRoot+": %v", hostReq.ResourceName, derr)
				}
				_ = xerr.AddConsequence(derr)
			} else {
				logrus.Infof("Cleaning up on failure, gateway '%s' deleted", hostReq.ResourceName)
			}
			_ = xerr.AddConsequence(derr)
		}
	}()

	// Binds gateway to VIP if needed
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		if as != nil && as.VIP != nil {
			xerr = svc.BindHostToVIP(as.VIP, rgw.GetID())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	r := data.Map{
		"host":     rgw,
		"userdata": userData,
	}
	return r, nil
}

type taskFinalizeGatewayConfigurationParameters struct {
	host     *Host
	userdata *userdata.Content
}

func (instance *Subnet) taskFinalizeGatewayConfiguration(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	objgw := params.(taskFinalizeGatewayConfigurationParameters).host
	if objgw == nil || objgw.IsNull() {
		return nil, fail.InvalidParameterError("params.host", "cannot be null value of 'host'")
	}
	userData := params.(taskFinalizeGatewayConfigurationParameters).userdata
	gwname := objgw.GetName()

	// Executes userdata phase2 script to finalize host installation
	tracer := debug.NewTracer(nil, true, "(%s)", gwname).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting final configuration phases on the gateway '%s'...", gwname),
		fmt.Sprintf("Ending final configuration phases on the gateway '%s'", gwname),
	)()

	xerr = objgw.runInstallPhase(task.Context(), userdata.PHASE3_GATEWAY_HIGH_AVAILABILITY, userData)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	xerr = objgw.runInstallPhase(task.Context(), userdata.PHASE4_SYSTEM_FIXES, userData)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// intermediate gateway reboot
	logrus.Infof("Rebooting gateway '%s'", gwname)
	command := `echo "sleep 4 ; sudo systemctl reboot" | at now`
	rebootCtx, cancelReboot := context.WithTimeout(task.Context(), 3*time.Minute)
	defer cancelReboot()
	_, _, _, xerr = objgw.Run(rebootCtx, command, outputs.COLLECT, 10*time.Second, 3*time.Minute)
	if xerr != nil {
		logrus.Debugf("there was an error sending the reboot command: %v", xerr)
	}
	time.Sleep(5 * time.Second)

	_, xerr = objgw.waitInstallPhase(task.Context(), userdata.PHASE4_SYSTEM_FIXES, 0)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// final phase...
	xerr = objgw.runInstallPhase(task.Context(), userdata.PHASE5_FINAL, userData)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Final gateway reboot
	logrus.Infof("Rebooting gateway '%s'", gwname)
	command = `echo "sleep 4 ; sudo systemctl reboot" | at now`
	lastRebootCtx, lastCancelReboot := context.WithTimeout(task.Context(), 3*time.Minute)
	defer lastCancelReboot()
	_, _, _, xerr = objgw.Run(lastRebootCtx, command, outputs.COLLECT, 10*time.Second, 3*time.Minute)
	if xerr != nil {
		logrus.Debugf("there was an error sending the reboot command: %v", xerr)
	}
	time.Sleep(5 * time.Second)

	_, xerr = objgw.waitInstallPhase(task.Context(), userdata.PHASE5_FINAL, time.Duration(0))
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return nil, nil
}
