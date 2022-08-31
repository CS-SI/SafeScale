/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

type taskCreateGatewayParameters struct {
	request abstract.HostRequest
	sizing  abstract.HostSizingRequirements
}

func (instance *Subnet) taskCreateGateway(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() (ferr fail.Error) {
		defer fail.OnPanic(&ferr)
		defer close(chRes)

		castedParams, ok := params.(taskCreateGatewayParameters)
		if !ok {
			ar := result{nil, fail.InconsistentError("failed to cast params to 'taskCreateGatewayParameters'")}
			chRes <- ar
			return ar.rErr
		}

		hostReq := castedParams.request
		if hostReq.TemplateID == "" {
			ar := result{nil, fail.InvalidRequestError("params.request.TemplateID cannot be empty string")}
			chRes <- ar
			return ar.rErr
		}
		if len(hostReq.Subnets) == 0 {
			ar := result{nil, fail.InvalidRequestError("params.request.Networks cannot be an empty '[]*abstract.Network'")}
			chRes <- ar
			return ar.rErr
		}

		hostSizing := castedParams.sizing

		logrus.WithContext(ctx).Infof("Requesting the creation of gateway '%s' using template ID '%s', template name '%s', with image ID '%s'", hostReq.ResourceName, hostReq.TemplateID, hostReq.TemplateRef, hostReq.ImageID)
		svc := instance.Service()
		hostReq.PublicIP = true
		hostReq.IsGateway = true

		rgw, xerr := NewHost(svc)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			ar := result{nil, xerr}
			chRes <- ar
			return ar.rErr
		}

		userData, createXErr := rgw.Create(ctx, hostReq, hostSizing) // createXErr is tested later

		// Set link to Subnet before testing if Host has been successfully created;
		// in case of failure, we need to have registered the gateway ID in Subnet in case KeepOnFailure is requested, to
		// be able to delete subnet on later safescale command
		xerr = instance.Alter(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
			as, ok := clonable.(*abstract.Subnet)
			if !ok {
				return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// If Host resources has been created and error occurred after (and KeepOnFailure is requested), rgw.ID() does contain the ID of the Host
			if rgw.IsTaken() {
				if id, _ := rgw.GetID(); id != "" {
					as.GatewayIDs = append(as.GatewayIDs, id)
				}
			}
			return nil
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			ar := result{nil, xerr}
			chRes <- ar
			return ar.rErr
		}

		// Now test result of gateway creation
		if createXErr != nil {
			ar := result{nil, createXErr}
			chRes <- ar
			return ar.rErr
		}

		// Starting from here, deletes the gateway if exiting with error
		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil {
				if !hostReq.KeepOnFailure {
					logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleting gateway '%s' Host resource...", hostReq.ResourceName)
					derr := rgw.Delete(context.Background())
					if derr != nil {
						msgRoot := "Cleaning up on failure, failed to delete gateway '%s'"
						switch derr.(type) {
						case *fail.ErrNotFound:
							// missing Host is considered as a successful deletion, continue
							debug.IgnoreError(derr)
						case *fail.ErrTimeout:
							logrus.WithContext(context.Background()).Errorf(msgRoot+", timeout: %v", hostReq.ResourceName, derr)
						default:
							logrus.WithContext(context.Background()).Errorf(msgRoot+": %v", hostReq.ResourceName, derr)
						}
						_ = ferr.AddConsequence(derr)
					} else {
						logrus.WithContext(ctx).Infof("Cleaning up on failure, gateway '%s' deleted", hostReq.ResourceName)
					}
					_ = ferr.AddConsequence(derr)
				} else {
					xerr = rgw.Alter(context.Background(), func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
						as, ok := clonable.(*abstract.HostCore)
						if !ok {
							return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}

						as.LastState = hoststate.Failed
						return nil
					})
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						logrus.WithContext(ctx).Warnf("error marking host '%s' in FAILED state: %v", hostReq.ResourceName, xerr)
					}
				}
			}
		}()

		// Binds gateway to VIP if needed
		xerr = instance.Review(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
			as, ok := clonable.(*abstract.Subnet)
			if !ok {
				return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			hid, err := rgw.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}

			if as != nil && as.VIP != nil {
				xerr = svc.BindHostToVIP(ctx, as.VIP, hid)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}
			}
			return nil
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			ar := result{nil, xerr}
			chRes <- ar
			return ar.rErr
		}

		r := data.Map{
			"host":     rgw,
			"userdata": userData,
		}
		ar := result{r, nil}
		chRes <- ar
		return ar.rErr // nolint
	}() // nolint
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait for defer finishes
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for defer finishes
		return nil, fail.ConvertError(inctx.Err())
	}

}

type taskFinalizeGatewayConfigurationParameters struct {
	host     *Host
	userdata *userdata.Content
}

func (instance *Subnet) taskFinalizeGatewayConfiguration(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, gerr fail.Error) {
	defer fail.OnPanic(&gerr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() (ferr fail.Error) {
		defer close(chRes)

		castedParams, ok := params.(taskFinalizeGatewayConfigurationParameters)
		if !ok {
			xerr := fail.InconsistentError("failed to cast params to 'taskFinalizeGatewayConfigurationParameters'")
			chRes <- result{nil, xerr}
			return xerr
		}

		timings, xerr := instance.Service().Timings()
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
		}

		objgw := castedParams.host
		if valid.IsNil(objgw) {
			xerr := fail.InvalidParameterError("params.host", "cannot be null value of 'host'")
			chRes <- result{nil, xerr}
			return xerr
		}

		userData := castedParams.userdata
		gwname := objgw.GetName()

		// Executes userdata phase2 script to finalize host installation
		tracer := debug.NewTracer(ctx, true, "(%s)", gwname).WithStopwatch().Entering()
		defer tracer.Exiting()
		defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage(""))
		defer temporal.NewStopwatch().OnExitLogInfo(ctx, fmt.Sprintf("Starting final configuration phases on the gateway '%s'...", gwname), fmt.Sprintf("Ending final configuration phases on the gateway '%s'", gwname))()

		waitingTime := temporal.MaxTimeout(24*timings.RebootTimeout()/10, timings.HostCreationTimeout())

		if objgw.thePhaseDoesSomething(ctx, userdata.PHASE3_GATEWAY_HIGH_AVAILABILITY, userData) {
			xerr = objgw.runInstallPhase(ctx, userdata.PHASE3_GATEWAY_HIGH_AVAILABILITY, userData, waitingTime)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{nil, xerr}
				return xerr
			}
		} else {
			logrus.WithContext(ctx).Debugf("Nothing to do for the phase '%s'", userdata.PHASE3_GATEWAY_HIGH_AVAILABILITY)
		}

		if objgw.thePhaseDoesSomething(ctx, userdata.PHASE4_SYSTEM_FIXES, userData) {
			// If we have an error here, we just ignore it
			xerr = objgw.runInstallPhase(ctx, userdata.PHASE4_SYSTEM_FIXES, userData, waitingTime)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				theCause := fail.ConvertError(fail.Cause(xerr))
				if _, ok := theCause.(*fail.ErrTimeout); !ok || valid.IsNil(theCause) {
					chRes <- result{nil, xerr}
					return xerr
				}

				debug.IgnoreError(xerr)
			}

			// intermediate gateway reboot
			logrus.WithContext(ctx).Infof("Rebooting gateway '%s'", gwname)
			xerr = objgw.Reboot(ctx, true)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{nil, xerr}
				return xerr
			}

			time.Sleep(timings.RebootTimeout())

			_, xerr = objgw.waitInstallPhase(ctx, userdata.PHASE4_SYSTEM_FIXES, waitingTime)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{nil, xerr}
				return xerr
			}
		} else {
			logrus.WithContext(ctx).Debugf("Nothing to do for the phase '%s'", userdata.PHASE4_SYSTEM_FIXES)
		}

		// final phase...
		xerr = objgw.runInstallPhase(ctx, userdata.PHASE5_FINAL, userData, waitingTime)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
		}

		// By design, phase 5 doesn't  touch network cfg, so no reboot needed
		_, xerr = objgw.waitInstallPhase(ctx, userdata.PHASE5_FINAL, waitingTime)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
		}

		chRes <- result{nil, nil}
		return nil // nolint
	}() // nolint
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}