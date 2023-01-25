/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package resources

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type taskCreateGatewayParameters struct {
	request abstract.HostRequest
	sizing  abstract.HostSizingRequirements
}

func (instance *Subnet) trxCreateGateway(inctx context.Context, subnetTrx subnetTransaction, request abstract.HostRequest, sizing abstract.HostSizingRequirements) (_ data.Map[string, any], _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	if request.TemplateID == "" {
		return nil, fail.InvalidRequestError("request.TemplateID cannot be empty string")
	}
	if len(request.Subnets) == 0 {
		return nil, fail.InvalidRequestError("request.Networks cannot be an empty '[]*abstract.Network'")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  data.Map[string, any]
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			logrus.WithContext(ctx).Infof("Requesting the creation of gateway '%s' using template ID '%s', template name '%s', with image ID '%s'", request.ResourceName, request.TemplateID, request.TemplateRef, request.ImageID)
			svc := instance.Service()
			request.PublicIP = true
			request.IsGateway = true

			rgw, xerr := NewHost(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}

			cluID, _ := instance.GetID()
			userData, createXErr := rgw.Create(ctx, request, sizing, map[string]string{
				"type":      "gateway",
				"clusterID": cluID,
			}) // createXErr is tested later

			// Set link to Subnet before testing if Host has been successfully created;
			// in case of failure, we need to have registered the gateway ID in Subnet in case KeepOnFailure is requested, to
			// be able to delete subnet on later safescale command
			xerr = alterSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
				// If Host resources has been created and error occurred after (and KeepOnFailure is requested), rgw.ID() does contain the ID of the Host
				if rgw.IsTaken() {
					id, _ := rgw.GetID()
					if id != "" {
						as.GatewayIDs = append(as.GatewayIDs, id)
					}
				}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}

			// Now test localresult of gateway creation
			if createXErr != nil {
				ar := result{nil, createXErr}
				return ar, ar.rErr
			}

			// Starting from here, deletes the gateway if exiting with error
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil {
					hid, _ := rgw.GetID()

					if request.CleanOnFailure() {
						logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleting gateway '%s' Host resource...", request.ResourceName)
						derr := rgw.Delete(cleanupContextFrom(ctx))
						if derr != nil {
							msgRoot := "Cleaning up on failure, failed to delete gateway '%s'"
							switch derr.(type) {
							case *fail.ErrNotFound:
								// missing Host is considered as a successful deletion, continue
								debug.IgnoreErrorWithContext(ctx, derr)
							case *fail.ErrTimeout:
								logrus.WithContext(cleanupContextFrom(ctx)).Errorf(msgRoot+", timeout: %v", request.ResourceName, derr)
							default:
								logrus.WithContext(cleanupContextFrom(ctx)).Errorf(msgRoot+": %v", request.ResourceName, derr)
							}
							_ = ferr.AddConsequence(derr)
						} else {
							logrus.WithContext(ctx).Infof("Cleaning up on failure, gateway '%s' deleted", request.ResourceName)
						}
						_ = ferr.AddConsequence(derr)
					} else {
						rgwTrx, derr := newHostTransaction(ctx, rgw)
						if derr == nil {
							defer rgwTrx.TerminateBasedOnError(ctx, &ferr)

							derr = alterHostMetadataAbstract(cleanupContextFrom(ctx), rgwTrx, func(as *abstract.HostCore) fail.Error {
								as.LastState = hoststate.Failed
								return nil
							})
							derr = debug.InjectPlannedFail(derr)
							if derr == nil {
								derr = rgwTrx.Commit(ctx)
							}
						}
						if derr != nil {
							logrus.WithContext(ctx).Warnf("error marking host '%s' in FAILED state: %v", request.ResourceName, xerr)
							_ = ferr.AddConsequence(derr)
						}
					}

					if hid != "" {
						_ = svc.DeleteHost(cleanupContextFrom(ctx), hid)
					}
				}
			}()

			// Binds gateway to VIP if needed
			xerr = reviewSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
				hid, err := rgw.GetID()
				if err != nil {
					return fail.Wrap(err)
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
				return ar, ar.rErr
			}

			r := data.Map[string, any]{
				"host":     rgw,
				"userdata": userData,
			}
			ar := result{r, nil}
			return ar, ar.rErr
		}()
		chRes <- gres
	}() // nolint

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait for defer finishes
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for defer finishes
		return nil, fail.Wrap(inctx.Err())
	}
}

func (instance *Subnet) finalizeGatewayConfiguration(inctx context.Context, host *Host, ud *userdata.Content) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	gwname := host.GetName()
	tracer := debug.NewTracer(ctx, true, "(%s)", gwname).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage(""))
			defer temporal.NewStopwatch().OnExitLogInfo(ctx, fmt.Sprintf("Starting final configuration phases on the gateway '%s' with err '%s' ...", gwname, ferr), fmt.Sprintf("Ending final configuration phases on the gateway '%s'", gwname))()

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}

			// Executes userdata phase2 script to finalize host installation
			waitingTime := temporal.MaxTimeout(24*timings.RebootTimeout()/10, timings.HostCreationTimeout())

			if host.thePhaseDoesSomething(ctx, userdata.PHASE3_GATEWAY_HIGH_AVAILABILITY, ud) {
				xerr = host.runInstallPhase(ctx, userdata.PHASE3_GATEWAY_HIGH_AVAILABILITY, ud, waitingTime)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{nil, xerr}
					return ar, ar.rErr
				}
			} else {
				logrus.WithContext(ctx).Debugf("Nothing to do for the phase '%s'", userdata.PHASE3_GATEWAY_HIGH_AVAILABILITY)
			}

			if host.thePhaseDoesSomething(ctx, userdata.PHASE4_SYSTEM_FIXES, ud) {
				// If we have an error here, we just ignore it
				xerr = host.runInstallPhase(ctx, userdata.PHASE4_SYSTEM_FIXES, ud, waitingTime)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					theCause := fail.Wrap(fail.Cause(xerr))
					if _, ok := theCause.(*fail.ErrTimeout); !ok || valid.IsNil(theCause) {
						ar := result{nil, xerr}
						return ar, ar.rErr
					}

					debug.IgnoreErrorWithContext(ctx, xerr)
				}

				// intermediate gateway reboot
				logrus.WithContext(ctx).Infof("Rebooting gateway '%s'", gwname)
				xerr = host.Reboot(ctx, true)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{nil, xerr}
					return ar, ar.rErr
				}

				time.Sleep(timings.RebootTimeout())

				_, xerr = host.waitInstallPhase(ctx, userdata.PHASE4_SYSTEM_FIXES, waitingTime)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{nil, xerr}
					return ar, ar.rErr
				}
			} else {
				logrus.WithContext(ctx).Debugf("Nothing to do for the phase '%s'", userdata.PHASE4_SYSTEM_FIXES)
			}

			// final phase...
			xerr = host.runInstallPhase(ctx, userdata.PHASE5_FINAL, ud, waitingTime)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}

			// By design, phase 5 doesn't touch network cfg, so no reboot needed
			_, xerr = host.waitInstallPhase(ctx, userdata.PHASE5_FINAL, waitingTime)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}

			ar := result{nil, nil}
			return ar, ar.rErr
		}()
		chRes <- gres
	}() // nolint

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}
}
