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

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"golang.org/x/sync/errgroup"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// taskUnbindFromHost unbinds a Host from the security group
// params is intended to receive a '*host'
func (instance *SecurityGroup) trxUnbindFromHost(inctx context.Context, sgTrx securityGroupTransaction, hostTrx hostTransaction) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}
	if sgTrx == nil {
		return fail.InvalidParameterCannotBeNilError("sgTrx")
	}
	if hostTrx == nil {
		return fail.InvalidParameterCannotBeNilError("hostTrx")
	}

	sgID, err := instance.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		xerr := alterHostMetadata(ctx, hostTrx, func(ahc *abstract.HostCore, hostProps *serialize.JSONProperties) fail.Error {
			return alterSecurityGroupMetadata(ctx, sgTrx, func(asg *abstract.SecurityGroup, sgProps *serialize.JSONProperties) fail.Error {
				// Unbind Security Group from Host on provider side
				innerXErr := instance.Service().UnbindSecurityGroupFromHost(ctx, asg, ahc)
				innerXErr = debug.InjectPlannedFail(innerXErr)
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound:
						// if the security group is not bound to the host, considered as a success and continue
						debug.IgnoreErrorWithContext(ctx, innerXErr)
					default:
						return innerXErr
					}
				}

				// Updates host metadata regarding Security Groups
				innerXErr = hostProps.Alter(hostproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
					hsgV1, innerErr := clonable.Cast[*propertiesv1.HostSecurityGroups](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					delete(hsgV1.ByID, sgID)
					delete(hsgV1.ByName, instance.GetName())
					return nil
				})
				if innerXErr != nil {
					return innerXErr
				}

				// updates security group properties
				return sgProps.Alter(securitygroupproperty.HostsV1, func(p clonable.Clonable) fail.Error {
					sgphV1, innerErr := lang.Cast[*propertiesv1.SecurityGroupHosts](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					delete(sgphV1.ByID, ahc.ID)
					delete(sgphV1.ByName, ahc.Name)
					return nil
				})

			})
		})
		chRes <- result{xerr}
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// trxUnbindFromHostsAttachedToSubnet unbinds security group from hosts attached to a Subnet
func (instance *SecurityGroup) trxUnbindFromHostsAttachedToSubnet(inctx context.Context, sgTrx securityGroupTransaction, subnetTrx subnetTransaction) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gerr := func() (ferr fail.Error) {
			return inspectSubnetMetadataProperty(ctx, subnetTrx, subnetproperty.HostsV1, func(shV1 *propertiesv1.SubnetHosts) fail.Error {
				if len(shV1.ByID) > 0 {
					tg := new(errgroup.Group)

					for k, v := range shV1.ByID {
						k, _ := k, v

						tg.Go(func() error {
							hostInstance, xerr := LoadHost(ctx, k)
							if xerr != nil {
								switch xerr.(type) {
								case *fail.ErrNotFound:
									// if Host is not found, consider operation as a success and continue
									debug.IgnoreErrorWithContext(ctx, xerr)
									return nil
								default:
									return xerr
								}
							}

							hostTrx, xerr := newHostTransaction(ctx, hostInstance)
							if xerr != nil {
								return xerr
							}
							defer func(trx hostTransaction) { trx.TerminateFromError(ctx, &ferr) }(hostTrx)

							return instance.trxUnbindFromHost(ctx, sgTrx, hostTrx)
						})

					}

					werr := fail.Wrap(tg.Wait())
					werr = debug.InjectPlannedFail(werr)
					if werr != nil {
						return werr
					}
				}
				return nil
			})
		}()

		chRes <- result{gerr}
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// taskBindEnabledOnHost binds the SG if needed (applying rules) and enables it on Host
// params is intended to receive a non-empty string corresponding to host ID
// returns:
// - nil, nil: everything is ok
// - nil, *fail.ErrInvalidParameter: some parameters are invalid
// - nil, *fail.ErrAborted: received abortion signal
// - nil, *fail.ErrNotFound: Host identified by params not found
func (instance *SecurityGroup) taskBindEnabledOnHost(inctx context.Context, params concurrency.TaskParameters) (_ concurrency.TaskResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		hostID, ok := params.(string)
		if !ok || hostID == "" {
			chRes <- result{nil, fail.InvalidParameterError("params", "must be a non-empty string")}
			return
		}

		hostInstance, innerXErr := LoadHost(ctx, hostID)
		if innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				// host vanished, considered as a success
				debug.IgnoreErrorWithContext(ctx, innerXErr)
			default:
				chRes <- result{nil, innerXErr}
				return
			}
		} else {
			// Before enabling SG on Host, make sure the SG is bound to Host
			xerr := hostInstance.BindSecurityGroup(ctx, instance, true)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrDuplicate:
					chRes <- result{nil, hostInstance.EnableSecurityGroup(ctx, instance)}
					return
				default:
					chRes <- result{nil, xerr}
					return
				}
			}
		}
		chRes <- result{nil, nil}
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}
}

// taskBindDisabledOnHost removes rules of security group from host
// params is intended to receive a non-empty string corresponding to host ID
func (instance *SecurityGroup) taskBindDisabledOnHost(inctx context.Context, params concurrency.TaskParameters) (_ concurrency.TaskResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		hostID, ok := params.(string)
		if !ok || hostID == "" {
			chRes <- result{nil, fail.InvalidParameterError("params", "must be a non-empty string")}
			return
		}

		hostInstance, innerXErr := LoadHost(ctx, hostID)
		if innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				// host vanished, considered as a success
				debug.IgnoreErrorWithContext(ctx, innerXErr)
			default:
				chRes <- result{nil, innerXErr}
				return
			}
		} else {
			xerr := hostInstance.BindSecurityGroup(ctx, instance, false)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrDuplicate:
					chRes <- result{nil, hostInstance.DisableSecurityGroup(ctx, instance)}
					return
				default:
					chRes <- result{nil, xerr}
					return
				}
			}
		}
		chRes <- result{nil, nil}
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}
}
