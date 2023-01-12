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

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
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
func (instance *SecurityGroup) taskUnbindFromHost(inctx context.Context, params concurrency.TaskParameters) (_ concurrency.TaskResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	hostInstance, ok := params.(*Host)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a '*Host'")
	}
	if hostInstance == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params")
	}

	sgID, err := instance.GetID()
	if err != nil {
		return nil, fail.ConvertError(err)
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

		xerr := metadata.Alter(ctx, hostInstance, func(ahc *abstract.HostCore, props *serialize.JSONProperties) fail.Error {
			entry, innerXErr := instance.Job().Scope().Resource(ahc.Kind(), ahc.Name)
			if innerXErr != nil {
				return innerXErr
			}

			ahf, innerErr := lang.Cast[*abstract.HostFull](entry)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			return metadata.Alter(ctx, instance, func(asg *abstract.SecurityGroup, _ *serialize.JSONProperties) fail.Error {
				// Unbind Security Group from Host on provider side
				innerXErr := instance.Service().UnbindSecurityGroupFromHost(ctx, asg, ahf)
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
				return props.Alter(hostproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
					hsgV1, innerErr := clonable.Cast[*propertiesv1.HostSecurityGroups](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					delete(hsgV1.ByID, sgID)
					delete(hsgV1.ByName, instance.GetName())
					return nil
				})
			})
		})
		chRes <- result{nil, xerr}
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

type taskUnbindFromHostsAttachedToSubnetParams struct {
	subnetID, subnetName string
	subnetHosts          *propertiesv1.SubnetHosts
	onRemoval            bool
}

// taskUnbindFromHostsAttachedToSubnet unbinds security group from hosts attached to a Subnet
// 'params' expects to be a *propertiesv1.SubnetHosts
func (instance *SecurityGroup) taskUnbindFromHostsAttachedToSubnet(inctx context.Context, params concurrency.TaskParameters) (_ concurrency.TaskResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	p, ok := params.(taskUnbindFromHostsAttachedToSubnetParams)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskUnbindFromHostsAttachedToSubnetParams'")
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

		if len(p.subnetHosts.ByID) > 0 {
			tg := new(errgroup.Group)

			for k, v := range p.subnetHosts.ByID {
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

					_, err := instance.taskUnbindFromHost(ctx, hostInstance)
					return err
				})

			}

			werr := fail.ConvertError(tg.Wait())
			werr = debug.InjectPlannedFail(werr)
			if werr != nil {
				chRes <- result{nil, werr}
				return
			}
		}

		chRes <- result{nil, nil}
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
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
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
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
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}
