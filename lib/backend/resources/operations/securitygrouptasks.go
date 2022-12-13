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
	"reflect"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"golang.org/x/sync/errgroup"
)

// taskUnbindFromHost unbinds a Host from the security group
// params is intended to receive a '*host'
func (instance *SecurityGroup) taskUnbindFromHost(
	inctx context.Context, params interface{},
) (_ interface{}, ferr fail.Error) {
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

		hostInstance, ok := params.(*Host)
		if !ok {
			chRes <- result{nil, fail.InvalidParameterError("params", "must be a '*Host'")}
			return
		}
		if hostInstance == nil {
			chRes <- result{nil, fail.InvalidParameterCannotBeNilError("params")}
			return
		}

		sgID, err := instance.GetID()
		if err != nil {
			chRes <- result{nil, fail.ConvertError(err)}
			return
		}

		hid, err := hostInstance.GetID()
		if err != nil {
			chRes <- result{nil, fail.ConvertError(err)}
			return
		}

		// Unbind Security Group from Host on provider side
		xerr := instance.Service().UnbindSecurityGroupFromHost(ctx, sgID, hid)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// if the security group is not bound to the host, considered as a success and continue
				debug.IgnoreError2(ctx, xerr)
			default:
				chRes <- result{nil, xerr}
				return
			}
		}

		// Updates host metadata regarding Security Groups
		xerr = hostInstance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
				hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				delete(hsgV1.ByID, sgID)
				delete(hsgV1.ByName, instance.GetName())
				return nil
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
func (instance *SecurityGroup) taskUnbindFromHostsAttachedToSubnet(
	inctx context.Context, params interface{},
) (_ interface{}, ferr fail.Error) {
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

			svc := instance.Service()
			for k, v := range p.subnetHosts.ByID {
				k, _ := k, v

				tg.Go(func() error {
					hostInstance, xerr := LoadHost(ctx, svc, k)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							// if Host is not found, consider operation as a success and continue
							debug.IgnoreError2(ctx, xerr)
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
func (instance *SecurityGroup) taskBindEnabledOnHost(
	inctx context.Context, params interface{},
) (_ interface{}, ferr fail.Error) {
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

		hostInstance, innerXErr := LoadHost(ctx, instance.Service(), hostID)
		if innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				// host vanished, considered as a success
				debug.IgnoreError2(ctx, innerXErr)
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
func (instance *SecurityGroup) taskBindDisabledOnHost(
	inctx context.Context, params interface{},
) (_ interface{}, ferr fail.Error) {
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

		svc := instance.Service()
		hostInstance, innerXErr := LoadHost(ctx, svc, hostID)
		if innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				// host vanished, considered as a success
				debug.IgnoreError2(ctx, innerXErr)
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
