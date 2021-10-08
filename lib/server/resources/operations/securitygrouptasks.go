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
	"fmt"
	"reflect"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// taskUnbindFromHost unbinds a Host from the security group
// params is intended to receive a '*host'
func (instance *SecurityGroup) taskUnbindFromHost(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	hostInstance, ok := params.(*Host)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a '*Host'")
	}
	if hostInstance == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	sgID := instance.GetID()

	// Unbind Security Group from Host on provider side
	xerr = instance.GetService().UnbindSecurityGroupFromHost(sgID, hostInstance.GetID())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// if the security group is not bound to the host, considered as a success and continue
			debug.IgnoreError(xerr)
		default:
			return nil, xerr
		}
	}

	// Updates host metadata regarding Security Groups
	xerr = hostInstance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
	return nil, xerr
}

type taskUnbindFromHostsAttachedToSubnetParams struct {
	subnetID, subnetName string
	subnetHosts          *propertiesv1.SubnetHosts
}

// taskUnbindFromHostsAttachedToSubnet unbinds security group from hosts attached to a Subnet
// 'params' expects to be a *propertiesv1.SubnetHosts
func (instance *SecurityGroup) taskUnbindFromHostsAttachedToSubnet(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
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

	p, ok := params.(taskUnbindFromHostsAttachedToSubnetParams)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskUnbindFromHostsAttachedToSubnetParams'")
	}

	if len(p.subnetHosts.ByID) > 0 {
		tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to start new task group to remove Security Group '%s' from Hosts attached to the Subnet '%s'", instance.GetName(), p.subnetName)
		}

		svc := instance.GetService()
		for k, v := range p.subnetHosts.ByID {
			hostInstance, xerr := LoadHost(svc, k)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// if Host is not found, consider operation as a success and continue
					continue
				default:
					return nil, xerr
				}
			}
			defer func(in resources.Host) {
				in.Released()
			}(hostInstance)

			_, xerr = tg.Start(instance.taskUnbindFromHost, hostInstance, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s/unbind", v)))
			if xerr != nil {
				break
			}
		}
		_, werr := tg.WaitGroup()
		if werr != nil {
			if xerr != nil {
				_ = xerr.AddConsequence(werr)
			} else {
				xerr = werr
			}
		}

		return nil, xerr
	}

	return nil, nil
}

// taskBindEnabledOnHost binds the SG if needed (applying rules) and enables it on Host
// params is intended to receive a non-empty string corresponding to host ID
// returns:
// - nil, nil: everything is ok
// - nil, *fail.ErrInvalidParameter: some parameters are invalid
// - nil, *fail.ErrAborted: received abortion signal
// - nil, *fail.ErrNotFound: Host identified by params not found
func (instance *SecurityGroup) taskBindEnabledOnHost(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
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

	hostID, ok := params.(string)
	if !ok || hostID == "" {
		return nil, fail.InvalidParameterError("params", "must be a non-empty string")
	}

	hostInstance, innerXErr := LoadHost(instance.GetService(), hostID)
	if innerXErr != nil {
		switch innerXErr.(type) {
		case *fail.ErrNotFound:
			// host vanished, considered as a success
			debug.IgnoreError(innerXErr)
			break
		default:
			return nil, innerXErr
		}
	} else {
		defer hostInstance.Released()

		// Before enabling SG on Host, make sure the SG is bound to Host
		xerr := hostInstance.BindSecurityGroup(task.Context(), instance, true)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrDuplicate:
				return nil, hostInstance.EnableSecurityGroup(task.Context(), instance)
			default:
				return nil, xerr
			}
		}
	}
	return nil, nil
}

// taskBindDisabledOnHost removes rules of security group from host
// params is intended to receive a non-empty string corresponding to host ID
func (instance *SecurityGroup) taskBindDisabledOnHost(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
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

	hostID, ok := params.(string)
	if !ok || hostID == "" {
		return nil, fail.InvalidParameterError("params", "must be a non-empty string")
	}

	svc := instance.GetService()
	hostInstance, innerXErr := LoadHost(svc, hostID)
	if innerXErr != nil {
		switch innerXErr.(type) {
		case *fail.ErrNotFound:
			// host vanished, considered as a success
			debug.IgnoreError(innerXErr)
		default:
			return nil, innerXErr
		}
	} else {
		xerr := hostInstance.BindSecurityGroup(task.Context(), instance, false)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrDuplicate:
				return nil, hostInstance.DisableSecurityGroup(task.Context(), instance)
			default:
				return nil, xerr
			}
		}
	}
	return nil, nil
}
