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

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// taskUnbindFromHost unbinds a host from the security group
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
	if !ok || hostInstance == nil {
		return nil, fail.InvalidParameterError("params", "must be a '*host' and cannot be nil")
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

// taskUnbindFromHostsAttachedToSubnet unbinds security group from hosts attached to a network
// 'params' expects to be a '*network'
func (instance *SecurityGroup) taskUnbindFromHostsAttachedToSubnet(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	subnetID, ok := params.(string)
	if !ok || subnetID == "" {
		return nil, fail.InvalidParameterError("params", "must be a non-empty string")
	}

	sgName := instance.GetName()

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	sgID := instance.GetID()
	svc := instance.GetService()

	rs, xerr := LoadNetwork(svc, subnetID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// subnet does not exist anymore ? considered as a success and continue
			debug.IgnoreError(xerr)
		default:
			return nil, xerr
		}
	} else {
		// Unbinds security group from hosts attached to subnet
		xerr = rs.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			innerXErr := props.Alter(subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
				nsgV1, ok := clonable.(*propertiesv1.SubnetHosts)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				tg, innerXErr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
				if innerXErr != nil {
					return fail.Wrap(innerXErr, "failed to start new task group to remove Security Group '%s' from Hosts attached to the Subnet '%s'", instance.GetName(), rs.GetName())
				}

				for _, v := range nsgV1.ByName {
					_, innerXErr = tg.Start(instance.taskUnbindFromHost, v, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s/unbind", v)))
					if innerXErr != nil {
						break
					}
				}
				_, innerXErr = tg.WaitGroup()
				return innerXErr
			})
			if innerXErr != nil {
				return innerXErr
			}

			return props.Alter(subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
				ssgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				delete(ssgV1.ByID, sgID)
				delete(ssgV1.ByName, sgName)
				return nil
			})
		})

		return nil, xerr
	}

	return nil, nil
}

// taskEnableOnHost applies rules of security group on host
// params is intended to receive a non-empty string corresponding to host ID
func (instance *SecurityGroup) taskEnableOnHost(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
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

	rh, innerXErr := LoadHost(instance.GetService(), hostID)
	if innerXErr != nil {
		switch innerXErr.(type) {
		case *fail.ErrNotFound:
			// host vanished, considered as a success
			debug.IgnoreError(innerXErr)
		default:
			return nil, innerXErr
		}
	} else {
		xerr := rh.EnableSecurityGroup(task.Context(), instance)
		rh.Released()
		return nil, xerr
	}
	return nil, nil
}

// taskDisableOnHost removes rules of security group from host
// params is intended to receive a non-empty string corresponding to host ID
func (instance *SecurityGroup) taskDisableOnHost(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
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
	rh, innerXErr := LoadHost(svc, hostID)
	if innerXErr != nil {
		switch innerXErr.(type) {
		case *fail.ErrNotFound:
			// host vanished, considered as a success
			debug.IgnoreError(innerXErr)
		default:
			return nil, innerXErr
		}
	} else {
		xerr := rh.DisableSecurityGroup(task.Context(), instance)
		rh.Released()
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// considered as a success
			debug.IgnoreError(xerr)
			return nil, nil
		default:
			return nil, xerr
		}
	}
	return nil, nil
}
