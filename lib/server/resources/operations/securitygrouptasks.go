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
	"reflect"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/networkproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// taskUnbindFromHost unbinds a host from the security group
// params is intended to receive a '*host'
func (sg *securityGroup) taskUnbindFromHost(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
	rh, ok := params.(*host)
	if !ok || rh == nil {
		return nil, fail.InvalidParameterError("params", "must be a '*host' and cannot be nil")
	}

	sgID := sg.GetID()

	// Unbind security group from host on provider side
	xerr := sg.GetService().UnbindSecurityGroupFromHost(rh.GetID(), sgID)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// if the security group is not binded to the host, consider as a success and continue
		default:
			return nil, xerr
		}
	}

	//// Updates metadata
	//rh, xerr := LoadHost(task, sg.GetService(), hostID)
	//if xerr != nil {
	//	switch xerr.(type) {
	//	case *fail.ErrNotFound:
	//		// host does not exist anymore ? consider as a success and continue
	//	default:
	//		return nil, xerr
	//	}
	//} else {
	// Updates host metadata regarding Security Groups
	xerr = rh.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			delete(hsgV1.ByID, sgID)
			delete(hsgV1.ByName, sg.GetName())
			return nil
		})
	})
	return nil, xerr
}

// taskUnbindFromHostsAttachedToNetwork unbinds security group from hosts attached to a network
// 'params" expects to be a '*network'
func (sg *securityGroup) taskUnbindFromHostsAttachedToNetwork(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	networkID, ok := params.(string)
	if !ok || networkID == "" {
		return nil, fail.InvalidParameterError("params", "must be a non-empty string")
	}

	sgID := sg.GetID()
	sgName := sg.GetName()
	svc := sg.GetService()

	rn, xerr := LoadNetwork(task, svc, networkID)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// network does not exist anymore ? consider as a success and continue
		default:
			return nil, xerr
		}
	}

	// Unbinds security group from hosts attached to network
	xerr = rn.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, networkproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			tg, innerXErr := concurrency.NewTaskGroup(task)
			if innerXErr != nil {
				return fail.Prepend(innerXErr, "failed to start new task group to remove security group '%s' from hosts attached to the network '%s'", sg.GetName(), rn.GetName())
			}
			for _, v := range nsgV1.ByName {
				_, innerXErr = tg.Start(sg.taskUnbindFromHost, v)
				if innerXErr != nil {
					break
				}
			}
			_, innerXErr = tg.Wait()
			return innerXErr
		})
	})
	if xerr != nil {
		return nil, xerr
	}

	// Alter network security groups property, deleting current security group
	xerr = rn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, networkproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			sgV1, ok := clonable.(*propertiesv1.NetworkSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			delete(sgV1.ByID, sgID)
			delete(sgV1.ByName, sgName)
			return nil
		})
	})
	return nil, xerr
}

// taskEnableOnHost applies rules of security group on host
// params is intended to receive a non-empty string corresponding to host ID
func (sg *securityGroup) taskEnableOnHost(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
	hostID, ok := params.(string)
	if !ok || hostID == "" {
		return nil, fail.InvalidParameterError("params", "must be a non-empty string")
	}

	rh, innerXErr := LoadHost(task, sg.GetService(), hostID)
	if innerXErr != nil {
		switch innerXErr.(type) {
		case *fail.ErrNotFound:
			// host vanished, consider as a success
		default:
			return nil, innerXErr
		}
	}

	return nil, rh.EnableSecurityGroup(task, sg)
}

// taskDisableOnHost removes rules of security group from host
// params is intended to receive a non-empty string corresponding to host ID
func (sg *securityGroup) taskDisableOnHost(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
	hostID, ok := params.(string)
	if !ok || hostID == "" {
		return nil, fail.InvalidParameterError("params", "must be a non-empty string")
	}

	svc := sg.GetService()
	rh, innerXErr := LoadHost(task, svc, hostID)
	if innerXErr != nil {
		switch innerXErr.(type) {
		case *fail.ErrNotFound:
			// host vanished, consider as a success
		default:
			return nil, innerXErr
		}
	}
	return nil, rh.DisableSecurityGroup(task, sg)
}
