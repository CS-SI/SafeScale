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
	"strings"

	"github.com/CS-SI/SafeScale/v21/lib/server/resources"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/securitygroupproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/v21/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v21/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
)

// delete effectively remove a Security Group
func (instance *SecurityGroup) unsafeDelete(ctx context.Context, force bool) fail.Error {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return xerr
			}
		default:
			return xerr
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	var (
		abstractSG *abstract.SecurityGroup
		networkID  string
	)

	value := ctx.Value(CurrentNetworkAbstractContextKey)
	if value != nil {
		castedValue, ok := value.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("failed to cast value to '*abstract.Network'")
		}

		networkID = castedValue.ID
	}

	xerr = instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		var ok bool
		abstractSG, ok = clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		if networkID == "" {
			networkID = abstractSG.Network
		}

		if !force {
			// check bonds to hosts
			innerXErr := props.Inspect(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
				hostsV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				// Do not remove a SecurityGroup used on hosts
				hostCount := len(hostsV1.ByName)
				if hostCount > 0 {
					keys := make([]string, 0, hostCount)
					for k := range hostsV1.ByName {
						keys = append(keys, k)
					}
					return fail.NotAvailableError("security group '%s' is currently bound to %d host%s: %s", instance.GetName(), hostCount, strprocess.Plural(uint(hostCount)), strings.Join(keys, ","))
				}

				// Do not remove a Security Group marked as default for a host
				if hostsV1.DefaultFor != "" {
					return fail.InvalidRequestError("failed to delete Security Group '%s': is default for host identified by %s", hostsV1.DefaultFor)
				}
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			if task.Aborted() {
				return fail.AbortedError(nil, "aborted")
			}

			// check bonds to subnets
			innerXErr = props.Inspect(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
				subnetsV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.SecurityGroupSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				// Do not remove a SecurityGroup used on subnet(s)
				subnetCount := len(subnetsV1.ByID)
				if subnetCount > 0 {
					keys := make([]string, subnetCount)
					for k := range subnetsV1.ByName {
						if task.Aborted() {
							return fail.AbortedError(nil, "aborted")
						}

						keys = append(keys, k)
					}
					return fail.NotAvailableError("security group is currently bound to %d subnet%s: %s", subnetCount, strprocess.Plural(uint(subnetCount)), strings.Join(keys, ","))
				}

				// Do not remove a Security Group marked as default for a subnet
				if subnetsV1.DefaultFor != "" {
					return fail.InvalidRequestError("failed to delete SecurityGroup '%s': is default for Subnet identified by '%s'", abstractSG.Name, subnetsV1.DefaultFor)
				}
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}
		}

		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		// FIXME: how to restore bindings in case of failure or abortion ? This would prevent the use of DisarmAbortSignal here...
		// defer task.DisarmAbortSignal()()

		// unbind from Subnets (which will unbind from Hosts attached to these Subnets...)
		innerXErr := props.Alter(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			sgnV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			return instance.unbindFromSubnets(ctx, sgnV1)
		})
		if innerXErr != nil {
			return innerXErr
		}

		// unbind from the Hosts if there are remaining ones
		innerXErr = props.Alter(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sghV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return instance.unbindFromHosts(ctx, sghV1)
		})
		if innerXErr != nil {
			return innerXErr
		}

		// delete SecurityGroup resource
		return deleteProviderSecurityGroup(instance.Service(), abstractSG)
	})
	if xerr != nil {
		return xerr
	}

	// delete Security Group metadata
	xerr = instance.MetadataCore.Delete()
	if xerr != nil {
		return xerr
	}

	// delete Security Groups in Network metadata if the current operation is not to remove this Network (otherwise may deadlock)
	removingNetworkAbstract := ctx.Value(CurrentNetworkAbstractContextKey)
	if removingNetworkAbstract == nil {
		return instance.updateNetworkMetadataOnRemoval(networkID)
	}
	return nil
}

// updateNetworkMetadataOnRemoval removes the reference to instance in Network metadata
func (instance *SecurityGroup) updateNetworkMetadataOnRemoval(networkID string) fail.Error {
	// -- update Security Groups in Network metadata
	networkInstance, xerr := LoadNetwork(instance.Service(), networkID)
	if xerr != nil {
		return xerr
	}

	return networkInstance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(networkproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.NetworkSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			delete(nsgV1.ByID, instance.GetID())
			delete(nsgV1.ByName, instance.GetName())
			return nil
		})
	})
}

// unsafeClear is the non goroutine-safe implementation for Clear, that does the real work faster (no locking, less if no parameter validations)
// Note: must be used wisely
func (instance *SecurityGroup) unsafeClear() fail.Error {
	return instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		_, innerXErr := instance.Service().ClearSecurityGroup(asg)
		return innerXErr
	})
}

// unsafeAddRule adds a rule to a security group
func (instance *SecurityGroup) unsafeAddRule(rule *abstract.SecurityGroupRule) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := rule.Validate()
	if xerr != nil {
		return xerr
	}

	return instance.Alter(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		_, innerXErr := instance.Service().AddRuleToSecurityGroup(asg, rule)
		if innerXErr != nil {
			return innerXErr
		}

		// asg.Replace(newAsg)
		return nil
	})
}

// unsafeUnbindFromSubnet unbinds the security group from a subnet
func (instance *SecurityGroup) unsafeUnbindFromSubnet(ctx context.Context, params taskUnbindFromHostsAttachedToSubnetParams) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return xerr
			}
		default:
			return xerr
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Unbind Security Group from Hosts attached to Subnet
	_, xerr = task.Run(instance.taskUnbindFromHostsAttachedToSubnet, params)
	if xerr != nil {
		return xerr
	}

	// Update instance metadata
	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			sgsV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
			if !ok {
				return fail.InconsistentError("'*securitygroupproperty.SubnetsV1' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			innerXErr := instance.Service().UnbindSecurityGroupFromSubnet(instance.GetID(), params.subnetID)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// consider a Security Group not found as a successful unbind, and continue to update metadata
					debug.IgnoreError(innerXErr)
				default:
					return innerXErr
				}
			}

			// updates security group metadata
			delete(sgsV1.ByID, params.subnetID)
			delete(sgsV1.ByName, params.subnetName)
			return nil
		})
	})
}

// unsafeBindToSubnet binds the security group to a host
// This method is called assuming Subnet resource is locked (so do not used the resource directly to prevent deadlock
func (instance *SecurityGroup) unsafeBindToSubnet(ctx context.Context, abstractSubnet *abstract.Subnet, subnetHosts *propertiesv1.SubnetHosts, enable resources.SecurityGroupActivation, mark resources.SecurityGroupMark) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if abstractSubnet == nil {
		return fail.InvalidParameterCannotBeNilError("abstractSubnet")
	}
	if subnetHosts == nil {
		return fail.InvalidParameterCannotBeNilError("subnetProps")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return xerr
			}
		default:
			return xerr
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	switch enable {
	case resources.SecurityGroupEnable:
		xerr = instance.enableOnHostsAttachedToSubnet(task, subnetHosts)
	case resources.SecurityGroupDisable:
		xerr = instance.disableOnHostsAttachedToSubnet(task, subnetHosts)
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		if mark == resources.MarkSecurityGroupAsDefault {
			asg, ok := clonable.(*abstract.SecurityGroup)
			if !ok {
				return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if asg.DefaultForHost != "" {
				return fail.InvalidRequestError("security group is already marked as default for subnet %s", asg.DefaultForSubnet)
			}

			asg.DefaultForSubnet = abstractSubnet.ID
		}

		return props.Alter(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			sgsV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// First check if subnet is present with the state requested; if present with same state, consider situation as a success
			disable := !bool(enable)
			if item, ok := sgsV1.ByID[abstractSubnet.ID]; !ok || item.Disabled == disable {
				item = &propertiesv1.SecurityGroupBond{
					ID:   abstractSubnet.ID,
					Name: abstractSubnet.Name,
				}
				sgsV1.ByID[abstractSubnet.ID] = item
				sgsV1.ByName[abstractSubnet.Name] = abstractSubnet.ID
			}

			// updates security group properties
			sgsV1.ByID[abstractSubnet.ID].Disabled = disable
			return nil
		})
	})
}

// unsafeBindToHost binds the security group to a host.
// instance is not locked, it must have been done outside to prevent data races
func (instance *SecurityGroup) unsafeBindToHost(ctx context.Context, hostInstance resources.Host, enable resources.SecurityGroupActivation, mark resources.SecurityGroupMark) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return xerr
			}
		default:
			return xerr
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	return instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		if mark == resources.MarkSecurityGroupAsDefault {
			asg, ok := clonable.(*abstract.SecurityGroup)
			if !ok {
				return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if asg.DefaultForHost != "" {
				return fail.InvalidRequestError("security group is already marked as default for host %s", asg.DefaultForHost)
			}

			asg.DefaultForHost = hostInstance.GetID()
		}

		return props.Alter(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sghV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// First check if host is present; if not present or state is different, replace the entry
			hostID := hostInstance.GetID()
			hostName := hostInstance.GetName()
			disable := !bool(enable)
			if item, ok := sghV1.ByID[hostID]; !ok || item.Disabled == disable {
				item = &propertiesv1.SecurityGroupBond{
					ID:   hostID,
					Name: hostName,
				}
				sghV1.ByID[hostID] = item
				sghV1.ByName[hostName] = hostID
			}

			// update the state
			sghV1.ByID[hostID].Disabled = disable

			switch enable {
			case resources.SecurityGroupEnable:
				// In case the security group is already bound, we must consider a "duplicate" error has a success
				xerr := instance.Service().BindSecurityGroupToHost(instance.GetID(), hostID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrDuplicate:
						debug.IgnoreError(xerr)
						// continue
					default:
						return xerr
					}
				}
			case resources.SecurityGroupDisable:
				// In case the security group has to be disabled, we must consider a "not found" error has a success
				xerr := instance.Service().UnbindSecurityGroupFromHost(instance.GetID(), hostID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						debug.IgnoreError(xerr)
						// continue
					default:
						return xerr
					}
				}
			}
			return nil
		})
	})
}
