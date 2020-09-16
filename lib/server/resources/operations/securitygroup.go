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
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
)

const (
	// securityGroupsFolderName is the technical name of the container used to store networks info
	securityGroupsFolderName = "security-groups"
)

// securityGroup ...
// follows interface resources.SecurityGroup
type securityGroup struct {
	*core
}

// NewSecurityGroup ...
func NewSecurityGroup(svc iaas.Service) (resources.SecurityGroup, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	coreInstance, xerr := newCore(svc, "security-group", securityGroupsFolderName, &abstract.SecurityGroup{})
	if xerr != nil {
		return nil, xerr
	}

	return &securityGroup{core: coreInstance}, nil
}

// nullSecurityGroup returns a *securityGroup corresponding to NullValue
func nullSecurityGroup() *securityGroup {
	return &securityGroup{core: nullCore()}
}

// LoadSecurityGroup ...
func LoadSecurityGroup(task concurrency.Task, svc iaas.Service, ref string) (_ resources.SecurityGroup, xerr fail.Error) {
	nullSg := nullSecurityGroup()
	if task.IsNull() {
		return nullSg, fail.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return nullSg, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nullSg, fail.InvalidParameterError("ref", "cannot be empty string")
	}
	defer fail.OnPanic(&xerr)

	rsg, xerr := NewSecurityGroup(svc)
	if xerr != nil {
		return nullSg, xerr
	}

	xerr = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			return rsg.Read(task, ref)
		},
		10*time.Second,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAlteredNothing: // This error means nothing has been change, so no need to update cache
			return nullSg, nil
		case *retry.ErrTimeout: // If retry timed out, log it and return error ErrNotFound
			return nullSg, fail.NotFoundError("metadata of securityGroup '%s' not found", ref)
		default:
			return nullSg, xerr
		}
	}
	return rsg, nil
}

// IsNull tests if instance is nil or empty
func (sg *securityGroup) IsNull() bool {
	return sg == nil || sg.core.IsNull()
}

// Browse walks through securityGroup folder and executes a callback for each entries
func (sg securityGroup) Browse(task concurrency.Task, callback func(*abstract.SecurityGroup) fail.Error) (xerr fail.Error) {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	return sg.core.BrowseFolder(task, func(buf []byte) fail.Error {
		asg := abstract.NewSecurityGroup("")
		if xerr = asg.Deserialize(buf); xerr != nil {
			return xerr
		}
		return callback(asg)
	})
}

// Reload reloads securityGroup from metadata and current securityGroup state on provider state
func (sg *securityGroup) Reload(task concurrency.Task) fail.Error {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}

	// Read data from metadata storage
	securityGroupID := sg.GetID()
	xerr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			return sg.Read(task, securityGroupID)
		},
		10*time.Second,
	)
	if xerr != nil {
		// If retry timed out, log it and return error ErrNotFound
		if _, ok := xerr.(*retry.ErrTimeout); ok {
			xerr = fail.NotFoundError("metadata of securityGroup '%s' not found; securityGroup deleted?", securityGroupID)
		}
		return xerr
	}
	//
	//// Request securityGroup inspection from provider
	//inspected, xerr := sg.GetService().InspectSecurityGroup(securityGroupID)
	//if xerr != nil {
	//    return xerr
	//}
	return nil
}

// Create creates a new securityGroup and its metadata
// If the metadata is already carrying a securityGroup, returns fail.ErrNotAvailable
func (sg *securityGroup) Create(task concurrency.Task, name string, description string, rules []abstract.SecurityGroupRule) (xerr fail.Error) {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}
	if strings.HasPrefix(name, "sg-") {
		return fail.InvalidParameterError("name", "cannot start with 'sg-'")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.security-group"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	// Log or propagate errors: here we propagate
	//defer fail.OnExitLogError(&xerr, "failed to create securityGroup")
	defer fail.OnPanic(&xerr)

	svc := sg.GetService()

	// Check if securityGroup exists and is managed bySafeScale
	if _, xerr = LoadSecurityGroup(task, svc, name); xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return fail.Wrap(xerr, "failed to check if securityGroup '%s' already exists", name)
		}
	} else {
		return fail.DuplicateError("a security group named '%s' already exists", name)
	}

	// Check if securityGroup exists but is not managed by SafeScale
	if _, xerr = svc.InspectSecurityGroup(name); xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return fail.Wrap(xerr, "failed to check if Security Group name '%s' is already used", name)
		}
	} else {
		return fail.DuplicateError("a Security Group named '%s' already exists (but not managed by SafeScale)", name)
	}

	asg, xerr := svc.CreateSecurityGroup(name, description, rules)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrInvalidRequest); ok {
			return xerr
		}
		return fail.Wrap(xerr, "failed to create security group '%s'", name)
	}

	defer func() {
		if xerr != nil {
			derr := svc.DeleteSecurityGroup(asg.ID)
			if derr != nil {
				logrus.Errorf("cleaning up after failure, failed to delete Security Group '%s': %v", name, derr)
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	// Creates metadata early to "reserve" securityGroup name
	if xerr = sg.Carry(task, asg); xerr != nil {
		return xerr
	}

	defer func() {
		if xerr != nil {
			derr := sg.core.Delete(task)
			if derr != nil {
				logrus.Errorf("cleaning up after failure, failed to delete Security Group '%s' metadata: %v", name, derr)
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	logrus.Infof("Security Group '%s' created successfully", name)
	return nil
}

// Delete deletes a Security Group
func (sg *securityGroup) Delete(task concurrency.Task) fail.Error {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}

	// sg.SafeLock(task)
	// defer sg.SafeUnlock(task)

	svc := sg.GetService()

	securityGroupID := sg.GetID()
	xerr := sg.Alter(task, func(_ data.Clonable, properties *serialize.JSONProperties) fail.Error {
		// Don't remove a securityGroup used on hosts
		innerXErr := properties.Inspect(task, securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			hostsV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostCount := len(hostsV1.ByID)
			if hostCount > 0 {
				return fail.NotAvailableError("security group is currently binded to %d host%s", hostCount, strprocess.Plural(uint(hostCount)))
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Don't remove a Security Group binded to networks
		innerXErr = properties.Inspect(task, securitygroupproperty.NetworksV1, func(clonable data.Clonable) fail.Error {
			securityGroupNetworksV1, ok := clonable.(*propertiesv1.SecurityGroupNetworks)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupNetworks' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			binded := uint(len(securityGroupNetworksV1.ByID))
			if binded > 0 {
				return fail.NotAvailableError("security group is currently used on %d network%s", binded, strprocess.Plural(binded))
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Conditions are met, delete securityGroup
		return retry.WhileUnsuccessfulDelay1Second(
			func() error {
				// FIXME: need to remove retry from svc.DeleteSecurityGroup!
				return svc.DeleteSecurityGroup(securityGroupID)
			},
			time.Minute*5,
		)
	})
	if xerr != nil {
		return xerr
	}

	// Deletes metadata from Object Storage
	if xerr = sg.core.Delete(task); xerr != nil {
		// If entry not found, considered as success
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return xerr
		}
	}

	newSecurityGroup := nullSecurityGroup()
	*sg = *newSecurityGroup
	return nil
}

// Clear removes all rules from a security group
func (sg *securityGroup) Clear(task concurrency.Task) (xerr fail.Error) {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}

	return sg.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		var innerXErr fail.Error
		asg, innerXErr = sg.GetService().ClearSecurityGroup(asg)
		return innerXErr
	})
}

// Reset clears a security group and readds associated rules as stored in metadata
func (sg *securityGroup) Reset(task concurrency.Task) (xerr fail.Error) {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of '*concurrency.Task'")
	}

	sg.SafeLock(task)
	defer sg.SafeUnlock(task)

	// Refresh content of the instance from metadata
	xerr = sg.Reload(task)
	if xerr != nil {
		return xerr
	}

	var rules []abstract.SecurityGroupRule
	xerr = sg.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		rules = asg.Rules
		return nil
	})
	if xerr != nil {
		return xerr
	}

	// Removes all rules...
	xerr = sg.Clear(task)
	if xerr != nil {
		return xerr
	}

	// ... then re-adds rules from metadata
	for _, v := range rules {
		xerr = sg.AddRule(task, v)
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// AddRule adds a rule to a security group
func (sg securityGroup) AddRule(task concurrency.Task, rule abstract.SecurityGroupRule) fail.Error {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if rule.IsNull() {
		return fail.InvalidParameterError("rule", "cannot be null value of abstract.SecurityGroupRule")
	}

	return sg.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		newAsg, innerXErr := sg.GetService().AddRuleToSecurityGroup(asg, rule)
		if innerXErr != nil {
			return innerXErr
		}
		asg.Replace(newAsg)
		return nil
	})
}

// DeleteRule deletes a rule identified by its ID from a security group
// If ruleID is not in the security group, returns *fail.ErrNotFound
func (sg securityGroup) DeleteRule(task concurrency.Task, ruleID string) fail.Error {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ruleID == "" {
		return fail.InvalidParameterError("ruleID", "cannot be empty string")
	}

	return sg.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		newAsg, innerXErr := sg.GetService().DeleteRuleFromSecurityGroup(asg, ruleID)
		if innerXErr != nil {
			return innerXErr
		}
		asg.Replace(newAsg)
		return nil
	})
}

// GetBindedHosts returns the list of ID of hosts binded to the security group
func (sg securityGroup) GetBindedHosts(task concurrency.Task) ([]string, fail.Error) {
	if sg.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	var list []string
	xerr := sg.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sghV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			list = make([]string, 0, len(sghV1.ByID))
			for k := range sghV1.ByID {
				list = append(list, k)
			}
			return nil
		})
	})
	return list, xerr
}

// GetBindedNetworks returns the list of ID of networks binded to the security group
func (sg securityGroup) GetBindedNetworks(task concurrency.Task) ([]string, fail.Error) {
	if sg.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	var list []string
	xerr := sg.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, securitygroupproperty.NetworksV1, func(clonable data.Clonable) fail.Error {
			sgnV1, ok := clonable.(*propertiesv1.SecurityGroupNetworks)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			list = make([]string, 0, len(sgnV1.ByID))
			for k := range sgnV1.ByID {
				list = append(list, k)
			}
			return nil
		})
	})
	return list, xerr
}

// CheckConsistency checks the rules in the security group on provider side are identical to the ones registered in metadata
func (sg securityGroup) CheckConsistency(task concurrency.Task) fail.Error {
	return fail.NotImplementedError()
}

// ToProtocol converts a Security Group to protobuf message
func (sg securityGroup) ToProtocol(task concurrency.Task) (*protocol.SecurityGroupResponse, fail.Error) {
	if sg.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	out := &protocol.SecurityGroupResponse{}
	return out, sg.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		out.Id = asg.ID
		out.Name = asg.Name
		out.Description = asg.Description
		out.Rules = converters.SecurityGroupRulesFromAbstractToProtocol(asg.Rules)
		return nil
	})
}

// BindToHost binds the security group to a host
func (sg *securityGroup) BindToHost(task concurrency.Task, rh resources.Host, enabled bool) fail.Error {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if rh.IsNull() {
		return fail.InvalidParameterError("rh", "cannot be null value of 'resources.Host'")
	}

	return sg.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sgphV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*securitygroupproperty.HostsV1' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// First check if host is present; if present with same state, consider situation as a success
			hostID := rh.GetID()
			for k, v := range sgphV1.ByID {
				if k == hostID && v == enabled {
					return nil
				}
			}

			// updates security group properties
			sgphV1.ByID[hostID] = enabled
			sgphV1.ByName[rh.GetName()] = enabled

			if enabled {
				return sg.GetService().BindSecurityGroupToHost(hostID, sg.GetID())
			}

			// In case the security group has to be disabled, we must consider a not found error has a success
			innerXErr := sg.GetService().UnbindSecurityGroupFromHost(hostID, sg.GetID())
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				return nil
			default:
				return innerXErr
			}
		})
	})
}

// UnbindFromHost unbinds the security group from an host
func (sg *securityGroup) UnbindFromHost(task concurrency.Task, rh resources.Host) fail.Error {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if rh.IsNull() {
		return fail.InvalidParameterError("rh", "cannot be null value of 'resources.Host'")
	}

	return sg.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sgphV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*securitygroupproperty.HostsV1' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// updates security group properties
			hostID := rh.GetID()
			delete(sgphV1.ByID, hostID)
			delete(sgphV1.ByName, rh.GetName())

			// Unbind security group on provider side; if not found, consider as a success
			innerXErr := sg.GetService().UnbindSecurityGroupFromHost(hostID, sg.GetID())
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				return nil
			default:
				return innerXErr
			}
		})
	})
}

// BindToNetwork binds the security group to a host
func (sg *securityGroup) BindToNetwork(task concurrency.Task, rn resources.Network, enabled bool) fail.Error {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if rn.IsNull() {
		return fail.InvalidParameterError("rh", "cannot be null value of 'resources.Network'")
	}

	return sg.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, securitygroupproperty.NetworksV1, func(clonable data.Clonable) fail.Error {
			sgpnV1, ok := clonable.(*propertiesv1.SecurityGroupNetworks)
			if !ok {
				return fail.InconsistentError("'*securitygroupproperty.NetworksV1' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// First check if host is present; if present with same state, consider situation as a success
			networkID := rn.GetID()
			for k, v := range sgpnV1.ByID {
				if k == networkID && v == enabled {
					return nil
				}
			}

			// updates security group properties
			sgpnV1.ByID[networkID] = enabled
			sgpnV1.ByName[rn.GetName()] = enabled

			if enabled {
				return sg.GetService().BindSecurityGroupToNetwork(networkID, sg.GetID())
			}

			// In case the security group has to be disabled, we must consider a not found error has a success
			innerXErr := sg.GetService().UnbindSecurityGroupFromNetwork(networkID, sg.GetID())
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				return nil
			default:
				return innerXErr
			}
		})
	})
}

// UnbindFromNetwork unbinds the security group from a network
func (sg *securityGroup) UnbindFromNetwork(task concurrency.Task, rn resources.Network) fail.Error {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if rn.IsNull() {
		return fail.InvalidParameterError("rh", "cannot be null value of 'resources.Network'")
	}

	return sg.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, securitygroupproperty.NetworksV1, func(clonable data.Clonable) fail.Error {
			sgpnV1, ok := clonable.(*propertiesv1.SecurityGroupNetworks)
			if !ok {
				return fail.InconsistentError("'*securitygroupproperty.NetworksV1' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// updates security group properties
			networkID := rn.GetID()
			delete(sgpnV1.ByID, networkID)
			delete(sgpnV1.ByName, rn.GetName())

			// Unbind security group on provider side; if not found, consider as a success
			innerXErr := sg.GetService().UnbindSecurityGroupFromNetwork(networkID, sg.GetID())
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				return nil
			default:
				return innerXErr
			}
		})
	})
}
