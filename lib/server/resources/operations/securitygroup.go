/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupstate"
	"reflect"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetproperty"
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

// lookupSecurityGroup returns true if security group exists, false otherwise
func lookupSecurityGroup(task concurrency.Task, svc iaas.Service, ref string) (bool, fail.Error) {
	if task.IsNull() {
		return false, fail.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return false, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return false, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	rsg, xerr := NewSecurityGroup(svc)
	if xerr != nil {
		return false, xerr
	}

	xerr = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			return rsg.Read(task, ref)
		},
		10*time.Second,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound, *retry.ErrTimeout:
			return false, nil
		default:
			return false, xerr
		}
	}
	return true, nil
}

// LoadSecurityGroup ...
func LoadSecurityGroup(task concurrency.Task, svc iaas.Service, ref string) (_ resources.SecurityGroup, xerr fail.Error) {
	defer fail.OnExitLogError(&xerr)
	defer fail.OnPanic(&xerr)

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
			return nullSg, fail.NotFoundError("metadata of Security Group '%s' not found", ref)
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

// Create creates a new securityGroup and its metadata.
// If needed by Cloud Provider, the Security Group will be attached to 'rn' Network (otherwise this parameter is ignored)
// If the metadata is already carrying a securityGroup, returns fail.ErrNotAvailable
func (sg *securityGroup) Create(task concurrency.Task, rn resources.Network, name, description string, rules []abstract.SecurityGroupRule) (xerr fail.Error) {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if rn.IsNull() {
		return fail.InvalidParameterError("rn", "cannot be null value of 'resources.Network'")
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
	var found bool
	if found, xerr = lookupSecurityGroup(task, svc, name); xerr != nil {
		return fail.Wrap(xerr, "failed to check if Security Group '%s' already exists", name)
	}
	if found {
		return fail.DuplicateError("a Security Group named '%s' already exists", name)
	}

	// Check if securityGroup exists but is not managed by SafeScale
	if _, xerr = svc.InspectSecurityGroup(name); xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return fail.Wrap(xerr, "failed to check if Security Group name '%s' is already used", name)
		}
	} else {
		return fail.DuplicateError("a Security Group named '%s' already exists (but not managed by SafeScale)", name)
	}

	asg, xerr := svc.CreateSecurityGroup(rn.GetID(), name, description, rules)
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

	// Creates metadata
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

	// VPL: not sure yet if this is wanted... If no rules are provided, Cloud Provider may put default rules in Security Group...
	if len(rules) == 0 {
		if xerr = sg.Clear(task); xerr != nil {
			return xerr
		}
	}

	logrus.Infof("Security Group '%s' created successfully", name)
	return nil
}

// ForceDelete deletes a Security Group unconditionnally
func (sg *securityGroup) ForceDelete(task concurrency.Task) fail.Error {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}

	return sg.delete(task, true)
}

// Delete deletes a Security Group
func (sg *securityGroup) Delete(task concurrency.Task) fail.Error {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}

	return sg.delete(task, false)
}

func (sg *securityGroup) delete(task concurrency.Task, force bool) fail.Error {
	// sg.SafeLock(task)
	// defer sg.SafeUnlock(task)

	svc := sg.GetService()

	securityGroupID := sg.GetID()
	xerr := sg.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		if !force {
			// check bonds to hosts
			innerXErr := props.Inspect(task, securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
				hostsV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				// Do not remove a securityGroup used on hosts
				hostCount := len(hostsV1.ByName)
				if hostCount > 0 {
					return fail.NotAvailableError("security group '%s' is currently bound to %d host%s", sg.GetName(), hostCount, strprocess.Plural(uint(hostCount)))
				}

				// Do not remove a Security Group marked as default for a host
				if hostsV1.DefaultFor != "" {
					if _, xerr := LoadHost(task, svc, hostsV1.DefaultFor); xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							hostsV1.DefaultFor = ""
							// clear the field and continue, the host does not exist anymore
						default:
							return xerr
						}
					}
				}
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			// check bonds to subnets
			innerXErr = props.Inspect(task, securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
				subnetsV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.SecurityGroupSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				// Do not remove a securityGroup used on subnet(s)
				subnetCount := len(subnetsV1.ByID)
				if subnetCount > 0 {
					return fail.NotAvailableError("security group is currently bound to %d subnet%s", subnetCount, strprocess.Plural(uint(subnetCount)))
				}

				// Do not remove a Security Group marked as default for a subnet
				if subnetsV1.DefaultFor != "" {
					if _, xerr := LoadSubnet(task, svc, "", subnetsV1.DefaultFor); xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							// clear the field and continue, the subnet does not exist anymore
							subnetsV1.DefaultFor = ""
						default:
							return xerr
						}
					}
				}
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}
		} else {
			// First unbind from subnets (which will unbind from hosts attached to these subnets...)
			innerXErr := props.Alter(task, securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
				sgnV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.SecurityGroupSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return sg.unbindFromSubnets(task, sgnV1)
			})
			if innerXErr != nil {
				return innerXErr
			}

			// Second, unbind from the hosts if there are remaining ones
			innerXErr = props.Alter(task, securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
				sghV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return sg.unbindFromHosts(task, sghV1)
			})
			if innerXErr != nil {
				return innerXErr
			}
		}

		// Conditions are met, delete securityGroup
		return retry.WhileUnsuccessfulDelay1Second(
			func() error {
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

// unbindFromHosts unbinds security group from all the hosts bound to it and update the host metadata accordingly
func (sg *securityGroup) unbindFromHosts(task concurrency.Task, in *propertiesv1.SecurityGroupHosts) fail.Error {
	tg, xerr := concurrency.NewTaskGroup(task)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to start new task group to remove security group '%s' from hosts", sg.GetName())
	}

	// iterate on hosts bound to the security group and start a go routine to unbind
	svc := sg.GetService()
	for _, v := range in.ByID {
		if v.FromSubnet {
			return fail.InvalidRequestError("cannot unbind from host a security group applied from subnet; use disable instead or remove from bound subnet")
		}
		rh, xerr := LoadHost(task, svc, v.ID)
		if xerr != nil {
			break
		}
		_, xerr = tg.Start(sg.taskUnbindFromHost, rh)
		if xerr != nil {
			break
		}
	}
	_, xerr = tg.Wait()
	if xerr != nil {
		return xerr
	}

	// Clear the DefaultFor field if needed
	if in.DefaultFor != "" {
		for k := range in.ByID {
			if k == in.DefaultFor {
				in.DefaultFor = ""
				break
			}
		}
	}

	// Resets the bonds on hosts
	in.ByID = map[string]*propertiesv1.SecurityGroupBond{}
	in.ByName = map[string]*propertiesv1.SecurityGroupBond{}
	return nil
}

// unbindFromSubnets unbinds security group from all the subnets bound to it and update the Subnet metadata accordingly
func (sg *securityGroup) unbindFromSubnets(task concurrency.Task, in *propertiesv1.SecurityGroupSubnets) fail.Error {
	tg, xerr := concurrency.NewTaskGroup(task)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to start new task group to remove security group '%s' from subnets", sg.GetName())
	}

	// iterate on all networks bound to the security group to unbind security group from hosts attached to those networks (in parallel)
	for _, v := range in.ByID {
		// Unbind security group from hosts attached to subnet
		_, xerr = tg.Start(sg.taskUnbindFromHostsAttachedToSubnet, v.ID)
		if xerr != nil {
			break
		}
	}
	_, xerr = tg.Wait()
	if xerr != nil {
		return xerr
	}

	// Clear the DefaultFor field if needed
	if in.DefaultFor != "" {
		for k := range in.ByID {
			if k == in.DefaultFor {
				in.DefaultFor = ""
				break
			}
		}
	}

	// Remove the bonds on subnets
	in.ByID = map[string]*propertiesv1.SecurityGroupBond{}
	in.ByName = map[string]*propertiesv1.SecurityGroupBond{}
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

// Reset clears a security group and re-adds associated rules as stored in metadata
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
func (sg securityGroup) DeleteRule(task concurrency.Task, rule abstract.SecurityGroupRule) fail.Error {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if rule.IsNull() {
		return fail.InvalidParameterError("rule", "cannot be null value of 'abstract.SecurityGroupRule'")
	}

	return sg.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		newAsg, innerXErr := sg.GetService().DeleteRuleFromSecurityGroup(asg, rule)
		if innerXErr != nil {
			return innerXErr
		}
		asg.Replace(newAsg)
		return nil
	})
}

// GetBoundHosts returns the list of ID of hosts bound to the security group
func (sg securityGroup) GetBoundHosts(task concurrency.Task) ([]*propertiesv1.SecurityGroupBond, fail.Error) {
	if sg.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	var list []*propertiesv1.SecurityGroupBond
	xerr := sg.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sghV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			list = make([]*propertiesv1.SecurityGroupBond, 0, len(sghV1.ByID))
			for _, v := range sghV1.ByID {
				list = append(list, v)
			}
			return nil
		})
	})
	return list, xerr
}

// GetBoundSubnets returns the subnet bound to the security group
func (sg securityGroup) GetBoundSubnets(task concurrency.Task) (list []*propertiesv1.SecurityGroupBond, xerr fail.Error) {
	if sg.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	xerr = sg.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			sgnV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			list = make([]*propertiesv1.SecurityGroupBond, 0, len(sgnV1.ByID))
			for _, v := range sgnV1.ByID {
				list = append(list, v)
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

// BindToHost binds the security group to a host.
// If 'ip' is not empty, applies the Security Group only on the interface hosting this IP address.
func (sg *securityGroup) BindToHost(task concurrency.Task, rh resources.Host /*ip string,*/, enable resources.SecurityGroupActivation, mark resources.SecurityGroupMark) fail.Error {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if rh.IsNull() {
		return fail.InvalidParameterError("rh", "cannot be null value of 'resources.Host'")
	}

	return sg.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		if mark == resources.MarkSecurityGroupAsDefault {
			asg, ok := clonable.(*abstract.SecurityGroup)
			if !ok {
				return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if asg.DefaultForHost != "" {
				return fail.InvalidRequestError("security group is already marked as default for host %s", asg.DefaultForHost)
			}
			asg.DefaultForHost = rh.GetID()
		}

		return props.Alter(task, securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sghV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// First check if host is present; if not present or state is different, replace the entry
			hostID := rh.GetID()
			hostName := rh.GetName()
			disable := !bool(enable)
			if item, ok := sghV1.ByID[hostID]; !ok || item.Disabled == disable {
				item = &propertiesv1.SecurityGroupBond{
					ID:   hostID,
					Name: hostName,
				}
				sghV1.ByID[hostID] = item
				sghV1.ByName[hostName] = item
			}

			// update the state
			sghV1.ByID[hostID].Disabled = disable
			sghV1.ByName[hostName].Disabled = disable

			switch enable {
			case resources.SecurityGroupEnable:
				// In case the security group is already bound, we must consider a "duplicate" error has a success
				xerr := sg.GetService().BindSecurityGroupToHost(hostID /*ip, */, sg.GetID())
				switch xerr.(type) {
				case *fail.ErrDuplicate:
					// continue
				default:
					return xerr
				}
			case resources.SecurityGroupDisable:
				// In case the security group has to be disabled, we must consider a "not found" error has a success
				innerXErr := sg.GetService().UnbindSecurityGroupFromHost(hostID, sg.GetID())
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// continue
				default:
					return innerXErr
				}
			}
			return nil
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

			// Unbind security group on provider side; if not found, consider as a success
			hostID := rh.GetID()
			if innerXErr := sg.GetService().UnbindSecurityGroupFromHost(hostID, sg.GetID()); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					return nil
				default:
					return innerXErr
				}
			}

			// updates security group properties
			delete(sgphV1.ByID, hostID)
			delete(sgphV1.ByName, rh.GetName())
			return nil
		})
	})
}

// BindToSubnet binds the security group to a host
func (sg *securityGroup) BindToSubnet(task concurrency.Task, rs resources.Subnet, enable resources.SecurityGroupActivation, mark resources.SecurityGroupMark) (xerr fail.Error) {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if rs.IsNull() {
		return fail.InvalidParameterError("rh", "cannot be null value of 'resources.Network'")
	}

	switch enable {
	case resources.SecurityGroupEnable:
		xerr = sg.enableOnHostsAttachedToSubnet(task, rs)
	case resources.SecurityGroupDisable:
		xerr = sg.disableOnHostsAttachedToSubnet(task, rs)
	}
	if xerr != nil {
		return xerr
	}

	return sg.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		if mark == resources.MarkSecurityGroupAsDefault {
			asg, ok := clonable.(*abstract.SecurityGroup)
			if !ok {
				return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if asg.DefaultForHost != "" {
				return fail.InvalidRequestError("security group is already marked as default for subnet %s", asg.DefaultForSubnet)
			}
			asg.DefaultForSubnet = rs.GetID()
		}

		return props.Alter(task, securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			sgsV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// First check if subnet is present with the state requested; if present with same state, consider situation as a success
			subnetID := rs.GetID()
			subnetName := rs.GetName()
			disable := !bool(enable)
			if item, ok := sgsV1.ByID[subnetID]; !ok || item.Disabled == disable {
				item = &propertiesv1.SecurityGroupBond{
					ID:   subnetID,
					Name: subnetName,
				}
				sgsV1.ByID[subnetID] = item
				sgsV1.ByName[subnetName] = item
			}

			// updates security group properties
			sgsV1.ByID[subnetID].Disabled = disable
			sgsV1.ByName[subnetName].Disabled = disable
			return nil
		})
	})
}

// enableOnHostsAttachedToSubnet enables the security group on hosts attached to the network
func (sg *securityGroup) enableOnHostsAttachedToSubnet(task concurrency.Task, rs resources.Subnet) fail.Error {
	tg, xerr := concurrency.NewTaskGroup(task)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to create a task group to disable security group '%s' on hosts", sg.GetName())
	}

	return rs.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			shV1, ok := clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for _, v := range shV1.ByID {
				if _, innerXErr := tg.Start(sg.taskEnableOnHost, v); innerXErr != nil {
					break
				}
			}
			_, innerXErr := tg.Wait()
			return innerXErr
		})
	})
}

// disableSecurityGroupOnHosts disables (ie remove) the security group from bound hosts
func (sg *securityGroup) disableOnHostsAttachedToSubnet(task concurrency.Task, rs resources.Subnet) fail.Error {
	tg, xerr := concurrency.NewTaskGroup(task)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to create a task group to disable security group '%s' on hosts", sg.GetName())
	}

	return rs.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			shV1, ok := clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for _, v := range shV1.ByID {
				if _, innerXErr := tg.Start(sg.taskDisableOnHost, v); innerXErr != nil {
					break
				}
			}
			_, innerXErr := tg.Wait()
			return innerXErr
		})
	})
}

// UnbindFromSubnet unbinds the security group from a subnet
func (sg *securityGroup) UnbindFromSubnet(task concurrency.Task, rs resources.Subnet) fail.Error {
	if sg.IsNull() {
		return fail.InvalidInstanceError()
	}
	if rs.IsNull() {
		return fail.InvalidParameterError("rs", "cannot be null value of 'resources.Subnet'")
	}

	return sg.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			sgsV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
			if !ok {
				return fail.InconsistentError("'*securitygroupproperty.SubnetsV1' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			innerXErr := sg.GetService().UnbindSecurityGroupFromSubnet(sg.GetID(), rs.GetID())
			if innerXErr != nil {
				return innerXErr
			}

			// updates security group metadata
			delete(sgsV1.ByID, rs.GetID())
			delete(sgsV1.ByName, rs.GetName())
			return nil
		})
	})
}

func filterBondsByKind(bonds map[string]*propertiesv1.SecurityGroupBond, state securitygroupstate.Enum) []*propertiesv1.SecurityGroupBond {
	list := make([]*propertiesv1.SecurityGroupBond, 0, len(bonds))
	switch state {
	case securitygroupstate.All:
		for _, v := range bonds {
			list = append(list, v)
		}
	case securitygroupstate.Enabled:
		for _, v := range bonds {
			if !v.Disabled {
				list = append(list, v)
			}
		}
	case securitygroupstate.Disabled:
		for _, v := range bonds {
			if v.Disabled {
				list = append(list, v)
			}
		}
	}
	return list
}
