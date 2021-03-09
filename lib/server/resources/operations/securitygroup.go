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
	"reflect"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupstate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

const (
	securityGroupKind = "security-group"
	// securityGroupsFolderName is the technical name of the container used to store networks info
	securityGroupsFolderName = "security-groups"
)

//var (
//	securityGroupCacheByID data.Cache
//	securityGroupIDsByName map[string]string
//)

// securityGroup ...
// follows interface resources.SecurityGroup
type securityGroup struct {
	*core

	lock sync.RWMutex
}

// NewSecurityGroup ...
func NewSecurityGroup(svc iaas.Service) (resources.SecurityGroup, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	coreInstance, xerr := newCore(svc, securityGroupKind, securityGroupsFolderName, &abstract.SecurityGroup{})
	if xerr != nil {
		return nil, xerr
	}

	instance := &securityGroup{
		core: coreInstance,
	}
	return instance, nil
}

// nullSecurityGroup returns a *securityGroup corresponding to NullValue
func nullSecurityGroup() *securityGroup {
	return &securityGroup{core: nullCore()}
}

// lookupSecurityGroup returns true if security group exists, false otherwise
func lookupSecurityGroup(/*ctx context.Context, */svc iaas.Service, ref string) (bool, fail.Error) {
	if task == nil {
		return false, fail.InvalidParameterError("task", "cannot be nil")
	}
	if task.Aborted() {
		return false, fail.AbortedError(nil, "aborted")
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

	if xerr = rsg.Read(ref); xerr != nil {
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
func LoadSecurityGroup(/*ctx context.Context, */svc iaas.Service, ref string) (rsg resources.SecurityGroup, xerr fail.Error) {
	// Note: do not log error from here; caller has the responsibility to log if needed
	defer fail.OnPanic(&xerr)

	if task == nil {
		return nullSecurityGroup(), fail.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return nullSecurityGroup(), fail.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nullSecurityGroup(), fail.InvalidParameterError("ref", "cannot be empty string")
	}

	if task.Aborted() {
		return nullSecurityGroup(), fail.AbortedError(nil, "aborted")
	}

	sgCache, xerr := svc.GetCache(securityGroupKind)
	if xerr != nil {
		return nullSecurityGroup(), fail.Wrap(xerr, "failed to get cache for Security Groups")
	}

	options := []data.ImmutableKeyValue{
		// defines action to perform if key is not found in cache
		data.NewImmutableKeyValue("onMiss", func() (cache.Cacheable, fail.Error) {
			rsg, innerXErr := NewSecurityGroup(svc)
			if innerXErr != nil {
				return nil, innerXErr
			}

			// TODO: core.ReadByID() does not check communication failure, side effect of limitations of Stow (waiting for stow replacement by rclone)
			if innerXErr = rsg.Read(ref); innerXErr != nil {
				return nil, innerXErr
			}

			return rsg, nil
		}),
	}
	cacheEntry, xerr := sgCache.Get(ref, options...)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// rewrite NotFoundError, user does not bother about metadata stuff
			return nullSecurityGroup(), fail.NotFoundError("failed to find Security Group '%s'", ref)
		default:
			return nullSecurityGroup(), xerr
		}
	}

	if rsg = cacheEntry.Content().(resources.SecurityGroup); rsg == nil {
		return nullSecurityGroup(), fail.InconsistentError("nil value found in Security Group cache for key '%s'", ref)
	}
	_ = cacheEntry.LockContent()
	defer func() {
		if xerr != nil {
			_ = cacheEntry.UnlockContent()
		}
	}()

	return rsg, nil
}

// isNull tests if instance is nil or empty
func (instance *securityGroup) isNull() bool {
	if instance == nil {
		return true
	}

	return instance.core.isNull()
}

// Carry overloads rv.core.Carry() to add Volume to service cache
func (instance *securityGroup) carry(/*ctx context.Context, */clonable data.Clonable) (xerr fail.Error) {
	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}
	identifiable, ok := clonable.(data.Identifiable)
	if !ok {
		return fail.InvalidParameterError("clonable", "must also satisfy interface 'data.Identifiable'")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	kindCache, xerr := instance.GetService().GetCache(instance.core.kind)
	if xerr != nil {
		return xerr
	}

	if xerr := kindCache.ReserveEntry(identifiable.GetID()); xerr != nil {
		return xerr
	}
	defer func() {
		if xerr != nil {
			if derr := kindCache.FreeEntry(identifiable.GetID()); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free %s cache entry for key '%s'", instance.core.kind, identifiable.GetID()))
			}

		}
	}()

	// Note: do not validate parameters, this call will do it
	if xerr := instance.core.Carry(clonable); xerr != nil {
		return xerr
	}

	cacheEntry, xerr := kindCache.CommitEntry(identifiable.GetID(), instance)
	if xerr != nil {
		return xerr
	}

	cacheEntry.LockContent()

	return nil
}

// Browse walks through securityGroup folder and executes a callback for each entries
func (instance *securityGroup) Browse(/*ctx context.Context, */callback func(*abstract.SecurityGroup) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: Browse is intended to be callable from null value, so do not validate instance
	// if instance.isNull() {
	// 	return fail.InvalidInstanceError()
	// }
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.core.BrowseFolder(func(buf []byte) fail.Error {
		asg := abstract.NewSecurityGroup()
		if xerr = asg.Deserialize(buf); xerr != nil {
			return xerr
		}

		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		return callback(asg)
	})
}

// Create creates a new securityGroup and its metadata.
// If needed by Cloud Provider, the Security Group will be attached to Network identified by 'networkID' (otherwise this parameter is ignored)
// If the metadata is already carrying a securityGroup, returns fail.ErrNotAvailable
func (instance *securityGroup) Create(/*ctx context.Context, */networkID, name, description string, rules []abstract.SecurityGroupRule) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if networkID == "" {
		return fail.InvalidParameterError("networkID", "cannot be empty string")
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}
	if strings.HasPrefix(name, "instance") {
		return fail.InvalidParameterError("name", "cannot start with 'instance'")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.security-group"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	// Log or propagate errors: here we propagate
	//defer fail.OnExitLogError(&xerr, "failed to create securityGroup")

	instance.lock.Lock()
	defer instance.lock.Unlock()

	// Check if securityGroup exists and is managed by SafeScale
	svc := instance.GetService()
	var found bool
	if found, xerr = lookupSecurityGroup(task, svc, name); xerr != nil {
		// switch xerr.(type) {
		// case *fail.ErrNotFound:
		// 	// not found, good, continue
		// default:
		return fail.Wrap(xerr, "failed to check if Security Group '%s' already exists", name)
		// }
	}
	if found {
		return fail.DuplicateError("a Security Group named '%s' already exists", name)
	}

	// Check if securityGroup exists but is not managed by SafeScale
	asg := abstract.NewSecurityGroup()
	asg.Name = name
	asg.Network = networkID
	if _, xerr = svc.InspectSecurityGroup(asg); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound, *fail.ErrNotAvailable:
		// continue
		default:
			return fail.Wrap(xerr, "failed to check if Security Group name '%s' is already used", name)
		}
	} else {
		return fail.DuplicateError("a Security Group named '%s' already exists (but not managed by SafeScale)", name)
	}

	asg, xerr = svc.CreateSecurityGroup(networkID, name, description, rules)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrInvalidRequest); ok {
			return xerr
		}
		return fail.Wrap(xerr, "failed to create security group '%s'", name)
	}

	defer func() {
		if xerr != nil {
			if derr := svc.DeleteSecurityGroup(asg); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s'", actionFromError(xerr), name))
			}
		}
	}()

	// Creates metadata
	if xerr = instance.Carry(/*task, */asg); xerr != nil {
		return xerr
	}

	defer func() {
		if xerr != nil {
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

			if derr := instance.core.Delete(); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s' metadata", actionFromError(xerr)))
			}
		}
	}()

	if len(rules) == 0 {
		if xerr = instance.unsafeClear(task); xerr != nil {
			return xerr
		}
	}

	logrus.Infof("Security Group '%s' created successfully", name)
	return nil
}

// ForceDelete deletes a Security Group unconditionally
func (instance *securityGroup) ForceDelete(/* ctx context.Context */) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeDelete(true)
}

// Delete deletes a Security Group
func (instance *securityGroup) Delete() (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeDelete(false)
}

// unbindFromHosts unbinds security group from all the hosts bound to it and update the host metadata accordingly
func (instance *securityGroup) unbindFromHosts(/*ctx context.Context, */in *propertiesv1.SecurityGroupHosts) fail.Error {
	tg, xerr := concurrency.NewTaskGroup(task)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to start new task group to remove security group '%s' from hosts", instance.GetName())
	}

	// iterate on hosts bound to the security group and start a go routine to unbind
	svc := instance.GetService()
	for _, v := range in.ByID {
		if v.FromSubnet {
			return fail.InvalidRequestError("cannot unbind from host a security group applied from subnet; use disable instead or remove from bound subnet")
		}
		rh, xerr := LoadHost(task, svc, v.ID)
		if xerr != nil {
			break
		}
		defer func(hostInstance resources.Host) {
			hostInstance.Released()
		}(rh)

		_, xerr = tg.Start(instance.taskUnbindFromHost, rh)
		if xerr != nil {
			break
		}
	}
	if _, xerr = tg.Wait(); xerr != nil {
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
	in.ByName = map[string]string{}
	return nil
}

// unbindFromSubnets unbinds security group from all the subnets bound to it and update the Subnet metadata accordingly
func (instance *securityGroup) unbindFromSubnets(task concurrency.Task, in *propertiesv1.SecurityGroupSubnets) fail.Error {
	tg, xerr := concurrency.NewTaskGroup(task)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to start new task group to remove security group '%s' from subnets", instance.GetName())
	}

	// iterate on all networks bound to the security group to unbind security group from hosts attached to those networks (in parallel)
	for _, v := range in.ByID {
		// Unbind security group from hosts attached to subnet
		if _, xerr = tg.Start(instance.taskUnbindFromHostsAttachedToSubnet, v.ID); xerr != nil {
			break
		}
	}
	if _, xerr = tg.Wait(); xerr != nil {
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
	in.ByName = map[string]string{}
	return nil
}

// Clear removes all rules from a security group
func (instance *securityGroup) Clear(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeClear(task)
}

// Reset clears a security group and re-adds associated rules as stored in metadata
func (instance *securityGroup) Reset(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be null value of '*concurrency.Task'")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	var rules []abstract.SecurityGroupRule
	xerr = instance.Inspect(/*task, */func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
	if xerr = instance.unsafeClear(task); xerr != nil {
		return xerr
	}

	// ... then re-adds rules from metadata
	for _, v := range rules {
		if xerr = instance.unsafeAddRule(task, v); xerr != nil {
			return xerr
		}
	}
	return nil
}

// AddRule adds a rule to a security group
func (instance *securityGroup) AddRule(task concurrency.Task, rule abstract.SecurityGroupRule) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	return instance.unsafeAddRule(task, rule)
}

// AddRules adds rules to a Security Group
func (instance *securityGroup) AddRules(task concurrency.Task, rules abstract.SecurityGroupRules) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if len(rules) == 0 {
		return fail.InvalidParameterError("rules", "cannot be empty slice")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(func(clonable data.Clonable, _ *serialize.JSONProperties) (innerXErr fail.Error) {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		// newAsg := asg.Clone().(*abstract.SecurityGroup)
		for k, v := range rules {
			if v.IsNull() {
				return fail.InvalidParameterError("rules", "entry #%d cannot be null value of 'abstract.SecurityGroupRule'", k)
			}

			if _, innerXErr = instance.GetService().AddRuleToSecurityGroup(asg, v); innerXErr != nil {
				return innerXErr
			}
		}
		// _ = asg.Replace(newAsg)
		return nil
	})
}

// DeleteRule deletes a rule identified by its ID from a security group
// If rule is not in the security group, returns *fail.ErrNotFound
func (instance *securityGroup) DeleteRule(task concurrency.Task, rule abstract.SecurityGroupRule) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if rule.IsNull() {
		return fail.InvalidParameterError("rule", "cannot be null value of 'abstract.SecurityGroupRule'")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(/*task,  */func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		newAsg, innerXErr := instance.GetService().DeleteRuleFromSecurityGroup(asg, rule)
		if innerXErr != nil {
			return innerXErr
		}

		asg.Replace(newAsg)
		return nil
	})
}

// GetBoundHosts returns the list of ID of hosts bound to the security group
func (instance *securityGroup) GetBoundHosts(task concurrency.Task) (_ []*propertiesv1.SecurityGroupBond, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var list []*propertiesv1.SecurityGroupBond
	xerr = instance.Inspect(/*task, */func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(/*task, */securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sghV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			list = make([]*propertiesv1.SecurityGroupBond, 0, len(sghV1.ByID))
			for _, v := range sghV1.ByID {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				list = append(list, v)
			}
			return nil
		})
	})
	return list, xerr
}

// GetBoundSubnets returns the subnet bound to the security group
func (instance *securityGroup) GetBoundSubnets(task concurrency.Task) (list []*propertiesv1.SecurityGroupBond, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	xerr = instance.Inspect(/*task, */func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(/*task, */securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			sgnV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			list = make([]*propertiesv1.SecurityGroupBond, 0, len(sgnV1.ByID))
			for _, v := range sgnV1.ByID {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				list = append(list, v)
			}
			return nil
		})
	})
	return list, xerr
}

// CheckConsistency checks the rules in the security group on provider side are identical to the ones registered in metadata
func (instance *securityGroup) CheckConsistency(_ concurrency.Task) fail.Error {
	return fail.NotImplementedError()
}

// ToProtocol converts a Security Group to protobuf message
func (instance *securityGroup) ToProtocol(task concurrency.Task) (_ *protocol.SecurityGroupResponse, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	out := &protocol.SecurityGroupResponse{}
	return out, instance.Inspect(/*task, */func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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

// BindToHost binds the security group to a IPAddress.
// If 'ip' is not empty, applies the Security Group only on the interface hosting this IP address.
func (instance *securityGroup) BindToHost(task concurrency.Task, rh resources.Host /*ip string,*/, enable resources.SecurityGroupActivation, mark resources.SecurityGroupMark) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if rh == nil {
		return fail.InvalidParameterError("rh", "cannot be nil")
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(/*task,  */func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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

		return props.Alter(/*task, */securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
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
				sghV1.ByName[hostName] = hostID
			}

			// update the state
			sghV1.ByID[hostID].Disabled = disable

			switch enable {
			case resources.SecurityGroupEnable:
				// In case the security group is already bound, we must consider a "duplicate" error has a success
				if xerr := instance.GetService().BindSecurityGroupToHost(instance.GetID(), hostID); xerr != nil {
					switch xerr.(type) {
					case *fail.ErrDuplicate:
						// continue
					default:
						return xerr
					}
				}
			case resources.SecurityGroupDisable:
				// In case the security group has to be disabled, we must consider a "not found" error has a success
				if xerr := instance.GetService().UnbindSecurityGroupFromHost(instance.GetID(), hostID); xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
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

// UnbindFromHost unbinds the security group from an host
func (instance *securityGroup) UnbindFromHost(task concurrency.Task, rh resources.Host) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if rh == nil {
		return fail.InvalidParameterError("rh", "cannot be nil")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(/*task,  */func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(/*task, */securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sgphV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*securitygroupproperty.HostsV1' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// Unbind security group on provider side; if not found, consider as a success
			hostID := rh.GetID()
			if innerXErr := instance.GetService().UnbindSecurityGroupFromHost(instance.GetID(), hostID); innerXErr != nil {
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

// UnbindFromHostByReference unbinds the security group from an host identified by reference (id or name)
func (instance *securityGroup) UnbindFromHostByReference(task concurrency.Task, hostRef string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if hostRef == "" {
		return fail.InvalidParameterError("hostRef", "cannot be empty string")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(/*task,  */func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(/*task, */securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sgphV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*securitygroupproperty.HostsV1' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var (
				b                *propertiesv1.SecurityGroupBond
				hostID, hostName string
			)
			if b, ok = sgphV1.ByID[hostRef]; ok {
				hostID = hostRef
				hostName = b.Name
			} else if hostID, ok = sgphV1.ByName[hostRef]; ok {
				hostName = hostRef
			}
			if hostID != "" {
				// Unbind security group on provider side; if not found, consider as a success
				if innerXErr := instance.GetService().UnbindSecurityGroupFromHost(instance.GetID(), hostID); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound:
						return nil
					default:
						return innerXErr
					}
				}
			}

			// updates security group properties
			delete(sgphV1.ByID, hostID)
			delete(sgphV1.ByName, hostName)
			return nil
		})
	})
}

// BindToSubnet binds the security group to a host
func (instance *securityGroup) BindToSubnet(task concurrency.Task, rs resources.Subnet, enable resources.SecurityGroupActivation, mark resources.SecurityGroupMark) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if rs == nil {
		return fail.InvalidParameterCannotBeNilError("rh")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	switch enable {
	case resources.SecurityGroupEnable:
		xerr = instance.enableOnHostsAttachedToSubnet(task, rs)
	case resources.SecurityGroupDisable:
		xerr = instance.disableOnHostsAttachedToSubnet(task, rs)
	}
	if xerr != nil {
		return xerr
	}

	return instance.Alter(/*task,  */func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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

		return props.Alter(/*task, */securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
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
				sgsV1.ByName[subnetName] = subnetID
			}

			// updates security group properties
			sgsV1.ByID[subnetID].Disabled = disable
			return nil
		})
	})
}

// enableOnHostsAttachedToSubnet enables the security group on hosts attached to the network
func (instance *securityGroup) enableOnHostsAttachedToSubnet(task concurrency.Task, rs resources.Subnet) fail.Error {
	tg, xerr := concurrency.NewTaskGroup(task)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to create a task group to disable security group '%s' on hosts", instance.GetName())
	}

	return rs.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			shV1, ok := clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			for _, v := range shV1.ByID {
				if _, innerXErr := tg.Start(instance.taskEnableOnHost, v); innerXErr != nil {

					break
				}
			}
			_, innerXErr := tg.Wait()
			return innerXErr
		})
	})
}

// disableSecurityGroupOnHosts disables (ie remove) the security group from bound hosts
func (instance *securityGroup) disableOnHostsAttachedToSubnet(task concurrency.Task, rs resources.Subnet) fail.Error {
	tg, xerr := concurrency.NewTaskGroup(task)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to create a task group to disable security group '%s' on hosts", instance.GetName())
	}

	return rs.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			shV1, ok := clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for _, v := range shV1.ByID {
				if _, innerXErr := tg.Start(instance.taskDisableOnHost, v); innerXErr != nil {
					break
				}
			}
			_, innerXErr := tg.Wait()
			return innerXErr
		})
	})
}

// UnbindFromSubnet unbinds the security group from a subnet
func (instance *securityGroup) UnbindFromSubnet(task concurrency.Task, rs resources.Subnet) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if rs == nil {
		return fail.InvalidParameterCannotBeNilError("rs")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(/*task,  */func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(/*task, */securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			sgsV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
			if !ok {
				return fail.InconsistentError("'*securitygroupproperty.SubnetsV1' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			innerXErr := instance.GetService().UnbindSecurityGroupFromSubnet(instance.GetID(), rs.GetID())
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
				// consider a Security Group not found as a successful unbind, and continue to update metadata
				default:
					return innerXErr
				}
			}

			// updates security group metadata
			delete(sgsV1.ByID, rs.GetID())
			delete(sgsV1.ByName, rs.GetName())
			return nil
		})
	})
}

// UnbindFromSubnetByReference unbinds the security group from a subnet
func (instance *securityGroup) UnbindFromSubnetByReference(task concurrency.Task, subnetRef string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if subnetRef == "" {
		return fail.InvalidParameterError("rs", "cannot be empty string")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(/*task,  */func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(/*task, */securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			sgsV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
			if !ok {
				return fail.InconsistentError("'*securitygroupproperty.SubnetsV1' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var (
				b                    *propertiesv1.SecurityGroupBond
				subnetID, subnetName string
			)
			if b, ok = sgsV1.ByID[subnetRef]; ok {
				subnetID = subnetRef
				subnetName = b.Name
			} else if subnetID, ok = sgsV1.ByName[subnetRef]; ok {
				subnetName = subnetRef
			}
			if subnetID != "" {
				if innerXErr := instance.GetService().UnbindSecurityGroupFromSubnet(instance.GetID(), subnetID); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound:
						// consider a Security Group not found as a successful unbind, and continue to update metadata
					default:
						return innerXErr
					}
				}
			}

			// updates security group metadata
			delete(sgsV1.ByID, subnetID)
			delete(sgsV1.ByName, subnetName)
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
