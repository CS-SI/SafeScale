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
	"context"
	"fmt"
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

// SecurityGroup ...
// follows interface resources.SecurityGroup
type SecurityGroup struct {
	*MetadataCore

	lock sync.RWMutex
}

// NewSecurityGroup ...
func NewSecurityGroup(svc iaas.Service) (resources.SecurityGroup, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	coreInstance, xerr := NewCore(svc, securityGroupKind, securityGroupsFolderName, &abstract.SecurityGroup{})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &SecurityGroup{
		MetadataCore: coreInstance,
	}
	return instance, nil
}

// SecurityGroupNullValue returns a *SecurityGroup corresponding to ShareNullValue
func SecurityGroupNullValue() *SecurityGroup {
	return &SecurityGroup{MetadataCore: NullCore()}
}

// lookupSecurityGroup returns true if security group exists, false otherwise
func lookupSecurityGroup(svc iaas.Service, ref string) (bool, fail.Error) {
	if svc == nil {
		return false, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return false, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	rsg, xerr := NewSecurityGroup(svc)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

	xerr = rsg.Read(ref)
	xerr = debug.InjectPlannedFail(xerr)
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
func LoadSecurityGroup(svc iaas.Service, ref string) (rsg resources.SecurityGroup, xerr fail.Error) {
	// Note: do not log error from here; caller has the responsibility to log if needed
	defer fail.OnPanic(&xerr)

	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	sgCache, xerr := svc.GetCache(securityGroupKind)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to get cache for Security Groups")
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// rewrite NotFoundError, user does not bother about metadata stuff
			return nil, fail.NotFoundError("failed to find Security Group '%s'", ref)
		default:
			return nil, xerr
		}
	}

	if rsg = cacheEntry.Content().(resources.SecurityGroup); rsg == nil {
		return nil, fail.InconsistentError("nil value found in Security Group cache for key '%s'", ref)
	}
	_ = cacheEntry.LockContent()
	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			_ = cacheEntry.UnlockContent()
		}
	}()

	return rsg, nil
}

// IsNull tests if instance is nil or empty
func (instance *SecurityGroup) IsNull() bool {
	if instance.MetadataCore == nil {
		return true
	}

	return instance.MetadataCore.IsNull()
}

// Carry overloads rv.core.Carry() to add Volume to service cache
func (instance *SecurityGroup) carry(clonable data.Clonable) (xerr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !instance.IsNull() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}
	identifiable, ok := clonable.(data.Identifiable)
	if !ok {
		return fail.InvalidParameterError("clonable", "must also satisfy interface 'data.Identifiable'")
	}

	kindCache, xerr := instance.GetService().GetCache(instance.MetadataCore.GetKind())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = kindCache.ReserveEntry(identifiable.GetID())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if derr := kindCache.FreeEntry(identifiable.GetID()); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free %s cache entry for key '%s'", instance.MetadataCore.GetKind(), identifiable.GetID()))
			}

		}
	}()

	// Note: do not validate parameters, this call will do it
	xerr = instance.MetadataCore.Carry(clonable)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	cacheEntry, xerr := kindCache.CommitEntry(identifiable.GetID(), instance)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	cacheEntry.LockContent()

	return nil
}

// Browse walks through SecurityGroup MetadataFolder and executes a callback for each entries
func (instance *SecurityGroup) Browse(ctx context.Context, callback func(*abstract.SecurityGroup) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: Browse is intended to be callable from null value, so do not validate instance with .IsNull()
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.MetadataCore.BrowseFolder(func(buf []byte) fail.Error {
		asg := abstract.NewSecurityGroup()
		xerr = asg.Deserialize(buf)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		return callback(asg)
	})
}

// Create creates a new SecurityGroup and its metadata.
// If needed by Cloud Provider, the Security Group will be attached to Network identified by 'networkID' (otherwise this parameter is ignored)
// If the metadata is already carrying a SecurityGroup, returns fail.ErrNotAvailable
func (instance *SecurityGroup) Create(ctx context.Context, networkID, name, description string, rules abstract.SecurityGroupRules) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !instance.IsNull() {
		sgName := instance.GetName()
		if sgName != "" {
			return fail.NotAvailableError("already carrying SecurityGroup '%s'", sgName)
		}
		return fail.InvalidInstanceContentError("instance", "is not null value")
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
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

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.security-group"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	// Log or propagate errors: here we propagate

	instance.lock.Lock()
	defer instance.lock.Unlock()

	// Check if SecurityGroup exists and is managed by SafeScale
	svc := instance.GetService()
	var found bool
	found, xerr = lookupSecurityGroup(svc, name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to check if Security Group '%s' already exists", name)
	}
	if found {
		return fail.DuplicateError("a Security Group named '%s' already exists", name)
	}

	// Check if SecurityGroup exists but is not managed by SafeScale
	asg := abstract.NewSecurityGroup()
	asg.Name = name
	asg.Network = networkID
	_, xerr = svc.InspectSecurityGroup(asg)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound, *fail.ErrNotAvailable:
			// continue
			debug.IgnoreError(xerr)
		default:
			return fail.Wrap(xerr, "failed to check if Security Group name '%s' is already used", name)
		}
	} else {
		return fail.DuplicateError("a Security Group named '%s' already exists (but not managed by SafeScale)", name)
	}

	asg, xerr = svc.CreateSecurityGroup(networkID, name, description, rules)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrInvalidRequest); ok {
			return xerr
		}
		return fail.Wrap(xerr, "failed to create security group '%s'", name)
	}

	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if derr := svc.DeleteSecurityGroup(asg); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s'", ActionFromError(xerr), name))
			}
		}
	}()

	// Creates metadata
	xerr = instance.carry(asg)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

			if derr := instance.MetadataCore.Delete(); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s' metadata", ActionFromError(xerr)))
			}
		}
	}()

	if len(rules) == 0 {
		xerr = instance.unsafeClear(task)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	logrus.Infof("Security Group '%s' created successfully", name)
	return nil
}

// Delete deletes a Security Group
func (instance *SecurityGroup) Delete(ctx context.Context, force bool) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeDelete(ctx, force)
}

// unbindFromHosts unbinds security group from all the hosts bound to it and update the host metadata accordingly
func (instance *SecurityGroup) unbindFromHosts(ctx context.Context, in *propertiesv1.SecurityGroupHosts) fail.Error {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if len(in.ByID) > 0 {
		tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/unbind"))
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to start new task group to remove security group '%s' from hosts", instance.GetName())
		}

		// iterate on hosts bound to the security group and start a go routine to unbind
		svc := instance.GetService()
		for _, v := range in.ByID {
			if v.FromSubnet {
				return fail.InvalidRequestError("cannot unbind from host a security group applied from subnet; use disable instead or remove from bound subnet")
			}
			hostInstance, xerr := LoadHost(svc, v.ID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					continue
				default:
					break
				}
			}

			//goland:noinspection ALL
			defer func(h resources.Host) {
				h.Released()
			}(hostInstance)

			_, xerr = tg.Start(instance.taskUnbindFromHost, hostInstance, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s/unbind", hostInstance.GetName())))
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				break
			}
		}

		if count, xerr := tg.Started(); xerr == nil && count > 0 {
			_, xerr = tg.WaitGroup()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}

		if count, xerr := tg.Started(); xerr == nil && count > 0 {
			_, xerr = tg.WaitGroup()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
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
func (instance *SecurityGroup) unbindFromSubnets(ctx context.Context, in *propertiesv1.SecurityGroupSubnets) fail.Error {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if len(in.ByID) > 0 {
		tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/unbind"))
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to start new task group to remove security group '%s' from subnets", instance.GetName())
		}

		// iterate on all networks bound to the security group to unbind security group from hosts attached to those networks (in parallel)
		for k, v := range in.ByName {
			_, xerr = tg.Start(instance.taskUnbindFromHostsAttachedToSubnet, v, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/subnet/%s/unbind", k)))
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				break
			}
		}

		_, xerr = tg.WaitGroup()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		// Remove the bonds on Subnets
		in.ByID = map[string]*propertiesv1.SecurityGroupBond{}
		in.ByName = map[string]string{}
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

	return nil
}

// Clear removes all rules from a security group
func (instance *SecurityGroup) Clear(ctx context.Context) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeClear(task)
}

// Reset clears a security group and re-adds associated rules as stored in metadata
func (instance *SecurityGroup) Reset(ctx context.Context) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
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
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	var rules abstract.SecurityGroupRules
	xerr = instance.Inspect(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		rules = asg.Rules
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Removes all rules...
	xerr = instance.unsafeClear(task)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// ... then re-adds rules from metadata
	for _, v := range rules {
		xerr = instance.unsafeAddRule(task, v)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// AddRule adds a rule to a security group
func (instance *SecurityGroup) AddRule(ctx context.Context, rule *abstract.SecurityGroupRule) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
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
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	return instance.unsafeAddRule(task, rule)
}

// AddRules adds rules to a Security Group
func (instance *SecurityGroup) AddRules(ctx context.Context, rules abstract.SecurityGroupRules) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if len(rules) == 0 {
		return fail.InvalidParameterError("rules", "cannot be empty slice")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
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
func (instance *SecurityGroup) DeleteRule(ctx context.Context, rule *abstract.SecurityGroupRule) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if rule.IsNull() {
		return fail.InvalidParameterError("rule", "cannot be null value of 'abstract.SecurityGroupRule'")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
func (instance *SecurityGroup) GetBoundHosts(ctx context.Context) (_ []*propertiesv1.SecurityGroupBond, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var list []*propertiesv1.SecurityGroupBond
	xerr = instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
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
func (instance *SecurityGroup) GetBoundSubnets(ctx context.Context) (list []*propertiesv1.SecurityGroupBond, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	xerr = instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
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
func (instance *SecurityGroup) CheckConsistency(_ context.Context) fail.Error {
	return fail.NotImplementedError()
}

// ToProtocol converts a Security Group to protobuf message
func (instance *SecurityGroup) ToProtocol() (_ *protocol.SecurityGroupResponse, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	out := &protocol.SecurityGroupResponse{}
	return out, instance.Inspect(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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

// BindToHost binds the security group to an Host.
func (instance *SecurityGroup) BindToHost(ctx context.Context, rh resources.Host, enable resources.SecurityGroupActivation, mark resources.SecurityGroupMark) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if rh == nil {
		return fail.InvalidParameterError("rh", "cannot be nil")
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
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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

		return props.Alter(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
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
				xerr := instance.GetService().BindSecurityGroupToHost(instance.GetID(), hostID)
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
				xerr := instance.GetService().UnbindSecurityGroupFromHost(instance.GetID(), hostID)
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

// UnbindFromHost unbinds the security group from an host
func (instance *SecurityGroup) UnbindFromHost(ctx context.Context, rh resources.Host) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if rh == nil {
		return fail.InvalidParameterError("rh", "cannot be nil")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sgphV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*securitygroupproperty.HostsV1' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// Unbind security group on provider side; if not found, considered as a success
			hostID := rh.GetID()
			if innerXErr := instance.GetService().UnbindSecurityGroupFromHost(instance.GetID(), hostID); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					debug.IgnoreError(innerXErr)
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
func (instance *SecurityGroup) UnbindFromHostByReference(ctx context.Context, hostRef string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostRef == "" {
		return fail.InvalidParameterError("hostRef", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
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
				// Unbind security group on provider side; if not found, considered as a success
				if innerXErr := instance.GetService().UnbindSecurityGroupFromHost(instance.GetID(), hostID); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound:
						debug.IgnoreError(innerXErr)
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
func (instance *SecurityGroup) BindToSubnet(ctx context.Context, rs resources.Subnet, enable resources.SecurityGroupActivation, mark resources.SecurityGroupMark) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if rs == nil {
		return fail.InvalidParameterCannotBeNilError("rh")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
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

			asg.DefaultForSubnet = rs.GetID()
		}

		return props.Alter(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
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
func (instance *SecurityGroup) enableOnHostsAttachedToSubnet(task concurrency.Task, rs resources.Subnet) fail.Error {
	return rs.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			shV1, ok := clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if len(shV1.ByID) > 0 {
				tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return fail.Wrap(xerr, "failed to create a TaskGroup to enable Security Group '%s' on Hosts", instance.GetName())
				}

				for _, v := range shV1.ByID {
					if _, innerXErr := tg.Start(instance.taskEnableOnHost, v); innerXErr != nil {
						break
					}
				}
				_, innerXErr := tg.WaitGroup()
				return innerXErr
			}
			return nil
		})
	})
}

// disableSecurityGroupOnHosts disables (ie remove) the security group from bound hosts
func (instance *SecurityGroup) disableOnHostsAttachedToSubnet(task concurrency.Task, rs resources.Subnet) fail.Error {
	return rs.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			shV1, ok := clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if len(shV1.ByID) > 0 {
				tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return fail.Wrap(xerr, "failed to create a TaskGroup to disable Security Group '%s' on Hosts", instance.GetName())
				}

				for _, v := range shV1.ByID {
					if _, innerXErr := tg.Start(instance.taskDisableOnHost, v); innerXErr != nil {
						break
					}
				}
				_, innerXErr := tg.WaitGroup()
				return innerXErr
			}
			return nil
		})
	})
}

// UnbindFromSubnet unbinds the security group from a subnet
func (instance *SecurityGroup) UnbindFromSubnet(ctx context.Context, rs resources.Subnet) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if rs == nil {
		return fail.InvalidParameterCannotBeNilError("rs")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			sgsV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
			if !ok {
				return fail.InconsistentError("'*securitygroupproperty.SubnetsV1' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			innerXErr := instance.GetService().UnbindSecurityGroupFromSubnet(instance.GetID(), rs.GetID())
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
			delete(sgsV1.ByID, rs.GetID())
			delete(sgsV1.ByName, rs.GetName())
			return nil
		})
	})
}

// UnbindFromSubnetByReference unbinds the security group from a subnet
func (instance *SecurityGroup) UnbindFromSubnetByReference(ctx context.Context, subnetRef string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if subnetRef == "" {
		return fail.InvalidParameterError("rs", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
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
						debug.IgnoreError(innerXErr)
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

func FilterBondsByKind(bonds map[string]*propertiesv1.SecurityGroupBond, state securitygroupstate.Enum) []*propertiesv1.SecurityGroupBond {
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
