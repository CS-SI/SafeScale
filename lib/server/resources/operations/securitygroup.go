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
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/securitygroupstate"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/v21/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v21/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/v21/lib/utils/net"
	"github.com/CS-SI/SafeScale/v21/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v21/lib/utils/temporal"
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
func NewSecurityGroup(svc iaas.Service) (*SecurityGroup, fail.Error) {
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

// lookupSecurityGroup returns true if security group exists, false otherwise
func lookupSecurityGroup(svc iaas.Service, ref string) (bool, fail.Error) {
	if svc == nil {
		return false, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return false, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	sgInstance, xerr := NewSecurityGroup(svc)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

	xerr = sgInstance.Read(ref)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound, *retry.ErrTimeout:
			return false, nil
		default:
			return false, xerr
		}
	}
	err := sgInstance.Released()
	if err != nil {
		return false, fail.Wrap(err)
	}

	return true, nil
}

// LoadSecurityGroup ...
func LoadSecurityGroup(svc iaas.Service, ref string) (sgInstance *SecurityGroup, ferr fail.Error) {
	// Note: do not log error from here; caller has the responsibility to log if needed
	defer fail.OnPanic(&ferr)

	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	timings, xerr := svc.Timings()
	if xerr != nil {
		return nil, xerr
	}

	sgCache, xerr := svc.GetCache(securityGroupKind)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to get cache for Security Groups")
	}

	options := iaas.CacheMissOption(
		func() (cache.Cacheable, fail.Error) { return onSGCacheMiss(svc, ref) },
		timings.MetadataTimeout(),
	)
	cacheEntry, xerr := sgCache.Get(ref, options...)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreError(xerr)
			// rewrite NotFoundError, user does not bother about metadata stuff
			return nil, fail.NotFoundError("failed to find Security Group '%s'", ref)
		default:
			return nil, xerr
		}
	}

	var ok bool
	sgInstance, ok = cacheEntry.Content().(*SecurityGroup)
	if !ok {
		return nil, fail.InconsistentError("cache content should be a *SecurityGroup", ref)
	}
	if sgInstance == nil {
		return nil, fail.InconsistentError("nil value found in Security Group cache for key '%s'", ref)
	}
	_ = cacheEntry.LockContent()
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			_ = cacheEntry.UnlockContent()
		}
	}()

	// If entry use is greater than 1, the metadata may have been updated, so Reload() the instance
	if cacheEntry.LockCount() > 1 {
		xerr = sgInstance.Reload()
		if xerr != nil {
			return nil, xerr
		}
	}

	return sgInstance, nil
}

// onSGCacheMiss is called when there is no instance in cache of Security Group 'ref'
func onSGCacheMiss(svc iaas.Service, ref string) (cache.Cacheable, fail.Error) {
	sgInstance, innerXErr := NewSecurityGroup(svc)
	if innerXErr != nil {
		return nil, innerXErr
	}

	// TODO: core.ReadByID() does not check communication failure, side effect of limitations of Stow (waiting for stow replacement by rclone)
	if innerXErr = sgInstance.Read(ref); innerXErr != nil {
		return nil, innerXErr
	}

	return sgInstance, nil
}

// IsNull tests if instance is nil or empty
func (instance *SecurityGroup) IsNull() bool {
	if instance.MetadataCore == nil {
		return true
	}

	return valid.IsNil(instance.MetadataCore)
}

// Carry overloads rv.core.Carry() to add Volume to service cache
func (instance *SecurityGroup) carry(clonable data.Clonable) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) {
		if instance.MetadataCore.IsTaken() {
			return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
		}
	}
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}
	identifiable, ok := clonable.(data.Identifiable)
	if !ok {
		return fail.InvalidParameterError("clonable", "must also satisfy interface 'data.Identifiable'")
	}

	kindCache, xerr := instance.Service().GetCache(instance.MetadataCore.GetKind())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = kindCache.ReserveEntry(identifiable.GetID(), temporal.MetadataTimeout())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := kindCache.FreeEntry(identifiable.GetID()); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free %s cache entry for key '%s'", instance.MetadataCore.GetKind(), identifiable.GetID()))
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
func (instance *SecurityGroup) Browse(ctx context.Context, callback func(*abstract.SecurityGroup) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// Note: Do not test with IsNull here, as Browse may be used from null value
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
func (instance *SecurityGroup) Create(ctx context.Context, networkID, name, description string, rules abstract.SecurityGroupRules) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance.MetadataCore) {
		if instance.MetadataCore.IsTaken() {
			return fail.InconsistentError("already carrying information")
		}
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

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.security-group"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	// Log or propagate errors: here we propagate

	instance.lock.Lock()
	defer instance.lock.Unlock()

	// Check if SecurityGroup exists and is managed by SafeScale
	svc := instance.Service()
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
		case *fail.ErrNotImplemented:
			// not all providers implement security groups, and I do not want to see it even in !release mode, so no debug.IgnoreError()
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError(xerr)
		default:
			return fail.Wrap(xerr, "failed to check if Security Group name '%s' is already used", name)
		}
	} else {
		return fail.DuplicateError("a Security Group named '%s' already exists (not managed by SafeScale)", name)
	}

	asg, xerr = svc.CreateSecurityGroup(networkID, name, description, rules)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrInvalidRequest); ok {
			return xerr
		}
		return fail.Wrap(xerr, "failed to create security group '%s'", name)
	}

	// make sure Network ID is stored in Security Group abstract
	asg.Network = networkID

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := svc.DeleteSecurityGroup(asg); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s'", ActionFromError(ferr), name))
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
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

			if derr := instance.MetadataCore.Delete(); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s' metadata", ActionFromError(ferr)))
			}
		}
	}()

	if len(rules) == 0 {
		xerr = instance.unsafeClear()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	// -- update SecurityGroups in Network metadata
	updateFunc := func(props *serialize.JSONProperties) fail.Error {
		return props.Alter(networkproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.NetworkSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			nsgV1.ByID[asg.ID] = asg.Name
			nsgV1.ByName[asg.Name] = asg.ID
			return nil
		})
	}

	currentNetworkProps, ok := ctx.Value(CurrentNetworkPropertiesContextKey).(*serialize.JSONProperties)
	if !ok { // Is nil or is something else
		if ctx.Value(CurrentNetworkPropertiesContextKey) != nil { // If it's something else, return inconsistent error
			return fail.InconsistentError("wrong value of type %T stored in context value, *serialize.JSONProperties was expected instead", ctx.Value(CurrentNetworkPropertiesContextKey))
		}

		// so it's nil...
		networkInstance, xerr := LoadNetwork(svc, networkID)
		if xerr != nil {
			return xerr
		}

		defer func() {
			issue := networkInstance.Released()
			if issue != nil {
				logrus.Warn(issue)
			}
		}()

		xerr = networkInstance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return updateFunc(props)
		})
		if xerr != nil {
			return xerr
		}

		logrus.Infof("Security Group '%s' created successfully", name)
		return nil
	}

	// it is a *serialize.JSONProperties, (it was ok, also avoid else if possible)
	xerr = updateFunc(currentNetworkProps)
	if xerr != nil {
		return xerr
	}

	logrus.Infof("Security Group '%s' created successfully", name)
	return nil
}

// Delete deletes a Security Group
func (instance *SecurityGroup) Delete(ctx context.Context, force bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
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

	return instance.unsafeDelete(ctx, force)
}

// deleteProviderSecurityGroup encapsulates the code responsible to the real Security Group deletion on Provider side
func deleteProviderSecurityGroup(svc iaas.Service, abstractSG *abstract.SecurityGroup) fail.Error {
	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	// FIXME: communication failure handled at service level, not necessary anymore to retry here
	xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			if innerXErr := svc.DeleteSecurityGroup(abstractSG); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					return retry.StopRetryError(innerXErr)
				default:
					return innerXErr
				}
			}
			return nil
		},
		timings.CommunicationTimeout(),
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// consider a Security Group not found as a successful deletion
			debug.IgnoreError(xerr)
		case *fail.ErrTimeout:
			// consider a Security Group not found as a successful deletion
			cause := fail.Cause(xerr)
			if _, ok := cause.(*fail.ErrNotFound); ok {
				debug.IgnoreError(cause)
			} else {
				return fail.Wrap(cause, "timeout")
			}
		case *retry.ErrStopRetry:
			// consider a Security Group not found as a successful deletion
			cause := fail.Cause(xerr)
			if _, ok := cause.(*fail.ErrNotFound); ok {
				debug.IgnoreError(cause)
			} else {
				return fail.Wrap(cause, "stopping retries")
			}
		default:
			return xerr
		}
	}
	return nil
}

// unbindFromHosts unbinds security group from all the hosts bound to it and update the host metadata accordingly
func (instance *SecurityGroup) unbindFromHosts(ctx context.Context, in *propertiesv1.SecurityGroupHosts) fail.Error {
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

	if len(in.ByID) > 0 {
		tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/unbind"))
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to start new task group to remove security group '%s' from hosts", instance.GetName())
		}

		// iterate on hosts bound to the security group and start a go routine to unbind
		svc := instance.Service()
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
				issue := h.Released()
				if issue != nil {
					logrus.Warn(issue)
				}
			}(hostInstance)

			_, xerr = tg.Start(instance.taskUnbindFromHost, hostInstance, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s/unbind", hostInstance.GetName())))
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				abErr := tg.AbortWithCause(xerr)
				if abErr != nil {
					logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
				}
				break
			}
		}

		_, xerr = tg.WaitGroup()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
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
//goland:noinspection GoDeferInLoop
func (instance *SecurityGroup) unbindFromSubnets(ctx context.Context, in *propertiesv1.SecurityGroupSubnets) fail.Error {
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

	if len(in.ByID) > 0 {
		tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/unbind"))
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to start new task group to remove security group '%s' from subnets", instance.GetName())
		}

		// recover from context the Subnet Abstract and properties (if it exists)
		var (
			currentSubnetAbstract *abstract.Subnet
			currentSubnetProps    *serialize.JSONProperties
			ok                    bool
		)
		value := ctx.Value(currentSubnetAbstractContextKey)
		if value != nil {
			currentSubnetAbstract, ok = value.(*abstract.Subnet)
			if !ok {
				return fail.InconsistentError("failed to cast value to '*abstract.Subnet'")
			}
		}
		value = ctx.Value(currentSubnetPropertiesContextKey)
		if value != nil {
			currentSubnetAbstract, ok = value.(*abstract.Subnet)
			if !ok {
				return fail.InconsistentError("failed to cast value to '*serialize.JSONProperties'")
			}
		}

		var subnetHosts *propertiesv1.SubnetHosts
		// inspectFunc will get Hosts linked to Subnet from properties
		inspectFunc := func(props *serialize.JSONProperties) fail.Error {
			return props.Inspect(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
				var ok bool
				subnetHosts, ok = clonable.(*propertiesv1.SubnetHosts)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return nil
			})
		}
		// iterate on all Subnets bound to the Security Group to unbind Security Group from Hosts attached to those subnets (in parallel)
		svc := instance.Service()
		for k, v := range in.ByName {
			// If current Subnet corresponds to the Subnet found in context, uses the data from the context to prevent deadlock
			if currentSubnetAbstract != nil && v == currentSubnetAbstract.ID {
				xerr = inspectFunc(currentSubnetProps)
				if xerr != nil {
					return xerr
				}
			} else {
				subnetInstance, xerr := LoadSubnet(svc, "", v)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// consider a missing subnet as a successful operation and continue the loop
						debug.IgnoreError(xerr)
						continue
					default:
						return xerr
					}
				}

				//goland:noinspection GoDeferInLoop
				defer func(in resources.Subnet) {
					issue := in.Released()
					if issue != nil {
						logrus.Warn(issue)
					}
				}(subnetInstance)

				xerr = subnetInstance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
					return inspectFunc(props)
				})
				if xerr != nil {
					return xerr
				}
			}

			_, xerr = tg.Start(instance.taskUnbindFromHostsAttachedToSubnet, taskUnbindFromHostsAttachedToSubnetParams{subnetName: k, subnetHosts: subnetHosts}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/subnet/%s/unbind", k)))
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				abErr := tg.AbortWithCause(xerr)
				if abErr != nil {
					logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
				}
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
func (instance *SecurityGroup) Clear(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
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

	return instance.unsafeClear()
}

// Reset clears a security group and re-adds associated rules as stored in metadata
func (instance *SecurityGroup) Reset(ctx context.Context) (ferr fail.Error) {
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
	xerr = instance.unsafeClear()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// ... then re-adds rules from metadata
	for _, v := range rules {
		xerr = instance.unsafeAddRule(v)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// AddRule adds a rule to a security group
func (instance *SecurityGroup) AddRule(ctx context.Context, rule *abstract.SecurityGroupRule) (ferr fail.Error) {
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

	return instance.unsafeAddRule(rule)
}

// AddRules adds rules to a Security Group
func (instance *SecurityGroup) AddRules(ctx context.Context, rules abstract.SecurityGroupRules) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
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

	return instance.Alter(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		// newAsg := asg.Clone().(*abstract.SecurityGroup)
		for k, v := range rules {
			if valid.IsNil(v) {
				return fail.InvalidParameterError("rules", "entry #%d cannot be null value of 'abstract.SecurityGroupRule'", k)
			}
			inErr := v.Validate()
			if inErr != nil {
				return inErr
			}
		}
		svc := instance.Service()
		for _, v := range rules {
			_, inErr := svc.AddRuleToSecurityGroup(asg, v)
			if inErr != nil {
				return inErr
			}
		}
		return nil
	})
}

// DeleteRule deletes a rule identified by its ID from a security group
// If rule is not in the security group, returns *fail.ErrNotFound
func (instance *SecurityGroup) DeleteRule(ctx context.Context, rule *abstract.SecurityGroupRule) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if rule == nil {
		return fail.InvalidParameterCannotBeNilError("rule")
	}

	xerr := rule.Validate()
	if xerr != nil {
		return xerr
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

	return instance.Alter(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		_, innerXErr := instance.Service().DeleteRuleFromSecurityGroup(asg, rule)
		if innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				break
			}
			return innerXErr
		}

		// asg.Replace(newAsg)
		return nil
	})
}

// GetBoundHosts returns the list of ID of hosts bound to the security group
func (instance *SecurityGroup) GetBoundHosts(ctx context.Context) (_ []*propertiesv1.SecurityGroupBond, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
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
			if xerr != nil {
				return nil, xerr
			}
		default:
			return nil, xerr
		}
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
func (instance *SecurityGroup) GetBoundSubnets(ctx context.Context) (list []*propertiesv1.SecurityGroupBond, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
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
			if xerr != nil {
				return nil, xerr
			}
		default:
			return nil, xerr
		}
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
func (instance *SecurityGroup) ToProtocol() (_ *protocol.SecurityGroupResponse, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
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

// BindToHost binds the security group to a host.
func (instance *SecurityGroup) BindToHost(ctx context.Context, hostInstance resources.Host, enable resources.SecurityGroupActivation, mark resources.SecurityGroupMark) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if hostInstance == nil {
		return fail.InvalidParameterError("hostInstance", "cannot be nil")
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeBindToHost(ctx, hostInstance, enable, mark)
}

// UnbindFromHost unbinds the security group from a host
func (instance *SecurityGroup) UnbindFromHost(ctx context.Context, hostInstance resources.Host) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostInstance == nil {
		return fail.InvalidParameterError("hostInstance", "cannot be nil")
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

	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sgphV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*securitygroupproperty.HostsV1' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// Unbind security group on provider side; if not found, considered as a success
			hostID := hostInstance.GetID()
			if innerXErr := instance.Service().UnbindSecurityGroupFromHost(instance.GetID(), hostID); innerXErr != nil {
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
			delete(sgphV1.ByName, hostInstance.GetName())
			return nil
		})
	})
}

// UnbindFromHostByReference unbinds the security group from a host identified by reference (id or name)
func (instance *SecurityGroup) UnbindFromHostByReference(ctx context.Context, hostRef string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
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
				if innerXErr := instance.Service().UnbindSecurityGroupFromHost(instance.GetID(), hostID); innerXErr != nil {
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
// This method assumes the Subnet is not called while the Subnet is currently locked (otherwise will deadlock...)
func (instance *SecurityGroup) BindToSubnet(
	ctx context.Context, subnetInstance resources.Subnet, enable resources.SecurityGroupActivation,
	mark resources.SecurityGroupMark,
) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if subnetInstance == nil {
		return fail.InvalidParameterCannotBeNilError("rh")
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

	xerr = subnetInstance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		var subnetHosts *propertiesv1.SubnetHosts
		innerXErr := props.Inspect(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			var ok bool
			subnetHosts, ok = clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv12.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		switch enable {
		case resources.SecurityGroupEnable:
			innerXErr = instance.enableOnHostsAttachedToSubnet(task, subnetHosts)
		case resources.SecurityGroupDisable:
			innerXErr = instance.disableOnHostsAttachedToSubnet(task, subnetHosts)
		}
		innerXErr = debug.InjectPlannedFail(innerXErr)
		return innerXErr
	})
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

			asg.DefaultForSubnet = subnetInstance.GetID()
		}

		return props.Alter(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			sgsV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// First check if subnet is present with the state requested; if present with same state, consider situation as a success
			subnetID := subnetInstance.GetID()
			subnetName := subnetInstance.GetName()
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
func (instance *SecurityGroup) enableOnHostsAttachedToSubnet(
	task concurrency.Task, subnetHosts *propertiesv1.SubnetHosts,
) fail.Error {
	if len(subnetHosts.ByID) > 0 {
		tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to create a TaskGroup to enable Security Group '%s' on Hosts", instance.GetName())
		}

		for _, v := range subnetHosts.ByID {
			if _, innerXErr := tg.Start(instance.taskBindEnabledOnHost, v); innerXErr != nil {
				abErr := tg.AbortWithCause(innerXErr)
				if abErr != nil {
					logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
				}
				break
			}
		}
		_, innerXErr := tg.WaitGroup()
		innerXErr = debug.InjectPlannedFail(innerXErr)
		return innerXErr
	}
	return nil
}

// disableSecurityGroupOnHosts disables (ie remove) the security group from bound hosts
func (instance *SecurityGroup) disableOnHostsAttachedToSubnet(
	task concurrency.Task, subnetHosts *propertiesv1.SubnetHosts,
) fail.Error {
	if len(subnetHosts.ByID) > 0 {
		tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to create a TaskGroup to disable Security Group '%s' on Hosts", instance.GetName())
		}

		for _, v := range subnetHosts.ByID {
			_, xerr = tg.Start(instance.taskBindDisabledOnHost, v)
			if xerr != nil {
				abErr := tg.AbortWithCause(xerr)
				if abErr != nil {
					logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
				}
				break
			}
		}
		_, xerr = tg.WaitGroup()
		xerr = debug.InjectPlannedFail(xerr)
		return xerr
	}
	return nil
}

// unbindFromHostsAttachedToSubnet unbinds (ie remove) the security group from Hosts in a Subnet
func (instance *SecurityGroup) unbindFromHostsAttachedToSubnet(
	task concurrency.Task, subnetHosts *propertiesv1.SubnetHosts,
) fail.Error {
	if len(subnetHosts.ByID) > 0 {
		tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to create a TaskGroup to disable Security Group '%s' on Hosts", instance.GetName())
		}

		for _, v := range subnetHosts.ByID {
			_, xerr = tg.Start(instance.taskBindDisabledOnHost, v)
			if xerr != nil {
				abErr := tg.AbortWithCause(xerr)
				if abErr != nil {
					logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
				}
				break
			}
		}
		_, xerr = tg.WaitGroup()
		xerr = debug.InjectPlannedFail(xerr)
		return xerr
	}
	return nil
}

// UnbindFromSubnet unbinds the security group from a subnet
func (instance *SecurityGroup) UnbindFromSubnet(
	ctx context.Context, subnetInstance resources.Subnet,
) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if subnetInstance == nil {
		return fail.InvalidParameterCannotBeNilError("subnetInstance")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	var subnetHosts *propertiesv1.SubnetHosts
	xerr := subnetInstance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			var ok bool
			subnetHosts, ok = clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	return instance.unsafeUnbindFromSubnet(ctx, taskUnbindFromHostsAttachedToSubnetParams{subnetID: subnetInstance.GetID(), subnetName: subnetInstance.GetName(), subnetHosts: subnetHosts})
}

// unbindFromSubnetHosts unbinds the security group from Hosts attached to a Subnet
func (instance *SecurityGroup) unbindFromSubnetHosts(
	ctx context.Context, params taskUnbindFromHostsAttachedToSubnetParams,
) (ferr fail.Error) {
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
	task, xerr = concurrency.NewTaskWithParent(task)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	// Unbind Security Group from Hosts attached to Subnet
	_, xerr = task.Run(instance.taskUnbindFromHostsAttachedToSubnet, params)
	if xerr != nil {
		return xerr
	}

	// -- Remove Hosts attached to Subnet referenced in Security Group
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sghV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// updates security group metadata
			for k, v := range sghV1.ByID {
				delete(sghV1.ByID, k)
				delete(sghV1.ByName, v.Name)
			}
			return nil
		})
	}, data.NewImmutableKeyValue("Reload", !params.onRemoval))
	if xerr != nil {
		return xerr
	}

	// -- Remove Subnet referenced in Security Group
	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			sgsV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
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

// UnbindFromSubnetByReference unbinds the security group from a subnet
func (instance *SecurityGroup) UnbindFromSubnetByReference(
	ctx context.Context, subnetRef string,
) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
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
				if innerXErr := instance.Service().UnbindSecurityGroupFromSubnet(instance.GetID(), subnetID); innerXErr != nil {
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

func FilterBondsByKind(
	bonds map[string]*propertiesv1.SecurityGroupBond, state securitygroupstate.Enum,
) []*propertiesv1.SecurityGroupBond {
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
