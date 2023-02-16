/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package resources

import (
	"context"
	"fmt"
	"strings"
	"time"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/converters"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	netretry "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/eko/gocache/v2/store"
	"github.com/sirupsen/logrus"
)

const (
	securityGroupKind = "security-group"
	// securityGroupsFolderName is the technical name of the container used to store networks info
	securityGroupsFolderName = "security-groups"
)

// SecurityGroupActivation represents activation state of a Security Group
type SecurityGroupActivation bool

const (
	// SecurityGroupEnable means the security group is enabled
	SecurityGroupEnable SecurityGroupActivation = true
	// SecurityGroupDisable means the security group is disabled
	SecurityGroupDisable SecurityGroupActivation = false
)

type SecurityGroupMark bool

const (
	MarkSecurityGroupAsDefault      = true  // mark the Security Group as a default
	MarkSecurityGroupAsSupplemental = false // mark the Security Group as supplemental
	KeepCurrentSecurityGroupMark    = false // Do not change current Security Group mark
)

// SecurityGroup ...
// follows interface resources.SecurityGroup
type SecurityGroup struct {
	*metadata.Core[*abstract.SecurityGroup]
}

// NewSecurityGroup ...
func NewSecurityGroup(ctx context.Context) (*SecurityGroup, fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	coreInstance, xerr := metadata.NewCore(ctx, metadata.MethodObjectStorage, securityGroupKind, securityGroupsFolderName, abstract.NewEmptySecurityGroup())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &SecurityGroup{
		Core: coreInstance,
	}
	return instance, nil
}

// LoadSecurityGroup ...
func LoadSecurityGroup(inctx context.Context, ref string) (*SecurityGroup, fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	myjob, xerr := jobapi.FromContext(inctx)
	if xerr != nil {
		return nil, xerr
	}

	type result struct {
		rTr  *SecurityGroup
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ *SecurityGroup, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// trick to avoid collisions
			var kt *SecurityGroup
			refcache := fmt.Sprintf("%T/%s", kt, ref)

			cache, xerr := myjob.Service().Cache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			var (
				sgInstance *SecurityGroup
				inCache    bool
				err        error
			)
			if cache != nil {
				entry, err := cache.Get(ctx, refcache)
				if err == nil {
					sgInstance, err = lang.Cast[*SecurityGroup](entry)
					if err != nil {
						return nil, fail.Wrap(err)
					}

					inCache = true

					// -- reload from metadata storage
					xerr := sgInstance.Core.Reload(ctx)
					if xerr != nil {
						return nil, xerr
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}
			if sgInstance == nil {
				anon, xerr := onSGCacheMiss(ctx, ref)
				if xerr != nil {
					return nil, xerr
				}

				sgInstance, err = lang.Cast[*SecurityGroup](anon)
				if err != nil {
					return nil, fail.Wrap(err)
				}
			}

			if cache != nil && !inCache {
				// -- add host instance in cache by name
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, sgInstance.GetName()), sgInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.Wrap(err)
				}

				time.Sleep(10 * time.Millisecond) // consolidate cache.Set
				hid, err := sgInstance.GetID()
				if err != nil {
					return nil, fail.Wrap(err)
				}

				// -- add host instance in cache by id
				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), sgInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.Wrap(err)
				}

				time.Sleep(10 * time.Millisecond) // consolidate cache.Set

				val, xerr := cache.Get(ctx, refcache)
				if xerr == nil {
					if _, ok := val.(*Host); !ok {
						logrus.WithContext(ctx).Warnf("wrong type of *SecurityGroup")
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}

			if myjob.Service().Capabilities().UseTerraformer {
				sgTrx, xerr := newSecurityGroupTransaction(ctx, sgInstance)
				if xerr != nil {
					return nil, xerr
				}
				defer sgTrx.TerminateFromError(ctx, &ferr)

				xerr = inspectSecurityGroupMetadataAbstract(ctx, sgTrx, func(asg *abstract.SecurityGroup) fail.Error {
					prov, xerr := myjob.Service().ProviderDriver()
					if xerr != nil {
						return xerr
					}
					castedProv, innerErr := lang.Cast[providers.ReservedForTerraformerUse](prov)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					innerXErr := castedProv.ConsolidateSecurityGroupSnippet(asg)
					if innerXErr != nil {
						return innerXErr
					}

					_, innerXErr = myjob.Scope().RegisterAbstractIfNeeded(asg)
					return innerXErr
				})
				if xerr != nil {
					return nil, xerr
				}
			}
			return sgInstance, nil
		}()
		chRes <- result{ga, gerr}
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}
}

// onSGCacheMiss is called when there is no instance in cache of Security Group 'ref'
func onSGCacheMiss(ctx context.Context, ref string) (data.Identifiable, fail.Error) {
	sgInstance, innerXErr := NewSecurityGroup(ctx)
	if innerXErr != nil {
		return nil, innerXErr
	}

	blank, innerXErr := NewSecurityGroup(ctx)
	if innerXErr != nil {
		return nil, innerXErr
	}

	if innerXErr = sgInstance.Read(ctx, ref); innerXErr != nil {
		return nil, innerXErr
	}

	if strings.Compare(fail.IgnoreError(sgInstance.String()).(string), fail.IgnoreError(blank.String()).(string)) == 0 {
		return nil, fail.NotFoundError("failed to find Security Group with ref '%s'", ref)
	}

	return sgInstance, nil
}

// IsNull tests if instance is nil or empty
func (instance *SecurityGroup) IsNull() bool {
	return instance == nil || valid.IsNil(instance.Core)
}

func (instance *SecurityGroup) Clone() (clonable.Clonable, error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}

	newInstance, err := newBulkSecurityGroup()
	if err != nil {
		return nil, err
	}

	return newInstance, newInstance.Replace(instance)
}

// newBulkSecurityGroup ...
func newBulkSecurityGroup() (*SecurityGroup, fail.Error) {
	protected, err := abstract.NewSecurityGroup()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	core, err := metadata.NewEmptyCore(abstract.SecurityGroupKind, protected)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	instance := &SecurityGroup{Core: core}
	return instance, nil
}

func (instance *SecurityGroup) Replace(in clonable.Clonable) error {
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*SecurityGroup](in)
	if err != nil {
		return err
	}

	// instance.Core, err = clonable.CastedClone[*metadata.Core[*abstract.SecurityGroup]](src.Core)
	return instance.Core.Replace(src.Core)
}

// Exists checks if the resource actually exists in provider side (not in stow metadata)
func (instance *SecurityGroup) Exists(ctx context.Context) (bool, fail.Error) {
	// FIXME: Not so easy, securitygroups are in some cases a metadata-only construct -> we need to turn those into tags (provider ones) 1st
	theID, err := instance.GetID()
	if err != nil {
		return false, fail.Wrap(err)
	}

	_, xerr := instance.Service().InspectSecurityGroup(ctx, theID)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return false, nil
		default:
			return false, xerr
		}
	}

	return true, nil
}

// Carry overloads rv.core.Carry() to add Volume to service cache
func (instance *SecurityGroup) Carry(ctx context.Context, asg *abstract.SecurityGroup) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) && instance.Core.IsTaken() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}
	if asg == nil {
		return fail.InvalidParameterCannotBeNilError("asg")
	}

	// Note: do not validate parameters, this call will do it
	xerr := instance.Core.Carry(ctx, asg)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = instance.Job().Scope().RegisterAbstract(asg)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Browse walks through SecurityGroup MetadataFolder and executes a callback for each entry
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

	return instance.Core.BrowseFolder(ctx, func(buf []byte) fail.Error {
		asg, _ := abstract.NewSecurityGroup()
		xerr := asg.Deserialize(buf)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		return callback(asg)
	})
}

// Create creates a new SecurityGroup and its metadata.
// If needed by Cloud Provider, the Security Group will be attached to Network identified by 'networkID' (otherwise this parameter is ignored)
// If the metadata is already carrying a SecurityGroup, returns fail.ErrNotAvailable
func (instance *SecurityGroup) Create(inctx context.Context, networkID, name, description string, rules abstract.SecurityGroupRules) (gerr fail.Error) {
	defer fail.OnPanic(&gerr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance.Core) && instance.Core.IsTaken() {
		return fail.InconsistentError("already carrying information")
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
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

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.securitygroup"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// Check if SecurityGroup exists and is managed by SafeScale
			svc := instance.Service()
			_, xerr := LoadSecurityGroup(ctx, name)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// continue
					debug.IgnoreErrorWithContext(ctx, xerr)
				default:
					xerr := fail.Wrap(xerr, "failed to check if Security Group '%s' already exists", name)
					ar := result{xerr}
					return ar, ar.rErr
				}
			} else {
				xerr := fail.DuplicateError("a Security Group named '%s' already exists", name)
				ar := result{xerr}
				return ar, ar.rErr
			}

			// Check if SecurityGroup exists but is not managed by SafeScale
			asg, xerr := abstract.NewSecurityGroup(abstract.WithName(name))
			if xerr != nil {
				ar := result{xerr}
				return ar, ar.rErr
			}

			asg.Network = networkID
			_, xerr = svc.InspectSecurityGroup(ctx, asg)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotImplemented:
					// not all providers implement security groups, and I do not want to see it even in !release mode, so no debug.IgnoreError()
				case *fail.ErrNotFound:
					// continue
					debug.IgnoreErrorWithContext(ctx, xerr)
				default:
					xerr := fail.Wrap(xerr, "failed to check if Security Group name '%s' is already used", name)
					ar := result{xerr}
					return ar, ar.rErr
				}
			} else {
				xerr := fail.DuplicateError("a Security Group named '%s' already exists (not managed by SafeScale)", name)
				ar := result{xerr}
				return ar, ar.rErr
			}

			asg, xerr = svc.CreateSecurityGroup(ctx, networkID, name, description, rules)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				if _, ok := xerr.(*fail.ErrInvalidRequest); ok {
					ar := result{xerr}
					return ar, ar.rErr
				}

				xerr := fail.Wrap(xerr, "failed to create security group '%s'", name)
				ar := result{xerr}
				return ar, ar.rErr
			}

			// make sure Network ID is stored in Security Group abstract
			asg.Network = networkID

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil {
					derr := svc.DeleteSecurityGroup(cleanupContextFrom(ctx), asg)
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete Security Group '%s'", ActionFromError(ferr), name))
					}
				}
			}()

			// Creates metadata
			xerr = instance.Carry(ctx, asg)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{xerr}
				return ar, ar.rErr
			}

			// Starting from here, Delete Subnet metadata on error
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil {
					derr := instance.Core.Delete(cleanupContextFrom(ctx))
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete metadata of Security Group '%s'", ActionFromError(ferr), name))
					}
				}
			}()

			var (
				networkTrx networkTransaction
				err        error
			)
			value := ctx.Value(CurrentNetworkTransactionContextKey)
			if value != nil {
				networkTrx, err = lang.Cast[networkTransaction](value)
				if err != nil { // Is nil or is something else
					ar := result{fail.Wrap(err)}
					return ar, ar.rErr
				}
			} else {
				// so it's nil...
				networkInstance, xerr := LoadNetwork(ctx, networkID)
				if xerr != nil {
					ar := result{xerr}
					return ar, ar.rErr
				}

				networkTrx, xerr = newNetworkTransaction(ctx, networkInstance)
				if xerr != nil {
					ar := result{xerr}
					return ar, ar.rErr
				}
				defer networkTrx.TerminateFromError(ctx, &ferr)
			}

			// -- update SecurityGroups in Network metadata
			xerr = alterNetworkMetadataProperty(ctx, networkTrx, networkproperty.SecurityGroupsV1, func(nsgV1 *propertiesv1.NetworkSecurityGroups) fail.Error {
				nsgV1.ByID[asg.ID] = asg.Name
				nsgV1.ByName[asg.Name] = asg.ID
				return nil
			})
			if xerr != nil {
				ar := result{xerr}
				return ar, ar.rErr
			}

			logrus.WithContext(ctx).Infof("Security Group '%s' created successfully", name)
			ar := result{nil}
			return ar, ar.rErr
		}()

		chRes <- gres
	}() // nolint

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for cleanup
		return fail.Wrap(inctx.Err())
	}
}

// Delete deletes a Security Group
func (instance *SecurityGroup) Delete(ctx context.Context, force bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.securitygroup"), "(force=%v)", force).WithStopwatch().Entering()
	defer tracer.Exiting()

	sgTrx, xerr := newSecurityGroupTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer sgTrx.TerminateFromError(ctx, &ferr)

	xerr = sgTrx.Delete(ctx, force)
	if xerr != nil {
		return xerr
	}

	// Need to terminate Security Group transaction to be able to Delete metadata (no need to check error as we will Delete metadata
	sgTrx.SilentTerminate(ctx)

	// Delete Security Group metadata
	return instance.Core.Delete(ctx)
}

// deleteProviderSecurityGroup encapsulates the code responsible to the real Security Group deletion on Provider side
func deleteProviderSecurityGroup(ctx context.Context, svc iaasapi.Service, abstractSG *abstract.SecurityGroup) fail.Error {
	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			innerXErr := svc.DeleteSecurityGroup(ctx, abstractSG)
			if innerXErr != nil {
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
			debug.IgnoreErrorWithContext(ctx, xerr)
		case *fail.ErrTimeout:
			// consider a Security Group not found as a successful deletion
			cause := fail.Cause(xerr)
			if _, ok := cause.(*fail.ErrNotFound); ok {
				debug.IgnoreErrorWithContext(ctx, cause)
			} else {
				return fail.Wrap(cause, "timeout")
			}
		case *retry.ErrStopRetry:
			// consider a Security Group not found as a successful deletion
			cause := fail.Cause(xerr)
			if _, ok := cause.(*fail.ErrNotFound); ok {
				debug.IgnoreErrorWithContext(ctx, cause)
			} else {
				return fail.Wrap(cause, "stopping retries")
			}
		default:
			return xerr
		}
	}
	return nil
}

// Clear removes all rules from a security group
func (instance *SecurityGroup) Clear(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.securitygroup")).WithStopwatch().Entering()
	defer tracer.Exiting()

	sgTrx, xerr := newSecurityGroupTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer sgTrx.TerminateFromError(ctx, &ferr)

	return sgTrx.Clear(ctx)
}

// Reset clears a security group and re-adds associated rules as stored in metadata
func (instance *SecurityGroup) Reset(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.securitygroup")).WithStopwatch().Entering()
	defer tracer.Exiting()

	sgTrx, xerr := newSecurityGroupTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer sgTrx.TerminateFromError(ctx, &ferr)

	var rules abstract.SecurityGroupRules
	xerr = inspectSecurityGroupMetadataAbstract(ctx, sgTrx, func(asg *abstract.SecurityGroup) fail.Error {
		rules = asg.Rules
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Removes all rules...
	xerr = sgTrx.Clear(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// ... then re-adds rules from metadata
	xerr = sgTrx.AddRules(ctx, rules...)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// AddRules adds rules to a Security Group
func (instance *SecurityGroup) AddRules(ctx context.Context, rules ...*abstract.SecurityGroupRule) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if len(rules) == 0 {
		return fail.InvalidParameterError("rules", "cannot be empty slice")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.securitygroup")).WithStopwatch().Entering()
	defer tracer.Exiting()

	trx, xerr := newSecurityGroupTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer func() {
		trx.TerminateFromError(ctx, &ferr)
	}()

	return alterSecurityGroupMetadataAbstract(ctx, trx, func(asg *abstract.SecurityGroup) fail.Error {
		for k, v := range rules {
			if valid.IsNull(v) {
				return fail.InvalidParameterError("rules", "entry #%d cannot be null value of '*abstract.SecurityGroupRule'", k)
			}

			inErr := v.Validate()
			if inErr != nil {
				return fail.Wrap(inErr, "failed to validate rule #%d", k)
			}
		}

		innerXErr := instance.Service().AddRulesToSecurityGroup(ctx, asg, rules...)
		if innerXErr != nil {
			return innerXErr
		}

		return nil
	})
}

// DeleteRules deletes rules from a security group
func (instance *SecurityGroup) DeleteRules(ctx context.Context, rules ...*abstract.SecurityGroupRule) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if len(rules) == 0 {
		return fail.InvalidParameterCannotBeNilError("rules")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.securitygroup")).WithStopwatch().Entering()
	defer tracer.Exiting()

	for k, v := range rules {
		xerr := v.Validate()
		if xerr != nil {
			return fail.Wrap(xerr, "failed to validate rule #%d", k)
		}
	}

	trx, xerr := newSecurityGroupTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	return alterSecurityGroupMetadataAbstract(ctx, trx, func(asg *abstract.SecurityGroup) fail.Error {
		innerXErr := instance.Service().DeleteRulesFromSecurityGroup(ctx, asg, rules...)
		if innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				debug.IgnoreError(innerXErr)
				break
			default:
				return innerXErr
			}
		}

		return nil
	})
}

// GetBoundHosts returns the list of ID of hosts bound to the security group
func (instance *SecurityGroup) GetBoundHosts(ctx context.Context) (_ []*propertiesv1.SecurityGroupBond, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	trx, xerr := newSecurityGroupTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	var list []*propertiesv1.SecurityGroupBond
	xerr = inspectSecurityGroupMetadataProperty(ctx, trx, securitygroupproperty.HostsV1, func(sghV1 *propertiesv1.SecurityGroupHosts) fail.Error {
		list = make([]*propertiesv1.SecurityGroupBond, 0, len(sghV1.ByID))
		for _, v := range sghV1.ByID {
			list = append(list, v)
		}
		return nil
	})
	return list, xerr
}

// GetBoundSubnets returns the subnet bound to the security group
func (instance *SecurityGroup) GetBoundSubnets(ctx context.Context) (list []*propertiesv1.SecurityGroupBond, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	trx, xerr := newSecurityGroupTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = inspectSecurityGroupMetadataProperty(ctx, trx, securitygroupproperty.SubnetsV1, func(sgnV1 *propertiesv1.SecurityGroupSubnets) fail.Error {
		list = make([]*propertiesv1.SecurityGroupBond, 0, len(sgnV1.ByID))
		for _, v := range sgnV1.ByID {
			list = append(list, v)
		}
		return nil
	})
	return list, xerr
}

// CheckConsistency checks the rules in the security group on provider side are identical to the ones registered in metadata
func (instance *SecurityGroup) CheckConsistency(_ context.Context) fail.Error {
	return fail.NotImplementedError() // FIXME: Technical debt
}

// ToProtocol converts a Security Group to protobuf message
func (instance *SecurityGroup) ToProtocol(ctx context.Context) (_ *protocol.SecurityGroupResponse, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	trx, xerr := newSecurityGroupTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	trx.TerminateFromError(ctx, &ferr)

	out := &protocol.SecurityGroupResponse{}
	return out, inspectSecurityGroupMetadataAbstract(ctx, trx, func(asg *abstract.SecurityGroup) fail.Error {
		out.Id = asg.ID
		out.Name = asg.Name
		out.Description = asg.Description
		out.Rules = converters.SecurityGroupRulesFromAbstractToProtocol(asg.Rules)
		return nil
	})
}

// BindToHost binds the security group to a host.
func (instance *SecurityGroup) BindToHost(ctx context.Context, hostInstance *Host, enable SecurityGroupActivation, mark SecurityGroupMark) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostInstance == nil {
		return fail.InvalidParameterError("hostInstance", "cannot be nil")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.securitygroup"), "(host='%s', enable=%v, mark=%v)", hostInstance.GetName(), enable, mark).WithStopwatch().Entering()
	defer tracer.Exiting()

	sgTrx, xerr := newSecurityGroupTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer sgTrx.TerminateFromError(ctx, &ferr)

	hostTrx, xerr := newHostTransaction(ctx, hostInstance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return sgTrx.BindToHost(ctx, hostTrx, enable, mark)
}

// UnbindFromHost unbinds the security group from a host
// FIXME: does not work as-is for provider using terraform
func (instance *SecurityGroup) UnbindFromHost(ctx context.Context, hostInstance *Host) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostInstance == nil {
		return fail.InvalidParameterError("hostInstance", "cannot be nil")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.securitygroup"), "(host='%s')", hostInstance.GetName()).WithStopwatch().Entering()
	defer tracer.Exiting()

	sgTrx, xerr := newSecurityGroupTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer sgTrx.TerminateFromError(ctx, &ferr)

	hostTrx, xerr := newHostTransaction(ctx, hostInstance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return sgTrx.UnbindFromHost(ctx, hostTrx)
}

// UnbindFromHostByReference unbinds the security group from a host identified by reference (id or name)
func (instance *SecurityGroup) UnbindFromHostByReference(ctx context.Context, hostRef string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.securitygroup"), "(host='%s', enable=%v, mark=%v)", hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()

	sgTrx, xerr := newSecurityGroupTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer sgTrx.TerminateFromError(ctx, &ferr)

	hostInstance, xerr := LoadHost(ctx, hostRef)
	if xerr != nil {
		return xerr
	}

	hostTrx, xerr := newHostTransaction(ctx, hostInstance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return sgTrx.UnbindFromHost(ctx, hostTrx)
}

// BindToSubnet binds the security group to a host
// This method assumes the Subnet is not called while the Subnet is currently locked (otherwise will deadlock...)
func (instance *SecurityGroup) BindToSubnet(ctx context.Context, subnetInstance *Subnet, enable SecurityGroupActivation, mark SecurityGroupMark) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if subnetInstance == nil {
		return fail.InvalidParameterCannotBeNilError("rh")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.securitygroup"), "(subnet='%s', enable=%v, mark=%v)", subnetInstance.GetName(), enable, mark).WithStopwatch().Entering()
	defer tracer.Exiting()

	sgTrx, xerr := newSecurityGroupTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer sgTrx.TerminateFromError(ctx, &ferr)

	subnetTrx, xerr := newSubnetTransaction(ctx, subnetInstance)
	if xerr != nil {
		return xerr
	}
	defer subnetTrx.TerminateFromError(ctx, &ferr)

	var subnetHosts *propertiesv1.SubnetHosts
	xerr = inspectSubnetMetadataProperty(ctx, subnetTrx, subnetproperty.HostsV1, func(shV1 *propertiesv1.SubnetHosts) fail.Error {
		subnetHosts = shV1
		return nil
	})
	if xerr != nil {
		return xerr
	}

	switch enable {
	case SecurityGroupEnable:
		xerr = sgTrx.EnableOnHostsAttachedToSubnet(ctx, subnetHosts)
	case SecurityGroupDisable:
		xerr = sgTrx.DisableOnHostsAttachedToSubnet(ctx, subnetHosts)
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	subnetName := subnetTrx.GetName()
	subnetID, err := subnetTrx.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	return alterSecurityGroupMetadata(ctx, sgTrx, func(asg *abstract.SecurityGroup, props *serialize.JSONProperties) fail.Error {
		if mark == MarkSecurityGroupAsDefault {
			if asg.DefaultForHost != "" {
				return fail.InvalidRequestError("security group is already marked as default for subnet %s", asg.DefaultForSubnet)
			}

			asg.DefaultForSubnet = subnetID
		}

		return props.Alter(securitygroupproperty.SubnetsV1, func(p clonable.Clonable) fail.Error {
			sgsV1, innerErr := lang.Cast[*propertiesv1.SecurityGroupSubnets](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			// First check if subnet is present with the state requested; if present with same state, consider situation as a success
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

// // unbindFromHostsAttachedToSubnet unbinds (ie remove) the security group from Hosts in a Subnet
// func (instance *SecurityGroup) unbindFromHostsAttachedToSubnet(ctx context.Context, subnetHosts *propertiesv1.SubnetHosts) fail.Error {
// 	if len(subnetHosts.ByID) > 0 {
// 		tg := new(errgroup.Group)
//
// 		for _, v := range subnetHosts.ByID {
// 			v := v
// 			tg.Go(func() error {
// 				_, err := sgTrx.BindAsDisabledOnHost(ctx, v)
// 				return err
// 			})
// 		}
// 		xerr := fail.Wrap(tg.Wait())
// 		xerr = debug.InjectPlannedFail(xerr)
// 		return xerr
// 	}
// 	return nil
// }

// UnbindFromSubnet unbinds the security group from a subnet
func (instance *SecurityGroup) UnbindFromSubnet(ctx context.Context, subnetInstance *Subnet) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if subnetInstance == nil {
		return fail.InvalidParameterCannotBeNilError("subnetInstance")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.securitygroup"), "(subnet='%s')", subnetInstance.GetName()).WithStopwatch().Entering()
	defer tracer.Exiting()

	sgTrx, xerr := newSecurityGroupTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer sgTrx.TerminateFromError(ctx, &ferr)

	subnetTrx, xerr := newSubnetTransaction(ctx, subnetInstance)
	if xerr != nil {
		return xerr
	}
	defer subnetTrx.TerminateFromError(ctx, &ferr)

	return sgTrx.UnbindFromSubnet(ctx, subnetTrx)
}

// UnbindFromSubnetByReference unbinds the security group from a subnet
func (instance *SecurityGroup) UnbindFromSubnetByReference(ctx context.Context, subnetRef string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if subnetRef == "" {
		return fail.InvalidParameterError("rs", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.securitygroup"), "(subnet='%s')", subnetRef).WithStopwatch().Entering()
	defer tracer.Exiting()

	trx, xerr := newSecurityGroupTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	return alterSecurityGroupMetadataProperty(ctx, trx, securitygroupproperty.SubnetsV1, func(sgsV1 *propertiesv1.SecurityGroupSubnets) fail.Error {
		var subnetID, subnetName string
		b, ok := sgsV1.ByID[subnetRef]
		if ok {
			subnetID = subnetRef
			subnetName = b.Name
		} else if subnetID, ok = sgsV1.ByName[subnetRef]; ok {
			subnetName = subnetRef
		}

		// updates security group metadata
		delete(sgsV1.ByID, subnetID)
		delete(sgsV1.ByName, subnetName)
		return nil
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
