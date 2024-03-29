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

package operations

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
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

// onSGCacheMiss is called when there is no instance in cache of Security Group 'ref'
func onSGCacheMiss(ctx context.Context, svc iaas.Service, ref string) (data.Identifiable, fail.Error) {
	sgInstance, innerXErr := NewSecurityGroup(svc)
	if innerXErr != nil {
		return nil, innerXErr
	}

	blank, innerXErr := NewSecurityGroup(svc)
	if innerXErr != nil {
		return nil, innerXErr
	}

	if innerXErr = sgInstance.Read(ctx, ref); innerXErr != nil {
		return nil, innerXErr
	}

	if strings.Compare(fail.IgnoreError(sgInstance.Sdump(ctx)).(string), fail.IgnoreError(blank.Sdump(ctx)).(string)) == 0 {
		return nil, fail.NotFoundError("security group with ref '%s' does NOT exist", ref)
	}

	return sgInstance, nil
}

// IsNull tests if instance is nil or empty
func (instance *SecurityGroup) IsNull() bool {
	return valid.IsNil(instance.MetadataCore)
}

// Exists checks if the resource actually exists in provider side (not in stow metadata)
func (instance *SecurityGroup) Exists(ctx context.Context) (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}

	// FIXME: Not so easy, securitygroups are in some cases a metadata-only construct -> we need to turn those into tags (provider ones) 1st
	theID, err := instance.GetID()
	if err != nil {
		return false, fail.ConvertError(err)
	}

	if beta := os.Getenv("SAFESCALE_DETECT_CORRUPTION"); beta != "yes" {
		return true, nil
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
func (instance *SecurityGroup) carry(ctx context.Context, clonable data.Clonable) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) && instance.MetadataCore.IsTaken() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}

	xerr := instance.MetadataCore.Carry(ctx, clonable)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Browse walks through SecurityGroup MetadataFolder and executes a callback for each entry
func (instance *SecurityGroup) Browse(
	ctx context.Context, callback func(*abstract.SecurityGroup) fail.Error,
) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	return instance.MetadataCore.BrowseFolder(ctx, func(buf []byte) fail.Error {
		asg := abstract.NewSecurityGroup()
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
func (instance *SecurityGroup) Create(
	inctx context.Context, networkID, name, description string, rules abstract.SecurityGroupRules,
) (_ fail.Error) {
	// NOTE: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance.MetadataCore) {
		if instance.MetadataCore.IsTaken() {
			return fail.InconsistentError("already carrying information")
		}
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

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if strings.HasPrefix(name, "instance") {
				xerr := fail.InvalidParameterError("name", "cannot start with 'instance'")
				ar := result{xerr}
				return ar, ar.rErr
			}

			// Check if SecurityGroup exists and is managed by SafeScale
			svc := instance.Service()
			_, xerr := LoadSecurityGroup(ctx, svc, name)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// continue
					debug.IgnoreError2(ctx, xerr)
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
			asg := abstract.NewSecurityGroup()
			asg.Name = name
			asg.Network = networkID
			_, xerr = svc.InspectSecurityGroup(ctx, asg)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotImplemented:
					debug.IgnoreError2(ctx, xerr)
				case *fail.ErrNotFound:
					// continue
					debug.IgnoreError2(ctx, xerr)
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
					if derr := svc.DeleteSecurityGroup(cleanupContextFrom(ctx), asg); derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s'", ActionFromError(ferr), name))
					}
				}
			}()

			// Creates metadata
			xerr = instance.carry(ctx, asg)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{xerr}
				return ar, ar.rErr
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil {
					theID, _ := instance.GetID()

					if derr := instance.MetadataCore.Delete(cleanupContextFrom(ctx)); derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s' metadata", ActionFromError(ferr)))
					}

					if ka, err := instance.Service().GetCache(ctx); err == nil {
						if ka != nil {
							if theID != "" {
								_ = ka.Delete(ctx, fmt.Sprintf("%T/%s", instance, theID))
							}
						}
					}
				}
			}()

			if len(rules) == 0 {
				xerr = instance.unsafeClear(ctx)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{xerr}
					return ar, ar.rErr
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
					xerr := fail.InconsistentError("wrong value of type %T stored in context value, *unsafeSerialize.JSONProperties was expected instead", ctx.Value(CurrentNetworkPropertiesContextKey))
					ar := result{xerr}
					return ar, ar.rErr
				}

				// so it's nil...
				networkInstance, xerr := LoadNetwork(ctx, svc, networkID)
				if xerr != nil {
					ar := result{xerr}
					return ar, ar.rErr
				}

				xerr = networkInstance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
					return updateFunc(props)
				})
				if xerr != nil {
					ar := result{xerr}
					return ar, ar.rErr
				}

				logrus.WithContext(ctx).Infof("Security Group '%s' created successfully", name)
				ar := result{nil}
				return ar, ar.rErr
			}

			// it is a *unsafeSerialize.JSONProperties, (it was ok, also avoid else if possible)
			xerr = updateFunc(currentNetworkProps)
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
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for cleanup
		return fail.ConvertError(inctx.Err())
	}
}

// Delete deletes a Security Group
func (instance *SecurityGroup) Delete(ctx context.Context, force bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	defer func() {
		// drop the cache when we are done creating the cluster
		if ka, err := instance.Service().GetCache(context.Background()); err == nil {
			if ka != nil {
				_ = ka.Clear(context.Background())
			}
		}
	}()

	return instance.unsafeDelete(ctx, force)
}

// deleteProviderSecurityGroup encapsulates the code responsible to the real Security Group deletion on Provider side
func deleteProviderSecurityGroup(ctx context.Context, svc iaas.Service, abstractSG *abstract.SecurityGroup) fail.Error {
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

			if innerXErr := svc.DeleteSecurityGroup(ctx, abstractSG); innerXErr != nil {
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
			debug.IgnoreError2(ctx, xerr)
		case *fail.ErrTimeout:
			// consider a Security Group not found as a successful deletion
			cause := fail.Cause(xerr)
			if _, ok := cause.(*fail.ErrNotFound); ok {
				debug.IgnoreError2(ctx, cause)
			} else {
				return fail.Wrap(cause, "timeout")
			}
		case *retry.ErrStopRetry:
			// consider a Security Group not found as a successful deletion
			cause := fail.Cause(xerr)
			if _, ok := cause.(*fail.ErrNotFound); ok {
				debug.IgnoreError2(ctx, cause)
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
	if len(in.ByID) > 0 {
		tg := new(errgroup.Group)

		// iterate on hosts bound to the security group and start a go routine to unbind
		svc := instance.Service()
		for _, v := range in.ByID {
			v := v
			tg.Go(func() error {
				if v.FromSubnet {
					return fail.InvalidRequestError("cannot unbind from host a security group applied from subnet; use disable instead or remove from bound subnet")
				}

				hostInstance, xerr := LoadHost(ctx, svc, v.ID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						return nil
					default:
						return xerr
					}
				}

				_, err := instance.taskUnbindFromHost(ctx, hostInstance)
				return err
			})
		}

		xerr := fail.ConvertError(tg.Wait())
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
//
//goland:noinspection GoDeferInLoop
func (instance *SecurityGroup) unbindFromSubnets(
	ctx context.Context, in *propertiesv1.SecurityGroupSubnets,
) fail.Error {
	if len(in.ByID) > 0 {
		tg := new(errgroup.Group)

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
		vpro := ctx.Value(currentSubnetPropertiesContextKey)
		if vpro != nil {
			currentSubnetProps, ok = vpro.(*serialize.JSONProperties)
			if !ok {
				return fail.InconsistentError("failed to cast value to '*unsafeSerialize.JSONProperties'")
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
			k, v := k, v

			tg.Go(func() error {
				// If current Subnet corresponds to the Subnet found in context, uses the data from the context to prevent deadlock
				if currentSubnetAbstract != nil && v == currentSubnetAbstract.ID {
					xerr := inspectFunc(currentSubnetProps)
					if xerr != nil {
						return xerr
					}
				} else {
					subnetInstance, xerr := LoadSubnet(ctx, svc, "", v)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							// consider a missing subnet as a successful operation and continue the loop
							debug.IgnoreError2(ctx, xerr)
							return nil
						default:
							return xerr
						}
					}

					xerr = subnetInstance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
						return inspectFunc(props)
					})
					if xerr != nil {
						return xerr
					}
				}

				_, xerr := instance.taskUnbindFromHostsAttachedToSubnet(ctx, taskUnbindFromHostsAttachedToSubnetParams{subnetName: k, subnetHosts: subnetHosts})
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}
				return nil
			})
		}

		xerr := fail.ConvertError(tg.Wait())
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

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}

	return instance.unsafeClear(ctx)
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

	var rules abstract.SecurityGroupRules
	xerr := instance.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
	xerr = instance.unsafeClear(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// ... then re-adds rules from metadata
	for _, v := range rules {
		xerr = instance.unsafeAddRule(ctx, v)
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

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	return instance.unsafeAddRule(ctx, rule)
}

// AddRules adds rules to a Security Group
func (instance *SecurityGroup) AddRules(ctx context.Context, rules abstract.SecurityGroupRules) (ferr fail.Error) {
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

	return instance.Alter(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
			_, inErr := svc.AddRuleToSecurityGroup(ctx, asg, v)
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

	if valid.IsNil(instance) {
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

	return instance.Alter(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		_, innerXErr := instance.Service().DeleteRuleFromSecurityGroup(ctx, asg, rule)
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
func (instance *SecurityGroup) GetBoundHosts(ctx context.Context) (
	_ []*propertiesv1.SecurityGroupBond, ferr fail.Error,
) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	var list []*propertiesv1.SecurityGroupBond
	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
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
func (instance *SecurityGroup) GetBoundSubnets(ctx context.Context) (
	list []*propertiesv1.SecurityGroupBond, ferr fail.Error,
) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
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

// ToProtocol converts a Security Group to protobuf message
func (instance *SecurityGroup) ToProtocol(ctx context.Context) (_ *protocol.SecurityGroupResponse, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	out := &protocol.SecurityGroupResponse{}
	return out, instance.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
func (instance *SecurityGroup) BindToHost(
	ctx context.Context, hostInstance resources.Host, enable resources.SecurityGroupActivation,
	mark resources.SecurityGroupMark,
) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if hostInstance == nil {
		return fail.InvalidParameterError("hostInstance", "cannot be nil")
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	xerr := instance.unsafeBindToHost(ctx, hostInstance, enable, mark)
	return xerr
}

// UnbindFromHost unbinds the security group from a host
func (instance *SecurityGroup) UnbindFromHost(ctx context.Context, hostInstance resources.Host) (ferr fail.Error) {
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

	sgid, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	return instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sgphV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*securitygroupproperty.HostsV1' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// Unbind security group on provider side; if not found, considered as a success
			hostID, err := hostInstance.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}
			if innerXErr := instance.Service().UnbindSecurityGroupFromHost(ctx, sgid, hostID); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					debug.IgnoreError2(ctx, innerXErr)
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

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostRef == "" {
		return fail.InvalidParameterError("hostRef", "cannot be empty string")
	}

	sgid, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	return instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
				if innerXErr := instance.Service().UnbindSecurityGroupFromHost(ctx, sgid, hostID); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound:
						debug.IgnoreError2(ctx, innerXErr)
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

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if subnetInstance == nil {
		return fail.InvalidParameterCannotBeNilError("rh")
	}

	xerr := subnetInstance.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
			innerXErr = instance.enableOnHostsAttachedToSubnet(ctx, subnetHosts)
		case resources.SecurityGroupDisable:
			innerXErr = instance.disableOnHostsAttachedToSubnet(ctx, subnetHosts)
		}
		innerXErr = debug.InjectPlannedFail(innerXErr)
		return innerXErr
	})
	if xerr != nil {
		return xerr
	}

	return instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		if mark == resources.MarkSecurityGroupAsDefault {
			asg, ok := clonable.(*abstract.SecurityGroup)
			if !ok {
				return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if asg.DefaultForHost != "" {
				return fail.InvalidRequestError("security group is already marked as default for subnet %s", asg.DefaultForSubnet)
			}

			var err error
			asg.DefaultForSubnet, err = subnetInstance.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}
		}

		return props.Alter(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			sgsV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// First check if subnet is present with the state requested; if present with same state, consider situation as a success
			subnetID, err := subnetInstance.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}

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
	ctx context.Context, subnetHosts *propertiesv1.SubnetHosts,
) fail.Error {
	if len(subnetHosts.ByID) > 0 {
		tg := new(errgroup.Group)

		for _, v := range subnetHosts.ByID {
			v := v
			tg.Go(func() error {
				_, err := instance.taskBindEnabledOnHost(ctx, v)
				return err
			})
		}
		innerXErr := fail.ConvertError(tg.Wait())
		innerXErr = debug.InjectPlannedFail(innerXErr)
		return innerXErr
	}
	return nil
}

// disableSecurityGroupOnHosts disables (ie remove) the security group from bound hosts
func (instance *SecurityGroup) disableOnHostsAttachedToSubnet(
	ctx context.Context, subnetHosts *propertiesv1.SubnetHosts,
) fail.Error {
	if len(subnetHosts.ByID) > 0 {
		tg := new(errgroup.Group)

		for _, v := range subnetHosts.ByID {
			v := v
			tg.Go(func() error {
				_, err := instance.taskBindDisabledOnHost(ctx, v)
				return err
			})
		}
		xerr := fail.ConvertError(tg.Wait())
		xerr = debug.InjectPlannedFail(xerr)
		return xerr
	}
	return nil
}

// unbindFromHostsAttachedToSubnet unbinds (ie remove) the security group from Hosts in a Subnet
func (instance *SecurityGroup) unbindFromHostsAttachedToSubnet(
	ctx context.Context, subnetHosts *propertiesv1.SubnetHosts,
) fail.Error {
	if len(subnetHosts.ByID) > 0 {
		tg := new(errgroup.Group)

		for _, v := range subnetHosts.ByID {
			v := v
			tg.Go(func() error {
				_, err := instance.taskBindDisabledOnHost(ctx, v)
				return err
			})
		}
		xerr := fail.ConvertError(tg.Wait())
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

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if subnetInstance == nil {
		return fail.InvalidParameterCannotBeNilError("subnetInstance")
	}

	sgid, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	var subnetHosts *propertiesv1.SubnetHosts
	xerr := subnetInstance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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

	xerr = instance.unsafeUnbindFromSubnet(ctx, taskUnbindFromHostsAttachedToSubnetParams{subnetID: sgid, subnetName: subnetInstance.GetName(), subnetHosts: subnetHosts})
	return xerr
}

// unbindFromSubnetHosts unbinds the security group from Hosts attached to a Subnet
func (instance *SecurityGroup) unbindFromSubnetHosts(
	inctx context.Context, params taskUnbindFromHostsAttachedToSubnetParams,
) (_ fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// Unbind Security Group from Hosts attached to Subnet
			_, xerr := instance.taskUnbindFromHostsAttachedToSubnet(ctx, params)
			if xerr != nil {
				return xerr
			}

			// -- Remove Hosts attached to Subnet referenced in Security Group
			xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
			})
			if xerr != nil {
				return xerr
			}

			// -- Remove Subnet referenced in Security Group
			return instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
					sgsV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.SecurityGroupSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					// updates security group metadata
					delete(sgsV1.ByID, params.subnetID)
					delete(sgsV1.ByName, params.subnetName)
					return nil
				})
			})
		}()
		chRes <- result{gerr}
	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}
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

	return instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
