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

package openstack

import (
	"context"

	secgroups "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	secrules "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const defaultSecurityGroupName = "default"

// ListSecurityGroups lists existing security groups
// Parameter 'networkRef' is not used in Openstack (they are tenant-wide)
func (instance *stack) ListSecurityGroups(ctx context.Context, networkRef string) ([]*abstract.SecurityGroup, fail.Error) {
	var emptySlice []*abstract.SecurityGroup
	if valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}
	if instance.NetworkClient == nil {
		return emptySlice, fail.InvalidInstanceContentError("instance.NetworkCLient", "cannot be nil")
	}

	var list []*abstract.SecurityGroup
	opts := secgroups.ListOpts{}
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			list = []*abstract.SecurityGroup{}
			return secgroups.List(instance.NetworkClient, opts).EachPage(func(page pagination.Page) (bool, error) {
				l, err := secgroups.ExtractGroups(page)
				if err != nil {
					return false, err
				}
				for _, e := range l {
					n, _ := abstract.NewSecurityGroup()
					n.Name = e.Name
					n.ID = e.ID
					n.Description = e.Description
					list = append(list, n)
				}
				return true, nil
			})
		},
		NormalizeError,
	)
	return list, xerr
}

// CreateSecurityGroup creates a security group
// Parameter 'networkRef' is not used in Openstack, Security Groups are tenant-wide.
// Returns nil, *fail.ErrDuplicate if already 1 security group exists with that name
// Returns nil, *fail.ErrDuplicate(with a cause *fail.ErrDuplicate) if more than 1 security group exist with that name
func (instance *stack) CreateSecurityGroup(ctx context.Context, networkRef, name, description string, rules abstract.SecurityGroupRules) (_ *abstract.SecurityGroup, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if instance.NetworkClient == nil {
		return nil, fail.InvalidInstanceContentError("instance.NetworkClient", "cannot be nil")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	asg, xerr := instance.InspectSecurityGroup(ctx, name)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			asg, _ = abstract.NewSecurityGroup()
			asg.Name = name
			// continue
			debug.IgnoreError(xerr)
		case *fail.ErrDuplicate:
			// Special case : a duplicate error may come from OpenStack after normalization, because there are already more than 1
			// security groups with the same name. In this situation, returns a DuplicateError with the xerr as cause
			return nil, fail.DuplicateErrorWithCause(xerr, nil, "more than one Security Group named '%s' found", name)
		default:
			return nil, xerr
		}
	} else {
		return nil, fail.DuplicateError("a security group named '%s' already exist", name)
	}

	// create security group on provider side
	createOpts := secgroups.CreateOpts{
		Name:        name,
		Description: description,
	}
	xerr = stacks.RetryableRemoteCall(ctx,
		func() error {
			r, innerErr := secgroups.Create(instance.NetworkClient, createOpts).Extract()
			if innerErr != nil {
				return innerErr
			}
			asg.ID = r.ID
			return nil
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	// Starting from here, delete security group on error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := instance.DeleteSecurityGroup(context.Background(), asg)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete security group"))
			}
		}
	}()

	// In OpenStack, freshly created security group may contain default rules; we do not want them
	asg, xerr = instance.ClearSecurityGroup(ctx, asg)
	if xerr != nil {
		return nil, xerr
	}

	// now adds security rules
	asg.Rules = make(abstract.SecurityGroupRules, 0, len(rules))
	asg, xerr = instance.AddRulesToSecurityGroup(ctx, asg, rules...)
	if xerr != nil {
		return nil, xerr
	}

	return asg, nil
}

// DeleteSecurityGroup deletes a security group and its rules
func (instance *stack) DeleteSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupIdentifier) (ferr fail.Error) {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}
	if instance.NetworkClient == nil {
		return fail.InvalidInstanceContentError("instance.NetworkClient", "cannot be nil")
	}
	asg, sgLabel, xerr := iaasapi.ValidateSecurityGroupIdentifier(sgParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.openstack"), "(%s)", sgLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	if !asg.IsConsistent() {
		asg, xerr = instance.InspectSecurityGroup(ctx, asg.ID)
		if xerr != nil {
			return xerr
		}
	}

	// delete security group rules
	for _, v := range asg.Rules {
		xerr = stacks.RetryableRemoteCall(ctx,
			func() error {
				for _, id := range v.IDs {
					innerErr := secrules.Delete(instance.NetworkClient, id).ExtractErr()
					if innerErr != nil {
						return innerErr
					}
				}
				return nil
			},
			NormalizeError,
		)
		if xerr != nil {
			return xerr
		}
	}

	// delete security group
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return secgroups.Delete(instance.NetworkClient, asg.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// InspectSecurityGroup returns information about a security group
func (instance *stack) InspectSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupIdentifier) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if instance.NetworkClient == nil {
		return nil, fail.InvalidInstanceContentError("instance.NetworkClient", "cannot be nil")
	}

	asg, asgLabel, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}

	var r *secgroups.SecGroup
	xerr = stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			var id string
			switch {
			case asg.ID != "":
				id = asg.ID
			case asg.Name != "":
				id, innerErr = getSGIDFromName(instance.NetworkClient, asg.Name)
				if innerErr != nil {
					return innerErr
				}
			}
			if id == "" {
				return fail.NotFoundError("failed to query Security Group %s", asgLabel)
			}
			r, innerErr = secgroups.Get(instance.NetworkClient, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry:
			cause := fail.ConvertError(xerr.Cause())
			switch cause.(type) {
			case *fail.ErrNotFound:
				return nil, fail.NotFoundError("failed to query Security Group %s", asgLabel)
			default:
				return nil, cause
			}
		case *fail.ErrNotFound:
			return nil, fail.NotFoundError("failed to query Security Group %s", asgLabel)
		default:
			return nil, xerr
		}
	}
	if r == nil {
		return nil, fail.NotFoundError("failed to find Security Group %s", asgLabel)
	}

	asg.ID = r.ID
	asg.Name = r.Name
	asg.Description = r.Description
	if asg.Rules, xerr = toAbstractSecurityGroupRules(r.Rules); xerr != nil {
		return nil, xerr
	}
	return asg, nil
}

// ClearSecurityGroup removes all rules but keep group
func (instance *stack) ClearSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupIdentifier) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if instance.NetworkClient == nil {
		return nil, fail.InvalidInstanceContentError("instance.NetworkClient", "cannot be nil")
	}

	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}
	asg, xerr = instance.InspectSecurityGroup(ctx, asg.ID)
	if xerr != nil {
		return asg, xerr
	}

	// delete security group rules
	for _, v := range asg.Rules {
		xerr = stacks.RetryableRemoteCall(ctx,
			func() error {
				for _, id := range v.IDs {
					if innerErr := secrules.Delete(instance.NetworkClient, id).ExtractErr(); innerErr != nil {
						return innerErr
					}
				}
				return nil
			},
			NormalizeError,
		)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				debug.IgnoreError(xerr)
				continue
			default:
				return asg, xerr
			}
		}
	}
	asg.Rules = abstract.SecurityGroupRules{}
	return asg, nil
}

// toAbstractSecurityGroupRules
func toAbstractSecurityGroupRules(in []secrules.SecGroupRule) (abstract.SecurityGroupRules, fail.Error) {
	out := make(abstract.SecurityGroupRules, 0, len(in))
	for k, v := range in {
		direction := convertDirectionToAbstract(v.Direction)
		if direction == securitygroupruledirection.Unknown {
			return nil, fail.InvalidRequestError("invalid value '%s' to 'Direction' field in rule #%d", v.Direction, k+1)
		}
		etherType := convertEtherTypeToAbstract(secrules.RuleEtherType(v.EtherType))
		if etherType == ipversion.Unknown {
			return nil, fail.InvalidRequestError("invalid value '%s' to 'EtherType' field in rule #%d", v.EtherType, k+1)
		}

		r := &abstract.SecurityGroupRule{
			IDs:         []string{v.ID},
			EtherType:   etherType,
			Description: v.Description,
			Direction:   direction,
			Protocol:    v.Protocol,
			PortFrom:    int32(v.PortRangeMin),
			PortTo:      int32(v.PortRangeMax),
		}
		switch direction {
		case securitygroupruledirection.Ingress:
			if v.RemoteGroupID != "" {
				r.Sources = []string{v.RemoteGroupID}
			} else {
				r.Sources = []string{v.RemoteIPPrefix}
			}
		case securitygroupruledirection.Egress:
			if v.RemoteGroupID != "" {
				r.Targets = []string{v.RemoteGroupID}
			} else {
				r.Targets = []string{v.RemoteIPPrefix}
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// convertDirectionToAbstract ...
func convertDirectionToAbstract(in string) securitygroupruledirection.Enum {
	switch secrules.RuleDirection(in) {
	case secrules.DirIngress:
		return securitygroupruledirection.Ingress
	case secrules.DirEgress:
		return securitygroupruledirection.Egress
	default:
		return securitygroupruledirection.Unknown
	}
}

// convertDirectionFromAbstract ...
func convertDirectionFromAbstract(in securitygroupruledirection.Enum) secrules.RuleDirection {
	switch in {
	case securitygroupruledirection.Egress:
		return secrules.DirEgress
	case securitygroupruledirection.Ingress:
		return secrules.DirIngress
	default:
		return ""
	}
}

func convertEtherTypeToAbstract(in secrules.RuleEtherType) ipversion.Enum {
	switch in {
	case secrules.EtherType4:
		return ipversion.IPv4
	case secrules.EtherType6:
		return ipversion.IPv6
	default:
		return ipversion.Unknown
	}
}

func convertEtherTypeFromAbstract(in ipversion.Enum) secrules.RuleEtherType {
	switch in {
	case ipversion.IPv4:
		return secrules.EtherType4
	case ipversion.IPv6:
		return secrules.EtherType6
	default:
		return ""
	}
}

// AddRulesToSecurityGroup adds rules to a Security Group
// On success, return Security Group with added rule
func (instance *stack) AddRulesToSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupIdentifier, rules ...*abstract.SecurityGroupRule) (asg *abstract.SecurityGroup, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if instance.NetworkClient == nil {
		return nil, fail.InvalidInstanceContentError("instance.NetworkClient", "cannot be nil")
	}

	var xerr fail.Error
	asg, _, xerr = stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}

	if !asg.IsConsistent() {
		asg, xerr = instance.InspectSecurityGroup(ctx, asg.ID)
		if xerr != nil {
			return asg, xerr
		}
	}

	for k, r := range rules {
		if _, xerr = asg.Rules.IndexOfEquivalentRule(r); xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// continue
				debug.IgnoreError(xerr)
			default:
				return asg, xerr
			}
		}

		direction := convertDirectionFromAbstract(r.Direction)
		if direction == "" { // Invalid direction is not permitted
			return asg, fail.InvalidRequestError("invalid value '%s' in 'Direction' field of rule #%d", r.Direction, k)
		}

		var (
			involved   []string
			usesGroups bool
		)
		switch r.Direction {
		case securitygroupruledirection.Ingress:
			involved = r.Sources
			usesGroups, xerr = r.SourcesConcernGroups()
			if xerr != nil {
				return nil, xerr
			}
		case securitygroupruledirection.Egress:
			involved = r.Targets
			usesGroups, xerr = r.TargetsConcernGroups()
			if xerr != nil {
				return nil, xerr
			}
		default:
			return nil, fail.InvalidParameterError("in.Direction", "contains an unsupported value in rule #%d", k)
		}

		etherType := convertEtherTypeFromAbstract(r.EtherType)
		if etherType == "" { // If no valid EtherType is provided, force to IPv4
			etherType = secrules.EtherType4
		}

		portFrom := r.PortFrom
		portTo := r.PortTo
		if portFrom == 0 && portTo != 0 {
			portFrom = portTo
		}
		if portFrom != 0 && portTo == 0 {
			portTo = portFrom
		}
		if portTo < portFrom {
			portFrom, portTo = portTo, portFrom
		}

		createOpts := secrules.CreateOpts{
			SecGroupID:   asg.ID,
			EtherType:    etherType,
			Direction:    direction,
			Description:  r.Description,
			PortRangeMin: int(portFrom),
			PortRangeMax: int(portTo),
			Protocol:     secrules.RuleProtocol(r.Protocol),
		}

		r.IDs = make([]string, 0, len(involved))
		if usesGroups {
			for _, v := range involved {
				createOpts.RemoteGroupID = v
				createOpts.Description = r.Description + " (" + v + ")"
				xerr = stacks.RetryableRemoteCall(ctx,
					func() error {
						rule, innerErr := secrules.Create(instance.NetworkClient, createOpts).Extract()
						if innerErr != nil {
							return innerErr
						}

						r.IDs = append(r.IDs, rule.ID)
						return nil
					},
					NormalizeError,
				)
				if xerr != nil {
					return asg, xerr
				}
			}
		} else {
			for _, v := range involved {
				createOpts.RemoteIPPrefix = v
				createOpts.Description = r.Description + " (" + v + ")"
				xerr = stacks.RetryableRemoteCall(ctx,
					func() error {
						rule, innerErr := secrules.Create(instance.NetworkClient, createOpts).Extract()
						if innerErr != nil {
							return innerErr
						}
						r.IDs = append(r.IDs, rule.ID)
						return nil
					},
					NormalizeError,
				)
				if xerr != nil {
					return asg, xerr
				}
			}
		}
		asg.Rules = append(asg.Rules, r)
	}

	return asg, nil
}

// DeleteRulesFromSecurityGroup deletes a rule identified by ID from a security group
// Checks first if the rule ID is present in the rules of the security group. If not found, returns (*abstract.SecurityGroup, *fail.ErrNotFound)
func (instance *stack) DeleteRulesFromSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupIdentifier, rules ...*abstract.SecurityGroupRule) (asg *abstract.SecurityGroup, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if instance.NetworkClient == nil {
		return nil, fail.InvalidInstanceContentError("instance.NetworkClient", "cannot be nil")
	}

	var xerr fail.Error
	asg, _, xerr = stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = instance.InspectSecurityGroup(ctx, asg.ID)
		if xerr != nil {
			return asg, xerr
		}
	}

	for _, currentRule := range rules {
		index, xerr := asg.Rules.IndexOfEquivalentRule(currentRule)
		if xerr != nil {
			return asg, xerr
		}

		ruleIDs := asg.Rules[index].IDs

		xerr = stacks.RetryableRemoteCall(ctx,
			func() error {
				var innerXErr fail.Error
				for k, v := range ruleIDs {
					innerErr := secrules.Delete(instance.NetworkClient, v).ExtractErr()
					if innerErr != nil {
						innerXErr = NormalizeError(innerErr)
						switch innerXErr.(type) {
						case *fail.ErrNotFound:
							// If rule not found on provider side, consider the deletion as successful and continue the loop
							debug.IgnoreError(innerXErr)
							goto success
						default:
							return fail.Wrap(innerErr, "failed to delete provider rule #%d", k)
						}
					}
				}
				innerXErr = asg.RemoveRuleByIndex(index)
				if innerXErr != nil {
					return innerXErr
				}

			success:
				return nil
			},
			NormalizeError,
		)
		if xerr != nil {
			return asg, xerr
		}
	}

	return asg, nil
}

// GetDefaultSecurityGroupName returns the name of the Security Group automatically bound to hosts
func (instance *stack) GetDefaultSecurityGroupName(ctx context.Context) (string, fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	cfg, err := instance.ConfigurationOptions()
	if err != nil {
		return "", err
	}

	return cfg.DefaultSecurityGroupName, nil
}

// EnableSecurityGroup enables a Security Group
// Does actually nothing for openstack
func (instance *stack) EnableSecurityGroup(ctx context.Context, _ *abstract.SecurityGroup) fail.Error {
	return fail.NotAvailableError("openstack cannot enable a Security Group")
}

// DisableSecurityGroup disables a Security Group
// Does actually nothing for openstack
func (instance *stack) DisableSecurityGroup(ctx context.Context, _ *abstract.SecurityGroup) fail.Error {
	return fail.NotAvailableError("openstack cannot disable a Security Group")
}
