// +build libvirt

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

package local

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ListSecurityGroups lists existing security groups
func (s stack) ListSecurityGroups(networkRef string) ([]*abstract.SecurityGroup, fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.securitygroup") || tracing.ShouldTrace("stack.gcp")).WithStopwatch().Entering()
	defer tracer.Exiting()

	return nil, fail.NotImplementedError()
}

// CreateSecurityGroup creates a security group
func (s stack) CreateSecurityGroup(networkRef, name string, description string, rules []abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	return &abstract.SecurityGroup{}, fail.NotImplementedError()
}

// DeleteSecurityGroup deletes a security group and its rules
func (s stack) DeleteSecurityGroup(asg *abstract.SecurityGroup) fail.Error {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if asg.IsNull() {
		return fail.InvalidParameterError("asg", "cannot be null value of '*abstract.SecurityGroup'")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	return fail.NotImplementedError()
}

// InspectSecurityGroup returns information about a security group
func (s stack) InspectSecurityGroup(sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return asg, xerr
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	return asg, fail.NotImplementedError()
}

// ClearSecurityGroup removes all rules but keep group
func (s stack) ClearSecurityGroup(sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return asg, xerr
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	return asg, fail.NotImplementedError()
}

// AddRuleToSecurityGroup adds a rule to a security group
func (s stack) AddRuleToSecurityGroup(sgParam stacks.SecurityGroupParameter, rule abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return asg, xerr
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s)", asg.ID).WithStopwatch().Entering()
	defer tracer.Exiting()

	return asg, fail.NotImplementedError()
}

// DeleteRuleFromSecurityGroup deletes a rule identified by ID from a security group
// Checks first if the rule ID is present in the rules of the security group. If not found, returns (*abstract.SecurityGroup, *fail.ErrNotFound)
func (s stack) DeleteRuleFromSecurityGroup(sgParam stacks.SecurityGroupParameter, rule abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	asg, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.gcp"), "(%s, %v)", asg.ID, rule).WithStopwatch().Entering()
	defer tracer.Exiting()

	return nil, fail.NotImplementedError()
}

// EnableSecurityGroup enables a Security Group
// Does actually nothing for openstack
func (s stack) EnableSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return fail.NotAvailableError("libvirt cannot enable a Security Group")
}

// DisableSecurityGroup disables a Security Group
// Does actually nothing for openstack
func (s stack) DisableSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return fail.NotAvailableError("libvirt cannot disable a Security Group")
}
