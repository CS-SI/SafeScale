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

package vclouddirector

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ListSecurityGroups lists existing security groups
func (s stack) ListSecurityGroups() ([]*abstract.SecurityGroup, fail.Error) {
	return nil, fail.NotImplementedError()
}

// CreateSecurityGroup creates a security group
func (s stack) CreateSecurityGroup(name string, rules []abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	return nil, fail.NotImplementedError()
}

// DeleteSecurityGroup deletes a security group and its rules
func (s stack) DeleteSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return fail.NotImplementedError()
}

// InspectSecurityGroup returns information about a security group
func (s stack) InspectSecurityGroup(ref string) (*abstract.SecurityGroup, fail.Error) {
	return nil, fail.NotImplementedError()
}

// ClearSecurityGroup removes all rules but keep group
func (s stack) ClearSecurityGroup(ref string) fail.Error {
	return fail.NotImplementedError()
}

// AddRuleToSecurityGroup adds a rule to a security group
func (s stack) AddRuleToSecurityGroup(groupRef string, rule abstract.SecurityGroupRule) fail.Error {
	return fail.NotImplementedError()
}

// DeleteRuleFromSecurityGroup deletes a rule identified by ID from a security group
// Checks first if the rule ID is present in the rules of the security group. If not found, returns (*abstract.SecurityGroup, *fail.ErrNotFound)
func (s stack) DeleteRuleFromSecurityGroup(sgParam stacks.SecurityGroupParameter, ruleID string) (*abstract.SecurityGroup, fail.Error) {
	return nil, fail.NotImplementedError()
}

// GetDefaultSecurityGroupName returns the name of the Security Group automatically bound to hosts
func (s stack) GetDefaultSecurityGroupName() string {
	return ""
}

// EnableSecurityGroup enables a Security Group
// Does actually nothing for openstack
func (s stack) EnableSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return fail.NotAvailableError("openstack cannot enable a Security Group")
}

// DisableSecurityGroup disables a Security Group
// Does actually nothing for openstack
func (s stack) DisableSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return fail.NotAvailableError("openstack cannot disable a Security Group")
}
