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

package azuretf

import (
	"context"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// ListSecurityGroups lists existing security groups
// There is no Security Group resource in GCP, so ListSecurityGroups always returns empty slice
func (s stack) ListSecurityGroups(ctx context.Context, networkRef string) ([]*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, nil
}

// CreateSecurityGroup creates a security group
// Actually creates GCP Firewall Rules corresponding to the Security Group rules
func (s stack) CreateSecurityGroup(ctx context.Context, networkRef, name, description string, rules abstract.SecurityGroupRules) (_ *abstract.SecurityGroup, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	return nil, fail.NotImplementedError("implement me")
}

// DeleteSecurityGroup deletes a security group and its rules
func (s stack) DeleteSecurityGroup(ctx context.Context, asg *abstract.SecurityGroup) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	return fail.NotImplementedError("implement me")
}

// InspectSecurityGroup returns information about a security group
// Actually there is no Security Group resource in GCP, so this function always returns a *fail.NotImplementedError error
func (s stack) InspectSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(s) {
		return &abstract.SecurityGroup{}, fail.InvalidInstanceError()
	}
	return nil, fail.NotImplementedError("implement me")
}

// ClearSecurityGroup removes all rules but keep group
func (s stack) ClearSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	return nil, fail.NotImplementedError("implement me")
}

// AddRuleToSecurityGroup adds a rule to a security group
func (s stack) AddRuleToSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	return nil, fail.NotImplementedError("implement me")
}

// DeleteRuleFromSecurityGroup deletes a rule from a security group
// For now, this function does nothing in GCP context (have to figure out how to identify Firewall rule corresponding to abstract Security Group rule
func (s stack) DeleteRuleFromSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	return nil, fail.NotImplementedError("implement me")
}

// DisableSecurityGroup disables the rules of a Security Group
func (s stack) DisableSecurityGroup(ctx context.Context, asg *abstract.SecurityGroup) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	return fail.NotImplementedError("implement me")
}

// EnableSecurityGroup enables the rules of a Security Group
func (s stack) EnableSecurityGroup(ctx context.Context, asg *abstract.SecurityGroup) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	return fail.NotImplementedError("implement me")
}

// GetDefaultSecurityGroupName returns the name of the Security Group automatically bound to hosts
func (s stack) GetDefaultSecurityGroupName(ctx context.Context) (string, fail.Error) {
	if valid.IsNil(s) {
		return "", fail.InvalidInstanceError()
	}

	cfg, err := s.GetRawConfigurationOptions(ctx)
	if err != nil {
		return "", err
	}

	return cfg.DefaultSecurityGroupName, nil
}
