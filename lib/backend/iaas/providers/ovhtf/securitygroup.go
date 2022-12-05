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

package ovhtf

import (
	"context"
	"fmt"

	terraformer "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer"
	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	designSecurityGroupResourceSnippetPath = "snippets/resource_sg_design.tf"
)

func (p *provider) ListSecurityGroups(ctx context.Context, networkRef string) ([]*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	return p.MiniStack.ListSecurityGroups(ctx, networkRef)
}

func (p *provider) CreateSecurityGroup(ctx context.Context, networkRef, name, description string, rules abstract.SecurityGroupRules) (_ *abstract.SecurityGroup, ferr fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stacks.securitygroup"), "('%s')", name).WithStopwatch().Entering().Exiting()

	asg, xerr := p.InspectSecurityGroup(ctx, name)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
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
	opts := []abstract.Option{
		abstract.WithName(name),
		abstract.UseTerraformSnippet(designSecurityGroupResourceSnippetPath),
		abstract.WithResourceType("openstack_networking_secgroup_v2"),
	}
	asg, xerr = abstract.NewSecurityGroup(opts...)
	if xerr != nil {
		return nil, xerr
	}

	asg.Description = description
	asg.Network = networkRef

	renderer, xerr := terraformer.New(p, p.TerraformerOptions())
	if xerr != nil {
		return nil, xerr
	}
	defer func() { _ = renderer.Close() }()

	xerr = renderer.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
	if xerr != nil {
		return nil, xerr
	}

	// FIXME: should be necessary to create local Resource for SG rules and add them to assemble, to be able to remove SG AND its rules with Destroy...
	def, xerr := renderer.Assemble(asg)
	if xerr != nil {
		return nil, xerr
	}

	outputs, xerr := renderer.Apply(ctx, def)
	if xerr != nil {
		return nil, xerr
	}

	values, xerr := unmarshalOutput[[]string](outputs["sg_"+asg.Name+"_id"])
	if xerr != nil {
		return nil, xerr
	}

	asg.ID = values[0]

	for k, v := range rules {
		id, xerr := unmarshalOutput[string](outputs[fmt.Sprintf("sg_%s_rule_%d_id", asg.Name, k)])
		if xerr != nil {
			return nil, xerr
		}

		v.IDs = append(v.IDs, id)
	}
	asg.Rules = rules

	// createOpts := secgroups.CreateOpts{
	// 	Name:        name,
	// 	Description: description,
	// }
	// xerr = stacks.RetryableRemoteCall(ctx,
	// 	func() error {
	// 		r, innerErr := secgroups.Create(s.NetworkClient, createOpts).Extract()
	// 		if innerErr != nil {
	// 			return innerErr
	// 		}
	// 		asg.ID = r.ID
	// 		return nil
	// 	},
	// 	NormalizeError,
	// )
	// if xerr != nil {
	// 	return nil, xerr
	// }

	// // Starting from here, delete security group on error
	// defer func() {
	// 	ferr = debug.InjectPlannedFail(ferr)
	// 	if ferr != nil {
	// 		derr := s.DeleteSecurityGroup(context.Background(), asg)
	// 		if derr != nil {
	// 			_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete security group"))
	// 		}
	// 	}
	// }()

	// // In OpenStack, freshly created security group may contain default rules; we do not want them
	// asg, xerr = p.ClearSecurityGroup(ctx, asg)
	// if xerr != nil {
	// 	return nil, xerr
	// }
	//
	// // now adds security rules
	// asg.Rules = make(abstract.SecurityGroupRules, 0, len(rules))
	// for _, v := range rules {
	// 	if asg, xerr = p.AddRuleToSecurityGroup(ctx, asg, v); xerr != nil {
	// 		return nil, xerr
	// 	}
	// }

	return asg, nil
}

func (p *provider) InspectSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}
	_, sgLabel, xerr := iaasapi.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stacks.securitygroup"), "(%s)", sgLabel).WithStopwatch().Entering().Exiting()

	return p.MiniStack.InspectSecurityGroup(ctx, sgParam)
}

func (p *provider) ClearSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	return nil, fail.NotImplementedError()
}

func (p *provider) DeleteSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupParameter) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	asg, sgLabel, xerr := iaasapi.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.securitygroup"), "(%s)", sgLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	asg, xerr = p.InspectSecurityGroup(ctx, asg)
	if xerr != nil {
		return xerr
	}

	// Make sure the Snippet data is here...
	xerr = asg.AddOptions(abstract.UseTerraformSnippet(networkDesignResourceSnippetPath))
	if xerr != nil {
		return xerr
	}

	// Instanciates terraform renderer
	renderer, xerr := terraformer.New(p, p.TerraformerOptions())
	if xerr != nil {
		return xerr
	}
	defer func() { _ = renderer.Close() }()

	// Sets env vars necessary for OVH provider
	xerr = renderer.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
	if xerr != nil {
		return xerr
	}

	// Creates the terraform definition file
	def, xerr := renderer.Assemble(asg)
	if xerr != nil {
		return xerr
	}

	// Instruct terraform to destroy the Security Group
	xerr = renderer.Destroy(ctx, def, terraformerapi.WithTarget(asg))
	if xerr != nil {
		return fail.Wrap(xerr, "failed to delete network %s", asg.ID)
	}

	return nil
}

func (p *provider) AddRulesToSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupParameter, rules ...*abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	asg, sgLabel, xerr := iaasapi.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return nil, xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.ovhtf") || tracing.ShouldTrace("stacks.securitygroup"), "(%s)", sgLabel).WithStopwatch().Entering().Exiting()

	asg, xerr = p.InspectSecurityGroup(ctx, asg)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreError(xerr)
		case *fail.ErrDuplicate:
			// Special case : a duplicate error may come from OpenStack after normalization, because there are already more than 1
			// security groups with the same name. In this situation, returns a DuplicateError with the xerr as cause
			return nil, fail.DuplicateErrorWithCause(xerr, nil, "more than one Security Group %s found", sgLabel)
		default:
			return nil, xerr
		}
	} else {
		return nil, fail.DuplicateError("a Security Group %s already exist", sgLabel)
	}

	newAsg, err := clonable.CastedClone[*abstract.SecurityGroup](asg)
	if err != nil {
		return nil, fail.Wrap(xerr)
	}

	xerr = newAsg.AddOptions(
		abstract.UseTerraformSnippet(designSecurityGroupResourceSnippetPath),
		abstract.WithResourceType("openstack_networking_secgroup_v2"),
	)
	if xerr != nil {
		return nil, xerr
	}

	newAsg.Rules = append(newAsg.Rules, rules...)

	renderer, xerr := terraformer.New(p, p.TerraformerOptions())
	if xerr != nil {
		return nil, xerr
	}
	defer func() { _ = renderer.Close() }()

	xerr = renderer.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
	if xerr != nil {
		return nil, xerr
	}

	// FIXME: should be necessary to create local Resource for SG rules and add them to assemble, to be able to remove SG AND its rules with Destroy...
	def, xerr := renderer.Assemble(asg)
	if xerr != nil {
		return nil, xerr
	}

	outputs, xerr := renderer.Apply(ctx, def)
	if xerr != nil {
		return nil, xerr
	}

	values, xerr := unmarshalOutput[[]string](outputs["sg_"+asg.Name+"_id"])
	if xerr != nil {
		return nil, xerr
	}

	asg.ID = values[0]

	for k, v := range rules {
		id, xerr := unmarshalOutput[string](outputs[fmt.Sprintf("sg_%s_rule_%d_id", asg.Name, k)])
		if xerr != nil {
			return nil, xerr
		}

		v.IDs = append(v.IDs, id)
	}
	asg.Rules = rules

	// createOpts := secgroups.CreateOpts{
	// 	Name:        name,
	// 	Description: description,
	// }
	// xerr = stacks.RetryableRemoteCall(ctx,
	// 	func() error {
	// 		r, innerErr := secgroups.Create(s.NetworkClient, createOpts).Extract()
	// 		if innerErr != nil {
	// 			return innerErr
	// 		}
	// 		asg.ID = r.ID
	// 		return nil
	// 	},
	// 	NormalizeError,
	// )
	// if xerr != nil {
	// 	return nil, xerr
	// }

	// // Starting from here, delete security group on error
	// defer func() {
	// 	ferr = debug.InjectPlannedFail(ferr)
	// 	if ferr != nil {
	// 		derr := s.DeleteSecurityGroup(context.Background(), asg)
	// 		if derr != nil {
	// 			_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete security group"))
	// 		}
	// 	}
	// }()

	// // In OpenStack, freshly created security group may contain default rules; we do not want them
	// asg, xerr = p.ClearSecurityGroup(ctx, asg)
	// if xerr != nil {
	// 	return nil, xerr
	// }
	//
	// // now adds security rules
	// asg.Rules = make(abstract.SecurityGroupRules, 0, len(rules))
	// for _, v := range rules {
	// 	if asg, xerr = p.AddRuleToSecurityGroup(ctx, asg, v); xerr != nil {
	// 		return nil, xerr
	// 	}
	// }

	return asg, nil
}

func (p *provider) DeleteRulesFromSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupParameter, rules ...*abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	return nil, fail.NotImplementedError()
}

func (p *provider) GetDefaultSecurityGroupName(ctx context.Context) (string, fail.Error) {
	return "", fail.NotImplementedError()
}

func (p *provider) EnableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) fail.Error {
	return fail.NotImplementedError()
}

func (p *provider) DisableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) fail.Error {
	return fail.NotImplementedError()
}

func (p *provider) ChangeSecurityGroupSecurity(ctx context.Context, b bool, b2 bool, s string, s2 string) fail.Error {
	return fail.NotImplementedError()
}

func (p *provider) ConsolidateSecurityGroupSnippet(asg *abstract.SecurityGroup) {
	if valid.IsNil(p) || asg == nil {
		return
	}

	_ = asg.AddOptions(abstract.UseTerraformSnippet(designSecurityGroupResourceSnippetPath))
}