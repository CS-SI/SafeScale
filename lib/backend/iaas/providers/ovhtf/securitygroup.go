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
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	designSecurityGroupResourceSnippetPath = "resource_sg_design.tf"
)

// type securityGroupResource struct {
// 	terraformer.ResourceCore
//
// 	id          string
// 	description string
// 	rules       abstract.SecurityGroupRules
// }
//
// func newSecurityGroupResource(name string) (*securityGroupResource, fail.Error) {
// 	rc, xerr := terraformer.NewResourceCore(name, createSecurityGroupResourceSnippet)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
//
// 	return &securityGroupResource{ResourceCore: rc}, nil
// }
//
// func (sgr *securityGroupResource) ToMap() map[string]any {
// 	return map[string]any{
// 		"ID":          sgr.id,
// 		"Name":        sgr.Name(),
// 		"Description": sgr.description,
// 		"Rules":       sgr.rules,
// 	}
// }
//

func (p *provider) ListSecurityGroups(ctx context.Context, networkRef string) ([]*abstract.SecurityGroup, fail.Error) {
	// TODO implement me
	panic("implement me")
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
	asg, xerr = abstract.NewSecurityGroup(abstract.WithName(name))
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

	def, xerr := renderer.Assemble(asg)
	if xerr != nil {
		return nil, xerr
	}

	outputs, xerr := renderer.Apply(ctx, def)
	if xerr != nil {
		return nil, xerr
	}

	asg.ID, xerr = unmarshalOutput[string](outputs["id"])
	if xerr != nil {
		return nil, xerr
	}

	for k, v := range rules {
		id, xerr := unmarshalOutput[string](outputs[fmt.Sprintf("rule_%d_id", k)])
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
	// 		if derr := s.DeleteSecurityGroup(context.Background(), asg); derr != nil {
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
	// TODO implement me
	panic("implement me")
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
	xerr = renderer.Destroy(ctx, def, terraformerapi.WithTarget(asg.GetName()))
	if xerr != nil {
		return fail.Wrap(xerr, "failed to delete network %s", asg.ID)
	}

	return nil
}

func (p *provider) AddRuleToSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) DeleteRuleFromSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) GetDefaultSecurityGroupName(ctx context.Context) (string, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) EnableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) fail.Error {
	// TODO implement me
	panic("implement me")
}

func (p *provider) DisableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) fail.Error {
	// TODO implement me
	panic("implement me")
}

func (p *provider) ChangeSecurityGroupSecurity(ctx context.Context, b bool, b2 bool, s string, s2 string) fail.Error {
	// TODO implement me
	panic("implement me")
}

func (p *provider) ConsolidateSecurityGroupSnippet(asg *abstract.SecurityGroup) {
	if valid.IsNil(p) || asg == nil {
		return
	}

	_ = asg.AddOptions(abstract.UseTerraformSnippet(designSecurityGroupResourceSnippetPath))
}
