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

package ovhtf

import (
	"context"

	terraformer "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer"
	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"
)

const (
	volumeDesignResourceSnippetPath = "snippets/resource_volume_design.tf"
)

func (p *provider) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (_ *abstract.Volume, ferr fail.Error) {
	var xerr fail.Error
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.volume"), "(%s)", request.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	abstractVolume, xerr := abstract.NewVolume(abstract.WithName(request.Name))
	if xerr != nil {
		return nil, xerr
	}

	abstractVolume.Size = request.Size
	abstractVolume.Speed = request.Speed

	xerr = p.ConsolidateVolumeSnippet(abstractVolume)
	if xerr != nil {
		return nil, xerr
	}

	// Pass information to terraformer that we are in creation process
	xerr = abstractVolume.AddOptions(abstract.MarkForCreation())
	if xerr != nil {
		return nil, xerr
	}

	renderer, xerr := terraformer.New(p, p.TerraformerOptions())
	if xerr != nil {
		return nil, xerr
	}
	defer func() { _ = renderer.Close() }()

	xerr = renderer.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
	if xerr != nil {
		return nil, xerr
	}

	def, xerr := renderer.Assemble(ctx, abstractVolume)
	if xerr != nil {
		return nil, xerr
	}

	outputs, xerr := renderer.Apply(ctx, def)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create volume '%s'", request.Name)
	}

	// Starting from here, delete network if exit with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && request.CleanOnFailure() {
			logrus.WithContext(ctx).Infof("Cleaning up on failure, deleting Network '%s'", request.Name)
			def, derr := renderer.Assemble(ctx)
			if xerr != nil {
				_ = ferr.AddConsequence(derr)
			} else {

				derr = renderer.Destroy(ctx, def, terraformerapi.WithTarget(abstractVolume))
				if derr != nil {
					logrus.WithContext(ctx).Errorf("failed to delete Network '%s': %v", request.Name, derr)
					_ = ferr.AddConsequence(derr)
				}
			}
		}
	}()

	xerr = abstractVolume.AddOptions(abstract.ClearMarkForCreation())
	if xerr != nil {
		return nil, xerr
	}

	abstractVolume.ID, xerr = unmarshalOutput[string](outputs["volume_"+request.Name+"_id"])
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to recover volume id")
	}

	return abstractVolume, nil
}

func (p *provider) InspectVolume(ctx context.Context, id string) (*abstract.Volume, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.volume"), "(%s)", id).WithStopwatch().Entering().Exiting()

	av, xerr := p.MiniStack.InspectVolume(ctx, id)
	if xerr != nil {
		return nil, xerr
	}

	return av, p.ConsolidateVolumeSnippet(av)
}

func (p *provider) ListVolumes(ctx context.Context) ([]*abstract.Volume, fail.Error) {
	var emptySlice []*abstract.Volume
	if valid.IsNull(p) {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.volume"), "").WithStopwatch().Entering().Exiting()

	return p.MiniStack.ListVolumes(ctx)
}

func (p *provider) DeleteVolume(ctx context.Context, parameter iaasapi.VolumeIdentifier) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	switch parameter.(type) {
	case string:
		return fail.InvalidParameterError("parameter", "must be an '*abstract.Volume'")
	}
	av, volumeLabel, xerr := iaasapi.ValidateVolumeIdentifier(parameter)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.volume"), "(%s)", volumeLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	xerr = av.AddOptions(abstract.MarkForDestruction())
	if xerr != nil {
		return xerr
	}

	renderer, xerr := terraformer.New(p, p.TerraformerOptions())
	if xerr != nil {
		return xerr
	}
	defer func() { _ = renderer.Close() }()

	xerr = renderer.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
	if xerr != nil {
		return xerr
	}

	def, xerr := renderer.Assemble(ctx)
	if xerr != nil {
		return xerr
	}

	xerr = renderer.Destroy(ctx, def)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to delete volume '%s'", av.Name)
	}

	return nil
}

func (p *provider) CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	// TODO implement me
	return "", fail.NotImplementedError("CreateVolumeAttachment() not implemented")
}

func (p *provider) InspectVolumeAttachment(ctx context.Context, serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.volume"), "(%s)", id).WithStopwatch().Entering().Exiting()

	ava, xerr := p.MiniStack.InspectVolumeAttachment(ctx, serverID, id)
	if xerr != nil {
		return nil, xerr
	}

	return ava, nil
}

func (p *provider) ListVolumeAttachments(ctx context.Context, serverID string) ([]*abstract.VolumeAttachment, fail.Error) {
	var emptySlice []*abstract.VolumeAttachment
	if valid.IsNull(p) {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.volume"), "").WithStopwatch().Entering().Exiting()

	return p.MiniStack.ListVolumeAttachments(ctx, serverID)
}

func (p *provider) DeleteVolumeAttachment(ctx context.Context, serverID, id string) fail.Error {
	// TODO implement me
	return fail.NotImplementedError("DeleteVolumeAttachment() not implemeted")
}

func (p *provider) ConsolidateVolumeSnippet(av *abstract.Volume) fail.Error {
	if valid.IsNil(p) || av == nil {
		return nil
	}

	return av.AddOptions(abstract.UseTerraformSnippet(volumeDesignResourceSnippetPath))
}
