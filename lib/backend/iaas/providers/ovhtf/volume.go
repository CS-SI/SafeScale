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

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	terraformer "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer"
	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"
)

const (
	volumeDesignResourceSnippetPath = "snippets/resource_volume_design.tf"
)

// CreateVolume ...
func (p *provider) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (_ *abstract.Volume, ferr fail.Error) {
	var xerr fail.Error
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
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

	cfg, xerr := p.ConfigurationOptions()
	if xerr != nil {
		return nil, xerr
	}

	// Pass information to terraformer that we are in creation process
	xerr = abstractVolume.AddOptions(
		abstract.MarkForCreation(),
		abstract.WithExtraData("Attachments", map[string]string{}),
		abstract.WithExtraData("VolumeTypes", cfg.VolumeTypes),
	)
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

// InspectVolume ...
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

// ListVolumes ...
func (p *provider) ListVolumes(ctx context.Context) ([]*abstract.Volume, fail.Error) {
	var emptySlice []*abstract.Volume
	if valid.IsNull(p) {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.volume"), "").WithStopwatch().Entering().Exiting()

	return p.MiniStack.ListVolumes(ctx)
}

// DeleteVolume ...
func (p *provider) DeleteVolume(ctx context.Context, volumeParam iaasapi.VolumeIdentifier) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	switch volumeParam.(type) {
	case string:
		return fail.InvalidParameterError("volumeParam", "must be an '*abstract.Volume'")
	}
	abstractVolume, volumeLabel, xerr := iaasapi.ValidateVolumeIdentifier(volumeParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.volume"), "(%s)", volumeLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	xerr = abstractVolume.AddOptions(abstract.MarkForDestruction())
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
		return fail.Wrap(xerr, "failed to delete volume '%s'", abstractVolume.Name)
	}

	return nil
}

// CreateVolumeAttachment ...
func (p *provider) CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (_ string, ferr fail.Error) {
	if valid.IsNil(p) {
		return "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return "", fail.InvalidParameterCannotBeNilError("ctx")
	}
	if valid.IsNull(request.Volume) {
		return "", fail.InvalidParameterCannotBeNilError("request.Volume")
	}
	if valid.IsNull(request.Host) {
		return "", fail.InvalidParameterCannotBeNilError("request.Host")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.compute"), "('%s', '%s', '%s')", request.Volume.Name, request.Host.Name, request.Name).WithStopwatch().Entering().Exiting()
	defer fail.OnPanic(&ferr)

	xerr := p.ConsolidateVolumeSnippet(request.Volume)
	if xerr != nil {
		return "", xerr
	}

	attachments, ok := request.Volume.Extra()["Attachments"].(map[string]string)
	if !ok {
		attachments = make(map[string]string)
	}
	attachments[request.Host.ID] = request.Host.Name
	xerr = request.Volume.AddOptions(abstract.WithExtraData("Attachments", attachments))
	if xerr != nil {
		return "", xerr
	}

	// --- query provider for host creation ---

	logrus.WithContext(ctx).Debugf("Creating volume attachment '%s' ...", request.Name)

	// Retry creation until success, for 10 minutes
	renderer, xerr := terraformer.New(p, p.TerraformerOptions())
	if xerr != nil {
		return "", xerr
	}
	defer func() { _ = renderer.Close() }()

	xerr = renderer.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
	if xerr != nil {
		return "", xerr
	}

	def, xerr := renderer.Assemble(ctx, request.Volume)
	if xerr != nil {
		return "", xerr
	}

	outputs, xerr := renderer.Apply(ctx, def)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return "", fail.Wrap(fail.Cause(xerr), "timeout")
		case *retry.ErrStopRetry, *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it'instance going to fail anyway
			return "", fail.Wrap(fail.Cause(xerr), "stopping retries")
		default:
			return "", xerr
		}
	}

	defer func() {
		if ferr != nil /*&& request.CleanOnFailure()*/ {
			logrus.WithContext(ctx).Infof("Cleaning up on failure, deleting Volume attachment '%s'", request.Name)

			attachments, _ := request.Volume.Extra()["Attachments"].(map[string]string) // nolint
			delete(attachments, request.Host.ID)
			derr := request.Volume.AddOptions(abstract.WithExtraData("Attachments", attachments))
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to remove volume Attachment '%s'", request.Name))
				return
			}

			derr = renderer.Reset()
			if derr != nil {
				_ = ferr.AddConsequence(derr)
				return
			}

			def, derr := renderer.Assemble(ctx)
			if derr != nil {
				_ = ferr.AddConsequence(derr)
				return
			}

			derr = renderer.Destroy(jobapi.NewContextPropagatingJob(ctx), def)
			if derr != nil {
				logrus.WithContext(ctx).Errorf("failed to delete Volume attachment '%s': %v", request.Name, derr)
				_ = ferr.AddConsequence(derr)
			} else {
				logrus.WithContext(ctx).Infof("Cleaning up on failure, deleted Volume attachment '%s'", request.Name)
			}
		}
	}()

	volAttachID, xerr := unmarshalOutput[string](outputs["volume_"+request.Name+"_host_"+request.Host.Name+"_id"])
	if xerr != nil {
		return "", fail.Wrap(xerr, "failed to recover volume attachment id")
	}

	logrus.Infof("Created Volume attachment '%s' successfully", request.Name)
	return volAttachID, nil
}

// InspectVolumeAttachment ...
func (p *provider) InspectVolumeAttachment(ctx context.Context, hostParam iaasapi.HostIdentifier, volumeParam iaasapi.VolumeIdentifier, _ string) (*abstract.VolumeAttachment, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	switch volumeParam.(type) {
	case string:
		return nil, fail.InvalidParameterError("volumeParam", "must be a '*abstract.Volume'")
	default:
	}
	abstractVolume, volumeLabel, xerr := iaasapi.ValidateVolumeIdentifier(volumeParam)
	if xerr != nil {
		return nil, xerr
	}
	abstractHost, hostLabel, xerr := iaasapi.ValidateHostIdentifier(hostParam)
	if xerr != nil {
		return nil, xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.volume"), "(%s, %s)", volumeLabel, hostLabel).WithStopwatch().Entering().Exiting()

	ava, xerr := p.MiniStack.InspectVolumeAttachment(ctx, abstractVolume, abstractHost, "")
	if xerr != nil {
		return nil, xerr
	}

	return ava, nil
}

// ListVolumeAttachments ...
func (p *provider) ListVolumeAttachments(ctx context.Context, hostParam iaasapi.HostIdentifier) ([]*abstract.VolumeAttachment, fail.Error) {
	var emptySlice []*abstract.VolumeAttachment
	if valid.IsNull(p) {
		return emptySlice, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptySlice, fail.InvalidParameterCannotBeNilError("ctx")
	}
	abstractHost, hostLabel, xerr := iaasapi.ValidateHostIdentifier(hostParam)
	if xerr != nil {
		return emptySlice, xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.volume"), "(%s)", hostLabel).WithStopwatch().Entering().Exiting()

	return p.MiniStack.ListVolumeAttachments(ctx, abstractHost.ID)
}

// DeleteVolumeAttachment ...
// parameter attachmentID is not used here
func (p *provider) DeleteVolumeAttachment(ctx context.Context, hostParam iaasapi.HostIdentifier, volumeParam iaasapi.VolumeIdentifier, attachmentID string) (ferr fail.Error) {
	if valid.IsNil(p) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	switch volumeParam.(type) {
	case string:
		return fail.InvalidParameterError("volumeParam", "must be a *abstract.Volume")
	default:
	}
	abstractVolume, volumeLabel, xerr := iaasapi.ValidateVolumeIdentifier(volumeParam)
	if xerr != nil {
		return xerr
	}
	abstractHost, hostLabel, xerr := iaasapi.ValidateHostIdentifier(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.compute"), "(%s, %s)", volumeLabel, hostLabel).WithStopwatch().Entering().Exiting()
	defer fail.OnPanic(&ferr)

	xerr = p.ConsolidateVolumeSnippet(abstractVolume)
	if xerr != nil {
		return xerr
	}

	attachments, ok := abstractVolume.Extra()["Attachments"].(map[string]string)
	if !ok {
		return nil
	}
	delete(attachments, abstractHost.ID)
	xerr = abstractVolume.AddOptions(abstract.WithExtraData("Attachments", attachments))
	if xerr != nil {
		return xerr
	}

	// Retry creation until success, for 10 minutes
	renderer, xerr := terraformer.New(p, p.TerraformerOptions())
	if xerr != nil {
		return xerr
	}
	defer func() { _ = renderer.Close() }()

	xerr = renderer.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
	if xerr != nil {
		return xerr
	}

	def, xerr := renderer.Assemble(ctx, abstractVolume)
	if xerr != nil {
		return xerr
	}

	_, xerr = renderer.Apply(ctx, def)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return fail.Wrap(fail.Cause(xerr), "timeout")
		case *retry.ErrStopRetry, *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it'instance going to fail anyway
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		default:
			return xerr
		}
	}

	return nil
}

// ConsolidateVolumeSnippet ...
func (p *provider) ConsolidateVolumeSnippet(av *abstract.Volume) fail.Error {
	if valid.IsNil(p) || av == nil {
		return nil
	}

	return av.AddOptions(abstract.UseTerraformSnippet(volumeDesignResourceSnippetPath))
}
