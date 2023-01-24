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

package handlers

import (
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	"github.com/sirupsen/logrus"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/host"
	volumefactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/volume"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/handlers.VolumeHandler -o mocks/mock_volume.go

// VolumeHandler defines API to manipulate hosts
type VolumeHandler interface {
	Attach(volume string, host string, path string, format string, doNotFormat bool, doNotMount bool) fail.Error
	Create(name string, size int, speed volumespeed.Enum) (*resources.Volume, fail.Error)
	Detach(volume string, host string) fail.Error
	Delete(ref string) fail.Error
	Inspect(ref string) (*resources.Volume, fail.Error)
	List(all bool) ([]*resources.Volume, fail.Error)
}

// NOTICE: At service level, we need to log before returning, because it's the last chance to track the real issue in server side, so we should catch panics here

// FIXME: ROBUSTNESS All functions MUST propagate context

// volumeHandler volume service
type volumeHandler struct {
	job jobapi.Job
}

// NewVolumeHandler creates a Volume service
func NewVolumeHandler(job jobapi.Job) VolumeHandler {
	return &volumeHandler{job: job}
}

// List returns the list of Volumes
func (handler *volumeHandler) List(all bool) (volumes []*resources.Volume, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	ctx := handler.job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("handlers.volume"), "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage())

	browseInstance, xerr := volumefactory.New(handler.job.Context())
	if xerr != nil {
		return nil, xerr
	}

	xerr = browseInstance.Browse(ctx, func(volume *abstract.Volume) fail.Error {
		volumeInstance, innerXErr := volumefactory.Load(handler.job.Context(), volume.ID)
		if innerXErr != nil {
			return innerXErr
		}

		volumes = append(volumes, volumeInstance)
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	return volumes, nil
}

// Delete deletes volume referenced by ref
func (handler *volumeHandler) Delete(ref string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	ctx := handler.job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("handlers.volume"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage())

	volumeInstance, xerr := volumefactory.Load(handler.job.Context(), ref)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return abstract.ResourceNotFoundError("volume", ref)
		default:
			logrus.WithContext(handler.job.Context()).Debugf("failed to delete volume: %+v", xerr)
			return xerr
		}
	}

	volumeTrx, xerr := metadata.NewTransaction[*abstract.Volume, *resources.Volume](ctx, volumeInstance)
	if xerr != nil {
		return xerr
	}
	defer volumeTrx.TerminateBasedOnError(ctx, &ferr)

	// FIXME: introduce a volumeInstance.GetAttachments() to replace the code below
	attachments, xerr := volumeInstance.GetAttachments(ctx)
	if xerr != nil {
		return xerr
	}

	nbAttach := uint(len(attachments.Hosts))
	if nbAttach > 0 {
		var list []string
		for _, v := range attachments.Hosts {
			list = append(list, v)
		}
		return fail.InvalidRequestError("still attached to %d host%s: %s", nbAttach, strprocess.Plural(nbAttach), strings.Join(list, ", "))
	}
	if xerr != nil {
		return xerr
	}

	return volumeInstance.Delete(ctx)
}

// Inspect returns the volume identified by ref and its attachment (if any)
func (handler *volumeHandler) Inspect(ref string) (volume *resources.Volume, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be empty!")
	}

	ctx := handler.job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("handlers.volume"), "('"+ref+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	volumeInstance, xerr := volumefactory.Load(handler.job.Context(), ref)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); ok {
			return nil, abstract.ResourceNotFoundError("volume", ref)
		}
		return nil, xerr
	}

	exists, xerr := volumeInstance.Exists(ctx)
	if xerr != nil {
		return nil, xerr
	}

	if !exists {
		return nil, abstract.ResourceNotFoundError("volume", ref)
	}

	return volumeInstance, nil
}

// Create a volume
func (handler *volumeHandler) Create(name string, size int, speed volumespeed.Enum) (_ *resources.Volume, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty!")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.volume"), "('%s', %d, %s)", name, size, speed.String()).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	volumeInstance, xerr := volumefactory.New(handler.job.Context())
	if xerr != nil {
		return nil, xerr
	}

	request := abstract.VolumeRequest{
		Name:  name,
		Size:  size,
		Speed: speed,
	}
	if xerr = volumeInstance.Create(handler.job.Context(), request); xerr != nil {
		return nil, xerr
	}

	return volumeInstance, nil
}

// Attach a volume to a host
func (handler *volumeHandler) Attach(volumeRef string, hostRef string, path string, format string, doNotFormat bool, doNotMount bool) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if volumeRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("volumeRef")
	}
	if hostRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if path == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("path")
	}
	if format == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("format")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.volume"), "('%s', '%s', '%s', '%s', %v)", volumeRef, hostRef, path, format, doNotFormat)
	defer tracer.WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	ctx := handler.job.Context()
	volumeInstance, xerr := volumefactory.Load(ctx, volumeRef)
	if xerr != nil {
		return xerr
	}

	hostInstance, xerr := hostfactory.Load(ctx, hostRef)
	if xerr != nil {
		return xerr
	}

	return volumeInstance.Attach(ctx, hostInstance, path, format, doNotFormat, doNotMount)
}

// Detach detach the volume identified by ref, ref can be the name or the id
func (handler *volumeHandler) Detach(volumeRef, hostRef string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if volumeRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("volumeRef")
	}
	if hostRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.volume"), "('%s', '%s')", volumeRef, hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	ctx := handler.job.Context()
	// Load volume data
	volumeInstance, xerr := volumefactory.Load(ctx, volumeRef)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok || valid.IsNil(xerr) {
			return xerr
		}

		return abstract.ResourceNotFoundError("volume", volumeRef)
	}
	// mountPath := ""

	// Load rh data
	rh, xerr := hostfactory.Load(ctx, hostRef)
	if xerr != nil {
		return xerr
	}

	return volumeInstance.Detach(handler.job.Context(), rh)
}
