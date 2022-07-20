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

package handlers

import (
	"reflect"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/server"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/volumeproperty"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/volumespeed"
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/server/resources/factories/host"
	volumefactory "github.com/CS-SI/SafeScale/v22/lib/server/resources/factories/volume"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/server/handlers.VolumeHandler -o mocks/mock_volume.go

// VolumeHandler defines API to manipulate hosts
type VolumeHandler interface {
	Attach(volume string, host string, path string, format string, doNotFormat bool, doNotMount bool) fail.Error
	Create(name string, size int, speed volumespeed.Enum) (resources.Volume, fail.Error)
	Detach(volume string, host string) fail.Error
	Delete(ref string) fail.Error
	Inspect(ref string) (resources.Volume, fail.Error)
	List(all bool) ([]resources.Volume, fail.Error)
}

// NOTICE: At service level, we need to log before returning, because it's the last chance to track the real issue in server side, so we should catch panics here

// FIXME: ROBUSTNESS All functions MUST propagate context

// volumeHandler volume service
type volumeHandler struct {
	job server.Job
}

// NewVolumeHandler creates a Volume service
func NewVolumeHandler(job server.Job) VolumeHandler {
	return &volumeHandler{job: job}
}

// List returns the list of Volumes
func (handler *volumeHandler) List(all bool) (volumes []resources.Volume, ferr fail.Error) {
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

	browseInstance, xerr := volumefactory.New(handler.job.Service())
	if xerr != nil {
		return nil, xerr
	}

	xerr = browseInstance.Browse(ctx, func(volume *abstract.Volume) fail.Error {
		volumeInstance, innerXErr := volumefactory.Load(handler.job.Context(), handler.job.Service(), volume.ID)
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

	volumeInstance, xerr := volumefactory.Load(handler.job.Context(), handler.job.Service(), ref)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return abstract.ResourceNotFoundError("volume", ref)
		default:
			logrus.WithContext(handler.job.Context()).Debugf("failed to delete volume: %+v", xerr)
			return xerr
		}
	}

	xerr = volumeInstance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
			volumeAttachmentsV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			nbAttach := uint(len(volumeAttachmentsV1.Hosts))
			if nbAttach > 0 {
				var list []string
				for _, v := range volumeAttachmentsV1.Hosts {
					list = append(list, v)
				}
				return fail.InvalidRequestError("still attached to %d host%s: %s", nbAttach, strprocess.Plural(nbAttach), strings.Join(list, ", "))
			}
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	return volumeInstance.Delete(ctx)
}

// Inspect returns the volume identified by ref and its attachment (if any)
func (handler *volumeHandler) Inspect(ref string) (volume resources.Volume, ferr fail.Error) {
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

	volumeInstance, xerr := volumefactory.Load(handler.job.Context(), handler.job.Service(), ref)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); ok {
			return nil, abstract.ResourceNotFoundError("volume", ref)
		}
		return nil, xerr
	}
	return volumeInstance, nil
}

// Create a volume
func (handler *volumeHandler) Create(name string, size int, speed volumespeed.Enum) (objv resources.Volume, ferr fail.Error) {
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

	var xerr fail.Error
	objv, xerr = volumefactory.New(handler.job.Service())
	if xerr != nil {
		return nil, xerr
	}
	request := abstract.VolumeRequest{
		Name:  name,
		Size:  size,
		Speed: speed,
	}
	if xerr = objv.Create(handler.job.Context(), request); xerr != nil {
		return nil, xerr
	}
	return objv, nil
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

	svc := handler.job.Service()
	ctx := handler.job.Context()
	volumeInstance, xerr := volumefactory.Load(ctx, svc, volumeRef)
	if xerr != nil {
		return xerr
	}

	hostInstance, xerr := hostfactory.Load(ctx, svc, hostRef)
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

	svc := handler.job.Service()
	ctx := handler.job.Context()
	// Load volume data
	rv, xerr := volumefactory.Load(ctx, svc, volumeRef)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok || valid.IsNil(xerr) {
			return xerr
		}

		return abstract.ResourceNotFoundError("volume", volumeRef)
	}
	// mountPath := ""

	// Load rh data
	rh, xerr := hostfactory.Load(ctx, svc, hostRef)
	if xerr != nil {
		return xerr
	}

	return rv.Detach(handler.job.Context(), rh)
}
