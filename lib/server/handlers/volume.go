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

package handlers

import (
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumeproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	volumefactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/volume"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
)

//go:generate minimock -o ../mocks/mock_volumeapi.go -i github.com/CS-SI/SafeScale/lib/server/handlers.VolumeHandler

// VolumeHandler defines API to manipulate hosts
type VolumeHandler interface {
	Delete(ref string) fail.Error
	List(all bool) ([]resources.Volume, fail.Error)
	Inspect(ref string) (resources.Volume, fail.Error)
	Create(name string, size int, speed volumespeed.Enum) (resources.Volume, fail.Error)
	Attach(volume string, host string, path string, format string, doNotFormat bool) fail.Error
	Detach(volume string, host string) fail.Error
}

// TODO: At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// FIXME: ROBUSTNESS All functions MUST propagate context

// volumeHandler volume service
type volumeHandler struct {
	job server.Job
}

// NewVolumeHandler creates a Volume service
func NewVolumeHandler(job server.Job) VolumeHandler {
	return &volumeHandler{job: job}
}

// List returns the network list
func (handler *volumeHandler) List(all bool) (volumes []resources.Volume, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.volume"), "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	objv, xerr := volumefactory.New(handler.job.Service())
	if xerr != nil {
		return nil, xerr
	}
	xerr = objv.Browse(task.Context(), func(volume *abstract.Volume) fail.Error {
		rv, innerXErr := volumefactory.Load(handler.job.Service(), volume.ID)
		if innerXErr != nil {
			return innerXErr
		}
		volumes = append(volumes, rv)
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}
	return volumes, nil
}

// Delete deletes volume referenced by ref
func (handler *volumeHandler) Delete(ref string) (xerr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.volume"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	volumeInstance, xerr := volumefactory.Load(handler.job.Service(), ref)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return abstract.ResourceNotFoundError("volume", ref)
		default:
			logrus.Debugf("failed to delete volume: %+v", xerr)
			return xerr
		}
	}

	xerr = volumeInstance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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

	return volumeInstance.Delete(task.Context())
}

// Inspect returns the volume identified by ref and its attachment (if any)
func (handler *volumeHandler) Inspect(ref string) (volume resources.Volume, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be empty!")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.volume"), "('"+ref+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	objv, xerr := volumefactory.Load(handler.job.Service(), ref)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); ok {
			return nil, abstract.ResourceNotFoundError("volume", ref)
		}
		return nil, xerr
	}
	return objv, nil
}

// Create a volume
func (handler *volumeHandler) Create(name string, size int, speed volumespeed.Enum) (objv resources.Volume, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty!")
	}

	tracer := debug.NewTracer(handler.job.Task(), tracing.ShouldTrace("handlers.volume"), "('%s', %d, %s)", name, size, speed.String()).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

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

// Attach a volume to an host
func (handler *volumeHandler) Attach(volumeRef, hostRef, path, format string, doNotFormat bool) (xerr fail.Error) {
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

	tracer := debug.NewTracer(handler.job.Task(), tracing.ShouldTrace("handlers.volume"), "('%s', '%s', '%s', '%s', %v)", volumeRef, hostRef, path, format, doNotFormat)
	defer tracer.WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	svc := handler.job.Service()
	volumeInstance, xerr := volumefactory.Load(svc, volumeRef)
	if xerr != nil {
		return xerr
	}

	hostInstance, xerr := hostfactory.Load(svc, hostRef)
	if xerr != nil {
		return xerr
	}

	return volumeInstance.Attach(handler.job.Context(), hostInstance, path, format, doNotFormat)
}

// Detach detach the volume identified by ref, ref can be the name or the id
func (handler *volumeHandler) Detach(volumeRef, hostRef string) (xerr fail.Error) {
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

	tracer := debug.NewTracer(handler.job.Task(), tracing.ShouldTrace("handlers.volume"), "('%s', '%s')", volumeRef, hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	// Load volume data
	rv, xerr := volumefactory.Load(handler.job.Service(), volumeRef)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return xerr
		}

		return abstract.ResourceNotFoundError("volume", volumeRef)
	}
	// mountPath := ""

	// Load rh data
	rh, xerr := hostfactory.Load(handler.job.Service(), hostRef)
	if xerr != nil {
		return xerr
	}

	return rv.Detach(handler.job.Context(), rh)
}
