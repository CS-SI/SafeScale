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
	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	labelfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/label"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// LabelHandler defines API to manipulate tags
type LabelHandler interface {
	Delete(ref string) fail.Error
	List(listTag bool) ([]*resources.Label, fail.Error)
	Inspect(ref string) (*resources.Label, fail.Error)
	Create(name string, hasDefault bool, defaultValue string) (*resources.Label, fail.Error)
}

// labelHandler Label service
type labelHandler struct {
	job jobapi.Job
}

// NewTagHandler creates a Label service
func NewTagHandler(job jobapi.Job) LabelHandler {
	return &labelHandler{job: job}
}

// List returns the network list
func (handler *labelHandler) List(listTag bool) (list []*resources.Label, ferr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	ctx := handler.job.Context()
	defer func() {
		if ferr != nil {
			ferr.WithContext(ctx)
		}
	}()
	defer fail.OnPanic(&ferr)

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("handlers.tag"), "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	browseInstance, xerr := labelfactory.New(handler.job.Context())
	if xerr != nil {
		return nil, xerr
	}

	xerr = browseInstance.Browse(ctx, func(label *abstract.Label) fail.Error {
		labelInstance, innerXErr := labelfactory.Load(handler.job.Context(), label.ID)
		if innerXErr != nil {
			return innerXErr
		}

		isTag, innerXErr := labelInstance.IsTag(ctx)
		if innerXErr != nil {
			return innerXErr
		}

		if listTag == isTag {
			list = append(list, labelInstance)
		}

		return nil
	})
	if xerr != nil {
		return nil, xerr
	}
	return list, nil
}

// Delete deletes Label referenced by ref
func (handler *labelHandler) Delete(ref string) (ferr fail.Error) {
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
	defer func() {
		if ferr != nil {
			ferr.WithContext(ctx)
		}
	}()
	defer fail.OnPanic(&ferr)

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("handlers.tag"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage())

	instance, xerr := labelfactory.Load(handler.job.Context(), ref)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return abstract.ResourceNotFoundError("tag", ref)
		default:
			logrus.WithContext(ctx).Debugf("failed to delete tag: %+v", xerr)
			return xerr
		}
	}

	return instance.Delete(ctx)
}

// Inspect returns the tag identified by ref and its attachment (if any)
func (handler *labelHandler) Inspect(ref string) (_ *resources.Label, ferr fail.Error) {
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
	defer func() {
		if ferr != nil {
			ferr.WithContext(ctx)
		}
	}()
	defer fail.OnPanic(&ferr)

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("handlers.tag"), "('"+ref+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage())

	instance, xerr := labelfactory.Load(ctx, ref)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nil, abstract.ResourceNotFoundError("tag", ref)
		default:
			return nil, xerr
		}
	}

	return instance, nil
}

// Create a tag
func (handler *labelHandler) Create(name string, hasDefault bool, defaultValue string) (_ *resources.Label, ferr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty!")
	}

	ctx := handler.job.Context()
	defer func() {
		if ferr != nil {
			ferr.WithContext(ctx)
		}
	}()
	defer fail.OnPanic(&ferr)

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("handlers.tag"), "('%s', %d, %s)", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage())

	instance, xerr := labelfactory.New(ctx)
	if xerr != nil {
		return nil, xerr
	}

	xerr = instance.Create(ctx, name, hasDefault, defaultValue)
	if xerr != nil {
		return nil, xerr
	}

	return instance, nil
}
