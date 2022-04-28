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
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/server"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	tagfactory "github.com/CS-SI/SafeScale/v22/lib/server/resources/factories/tag"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// TagHandler defines API to manipulate tags
type TagHandler interface {
	Delete(ref string) fail.Error
	List(all bool) ([]resources.Tag, fail.Error)
	Inspect(ref string) (resources.Tag, fail.Error)
	Create(name string) (resources.Tag, fail.Error)
}

// tagHandler tag service
type tagHandler struct {
	job server.Job
}

// NewTagHandler creates a Tag service
func NewTagHandler(job server.Job) TagHandler {
	return &tagHandler{job: job}
}

// List returns the network list
func (handler *tagHandler) List(all bool) (tags []resources.Tag, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.tag"), "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

	objt, xerr := tagfactory.New(handler.job.Service())
	if xerr != nil {
		return nil, xerr
	}
	xerr = objt.Browse(task.Context(), func(tag *abstract.Tag) fail.Error {
		rv, innerXErr := tagfactory.Load(handler.job.Context(), handler.job.Service(), tag.ID)
		if innerXErr != nil {
			return innerXErr
		}
		tags = append(tags, rv)
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}
	return tags, nil
}

// Delete deletes tag referenced by ref
func (handler *tagHandler) Delete(ref string) (ferr fail.Error) {
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

	task := handler.job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.tag"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

	tagInstance, xerr := tagfactory.Load(handler.job.Context(), handler.job.Service(), ref)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return abstract.ResourceNotFoundError("tag", ref)
		default:
			logrus.Debugf("failed to delete tag: %+v", xerr)
			return xerr
		}
	}

	return tagInstance.Delete(task.Context())
}

// Inspect returns the tag identified by ref and its attachment (if any)
func (handler *tagHandler) Inspect(ref string) (tag resources.Tag, ferr fail.Error) {
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

	task := handler.job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.tag"), "('"+ref+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

	objt, xerr := tagfactory.Load(handler.job.Context(), handler.job.Service(), ref)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); ok {
			return nil, abstract.ResourceNotFoundError("tag", ref)
		}
		return nil, xerr
	}
	return objt, nil
}

// Create a tag
func (handler *tagHandler) Create(name string) (objt resources.Tag, ferr fail.Error) {
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

	tracer := debug.NewTracer(handler.job.Task(), tracing.ShouldTrace("handlers.tag"), "('%s', %d, %s)", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

	var xerr fail.Error
	objt, xerr = tagfactory.New(handler.job.Service())
	if xerr != nil {
		return nil, xerr
	}
	request := abstract.TagRequest{
		Name: name,
	}
	if xerr = objt.Create(handler.job.Context(), request); xerr != nil {
		return nil, xerr
	}
	return objt, nil
}
