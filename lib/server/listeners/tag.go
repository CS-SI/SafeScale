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

package listeners

import (
	"context"
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/handlers"
	tagfactory "github.com/CS-SI/SafeScale/v22/lib/server/resources/factories/tag"
	srvutils "github.com/CS-SI/SafeScale/v22/lib/server/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
)

// TagHandler ...
var TagHandler = handlers.NewTagHandler

// TagListener is the tag service gRPC server
type TagListener struct {
	protocol.UnimplementedTagServiceServer
}

// List the available tags
func (s *TagListener) List(ctx context.Context, in *protocol.TagListRequest) (_ *protocol.TagListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list tag")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "/tags/list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	all := in.GetAll()
	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.tag"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := TagHandler(job)
	tags, xerr := handler.List(in.GetAll())
	if xerr != nil {
		return nil, xerr
	}

	// Map resources.Tag to protocol.Tag
	var pbtags []*protocol.TagInspectResponse
	for _, v := range tags {
		pbTag, xerr := v.ToProtocol(job.Context())
		if xerr != nil {
			return nil, xerr
		}

		pbtags = append(pbtags, pbTag)
	}
	rv := &protocol.TagListResponse{Tags: pbtags}
	return rv, nil
}

// Create a new tag
func (s *TagListener) Create(ctx context.Context, in *protocol.TagCreateRequest) (_ *protocol.TagInspectResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot create tag")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	name := in.GetName()
	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/tag/%s/create", name))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.tag"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())
	handler := handlers.NewTagHandler(job)
	rv, xerr := handler.Create(name)
	if xerr != nil {
		return nil, xerr
	}

	tracer.Trace("Tag '%s' created", name)
	return rv.ToProtocol(job.Context())
}

// Delete a tag
func (s *TagListener) Delete(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete tag")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}
	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/tag/%s/delete", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), true, "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := TagHandler(job)
	if xerr = handler.Delete(ref); xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Tag %s successfully deleted.", refLabel)
	return empty, nil
}

// Inspect a tag
func (s *TagListener) Inspect(ctx context.Context, in *protocol.Reference) (_ *protocol.TagInspectResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect tag")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/tag/%s/inspect", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.tag"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	tagInstance, xerr := tagfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return nil, xerr
	}

	return tagInstance.ToProtocol(job.Context())
}
