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
	labelfactory "github.com/CS-SI/SafeScale/v22/lib/server/resources/factories/label"
	srvutils "github.com/CS-SI/SafeScale/v22/lib/server/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
)

// LabelHandler ...
var LabelHandler = handlers.NewTagHandler

// LabelListener is the tag service gRPC server
type LabelListener struct {
	protocol.UnimplementedLabelServiceServer
}

// List the available tags
func (s *LabelListener) List(ctx context.Context, in *protocol.LabelListRequest) (_ *protocol.LabelListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list labels")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "/labels/list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	selectTags := in.GetTags()
	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.label"), "(%v)", selectTags).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := LabelHandler(job)
	list, xerr := handler.List(selectTags)
	if xerr != nil {
		return nil, xerr
	}

	// Map resources.Tag to protocol.Tag
	var outList []*protocol.LabelInspectResponse
	for _, v := range list {
		item, xerr := v.ToProtocol(job.Context(), false)
		if xerr != nil {
			return nil, xerr
		}

		item.Hosts = nil // We do not need Hosts in this response
		outList = append(outList, item)
	}
	out := &protocol.LabelListResponse{Labels: outList}
	return out, nil
}

// Create a new label/tag
func (s *LabelListener) Create(ctx context.Context, in *protocol.LabelCreateRequest) (_ *protocol.LabelInspectResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot create label")

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
	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/label/%s/create", name))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.label"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewTagHandler(job)
	labelInstance, xerr := handler.Create(name, in.GetHasDefault(), in.GetDefaultValue())
	if xerr != nil {
		return nil, xerr
	}

	tracer.Trace("%s '%s' created", kindToString(in.GetHasDefault()), name)
	return labelInstance.ToProtocol(job.Context(), true)
}

// Delete a Label
func (s *LabelListener) Delete(ctx context.Context, in *protocol.LabelInspectRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete Label")

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
	ref, refLabel := srvutils.GetReference(in.GetLabel())
	if ref == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, xerr := PrepareJob(ctx, in.GetLabel().GetTenantId(), fmt.Sprintf("/label/%s/delete", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.label"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := LabelHandler(job)
	if xerr = handler.Delete(ref); xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Label/Tag %s successfully deleted.", refLabel)
	return empty, nil
}

// Inspect a Label/Tag
func (s *LabelListener) Inspect(ctx context.Context, in *protocol.LabelInspectRequest) (_ *protocol.LabelInspectResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect label")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	ref, refLabel := srvutils.GetReference(in.GetLabel())
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, xerr := PrepareJob(ctx, in.GetLabel().GetTenantId(), fmt.Sprintf("/label/%s/inspect", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.label"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance, xerr := labelfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return nil, xerr
	}

	istag, xerr := instance.IsTag(ctx)
	if xerr != nil {
		return nil, xerr
	}

	if in.GetIsTag() != istag {
		return nil, fail.NotFoundError("failed to find %s '%s'", kindToString(istag), ref)
	}

	return instance.ToProtocol(job.Context(), true)
}
