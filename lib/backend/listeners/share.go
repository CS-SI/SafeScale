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

	srvutils "github.com/CS-SI/SafeScale/v22/lib/backend/common"
	"github.com/CS-SI/SafeScale/v22/lib/backend/handlers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
)

// safescale share create --path="/shared/data" share1 host1
// safescale share delete share1
// safescale share mount --path="/data" share1 host2
// safescale share umount share1 host2
// safescale share list
// safescale share inspect share1

// ShareListener Share service server grpc
type ShareListener struct {
	protocol.UnimplementedShareServiceServer
}

// Create calls share service creation
func (s *ShareListener) Create(inctx context.Context, in *protocol.ShareCreateRequest) (_ *protocol.ShareCreateRequest, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot create share")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	shareName := in.GetName()
	job, xerr := prepareJob(inctx, in.GetHost(), fmt.Sprintf("/share/%s/create", shareName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	sharePath := in.GetPath()
	shareType := in.GetType()
	tracer := debug.NewTracer(ctx, true, "('%s', %s, '%s', %s)", shareName, hostRefLabel, sharePath, shareType).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	// LEGACY: NFSExportOptions of protocol has been deprecated and replaced by OptionsAsString
	if in.OptionsAsString == "" && in.Options != nil {
		in.OptionsAsString = converters.NFSExportOptionsFromProtocolToString(in.Options)
	}

	handler := handlers.NewShareHandler(job)
	shareInstance, xerr := handler.Create(shareName, hostRef, sharePath, in.GetOptionsAsString())
	if xerr != nil {
		return nil, xerr
	}

	out, xerr := shareInstance.ToProtocol(ctx)
	if xerr != nil {
		return nil, xerr
	}

	return out.Share, nil
}

// Delete call share service deletion
func (s *ShareListener) Delete(inctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot delete share")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	shareName := in.GetName()

	job, xerr := prepareJob(inctx, in, fmt.Sprintf("/share/%s/delete", shareName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.share"), "('%s')", shareName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewShareHandler(job)
	return empty, handler.Delete(shareName)
}

// List return the list of all available shares
func (s *ShareListener) List(inctx context.Context, in *protocol.Reference) (_ *protocol.ShareListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list shares")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	job, xerr := prepareJob(inctx, in, "/shares/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.share")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewShareHandler(job)
	shares, xerr := handler.List()
	if xerr != nil {
		return nil, xerr
	}

	var pbshares []*protocol.ShareCreateRequest
	for k, item := range shares {
		for _, share := range item {
			pbshares = append(pbshares, converters.ShareFromPropertyToProtocol(k, share))
		}
	}
	list := &protocol.ShareListResponse{ShareList: pbshares}
	return list, nil
}

// Mount mounts share on a local directory of the given host
func (s *ShareListener) Mount(inctx context.Context, in *protocol.ShareMountRequest) (smd *protocol.ShareMountRequest, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot mount share")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	shareRef, _ := srvutils.GetReference(in.GetShare())

	job, xerr := prepareJob(inctx, in.GetHost(), fmt.Sprintf("/share/%s/host/%s/mount", shareRef, hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	hostPath := in.GetPath()
	shareType := in.GetType()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.share"), "(%s, '%s', '%s', %s)", hostRefLabel, shareRef, hostPath, shareType).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewShareHandler(job)
	mount, xerr := handler.Mount(shareRef, hostRef, hostPath, in.GetWithCache())
	if xerr != nil {
		return nil, xerr
	}

	return converters.ShareMountFromPropertyToProtocol(in.GetShare().GetName(), in.GetHost().GetName(), mount), nil
}

// Unmount unmounts share from the given host
func (s *ShareListener) Unmount(inctx context.Context, in *protocol.ShareMountRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot unmount share")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	shareRef, _ := srvutils.GetReference(in.GetShare())

	job, xerr := prepareJob(inctx, in.GetHost(), fmt.Sprintf("/share/%s/host/%s/unmount", shareRef, hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	hostPath := in.GetPath()
	shareType := in.GetType()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.share"), "(%s, '%s', '%s', %s)", hostRefLabel, shareRef, hostPath, shareType).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewShareHandler(job)
	if xerr = handler.Unmount(shareRef, hostRef); xerr != nil {
		return empty, xerr
	}
	return empty, nil
}

// Inspect shows the detail of a share and all connected clients
func (s *ShareListener) Inspect(inctx context.Context, in *protocol.Reference) (sml *protocol.ShareMountListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot inspect share")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	shareRef, _ := srvutils.GetReference(in)

	job, xerr := prepareJob(inctx, in, fmt.Sprintf("/share/%s/inspect", shareRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.share"), "('%s')", shareRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewShareHandler(job)
	shareInstance, xerr := handler.Inspect(shareRef)
	if xerr != nil {
		return nil, xerr
	}

	// VPL: operations.Host should filter these behavioral differences
	// // DEFENSIVE CODING: this _must not_ happen, but InspectShare has different implementations for each stack, and sometimes mistakes happens, so the test is necessary
	// if shareInstance == nil {
	//	return nil, abstract.ResourceNotFoundError("share", shareRef)
	// }

	return shareInstance.ToProtocol(ctx)
}
