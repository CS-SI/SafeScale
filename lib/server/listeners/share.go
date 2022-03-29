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

	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	"github.com/CS-SI/SafeScale/v21/lib/server/handlers"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	hostfactory "github.com/CS-SI/SafeScale/v21/lib/server/resources/factories/host"
	sharefactory "github.com/CS-SI/SafeScale/v21/lib/server/resources/factories/share"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/v21/lib/server/utils"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
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
func (s *ShareListener) Create(ctx context.Context, in *protocol.ShareDefinition) (_ *protocol.ShareDefinition, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot create share")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	shareName := in.GetName()
	job, xerr := PrepareJob(ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/share/%s/create", shareName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	sharePath := in.GetPath()
	shareType := in.GetType()
	tracer := debug.NewTracer(job.Task(), true, "('%s', %s, '%s', %s)", shareName, hostRefLabel, sharePath, shareType).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	// LEGACY: NFSExportOptions of protocol has been deprecated and replaced by OptionsAsString
	if in.OptionsAsString == "" && in.Options != nil {
		in.OptionsAsString = converters.NFSExportOptionsFromProtocolToString(in.Options)
	}
	svc := job.Service()
	rh, xerr := hostfactory.Load(job.Context(), svc, hostRef)
	if xerr != nil {
		return nil, xerr
	}

	shareInstance, xerr := sharefactory.New(svc)
	if xerr != nil {
		return nil, xerr
	}

	xerr = shareInstance.Create(job.Context(), shareName, rh, sharePath, in.OptionsAsString)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		issue := shareInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	out, xerr := shareInstance.ToProtocol(job.Context())
	if xerr != nil {
		return nil, xerr
	}

	return out.Share, nil
}

// Delete call share service deletion
func (s *ShareListener) Delete(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete share")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}

	shareName := in.GetName()
	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/share/%s/delete", shareName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.share"), "('%s')", shareName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	shareInstance, xerr := sharefactory.Load(job.Context(), job.Service(), shareName)
	if xerr != nil {
		return empty, xerr
	}

	defer func() {
		issue := shareInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	if xerr = shareInstance.Delete(job.Context()); xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// List return the list of all available shares
func (s *ShareListener) List(ctx context.Context, in *protocol.Reference) (_ *protocol.ShareList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list shares")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "/shares/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.share")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewShareHandler(job)
	shares, xerr := handler.List()
	if xerr != nil {
		return nil, xerr
	}

	var pbshares []*protocol.ShareDefinition
	for k, item := range shares {
		for _, share := range item {
			pbshares = append(pbshares, converters.ShareFromPropertyToProtocol(k, share))
		}
	}
	list := &protocol.ShareList{ShareList: pbshares}
	return list, nil
}

// Mount mounts share on a local directory of the given host
func (s *ShareListener) Mount(ctx context.Context, in *protocol.ShareMountDefinition) (smd *protocol.ShareMountDefinition, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot mount share")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	shareRef, _ := srvutils.GetReference(in.GetShare())
	job, xerr := PrepareJob(ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/share/%s/host/%s/mount", shareRef, hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	hostPath := in.GetPath()
	shareType := in.GetType()
	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.share"), "(%s, '%s', '%s', %s)", hostRefLabel, shareRef, hostPath, shareType).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewShareHandler(job)
	mount, xerr := handler.Mount(shareRef, hostRef, hostPath, in.GetWithCache())
	if xerr != nil {
		return nil, xerr
	}

	return converters.ShareMountFromPropertyToProtocol(in.GetShare().GetName(), in.GetHost().GetName(), mount), nil
}

// Unmount unmounts share from the given host
func (s *ShareListener) Unmount(ctx context.Context, in *protocol.ShareMountDefinition) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot unmount share")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	shareRef, _ := srvutils.GetReference(in.GetShare())
	job, xerr := PrepareJob(ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/share/%s/host/%s/unmount", shareRef, hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	hostPath := in.GetPath()
	shareType := in.GetType()
	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.share"), "(%s, '%s', '%s', %s)", hostRefLabel, shareRef, hostPath, shareType).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewShareHandler(job)
	if xerr = handler.Unmount(shareRef, hostRef); xerr != nil {
		return empty, xerr
	}
	return empty, nil
}

// Inspect shows the detail of a share and all connected clients
func (s *ShareListener) Inspect(ctx context.Context, in *protocol.Reference) (sml *protocol.ShareMountList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect share")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	shareRef, _ := srvutils.GetReference(in)
	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/share/%s/inspect", shareRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	task := job.Task()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.share"), "('%s')", shareRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewShareHandler(job)
	shareInstance, xerr := handler.Inspect(shareRef)
	if xerr != nil {
		return nil, xerr
	}

	// DEFENSIVE CODING: this _must not_ happen, but InspectHost has different implementations for each stack, and sometimes mistakes happens, so the test is necessary
	if shareInstance == nil {
		return nil, abstract.ResourceNotFoundError("share", shareRef)
	}

	defer func() {
		issue := shareInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	return shareInstance.ToProtocol(job.Context())
}
