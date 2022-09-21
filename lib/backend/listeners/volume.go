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

	"github.com/CS-SI/SafeScale/v22/lib/backend/handlers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	srvutils "github.com/CS-SI/SafeScale/v22/lib/backend/utils"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
)

// safescale volume create v1 --speed="Ssd" --size=2000 (par default Hdd, possible Ssd, Hdd, Cold)
// safescale volume attach v1 host1 --path="/shared/data" --format="xfs" (par default /shared/v1 et ext4)
// safescale volume detach v1
// safescale volume delete v1
// safescale volume inspect v1
// safescale volume update v1 --speed="Hdd" --size=1000

// VolumeHandler ...
var VolumeHandler = handlers.NewVolumeHandler

// VolumeListener is the volume service gRPC server
type VolumeListener struct {
	protocol.UnimplementedVolumeServiceServer
}

// List the available volumes
func (s *VolumeListener) List(inctx context.Context, in *protocol.VolumeListRequest) (_ *protocol.VolumeListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list volume")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	scope := extractScopeFromProtocol(in, "/volumes/list")
	job, err := prepareJob(inctx, scope)
	if err != nil {
		return nil, err
	}
	defer job.Close()

	all := in.GetAll()
	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.volume"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := VolumeHandler(job)
	volumes, xerr := handler.List(in.GetAll())
	if xerr != nil {
		return nil, xerr
	}

	// Map resources.Volume to protocol.Volume
	var pbvolumes []*protocol.VolumeInspectResponse
	for _, v := range volumes {
		pbVolume, xerr := v.ToProtocol(ctx)
		if xerr != nil {
			return nil, xerr
		}

		pbvolumes = append(pbvolumes, pbVolume)
	}
	rv := &protocol.VolumeListResponse{Volumes: pbvolumes}
	return rv, nil
}

// Create a new volume
func (s *VolumeListener) Create(inctx context.Context, in *protocol.VolumeCreateRequest) (_ *protocol.VolumeInspectResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot create volume")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	name := in.GetName()
	scope := extractScopeFromProtocol(in, fmt.Sprintf("/volume/%s/create", name))
	job, xerr := prepareJob(inctx, scope)
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	speed := in.GetSpeed()
	size := in.GetSize()
	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.volume"), "('%s', %s, %d)", name, speed.String(), size).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewVolumeHandler(job)
	volumeInstance, xerr := handler.Create(name, int(size), volumespeed.Enum(speed))
	if xerr != nil {
		return nil, xerr
	}

	return volumeInstance.ToProtocol(ctx)
}

// Attach a volume to a host and create a mount point
func (s *VolumeListener) Attach(inctx context.Context, in *protocol.VolumeAttachmentRequest) (_ *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot attach volume")

	empty := &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	volumeRef, volumeRefLabel := srvutils.GetReference(in.GetVolume())
	if volumeRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for volume")
	}
	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for host")
	}
	mountPath := in.GetMountPath()

	filesystem := in.GetFormat()
	doNotFormat := in.DoNotFormat
	doNotMount := in.DoNotMount

	var doNotFormatStr string
	if doNotFormat {
		doNotFormatStr = "NOFORMAT"
	} else {
		doNotFormatStr = "FORMAT"
	}

	scope := extractScopeFromProtocol(in.GetVolume(), fmt.Sprintf("/volume/%s/host/%s/attach", volumeRef, hostRef))
	job, xerr := prepareJob(inctx, scope)
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.volume"), "(%s, %s, '%s', %s, %s)", volumeRefLabel, hostRefLabel, mountPath, filesystem, doNotFormatStr).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := VolumeHandler(job)
	if xerr = handler.Attach(volumeRef, hostRef, mountPath, filesystem, doNotFormat, doNotMount); xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// Detach a volume from a host. It umount associated mountpoint
func (s *VolumeListener) Detach(inctx context.Context, in *protocol.VolumeDetachmentRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot detach volume")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}

	volumeRef, volumeRefLabel := srvutils.GetReference(in.GetVolume())
	if volumeRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for volume")
	}
	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for host")
	}

	scope := extractScopeFromProtocol(in.GetVolume(), fmt.Sprintf("/volume/%s/host/%s/detach", volumeRef, hostRef))
	job, xerr := prepareJob(inctx, scope)
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.volume"), "(%s, %s)", volumeRefLabel, hostRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := VolumeHandler(job)
	if xerr = handler.Detach(volumeRef, hostRef); xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Volume %s successfully detached from %s.", volumeRefLabel, hostRefLabel)
	return empty, nil
}

// Delete a volume
func (s *VolumeListener) Delete(inctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot delete volume")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}
	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference")
	}

	scope := extractScopeFromProtocol(in, fmt.Sprintf("/volume/%s/delete", ref))
	job, xerr := prepareJob(inctx, scope)
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, true, "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := VolumeHandler(job)
	if xerr = handler.Delete(ref); xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Volume %s successfully deleted.", refLabel)
	return empty, nil
}

// Inspect a volume
func (s *VolumeListener) Inspect(inctx context.Context, in *protocol.Reference) (_ *protocol.VolumeInspectResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot inspect volume")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	scope := extractScopeFromProtocol(in, fmt.Sprintf("/volume/%s/inspect", ref))
	job, xerr := prepareJob(inctx, scope)
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.volume"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewVolumeHandler(job)
	volumeInstance, xerr := handler.Inspect(ref)
	if xerr != nil {
		return nil, xerr
	}

	return volumeInstance.ToProtocol(ctx)
}
