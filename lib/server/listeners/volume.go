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

package listeners

import (
	"context"
	"fmt"

	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"

	"github.com/asaskevich/govalidator"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
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
func (s *VolumeListener) List(ctx context.Context, in *protocol.VolumeListRequest) (_ *protocol.VolumeListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list volume")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "/volumes/list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	all := in.GetAll()
	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.volume"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := VolumeHandler(job)
	volumes, xerr := handler.List(in.GetAll())
	if xerr != nil {
		return nil, xerr
	}

	// Map resources.Volume to protocol.Volume
	var pbvolumes []*protocol.VolumeInspectResponse
	for _, v := range volumes {
		pbVolume, xerr := v.ToProtocol()
		if xerr != nil {
			return nil, xerr
		}

		pbvolumes = append(pbvolumes, pbVolume)
	}
	rv := &protocol.VolumeListResponse{Volumes: pbvolumes}
	return rv, nil
}

// Create a new volume
func (s *VolumeListener) Create(ctx context.Context, in *protocol.VolumeCreateRequest) (_ *protocol.VolumeInspectResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot create volume")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	name := in.GetName()
	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/volume/%s/create", name))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	speed := in.GetSpeed()
	size := in.GetSize()
	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.volume"), "('%s', %s, %d)", name, speed.String(), size).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())
	handler := handlers.NewVolumeHandler(job)
	rv, xerr := handler.Create(name, int(size), volumespeed.Enum(speed))
	if xerr != nil {
		return nil, xerr
	}

	tracer.Trace("Volume '%s' created", name)
	return rv.ToProtocol()
}

// Attach a volume to an host and create a mount point
func (s *VolumeListener) Attach(ctx context.Context, in *protocol.VolumeAttachmentRequest) (_ *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot attach volume")

	empty := &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
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
	// FIXME: change Format to Filesystem in protobuf
	filesystem := in.GetFormat()
	doNotFormat := in.DoNotFormat

	var doNotFormatStr string
	if doNotFormat {
		doNotFormatStr = "NOFORMAT"
	} else {
		doNotFormatStr = "FORMAT"
	}

	job, xerr := PrepareJob(ctx, in.GetVolume().GetTenantId(), fmt.Sprintf("/volume/%s/host/%s/attach", volumeRef, hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.volume"),
		"(%s, %s, '%s', %s, %s)", volumeRefLabel, hostRefLabel, mountPath, filesystem, doNotFormatStr,
	).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := VolumeHandler(job)
	if xerr = handler.Attach(volumeRef, hostRef, mountPath, filesystem, doNotFormat); xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// Detach a volume from an host. It umount associated mountpoint
func (s *VolumeListener) Detach(ctx context.Context, in *protocol.VolumeDetachmentRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot detach volume")

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

	ok, err := govalidator.ValidateStruct(in)
	if err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	volumeRef, volumeRefLabel := srvutils.GetReference(in.GetVolume())
	if volumeRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for volume")
	}
	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for host")
	}

	job, xerr := PrepareJob(ctx, in.GetVolume().GetTenantId(), fmt.Sprintf("/volume/%s/host/%s/detach", volumeRef, hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.volume"), "(%s, %s)", volumeRefLabel, hostRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := VolumeHandler(job)
	if xerr = handler.Detach(volumeRef, hostRef); xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Volume %s successfully detached from %s.", volumeRefLabel, hostRefLabel)
	return empty, nil
}

// Delete a volume
func (s *VolumeListener) Delete(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete volume")

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

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/volume/%s/delete", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), true, "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := VolumeHandler(job)
	if xerr = handler.Delete(ref); xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Volume %s successfully deleted.", refLabel)
	return empty, nil
}

// Inspect a volume
func (s *VolumeListener) Inspect(ctx context.Context, in *protocol.Reference) (_ *protocol.VolumeInspectResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect volume")

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

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/volume/%s/inspect", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.volume"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := VolumeHandler(job)
	rv, xerr := handler.Inspect(ref)
	if xerr != nil {
		return nil, xerr
	}

	return rv.ToProtocol()
}
