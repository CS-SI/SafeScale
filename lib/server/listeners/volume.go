/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

    "github.com/asaskevich/govalidator"
    googleprotobuf "github.com/golang/protobuf/ptypes/empty"
    "github.com/sirupsen/logrus"

    "github.com/CS-SI/SafeScale/lib/protocol"
    "github.com/CS-SI/SafeScale/lib/server/handlers"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
    srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
)

// safescale volume create v1 --speed="SSD" --size=2000 (par default HDD, possible SSD, HDD, COLD)
// safescale volume attach v1 host1 --path="/shared/data" --format="xfs" (par default /shared/v1 et ext4)
// safescale volume detach v1
// safescale volume delete v1
// safescale volume inspect v1
// safescale volume update v1 --speed="HDD" --size=1000

// FIXME Think about this
// //go:generate mockgen -destination=../mocks/mock_volumeserviceserver.go -package=mocks github.com/CS-SI/SafeScale/lib VolumeServiceServer

// VolumeHandler ...
var VolumeHandler = handlers.NewVolumeHandler

// VolumeListener is the volume service gRPC server
type VolumeListener struct{}

// ErrorList the available volumes
func (s *VolumeListener) List(ctx context.Context, in *protocol.VolumeListRequest) (_ *protocol.VolumeListResponse, err error) {
    defer fail.OnExitConvertToGRPCStatus(&err)
    defer fail.OnExitWrapError(&err, "cannot list volume")

    if s == nil {
        return nil, fail.InvalidInstanceError()
    }
    if in == nil {
        return nil, fail.InvalidParameterError("in", "cannot be nil")
    }
    if ctx == nil {
        return nil, fail.InvalidParameterError("ctx", "cannot be nil")
    }

    ok, err := govalidator.ValidateStruct(in)
    if err == nil {
        if !ok {
            logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
        }
    }

    job, err := PrepareJob(ctx, "", "volume list")
    if err != nil {
        return nil, err
    }
    defer job.Close()
    task := job.GetTask()

    all := in.GetAll()
    tracer := debug.NewTracer(task, true, "(%v)", all).WithStopwatch().Entering()
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
        pbVolume, xerr := v.ToProtocol(task)
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
        return nil, fail.InvalidParameterError("in", "cannot be nil")
    }
    if ctx == nil {
        return nil, fail.InvalidParameterError("ctx", "cannot be nil")
    }

    ok, err := govalidator.ValidateStruct(in)
    if err != nil || !ok {
        logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
    }

    job, xerr := PrepareJob(ctx, "", "volume create")
    if xerr != nil {
        return nil, xerr
    }
    defer job.Close()
    task := job.GetTask()

    name := in.GetName()
    speed := in.GetSpeed()
    size := in.GetSize()
    tracer := debug.NewTracer(task, true, "('%s', %s, %d)", name, speed.String(), size).WithStopwatch().Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&err, tracer.TraceMessage())
    handler := handlers.NewVolumeHandler(job)
    rv, xerr := handler.Create(name, int(size), volumespeed.Enum(speed))
    if xerr != nil {
        return nil, xerr
    }

    tracer.Trace("Volume '%s' created", name)
    return rv.ToProtocol(task)
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
        return empty, fail.InvalidParameterError("in", "cannot be nil")
    }
    if ctx == nil {
        return nil, fail.InvalidParameterError("ctx", "cannot be nil")
    }

    ok, err := govalidator.ValidateStruct(in)
    if err != nil || !ok {
        logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
    }

    volumeRef := srvutils.GetReference(in.GetVolume())
    if volumeRef == "" {
        return empty, fail.InvalidRequestError("neither name nor id given as reference for volume")
    }
    hostRef := srvutils.GetReference(in.GetHost())
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

    job, xerr := PrepareJob(ctx, "", "volume attach")
    if xerr != nil {
        return nil, xerr
    }
    defer job.Close()

    tracer := debug.NewTracer(job.GetTask(), true, "('%s', '%s', '%s', %s, %s)", volumeRef, hostRef, mountPath, filesystem, doNotFormatStr).WithStopwatch().Entering()
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
        return empty, fail.InvalidParameterError("in", "cannot be nil")
    }
    if ctx == nil {
        return empty, fail.InvalidParameterError("ctx", "cannot be nil")
    }

    ok, err := govalidator.ValidateStruct(in)
    if err != nil || !ok {
        logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
    }

    volumeRef := srvutils.GetReference(in.GetVolume())
    if volumeRef == "" {
        return empty, fail.InvalidRequestError("neither name nor id given as reference for volume")
    }
    hostRef := srvutils.GetReference(in.GetHost())
    if hostRef == "" {
        return empty, fail.InvalidRequestError("neither name nor id given as reference for host")
    }

    job, xerr := PrepareJob(ctx, "", "volume detach")
    if xerr != nil {
        return nil, xerr
    }
    defer job.Close()

    tracer := debug.NewTracer(job.GetTask(), true, "('%s', '%s')", volumeRef, hostRef).WithStopwatch().Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&err, tracer.TraceMessage())

    handler := VolumeHandler(job)
    if xerr = handler.Detach(volumeRef, hostRef); xerr != nil {
        return empty, xerr
    }

    tracer.Trace("Volume '%s' successfully detached from '%s'.", volumeRef, hostRef)
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
        return empty, fail.InvalidParameterError("in", "cannot be nil")
    }
    if ctx == nil {
        return empty, fail.InvalidParameterError("ctx", "cannot be nil")
    }
    ref := srvutils.GetReference(in)
    if ref == "" {
        return empty, fail.InvalidRequestError("neither name nor id given as reference")
    }

    if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
        logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
    }

    job, xerr := PrepareJob(ctx, "", "volume delete")
    if xerr != nil {
        return nil, xerr
    }
    defer job.Close()

    tracer := debug.NewTracer(job.GetTask(), true, "('%s')", ref).WithStopwatch().Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&err, tracer.TraceMessage())

    handler := VolumeHandler(job)
    if xerr = handler.Delete(ref); xerr != nil {
        return empty, xerr
    }

    tracer.Trace("Volume '%s' successfully deleted.", ref)
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
        return nil, fail.InvalidParameterError("in", "cannot be nil")
    }
    if ctx == nil {
        return nil, fail.InvalidParameterError("ctx", "cannot be nil")
    }
    ref := srvutils.GetReference(in)
    if ref == "" {
        return nil, fail.InvalidRequestError("neither name nor id given as reference")
    }

    if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
        logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
    }

    job, xerr := PrepareJob(ctx, "", "volume inspect")
    if xerr != nil {
        return nil, xerr
    }
    defer job.Close()
    task := job.GetTask()

    tracer := debug.NewTracer(task, true, "('%s')", ref).WithStopwatch().Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&err, tracer.TraceMessage())

    handler := VolumeHandler(job)
    rv, xerr := handler.Inspect(ref)
    if xerr != nil {
        return nil, xerr
    }

    return rv.ToProtocol(task)
}
