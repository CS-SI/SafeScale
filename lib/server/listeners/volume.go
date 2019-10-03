/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeSpeed"
	conv "github.com/CS-SI/SafeScale/lib/server/utils"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
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

// VolumeListener is the volume service grps server
type VolumeListener struct{}

// List the available volumes
func (s *VolumeListener) List(ctx context.Context, in *pb.VolumeListRequest) (_ *pb.VolumeList, err error) {
	if s == nil {
		return nil, status.Errorf(codes.InvalidArgument, scerr.InvalidInstanceError().Error())
	}
	if in == nil {
		return nil, status.Errorf(codes.InvalidArgument, scerr.InvalidParameterError("in", "can't be nil").Error())
	}
	all := in.GetAll()

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("(%v)", all), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// FIXME: handle error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Volumes List"); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		// log.Info("Can't list volumes: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "can't list volumes: no tenant set")
	}

	handler := VolumeHandler(tenant.Service)
	volumes, err := handler.List(ctx, in.GetAll())
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	// Map resources.Volume to pb.Volume
	var pbvolumes []*pb.Volume
	for _, volume := range volumes {
		pbvolumes = append(pbvolumes, conv.ToPBVolume(&volume))
	}
	rv := &pb.VolumeList{Volumes: pbvolumes}
	return rv, nil
}

// Create a new volume
func (s *VolumeListener) Create(ctx context.Context, in *pb.VolumeDefinition) (_ *pb.Volume, err error) {
	if s == nil {
		return nil, status.Errorf(codes.InvalidArgument, scerr.InvalidInstanceError().Error())
	}
	if in == nil {
		return nil, status.Errorf(codes.InvalidArgument, scerr.InvalidParameterError("in", "can't be nil").Error())
	}
	name := in.GetName()
	speed := in.GetSpeed()
	size := in.GetSize()
	// FIXME: validate parameters

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', %s, %d)", name, speed.String(), size), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Volumes Create "+in.GetName()); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, fmt.Errorf("failed to register the process : %s", err.Error()).Error())
	}
	defer srvutils.JobDeregister(ctx)

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't create volumes: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "can't create volume: no tenant set")
	}

	handler := VolumeHandler(tenant.Service)
	vol, err := handler.Create(ctx, name, int(size), VolumeSpeed.Enum(speed))
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	log.Infof("Volume '%s' created", name)
	return conv.ToPBVolume(vol), nil
}

// Attach a volume to an host and create a mount point
func (s *VolumeListener) Attach(ctx context.Context, in *pb.VolumeAttachment) (_ *google_protobuf.Empty, err error) {
	empty := &google_protobuf.Empty{}
	if s == nil {
		return empty, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	if in == nil {
		return empty, status.Errorf(codes.InvalidArgument, scerr.InvalidParameterError("in", "can't be nil").Error())
	}
	volumeRef := srvutils.GetReference(in.GetVolume())
	if volumeRef == "" {
		return empty, status.Errorf(codes.InvalidArgument, "can't attach volume: neither name nor id given as reference for volume")
	}
	hostRef := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return empty, status.Errorf(codes.InvalidArgument, "can't attach volume: neither name nor id given as reference for host")
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

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s', '%s', %s, %s)", volumeRef, hostRef, mountPath, filesystem, doNotFormatStr), true)
	defer tracer.WithStopwatch().GoingIn().OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	err = srvutils.JobRegister(ctx, cancelFunc, "Volumes Attach "+volumeRef+" to host "+hostRef)
	if err != nil {
		return empty, status.Errorf(codes.FailedPrecondition, fmt.Errorf("failed to register the process : %s", err.Error()).Error())
	}
	defer srvutils.JobDeregister(ctx)

	tenant := GetCurrentTenant()
	if tenant == nil {
		// log.Info("Can't attach volumes: no tenant set")
		return empty, status.Errorf(codes.FailedPrecondition, "can't attach volume: no tenant set")
	}

	handler := VolumeHandler(tenant.Service)
	err = handler.Attach(ctx, volumeRef, hostRef, mountPath, filesystem, doNotFormat)
	if err != nil {
		return empty, status.Errorf(codes.Internal, err.Error())
	}

	return empty, nil
}

// Detach a volume from an host. It umount associated mountpoint
func (s *VolumeListener) Detach(ctx context.Context, in *pb.VolumeDetachment) (_ *google_protobuf.Empty, err error) {
	empty := &google_protobuf.Empty{}
	if s == nil {
		return empty, status.Errorf(codes.InvalidArgument, scerr.InvalidInstanceError().Error())
	}
	if in == nil {
		return empty, status.Errorf(codes.InvalidArgument, scerr.InvalidParameterError("in", "can't be nil").Error())
	}
	volumeRef := srvutils.GetReference(in.GetVolume())
	if volumeRef == "" {
		return empty, status.Errorf(codes.InvalidArgument, "can't detach volume: neither name nor id given as reference for volume")
	}
	hostRef := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return empty, status.Errorf(codes.InvalidArgument, "can't detach volume: neither name nor id given as reference for host")
	}

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s')", volumeRef, hostRef), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// FIXME: handle error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Volume detach "+volumeRef+" from host "+hostRef); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		// log.Info("Can't detach volumes: no tenant set")
		return empty, status.Errorf(codes.FailedPrecondition, "can't detach volume: no tenant set")
	}

	handler := VolumeHandler(tenant.Service)
	err = handler.Detach(ctx, volumeRef, hostRef)
	if err != nil {
		return empty, status.Errorf(codes.Internal, err.Error())
	}

	log.Infof("Volume '%s' detached from '%s'", volumeRef, hostRef)
	return empty, nil
}

// Delete a volume
func (s *VolumeListener) Delete(ctx context.Context, in *pb.Reference) (_ *google_protobuf.Empty, err error) {
	empty := &google_protobuf.Empty{}
	if s == nil {
		return empty, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	if in == nil {
		return empty, status.Errorf(codes.InvalidArgument, scerr.InvalidParameterError("in", "can't be nil").Error())
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, status.Errorf(codes.InvalidArgument, "can't delete volume: neither name nor id given as reference")
	}

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// FIXME: handle error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Volume delete "+in.GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't delete volumes: no tenant set")
		return empty, status.Errorf(codes.FailedPrecondition, "can't delete volume: no tenant set")
	}

	handler := VolumeHandler(tenant.Service)
	err = handler.Delete(ctx, ref)
	if err != nil {
		return empty, status.Errorf(codes.Internal, fmt.Sprintf("can't delete volume '%s': %s", ref, err.Error()))
	}
	log.Infof("Volume '%s' successfully deleted.", ref)
	return empty, nil
}

// Inspect a volume
func (s *VolumeListener) Inspect(ctx context.Context, in *pb.Reference) (_ *pb.VolumeInfo, err error) {
	if s == nil {
		return nil, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	if in == nil {
		return nil, status.Errorf(codes.InvalidArgument, scerr.InvalidParameterError("in", "can't be nil").Error())
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return nil, status.Errorf(codes.InvalidArgument, "can't inspect volume: neither name nor id given as reference")
	}

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// FIXME: handle error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Volume Inspect "+in.GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		// log.Info("Can't inspect volumes: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "can't inspect volume: no tenant set")
	}

	handler := VolumeHandler(tenant.Service)
	volume, mounts, err := handler.Inspect(ctx, ref)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if volume == nil {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("can't inspect volume '%s': volume not found", ref))
	}

	return conv.ToPBVolumeInfo(volume, mounts), nil
}
