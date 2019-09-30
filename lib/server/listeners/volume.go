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

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/lib/server/utils"
	conv "github.com/CS-SI/SafeScale/lib/server/utils"
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
func (s *VolumeListener) List(ctx context.Context, in *pb.VolumeListRequest) (*pb.VolumeList, error) {
	// defer timing.TimerWithLevel(fmt.Sprintf("server.listeners.VolumeListener::List() called"), log.TraceLevel)()

	if s == nil {
		panic("Calling server.listeners.VolumeListener::List from nil pointer!")
	}
	if in == nil {
		panic("Calling server.listeners.VolumeListener::List with nil parameter!")
	}

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "Volumes List"); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't list volumes: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't list volumes: no tenant set")
	}

	handler := VolumeHandler(tenant.Service)
	volumes, err := handler.List(ctx, in.GetAll())
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, err.Error())
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
func (s *VolumeListener) Create(ctx context.Context, in *pb.VolumeDefinition) (*pb.Volume, error) {
	if s == nil {
		panic("Calling server.listeners.VolumeListener::Create from nil pointer!")
	}
	if in == nil {
		panic("Calling server.listeners.VolumeListener::Create with nil parameter!")
	}

	volumeName := in.GetName()
	// defer timing.TimerWithLevel(fmt.Sprintf("server.listeners.VolumeListener::Create(%s) called", volumeName), log.TraceLevel)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := utils.ProcessRegister(ctx, cancelFunc, "Volumes Create "+in.GetName()); err != nil {
		return nil, fmt.Errorf("failed to register the process : %s", err.Error())
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't create volumes: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't create volume: no tenant set")
	}

	handler := VolumeHandler(tenant.Service)
	volume, err := handler.Create(ctx, volumeName, int(in.GetSize()), VolumeSpeed.Enum(in.GetSpeed()))
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}

	log.Infof("Volume '%s' created: %v", in.GetName(), volume.Name)
	return conv.ToPBVolume(volume), nil
}

// Attach a volume to an host and create a mount point
func (s *VolumeListener) Attach(ctx context.Context, in *pb.VolumeAttachment) (*google_protobuf.Empty, error) {
	if s == nil {
		panic("Calling server.listeners.VolumeListener::Attach from nil pointer!")
	}
	if in == nil {
		panic("Calling server.listeners.VolumeListener::Attach with nil parameter!")
	}

	volumeName := in.GetVolume().GetName()
	hostName := in.GetHost().GetName()

	// defer timing.TimerWithLevel(fmt.Sprintf("server.listeners.VolumeListener::Attach(%s, %s) called", volumeName, hostName), log.TraceLevel)()

	ctx, cancelFunc := context.WithCancel(ctx)
	err := utils.ProcessRegister(ctx, cancelFunc, "Volumes Attach "+volumeName+" to host "+hostName)
	if err != nil {
		return nil, fmt.Errorf("failed to register the process : %s", err.Error())
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't attach volumes: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't attach volume: no tenant set")
	}

	handler := VolumeHandler(tenant.Service)
	err = handler.Attach(ctx, volumeName, hostName, in.GetMountPath(), in.GetFormat(), in.GetDoNotFormat())
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}

	return &google_protobuf.Empty{}, nil
}

// Detach a volume from an host. It umount associated mountpoint
func (s *VolumeListener) Detach(ctx context.Context, in *pb.VolumeDetachment) (*google_protobuf.Empty, error) {
	if s == nil {
		panic("Calling server.listeners.VolumeListener::Detach from nil pointer!")
	}
	if in == nil {
		panic("Calling server.listeners.VolumeListener::Detach with nil parameter!")
	}

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "Volumes Dettach "+in.GetVolume().GetName()+"from host"+in.GetHost().GetName()); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	volumeName := in.GetVolume().GetName()
	hostName := in.GetHost().GetName()
	// defer timing.TimerWithLevel(fmt.Sprintf("server.listeners.VolumeListener::Detach(%s, %s) called", volumeName, hostName), log.TraceLevel)()

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't detach volumes: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't detach volume: no tenant set")
	}

	handler := VolumeHandler(tenant.Service)
	err := handler.Detach(ctx, volumeName, hostName)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}

	log.Println(fmt.Sprintf("Volume '%s' detached from '%s'", volumeName, hostName))
	return &google_protobuf.Empty{}, nil
}

// Delete a volume
func (s *VolumeListener) Delete(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	if s == nil {
		panic("Calling server.listeners.VolumeListener::Delete from nil pointer!")
	}
	if in == nil {
		panic("Calling server.listeners.VolumeListener::Delete with nil parameter!")
	}

	// defer timing.TimerWithLevel(fmt.Sprintf("server.listeners.VolumeListener::Delete(%s) called", in.Name), log.TraceLevel)()

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "Volumes Delete "+in.GetName()); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, grpc.Errorf(codes.InvalidArgument, "can't inspect volume: neither name nor id given as reference")
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't delete volumes: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't delete volume: no tenant set")
	}

	handler := VolumeHandler(tenant.Service)
	err := handler.Delete(ctx, ref)
	if err != nil {
		return &google_protobuf.Empty{}, grpc.Errorf(codes.Internal, fmt.Sprintf("can't delete volume '%s': %s", ref, err.Error()))
	}
	log.Infof("Volume '%s' successfully deleted.", ref)
	return &google_protobuf.Empty{}, nil
}

// Inspect a volume
func (s *VolumeListener) Inspect(ctx context.Context, in *pb.Reference) (*pb.VolumeInfo, error) {
	if s == nil {
		panic("Calling server.listeners.VolumeListener::Inspect from nil pointer!")
	}
	if in == nil {
		panic("Calling server.listeners.VolumeListener::Inspect with nil parameter!")
	}

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "Volume Inspect "+in.GetName()); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, grpc.Errorf(codes.InvalidArgument, "can't inspect volume: neither name nor id given as reference")
	}

	// defer timing.TimerWithLevel(fmt.Sprintf("server.listeners.VolumeListener::Inspect(%s) called", ref), log.TraceLevel)()

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't inspect volumes: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't inspect volume: no tenant set")
	}

	handler := VolumeHandler(tenant.Service)
	volume, mounts, err := handler.Inspect(ctx, ref)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}
	if volume == nil {
		return nil, grpc.Errorf(codes.NotFound, fmt.Sprintf("can't inspect volume '%s': volume not found", ref))
	}

	return conv.ToPBVolumeInfo(volume, mounts), nil
}
