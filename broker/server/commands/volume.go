/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package commands

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/server/services"
	"github.com/CS-SI/SafeScale/broker/utils"
	conv "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
)

// broker volume create v1 --speed="SSD" --size=2000 (par default HDD, possible SSD, HDD, COLD)
// broker volume attach v1 host1 --path="/shared/data" --format="xfs" (par default /shared/v1 et ext4)
// broker volume detach v1
// broker volume delete v1
// broker volume inspect v1
// broker volume update v1 --speed="HDD" --size=1000

// VolumeServiceServer is the volume service grps server
type VolumeServiceServer struct{}

// VolumeServiceCreator is the function tu use to create a VolumeService instance
var VolumeServiceCreator = services.NewVolumeService

// List the available volumes
func (s *VolumeServiceServer) List(ctx context.Context, in *pb.VolumeListRequest) (*pb.VolumeList, error) {
	log.Printf("Volume List called")
	tenant := GetCurrentTenant()
	if tenant == nil {
		return nil, fmt.Errorf("Cannot list volumes : No tenant set")
	}
	service := VolumeServiceCreator(providers.FromClient(tenant.Client))
	volumes, err := service.List(in.GetAll())
	if err != nil {
		return nil, err
	}
	var pbvolumes []*pb.Volume

	// Map api.Volume to pb.Volume
	for _, volume := range volumes {
		pbvolumes = append(pbvolumes, conv.ToPBVolume(&volume))
	}
	rv := &pb.VolumeList{Volumes: pbvolumes}
	return rv, nil
}

// Create a new volume
func (s *VolumeServiceServer) Create(ctx context.Context, in *pb.VolumeDefinition) (*pb.Volume, error) {
	log.Printf("Create Volume called '%s'", in.Name)
	tenant := GetCurrentTenant()
	if tenant == nil {
		return nil, fmt.Errorf("Cannot create volume : No tenant set")
	}

	service := VolumeServiceCreator(providers.FromClient(tenant.Client))
	vol, err := service.Create(in.GetName(), int(in.GetSize()), VolumeSpeed.Enum(in.GetSpeed()))
	if err != nil {
		return nil, err
	}

	log.Printf("Volume '%s' created: %v", in.GetName(), vol)
	return conv.ToPBVolume(vol), nil
}

// Attach a volume to an host and create a mount point
func (s *VolumeServiceServer) Attach(ctx context.Context, in *pb.VolumeAttachment) (*google_protobuf.Empty, error) {
	log.Printf("Attach volume called '%s', '%s'", in.Host.Name, in.MountPath)

	tenant := GetCurrentTenant()
	if tenant == nil {
		return nil, fmt.Errorf("Cannot attach volume : No tenant set")
	}

	service := services.NewVolumeService(providers.FromClient(currentTenant.Client))
	err := service.Attach(in.GetVolume().GetName(), in.GetHost().GetName(), in.GetMountPath(), in.GetFormat())

	if err != nil {
		return nil, err
	}

	return &google_protobuf.Empty{}, nil
}

// Detach a volume from an host. It umount associated mountpoint
func (s *VolumeServiceServer) Detach(ctx context.Context, in *pb.VolumeDetachment) (*google_protobuf.Empty, error) {
	log.Printf("Detach volume called '%s', '%s'", in.Host.Name, in.Volume.Name)

	tenant := GetCurrentTenant()
	if tenant == nil {
		return nil, fmt.Errorf("Cannot detach volume : No tenant set")
	}

	service := services.NewVolumeService(providers.FromClient(currentTenant.Client))
	err := service.Detach(in.GetVolume().GetName(), in.GetHost().GetName())

	if err != nil {
		return nil, err
	}

	log.Println(fmt.Sprintf("Volume '%s' detached from '%s'", in.GetVolume().GetName(), in.GetHost().GetName()))
	return &google_protobuf.Empty{}, nil
}

// Delete a volume
func (s *VolumeServiceServer) Delete(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Volume delete called '%s'", in.Name)

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Cannot delete volume: neither name nor id given as reference")
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		return nil, fmt.Errorf("cannot delete volume '%s': no tenant set", ref)
	}
	service := services.NewVolumeService(providers.FromClient(currentTenant.Client))
	err := service.Delete(ref)
	if err != nil {
		return &google_protobuf.Empty{}, fmt.Errorf("Can't delete volume '%s': %s", ref, err.Error())
	}
	log.Printf("Volume '%s' deleted", ref)
	return &google_protobuf.Empty{}, nil
}

// Inspect a volume
func (s *VolumeServiceServer) Inspect(ctx context.Context, in *pb.Reference) (*pb.VolumeInfo, error) {
	log.Printf("Inspect Volume called '%s'", in.Name)

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("cannot inspect volume: neither name nor id given as reference")
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		return nil, fmt.Errorf("cannot inspect volume: No tenant set")
	}

	service := services.NewVolumeService(providers.FromClient(currentTenant.Client))
	volume, mounts, err := service.Inspect(ref)
	if err != nil {
		return nil, err
	}
	if volume == nil {
		return nil, fmt.Errorf("cannot inspect volume: no volume '%s' found", ref)
	}

	return conv.ToPBVolumeInfo(volume, mounts), nil
}
