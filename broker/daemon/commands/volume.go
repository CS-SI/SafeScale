package commands

import (
	"context"
	"fmt"
	"log"

	pb "github.com/SafeScale/broker"
	services "github.com/SafeScale/broker/daemon/services"
	conv "github.com/SafeScale/broker/utils"
	utils "github.com/SafeScale/broker/utils"
	"github.com/SafeScale/providers/api/VolumeSpeed"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// broker volume create v1 --speed="SSD" --size=2000 (par default HDD, possible SSD, HDD, COLD)
// broker volume attach v1 vm1 --path="/shared/data" --format="xfs" (par default /shared/v1 et ext4)
// broker volume detach v1
// broker volume delete v1
// broker volume inspect v1
// broker volume update v1 --speed="HDD" --size=1000

//VolumeServiceServer is the volume service grps server
type VolumeServiceServer struct{}

//List the available volumes
func (s *VolumeServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.VolumeList, error) {
	log.Printf("Volume List called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}
	service := services.NewVolumeService(currentTenant.client)
	volumes, err := service.List()
	if err != nil {
		return nil, err
	}
	var pbvolumes []*pb.Volume

	// Map api.Volume to pb.Volume
	for _, volume := range volumes {
		pbvolumes = append(pbvolumes, conv.ToPbVolume(volume))
	}
	rv := &pb.VolumeList{Volumes: pbvolumes}
	log.Printf("End Volume List")
	return rv, nil
}

//Create a new volume
func (s *VolumeServiceServer) Create(ctx context.Context, in *pb.VolumeDefinition) (*pb.Volume, error) {
	log.Printf("Create Volume called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := services.NewVolumeService(currentTenant.client)
	vol, err := service.Create(in.GetName(), int(in.GetSize()), VolumeSpeed.Enum(in.GetSpeed()))
	if err != nil {
		return nil, err
	}

	log.Printf("Volume '%s' created: %v", in.GetName(), vol)
	return conv.ToPbVolume(*vol), nil
}

//Attach a volume to a VM and create a mount point
func (s *VolumeServiceServer) Attach(ctx context.Context, in *pb.VolumeAttachment) (*google_protobuf.Empty, error) {
	log.Println("Attach volume called")

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := services.NewVolumeService(currentTenant.client)
	err := service.Attach(in.GetVolume().GetName(), in.GetVM().GetName(), in.GetMountPath(), in.GetFormat())

	if err != nil {
		log.Println(err)
		return nil, err
	}

	return &google_protobuf.Empty{}, nil
}

//Detach a volume from a VM. It umount associated mountpoint
func (s *VolumeServiceServer) Detach(ctx context.Context, in *pb.VolumeDetachment) (*google_protobuf.Empty, error) {
	log.Println("Detach volume called")

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := services.NewVolumeService(currentTenant.client)
	err := service.Detach(in.GetVolume().GetName(), in.GetVM().GetName())

	if err != nil {
		log.Println(err)
		return nil, err
	}

	log.Println(fmt.Sprintf("Volume '%s' detached from '%s'", in.GetVolume().GetName(), in.GetVM().GetName()))
	return &google_protobuf.Empty{}, nil
}

//Delete a volume
func (s *VolumeServiceServer) Delete(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Volume delete called")

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}
	service := services.NewVolumeService(currentTenant.client)
	err := service.Delete(ref)
	if err != nil {
		return nil, err
	}
	log.Printf("Volume '%s' deleted", ref)
	return &google_protobuf.Empty{}, nil
}

//Inspect a volume
func (s *VolumeServiceServer) Inspect(ctx context.Context, in *pb.Reference) (*pb.Volume, error) {
	log.Printf("Inspect Volume called")

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := services.NewVolumeService(currentTenant.client)
	vol, err := service.Get(ref)
	if err != nil {
		return nil, err
	}

	log.Printf("End Inspect volume: '%s'", ref)
	return conv.ToPbVolume(*vol), nil
}
