package commands

import (
	"context"
	"fmt"
	"log"

	pb "github.com/SafeScale/broker"
	conv "github.com/SafeScale/broker/utils"
	utils "github.com/SafeScale/broker/utils"
	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/providers/api/VolumeSpeed"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// broker volume create v1 --speed="SSD" --size=2000 (par default HDD, possible SSD, HDD, COLD)
// broker volume attach v1 vm1 --path="/shared/data" --format="xfs" (par default /shared/v1 et ext4)
// broker volume detach v1
// broker volume delete v1
// broker volume inspect v1
// broker volume update v1 --speed="HDD" --size=1000

//VolumeAPI defines API to manipulate VMs
type VolumeAPI interface {
	Delete(ref string) error
	Get(ref string) (*api.Volume, error)
	List() ([]api.Volume, error)
	Create(name string, size int, speed VolumeSpeed.Enum) (*api.Volume, error)
	Attach(volume string, vm string, path string, format string) error
	Detach(volume string, vm string) error
}

//NewVolumeService creates a Volume service
func NewVolumeService(api api.ClientAPI) VolumeAPI {
	return &VolumeService{
		provider: providers.FromClient(api),
	}
}

//VolumeService volume service
type VolumeService struct {
	provider *providers.Service
}

//List returns the network list
func (srv *VolumeService) List() ([]api.Volume, error) {
	return srv.provider.ListVolumes()
}

//Delete deletes volume referenced by ref
func (srv *VolumeService) Delete(ref string) error {
	vol, err := srv.Get(ref)
	if err != nil {
		return fmt.Errorf("Volume '%s' does not exists", ref)
	}
	return srv.provider.DeleteVolume(vol.ID)
}

//Get returns the volume identified by ref, ref can be the name or the id
func (srv *VolumeService) Get(ref string) (*api.Volume, error) {
	volumes, err := srv.List()
	if err != nil {
		return nil, err
	}
	for _, volume := range volumes {
		if volume.ID == ref || volume.Name == ref {
			return &volume, nil
		}
	}
	return nil, fmt.Errorf("Volume '%s' does not exists", ref)
}

// Create a volume
func (srv *VolumeService) Create(name string, size int, speed VolumeSpeed.Enum) (*api.Volume, error) {
	volume, err := srv.provider.CreateVolume(api.VolumeRequest{
		Name:  name,
		Size:  size,
		Speed: speed,
	})
	if err != nil {
		return nil, err
	}
	return volume, nil
}

// Attach a volume to a VM
func (srv *VolumeService) Attach(volumename string, vmname string, path string, format string) error {
	// Get volume ID
	volume, err := srv.Get(volumename)
	if err != nil {
		return fmt.Errorf("No volume found with name or id '%s'", volumename)
	}

	// Get VM ID
	vmService := NewVMService(srv.provider)
	vm, err := vmService.Get(vmname)
	if err != nil {
		return fmt.Errorf("No VM found with name or id '%s'", vmname)
	}

	volatt, err := srv.provider.CreateVolumeAttachment(api.VolumeAttachmentRequest{
		Name:     fmt.Sprintf("%s-%s", volume.Name, vm.Name),
		ServerID: vm.ID,
		VolumeID: volume.ID,
	})
	if err != nil {
		// TODO Use more explicit error
		return err
	}

	// Create mount point
	mountPoint := path
	if path == api.DefaultVolumeMountPoint {
		mountPoint = api.DefaultVolumeMountPoint + volume.Name
	}
	data := struct {
		Device     string
		Fsformat   string
		MountPoint string
	}{
		Device:     volatt.Device,
		Fsformat:   format,
		MountPoint: mountPoint,
	}
	scriptCmd, err := getBoxContent("mount_block_device.sh", data)
	if err != nil {
		// TODO Use more explicit error
		srv.Detach(volumename, vmname)
		return err
	}

	// retrieve ssh config to perform some commands
	ssh, err := srv.provider.GetSSHConfig(vm.ID)
	if err != nil {
		// TODO Use more explicit error
		srv.Detach(volumename, vmname)
		return err
	}

	cmd, err := ssh.SudoCommand(scriptCmd)
	if err != nil {
		// TODO Use more explicit error
		srv.Detach(volumename, vmname)
		return err
	}
	_, err = cmd.Output()
	if err != nil {
		srv.Detach(volumename, vmname)
		return err
	}

	return nil
}

//Detach detach the volume identified by ref, ref can be the name or the id
func (srv *VolumeService) Detach(volumename string, vmname string) error {
	vol, err := srv.Get(volumename)
	if err != nil {
		return fmt.Errorf("No volume found with name or id '%s'", volumename)
	}

	// Get VM ID
	vmService := NewVMService(srv.provider)
	vm, err := vmService.Get(vmname)
	if err != nil {
		return fmt.Errorf("No VM found with name or id '%s'", vmname)
	}

	volatt, err := srv.provider.GetVolumeAttachment(vm.ID, vol.ID)
	if err != nil {
		return fmt.Errorf("Error getting volume attachment: %s", err)
	}

	// Use script to:
	//  - umount volume
	//  - remove mount directory
	//  - update fstab (remove line with device)
	// TODO Put all rice-box stuff in a dedicated method to return only formatted cmd to use in ssh cmd
	data := struct {
		Device string
	}{
		Device: volatt.Device,
	}
	scriptCmd, err := getBoxContent("umount_block_device.sh", data)
	if err != nil {
		// TODO Use more explicit error
		return err
	}

	// retrieve ssh config to perform some commands
	ssh, err := srv.provider.GetSSHConfig(vm.ID)
	if err != nil {
		// TODO Use more explicit error
		return err
	}

	cmd, err := ssh.SudoCommand(scriptCmd)
	if err != nil {
		// TODO Use more explicit error
		return err
	}
	_, err = cmd.Output()
	if err != nil {
		return err
	}

	// Finaly delete the attachment
	return srv.provider.DeleteVolumeAttachment(vm.ID, vol.ID)
}

//VolumeServiceServer is the volume service grps server
type VolumeServiceServer struct{}

//List the available volumes
func (s *VolumeServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.VolumeList, error) {
	log.Printf("Volume List called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}
	service := NewVolumeService(currentTenant.client)
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

	service := NewVolumeService(currentTenant.client)
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

	service := NewVolumeService(currentTenant.client)
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

	service := NewVolumeService(currentTenant.client)
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
	service := NewVolumeService(currentTenant.client)
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

	service := NewVolumeService(currentTenant.client)
	vol, err := service.Get(ref)
	if err != nil {
		return nil, err
	}

	log.Printf("End Inspect volume: '%s'", ref)
	return conv.ToPbVolume(*vol), nil
}
