package commands

import (
	"fmt"

	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/providers/api/VolumeSpeed"
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
		return err
	}
	// TODO: finish implementation ie format filessytem and add mount point
	_ = volatt

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

	err = srv.provider.DeleteVolumeAttachment(vm.ID, vol.ID)
	return err
}
