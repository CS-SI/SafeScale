package commands

import (
	"fmt"

	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
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
