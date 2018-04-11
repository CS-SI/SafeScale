package flexibleengine

import (
	"fmt"

	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/providers/api/VolumeSpeed"
	"github.com/SafeScale/providers/api/VolumeState"

	"github.com/gophercloud/gophercloud/openstack/blockstorage/v1/volumes"
	v2_vol "github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
)

//toVM converts a Volume status returned by the OpenStack driver into VolumeState enum
func toVolumeState(status string) VolumeState.Enum {
	switch status {
	case "creating":
		return VolumeState.CREATING
	case "available":
		return VolumeState.AVAILABLE
	case "attaching":
		return VolumeState.ATTACHING
	case "detaching":
		return VolumeState.DETACHING
	case "in-use":
		return VolumeState.USED
	case "deleting":
		return VolumeState.DELETING
	case "error", "error_deleting", "error_backing-up", "error_restoring", "error_extending":
		return VolumeState.ERROR
	default:
		return VolumeState.OTHER
	}
}

func (client *Client) getVolumeType(speed VolumeSpeed.Enum) string {
	for t, s := range client.Cfg.VolumeSpeeds {
		if s == speed {
			return t
		}
	}
	switch speed {
	case VolumeSpeed.SSD:
		return client.getVolumeType(VolumeSpeed.SSD)
	case VolumeSpeed.HDD:
		return client.getVolumeType(VolumeSpeed.HDD)
	default:
		return ""
	}
}

func (client *Client) getVolumeSpeed(vType string) VolumeSpeed.Enum {
	speed, ok := client.Cfg.VolumeSpeeds[vType]
	if ok {
		return speed
	}
	return VolumeSpeed.HDD
}

//CreateVolume creates a block volume
//- name is the name of the volume
//- size is the size of the volume in GB
//- volumeType is the type of volume to create, if volumeType is empty the driver use a default type
//- imageID is the ID of the image to initialize the volume with
func (client *Client) CreateVolume(request api.VolumeRequest) (*api.Volume, error) {
	return client.ExCreateVolume(request, "")
}

//ExCreateVolume creates a block volume
//- name is the name of the volume
//- size is the size of the volume in GB
//- volumeType is the type of volume to create, if volumeType is empty the driver use a default type
//- imageID is the ID of the image to initialize the volume with
func (client *Client) ExCreateVolume(request api.VolumeRequest, imageID string) (*api.Volume, error) {
	opts := v2_vol.CreateOpts{
		Name:       request.Name,
		Size:       request.Size,
		VolumeType: client.getVolumeType(request.Speed),
		ImageID:    imageID,
	}
	vol, err := volumes.Create(client.Volume, opts).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating volume : %s", errorString(err))
	}
	v := api.Volume{
		ID:    vol.ID,
		Name:  vol.Name,
		Size:  vol.Size,
		Speed: client.getVolumeSpeed(vol.VolumeType),
		State: toVolumeState(vol.Status),
	}
	return &v, nil
}
