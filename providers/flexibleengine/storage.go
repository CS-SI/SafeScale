package flexibleengine

import (
	"fmt"

	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/providers/api/VolumeSpeed"
	"github.com/SafeScale/providers/api/VolumeState"
	"github.com/SafeScale/providers/aws/s3"

	v2_vol "github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"

	awss3 "github.com/aws/aws-sdk-go/service/s3"
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
	vol, err := v2_vol.Create(client.Volume, opts).Extract()
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

/*
func (client *Client) containerFixUrl(uri string) (*string, error) {
	u, err := url.Parse(client.Container.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("Failed to fix Object Storage URL: %s", errorString(err))
	}
	url := u.Scheme + "://" + u.Hostname() + uri
	return &url, nil
}
*/

//CreateContainer creates an object container
func (client *Client) CreateContainer(name string) error {
	return s3.CreateContainer(awss3.New(client.S3Session), name, client.Opts.Region)
}

//DeleteContainer deletes an object container
func (client *Client) DeleteContainer(name string) error {
	return s3.DeleteContainer(awss3.New(client.S3Session), name)
}

//ListContainers list object containers
func (client *Client) ListContainers() ([]string, error) {
	return s3.ListContainers(awss3.New(client.S3Session))
}

//PutObject put an object into an object container
func (client *Client) PutObject(container string, obj api.Object) error {
	return s3.PutObject(awss3.New(client.S3Session), container, obj)
}

//UpdateObjectMetadata update an object into an object container
func (client *Client) UpdateObjectMetadata(container string, obj api.Object) error {
	return s3.UpdateObjectMetadata(awss3.New(client.S3Session), container, obj)
}

//GetObject get object content from an object container
func (client *Client) GetObject(container string, name string, ranges []api.Range) (*api.Object, error) {
	return s3.GetObject(awss3.New(client.S3Session), container, name, ranges)
}

//GetObjectMetadata get  object metadata from an object container
func (client *Client) GetObjectMetadata(container string, name string) (*api.Object, error) {
	return s3.GetObjectMetadata(awss3.New(client.S3Session), container, name)
}

//ListObjects list objects of a container
func (client *Client) ListObjects(container string, filter api.ObjectFilter) ([]string, error) {
	return s3.ListObjects(awss3.New(client.S3Session), container, filter)
}

//CopyObject copies an object
func (client *Client) CopyObject(containerSrc, objectSrc, objectDst string) error {
	return s3.CopyObject(awss3.New(client.S3Session), containerSrc, objectSrc, objectDst)
}

//DeleteObject deleta an object from a container
func (client *Client) DeleteObject(container, object string) error {
	return s3.DeleteObject(awss3.New(client.S3Session), container, object)
}
