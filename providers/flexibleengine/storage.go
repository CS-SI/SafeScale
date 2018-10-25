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

package flexibleengine

import (
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/aws/s3"
	"github.com/CS-SI/SafeScale/providers/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/enums/VolumeState"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/openstack"

	v2_vol "github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"

	awss3 "github.com/aws/aws-sdk-go/service/s3"
)

// CreateVolumeAttachment attaches a volume to an host
//- 'name' of the volume attachment
//- 'volume' to attach
//- 'host' on which the volume is attached
func (client *Client) CreateVolumeAttachment(request api.VolumeAttachmentRequest) (*api.VolumeAttachment, error) {
	// Ensure volume and host are known
	mtdVol, err := metadata.LoadVolume(providers.FromClient(client), request.VolumeID)
	if err != nil {
		return nil, err
	}
	if mtdVol == nil {
		return nil, errors.Wrap(providers.ResourceNotFoundError("volume", request.VolumeID), "Cannot create volume attachment")
	}
	_volumeAttachment, err := mtdVol.GetAttachment()
	if err != nil {
		return nil, err
	}
	if _volumeAttachment != nil && _volumeAttachment.ID != "" {
		return nil, fmt.Errorf("Volume '%s' already has an attachment on '%s", _volumeAttachment.VolumeID, _volumeAttachment.ServerID)
	}

	mdtHost, err := metadata.LoadHost(providers.FromClient(client), request.ServerID)
	if err != nil {
		return nil, err
	}
	if mdtHost == nil {
		return nil, errors.Wrap(providers.ResourceNotFoundError("host", request.ServerID), "Cannot create volume attachment")
	}

	// return client.osclt.CreateVolumeAttachment(request)
	va, err := volumeattach.Create(client.osclt.Compute, request.ServerID, volumeattach.CreateOpts{
		VolumeID: request.VolumeID,
	}).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating volume attachment between server %s and volume %s: %s", request.ServerID, request.VolumeID, openstack.ProviderErrorToString(err))
	}

	volumeAttachment := &api.VolumeAttachment{
		ID:       va.ID,
		ServerID: va.ServerID,
		VolumeID: va.VolumeID,
		Device:   va.Device,
	}

	err = mtdVol.Attach(volumeAttachment)
	if err != nil {
		// Detach volume
		detach_err := volumeattach.Delete(client.osclt.Compute, va.ServerID, va.ID).ExtractErr()
		if detach_err != nil {
			return nil, fmt.Errorf("Error deleting volume attachment %s: %s", va.ID, openstack.ProviderErrorToString(err))
		}

		return volumeAttachment, err
	}

	return volumeAttachment, nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (client *Client) GetVolumeAttachment(serverID, id string) (*api.VolumeAttachment, error) {
	return client.osclt.GetVolumeAttachment(serverID, id)
}

// ListVolumeAttachments lists available volume attachment
func (client *Client) ListVolumeAttachments(serverID string) ([]api.VolumeAttachment, error) {
	return client.osclt.ListVolumeAttachments(serverID)
}

// DeleteVolumeAttachment deletes the volume attachment identifed by id
func (client *Client) DeleteVolumeAttachment(serverID, id string) error {
	va, err := client.GetVolumeAttachment(serverID, id)
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, openstack.ProviderErrorToString(err))
	}

	err = volumeattach.Delete(client.osclt.Compute, serverID, id).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, openstack.ProviderErrorToString(err))
	}

	mtdVol, err := metadata.LoadVolume(providers.FromClient(client), id)
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, openstack.ProviderErrorToString(err))
	}

	err = mtdVol.Detach(va)
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, openstack.ProviderErrorToString(err))
	}

	return nil
}

// DeleteVolume deletes the volume identified by id
func (client *Client) DeleteVolume(id string) error {
	volume, err := metadata.LoadVolume(providers.FromClient(client), id)
	if err != nil {
		return err
	}
	if volume == nil {
		return errors.Wrap(providers.ResourceNotFoundError("volume", id), "Cannot delete volume")
	}

	err = v2_vol.Delete(client.osclt.Volume, id).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting volume: %s", openstack.ProviderErrorToString(err))
	}
	err = metadata.RemoveVolume(providers.FromClient(client), id)
	if err != nil {
		return fmt.Errorf("Error deleting volume: %s", openstack.ProviderErrorToString(err))
	}
	return nil
}

// toVolumeState converts a Volume status returned by the OpenStack driver into VolumeState enum
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
	for t, s := range client.osclt.Cfg.VolumeSpeeds {
		if s == speed {
			return t
		}
	}
	switch speed {
	case VolumeSpeed.SSD:
		return client.getVolumeType(VolumeSpeed.HDD)
	case VolumeSpeed.HDD:
		return client.getVolumeType(VolumeSpeed.COLD)
	default:
		return ""
	}
}

func (client *Client) getVolumeSpeed(vType string) VolumeSpeed.Enum {
	speed, ok := client.osclt.Cfg.VolumeSpeeds[vType]
	if ok {
		return speed
	}
	return VolumeSpeed.HDD
}

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
// - imageID is the ID of the image to initialize the volume with
func (client *Client) CreateVolume(request api.VolumeRequest) (*api.Volume, error) {
	vol, err := client.ExCreateVolume(request, "")

	err = metadata.SaveVolume(providers.FromClient(client), vol)
	if err != nil {
		nerr := client.DeleteVolume(vol.ID)
		if nerr != nil {
			log.Warnf("Error deleting volume: %v", nerr)
		}
		return nil, fmt.Errorf("failed to create Volume: %s", openstack.ProviderErrorToString(err))
	}

	return vol, err
}

// ExCreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
// - imageID is the ID of the image to initialize the volume with
func (client *Client) ExCreateVolume(request api.VolumeRequest, imageID string) (*api.Volume, error) {
	// Check if a volume already exists with the same name
	volume, err := metadata.LoadVolume(providers.FromClient(client), request.Name)
	if err != nil {
		return nil, err
	}
	if volume != nil {
		return nil, providers.ResourceAlreadyExistsError("Volume", request.Name)
	}

	opts := v2_vol.CreateOpts{
		Name:       request.Name,
		Size:       request.Size,
		VolumeType: client.getVolumeType(request.Speed),
		ImageID:    imageID,
	}
	vol, err := v2_vol.Create(client.osclt.Volume, opts).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating volume : %s", openstack.ProviderErrorToString(err))
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

// GetVolume returns the volume identified by id
func (client *Client) GetVolume(id string) (*api.Volume, error) {
	return client.osclt.GetVolume(id)
}

// ListVolumes list available volumes
func (client *Client) ListVolumes(all bool) ([]api.Volume, error) {
	// return client.osclt.ListVolumes(all)
	if all {
		return client.osclt.ListVolumes(all)
	}
	return client.listMonitoredVolumes()
}

// listMonitoredVolumes lists available volumes created by SafeScale (ie registered in object storage)
// This code seems to be the same than openstack provider, but it HAS TO BE DUPLICATED
// because client.ListObjects() is different (Swift for openstack, S3 for flexibleengine).
func (client *Client) listMonitoredVolumes() ([]api.Volume, error) {
	var vols []api.Volume
	m := metadata.NewVolume(providers.FromClient(client))
	err := m.Browse(func(vol *api.Volume) error {
		vols = append(vols, *vol)
		return nil
	})
	if len(vols) == 0 && err != nil {
		return nil, fmt.Errorf("Error listing volumes : %s", openstack.ProviderErrorToString(err))
	}
	return vols, nil
}

// CreateContainer creates an object container
func (client *Client) CreateContainer(name string) error {
	return s3.CreateContainer(awss3.New(client.S3Session), name, client.Opts.Region)
}

// GetContainer get container info
func (client *Client) GetContainer(name string) (*api.ContainerInfo, error) {
	//	return s3.GetContainer(awss3.New(client.S3Session), name)
	return nil, fmt.Errorf("flexibleengine GetContainer not implemened")
}

// DeleteContainer deletes an object container
func (client *Client) DeleteContainer(name string) error {
	return s3.DeleteContainer(awss3.New(client.S3Session), name)
}

// ListContainers list object containers
func (client *Client) ListContainers() ([]string, error) {
	return s3.ListContainers(awss3.New(client.S3Session))
}

// PutObject put an object into an object container
func (client *Client) PutObject(container string, obj api.Object) error {
	return s3.PutObject(awss3.New(client.S3Session), container, obj)
}

// UpdateObjectMetadata update an object into an object container
func (client *Client) UpdateObjectMetadata(container string, obj api.Object) error {
	return s3.UpdateObjectMetadata(awss3.New(client.S3Session), container, obj)
}

// GetObject get object content from an object container
func (client *Client) GetObject(container string, name string, ranges []api.Range) (*api.Object, error) {
	return s3.GetObject(awss3.New(client.S3Session), container, name, ranges)
}

// GetObjectMetadata get  object metadata from an object container
func (client *Client) GetObjectMetadata(container string, name string) (*api.Object, error) {
	return s3.GetObjectMetadata(awss3.New(client.S3Session), container, name)
}

// ListObjects list objects of a container
func (client *Client) ListObjects(container string, filter api.ObjectFilter) ([]string, error) {
	return s3.ListObjects(awss3.New(client.S3Session), container, filter)
}

// CopyObject copies an object
func (client *Client) CopyObject(containerSrc, objectSrc, objectDst string) error {
	return s3.CopyObject(awss3.New(client.S3Session), containerSrc, objectSrc, objectDst)
}

// DeleteObject deleta an object from a container
func (client *Client) DeleteObject(container, object string) error {
	return s3.DeleteObject(awss3.New(client.S3Session), container, object)
}
