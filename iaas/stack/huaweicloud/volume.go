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

package huaweicloud

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/CS-SI/SafeScale/iaas/provider"
	"github.com/CS-SI/SafeScale/iaas/resource/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/iaas/resource/enums/VolumeState"
	openstack "github.com/CS-SI/SafeScale/iaas/stack/openstack"

	v2_vol "github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"
)

// CreateVolumeAttachment attaches a volume to an host
//- 'name' of the volume attachment
//- 'volume' to attach
//- 'host' on which the volume is attached
func (s *Stack) CreateVolumeAttachment(request model.VolumeAttachmentRequest) (*model.VolumeAttachment, error) {
	// Ensure volume and host are known
	mtdVol, err := s.GetVolume(request.VolumeID)
	if err != nil {
		return nil, err
	}
	if mtdVol == nil {
		return nil, errors.Wrap(provider.ResourceNotFoundError("volume", request.VolumeID), "Cannot create volume attachment")
	}
	_volumeAttachment, err := mtdVol.GetAttachment()
	if err != nil {
		return nil, err
	}
	if _volumeAttachment != nil && _volumeAttachment.ID != "" {
		return nil, fmt.Errorf("Volume '%s' already has an attachment on '%s", _volumeAttachment.VolumeID, _volumeAttachment.ServerID)
	}

	mdtHost, err := s.GetHost(request.ServerID)
	if err != nil {
		return nil, err
	}
	if mdtHost == nil {
		return nil, errors.Wrap(provider.ResourceNotFoundError("host", request.ServerID), "Cannot create volume attachment")
	}

	// return client.osclt.CreateVolumeAttachment(request)
	va, err := volumeattach.Create(s.osclt.Compute, request.ServerID, volumeattach.CreateOpts{
		VolumeID: request.VolumeID,
	}).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating volume attachment between server %s and volume %s: %s",
			request.ServerID, request.VolumeID, openstack.ErrorToString(err))
	}

	volumeAttachment := &model.VolumeAttachment{
		ID:       va.ID,
		ServerID: va.ServerID,
		VolumeID: va.VolumeID,
		Device:   va.Device,
	}

	err = mtdVol.Attach(volumeAttachment)
	if err != nil {
		// Detach volume
		detachErr := volumeattach.Delete(s.osclt.Compute, va.ServerID, va.ID).ExtractErr()
		if detachErr != nil {
			return nil, fmt.Errorf("Error deleting volume attachment %s: %s", va.ID, openstack.ErrorToString(err))
		}

		return volumeAttachment, err
	}

	return volumeAttachment, nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *Stack) GetVolumeAttachment(serverID, id string) (*model.VolumeAttachment, error) {
	return client.osclt.GetVolumeAttachment(serverID, id)
}

// ListVolumeAttachments lists available volume attachment
func (s *Stack) ListVolumeAttachments(serverID string) ([]model.VolumeAttachment, error) {
	return client.osclt.ListVolumeAttachments(serverID)
}

// DeleteVolumeAttachment deletes the volume attachment identifed by id
func (s *Stack) DeleteVolumeAttachment(serverID, id string) error {
	va, err := s.GetVolumeAttachment(serverID, id)
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, openstack.ErrorToString(err))
	}

	err = volumeattach.Delete(s.osclt.Compute, serverID, id).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, openstack.ErrorToString(err))
	}

	mtdVol, err := s.GetVolume(id)
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, openstack.ErrorToString(err))
	}

	err = mtdVol.Detach(va)
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, openstack.ErrorToString(err))
	}

	return nil
}

// DeleteVolume deletes the volume identified by id
func (s *Stack) DeleteVolume(id string) error {
	volume, err := s.GetVolume(id)
	if err != nil {
		return err
	}
	if volume == nil {
		return errors.Wrap(provider.ResourceNotFoundError("volume", id), "Cannot delete volume")
	}

	err = v2_vol.Delete(s.osclt.Volume, id).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting volume: %s", openstack.ErrorToString(err))
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

func (s *Stack) getVolumeType(speed VolumeSpeed.Enum) string {
	for t, s := range s.CfgOpts.VolumeSpeeds {
		if s == speed {
			return t
		}
	}
	switch speed {
	case VolumeSpeed.SSD:
		return s.getVolumeType(VolumeSpeed.HDD)
	case VolumeSpeed.HDD:
		return s.getVolumeType(VolumeSpeed.COLD)
	default:
		return ""
	}
}

func (s *Stack) getVolumeSpeed(vType string) VolumeSpeed.Enum {
	speed, ok := s.CfgOpts.VolumeSpeeds[vType]
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
func (s *Stack) CreateVolume(request model.VolumeRequest) (*model.Volume, error) {
	return s.ExCreateVolume(request, "")
}

// ExCreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
// - imageID is the ID of the image to initialize the volume with
func (s *Stack) ExCreateVolume(request model.VolumeRequest, imageID string) (*model.Volume, error) {
	// Check if a volume already exists with the same name
	volume, err := s.GetVolume(request.Name)
	if err != nil {
		return nil, err
	}
	if volume != nil {
		return nil, providers.ResourceAlreadyExistsError("Volume", request.Name)
	}

	opts := v2_vol.CreateOpts{
		Name:       request.Name,
		Size:       request.Size,
		VolumeType: s.getVolumeType(request.Speed),
		ImageID:    imageID,
	}
	vol, err := v2_vol.Create(s.osclt.Volume, opts).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating volume : %s", stack_openstack.ErrorToString(err))
	}
	v := model.Volume{
		ID:    vol.ID,
		Name:  vol.Name,
		Size:  vol.Size,
		Speed: s.getVolumeSpeed(vol.VolumeType),
		State: toVolumeState(vol.Status),
	}
	return &v, nil
}

// GetVolume returns the volume identified by id
func (s *Stack) GetVolume(id string) (*model.Volume, error) {
	return s.osclt.GetVolume(id)
}

// ListVolumes list available volumes
func (s *Stack) ListVolumes() ([]model.Volume, error) {
	return s.osclt.ListVolumes()
}
