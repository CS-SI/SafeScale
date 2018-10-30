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

package openstack

import (
	"fmt"

	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/enums/VolumeState"

	"github.com/gophercloud/gophercloud/openstack/blockstorage/v1/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"
	"github.com/gophercloud/gophercloud/pagination"
)

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
	for t, s := range s.Cfg.VolumeSpeeds {
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
	speed, ok := s.Cfg.VolumeSpeeds[vType]
	if ok {
		return speed
	}
	return VolumeSpeed.HDD
}

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s *Stack) CreateVolume(request model.VolumeRequest) (*model.Volume, error) {
	vol, err := volumes.Create(s.Volume, volumes.CreateOpts{
		Name:       request.Name,
		Size:       request.Size,
		VolumeType: client.getVolumeType(request.Speed),
	}).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating volume : %s", ProviderErrorToString(err))
	}
	v := api.Volume{
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
	vol, err := volumes.Get(s.Volume, id).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting volume: %s", ProviderErrorToString(err))
	}
	av := model.Volume{
		ID:    vol.ID,
		Name:  vol.Name,
		Size:  vol.Size,
		Speed: s.getVolumeSpeed(vol.VolumeType),
		State: toVolumeState(vol.Status),
	}
	return &av, nil
}

// ListVolumes return the list of all volume known on the current tenant (all=ture)
//or 'only' thode monitored by safescale (all=false) ie those monitored by metadata
func (s *Stack) ListVolumes() ([]model.Volume, error) {
	var vs []api.Volume
	err := volumes.List(s.Volume, volumes.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
		list, err := volumes.ExtractVolumes(page)
		if err != nil {
			return false, err
		}
		for _, vol := range list {
			av := api.Volume{
				ID:    vol.ID,
				Name:  vol.Name,
				Size:  vol.Size,
				Speed: client.getVolumeSpeed(vol.VolumeType),
				State: toVolumeState(vol.Status),
			}
			vs = append(vs, av)
		}
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error listing volume types: %s", ProviderErrorToString(err))
	}
	return vs, nil
}

// DeleteVolume deletes the volume identified by id
func (s *Stack) DeleteVolume(id string) error {
	err := volumes.Delete(s.Volume, id).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting volume: %s", ProviderErrorToString(err))
	}
	return nil
}

// CreateVolumeAttachment attaches a volume to an host
// - 'name' of the volume attachment
// - 'volume' to attach
// - 'host' on which the volume is attached
func (s *Stack) CreateVolumeAttachment(request model.VolumeAttachmentRequest) (*model.VolumeAttachment, error) {
	// Create the attachment
	va, err := volumeattach.Create(s.Compute, request.ServerID, volumeattach.CreateOpts{
		VolumeID: request.VolumeID,
	}).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating volume attachment between server %s and volume %s: %s", request.ServerID, request.VolumeID, ProviderErrorToString(err))
	}

	vaapi := &api.VolumeAttachment{
		ID:       va.ID,
		ServerID: va.ServerID,
		VolumeID: va.VolumeID,
		Device:   va.Device,
	}

	mtdVol, err := s.GetVolume(request.VolumeID)
	if err != nil {
		return nil, err
	}
	err = mtdVol.Attach(vaapi)
	if err != nil {
		// Detach volume
		detachErr := volumeattach.Delete(s.Compute, va.ServerID, va.ID).ExtractErr()
		if detachErr != nil {
			return nil, fmt.Errorf("Error deleting volume attachment %s: %s", va.ID, ErrorToString(err))
		}
	}

	return vaapi, err
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *Stack) GetVolumeAttachment(serverID, id string) (*model.VolumeAttachment, error) {
	va, err := volumeattach.Get(s.Compute, serverID, id).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting volume attachment %s: %s", id, ErrorToString(err))
	}
	return &api.VolumeAttachment{
		ID:       va.ID,
		ServerID: va.ServerID,
		VolumeID: va.VolumeID,
		Device:   va.Device,
	}, nil
}

// ListVolumeAttachments lists available volume attachment
func (s *Stack) ListVolumeAttachments(serverID string) ([]model.VolumeAttachment, error) {
	var vs []model.VolumeAttachment
	err := volumeattach.List(s.Compute, serverID).EachPage(func(page pagination.Page) (bool, error) {
		list, err := volumeattach.ExtractVolumeAttachments(page)
		if err != nil {
			return false, err
		}
		for _, va := range list {
			ava := api.VolumeAttachment{
				ID:       va.ID,
				ServerID: va.ServerID,
				VolumeID: va.VolumeID,
				Device:   va.Device,
			}
			vs = append(vs, ava)
		}
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error listing volume types: %s", ProviderErrorToString(err))
	}
	return vs, nil
}

// DeleteVolumeAttachment deletes the volume attachment identified by id
func (s *Stack) DeleteVolumeAttachment(serverID, id string) error {
	va, err := client.GetVolumeAttachment(serverID, id)
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, ProviderErrorToString(err))
	}

	err = volumeattach.Delete(s.Compute, serverID, id).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, ProviderErrorToString(err))
	}

	mtdVol, err := s.GetVolume(id)
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, ProviderErrorToString(err))
	}

	err = mtdVol.Detach(va)
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, ProviderErrorToString(err))
	}

	return nil
}
