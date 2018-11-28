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

	gc "github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v1/volumes"
	v2_vol "github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
	"github.com/gophercloud/gophercloud/pagination"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/iaas/provider"
	"github.com/CS-SI/SafeScale/iaas/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/iaas/model/enums/VolumeState"
	"github.com/CS-SI/SafeScale/iaas/stack/openstack"

	v2_vol "github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"
)

// DeleteVolume deletes the volume identified by id
func (s *Stack) DeleteVolume(id string) error {
	return s.osclt.DeleteVolume(id)
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
func (s *Stack) CreateVolume(request model.VolumeRequest) (*model.Volume, error) {
	volume, err := client.GetVolume(request.Name)
	if err != nil {
		return nil, err
	}
	if volume != nil {
		return nil, fmt.Errorf("volume '%s' already exists", request.Name)
	}

	opts := v2_vol.CreateOpts{
		Name:       request.Name,
		Size:       request.Size,
		VolumeType: s.getVolumeType(request.Speed),
	}
	vol, err := v2_vol.Create(s.osclt.Volume, opts).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating volume : %s", openstack.ProviderErrorToString(err))
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
// If volume not found, returns (nil, nil) - TODO: returns model.ErrResourceNotFound
func (s *Stack) GetVolume(id string) (*model.Volume, error) {
	r := volumes.Get(client.osclt.Volume, id)
	volume, err := r.Extract()
	if err != nil {
		switch err.(type) {
		case gc.ErrDefault404:
			return nil, nil
		}
		log.Debugf("Error getting volume: getting volume invocation: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting volume: %s", openstack.ProviderErrorToString(err)))
	}

	av := model.Volume{
		ID:    volume.ID,
		Name:  volume.Name,
		Size:  volume.Size,
		Speed: client.getVolumeSpeed(volume.VolumeType),
		State: toVolumeState(volume.Status),
	}
	return &av, nil
}

// ListVolumes lists volumes
func (s *Stack) ListVolumes() ([]model.Volume, error) {
	var vs []model.Volume
	err := volumes.List(s.osclt.Volume, volumes.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
		list, err := volumes.ExtractVolumes(page)
		if err != nil {
			log.Errorf("Error listing volumes: volume extraction: %+v", err)
			return false, err
		}
		for _, vol := range list {
			av := model.Volume{
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
	if err != nil || len(vs) == 0 {
		if err != nil {
			log.Debugf("Error listing volumes: list invocation: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error listing volume types: %s", openstack.ProviderErrorToString(err)))
		}
		log.Warnf("Complete volume list empty")
	}
	return vs, nil
}

// CreateVolumeAttachment attaches a volume to an host
func (s *Stack) CreateVolumeAttachment(request model.VolumeAttachmentRequest) (string, error) {
	return s.osclt.CreateVolumeAttachment(request)
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *Stack) GetVolumeAttachment(serverID, id string) (*model.VolumeAttachment, error) {
	return s.osclt.GetVolumeAttachment(serverID, id)
}

// ListVolumeAttachments lists available volume attachment
func (s *Stack) ListVolumeAttachments(serverID string) ([]model.VolumeAttachment, error) {
	return s.osclt.ListVolumeAttachments(serverID)
}

// DeleteVolumeAttachment deletes the volume attachment identifed by id
func (s *Stack) DeleteVolumeAttachment(serverID, vaID string) error {
	return s.osclt.DeleteVolumeAttachment(serverID, vaID)
}
