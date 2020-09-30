/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"

	"github.com/CS-SI/SafeScale/lib/utils/fail"

	log "github.com/sirupsen/logrus"

	gc "github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/volumestate"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
)

// // DeleteVolume deletes the volume identified by id
// func (s *Stack) DeleteVolume(id string) error {
// 	return s.Stack.DeleteVolume(id)
// }

// toVolumeState converts a Volume status returned by the OpenStack driver into VolumeState enum
func toVolumeState(status string) volumestate.Enum {
	switch status {
	case "creating":
		return volumestate.CREATING
	case "available":
		return volumestate.AVAILABLE
	case "attaching":
		return volumestate.ATTACHING
	case "detaching":
		return volumestate.DETACHING
	case "in-use":
		return volumestate.USED
	case "deleting":
		return volumestate.DELETING
	case "error", "error_deleting", "error_backing-up", "error_restoring", "error_extending":
		return volumestate.ERROR
	default:
		return volumestate.OTHER
	}
}

func (s *Stack) getVolumeType(speed volumespeed.Enum) string {
	for t, s := range s.cfgOpts.VolumeSpeeds {
		if s == speed {
			return t
		}
	}
	switch speed {
	case volumespeed.SSD:
		return s.getVolumeType(volumespeed.HDD)
	case volumespeed.HDD:
		return s.getVolumeType(volumespeed.COLD)
	default:
		return ""
	}
}

func (s *Stack) getVolumeSpeed(vType string) volumespeed.Enum {
	speed, ok := s.cfgOpts.VolumeSpeeds[vType]
	if ok {
		return speed
	}
	return volumespeed.HDD
}

// CreateVolume creates a block volume
func (s *Stack) CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, error) {
	volume, err := s.GetVolume(request.Name)
	if volume != nil && err == nil {
		return nil, fail.Errorf(fmt.Sprintf("volume '%s' already exists", request.Name), err)
	}

	az, err := s.SelectedAvailabilityZone()
	if err != nil {
		return nil, err
	}
	opts := volumes.CreateOpts{
		AvailabilityZone: az,
		Name:             request.Name,
		Size:             request.Size,
		VolumeType:       s.getVolumeType(request.Speed),
	}
	vol, err := volumes.Create(s.Stack.VolumeClient, opts).Extract()
	if err != nil {
		return nil, fail.Errorf(fmt.Sprintf("error creating volume : %s", openstack.ProviderErrorToString(err)), err)
	}
	v := abstract.Volume{
		ID:    vol.ID,
		Name:  vol.Name,
		Size:  vol.Size,
		Speed: s.getVolumeSpeed(vol.VolumeType),
		State: toVolumeState(vol.Status),
	}
	return &v, nil
}

// GetVolume returns the volume identified by id
// If volume not found, returns (nil, nil) - TODO: returns utils.ErrNotFound
func (s *Stack) GetVolume(id string) (_ *abstract.Volume, err error) {
	var volume *volumes.Volume

	unwrap := false
	getErr := retry.WhileSuccessfulDelay1Second(
		func() error {
			r := volumes.Get(s.Stack.VolumeClient, id)
			volume, err = r.Extract()
			if err != nil {
				return openstack.ReinterpretGophercloudErrorCode(
					err, nil, []int64{408, 429, 500, 503}, []int64{401, 403, 409}, func(ferr error) error {
						if _, ok := ferr.(gc.ErrDefault404); ok {
							unwrap = true
							return fail.AbortedError("", abstract.ResourceNotFoundError("volume", id))
						}

						return fail.Wrap(
							ferr, fmt.Sprintf("error getting volume: %s", openstack.ProviderErrorToString(ferr)),
						)
					},
				)
			}

			return nil
		},
		temporal.GetContextTimeout(),
	)

	if getErr != nil {
		if unwrap {
			return nil, fail.Cause(getErr)
		}
		return nil, getErr
	}

	av := abstract.Volume{
		ID:    volume.ID,
		Name:  volume.Name,
		Size:  volume.Size,
		Speed: s.getVolumeSpeed(volume.VolumeType),
		State: toVolumeState(volume.Status),
	}
	return &av, nil
}

// ListVolumes lists volumes
func (s *Stack) ListVolumes() ([]abstract.Volume, error) {
	var vs []abstract.Volume
	err := volumes.List(s.Stack.VolumeClient, volumes.ListOpts{}).EachPage(
		func(page pagination.Page) (bool, error) {
			list, err := volumes.ExtractVolumes(page)
			if err != nil {
				log.Errorf("Error listing volumes: volume extraction: %+v", err)
				return false, err
			}
			for _, vol := range list {
				av := abstract.Volume{
					ID:    vol.ID,
					Name:  vol.Name,
					Size:  vol.Size,
					Speed: s.getVolumeSpeed(vol.VolumeType),
					State: toVolumeState(vol.Status),
				}
				vs = append(vs, av)
			}
			return true, nil
		},
	)
	if err != nil || len(vs) == 0 {
		if err != nil {
			return nil, fail.Wrap(
				err, fmt.Sprintf("error listing volume types: %s", openstack.ProviderErrorToString(err)),
			)
		}
		log.Warnf("Complete volume list empty")
	}
	return vs, nil
}

// CreateVolumeAttachment attaches a volume to an host
func (s *Stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, error) {
	return s.Stack.CreateVolumeAttachment(request)
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *Stack) GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, error) {
	return s.Stack.GetVolumeAttachment(serverID, id)
}

// ListVolumeAttachments lists available volume attachment
func (s *Stack) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, error) {
	return s.Stack.ListVolumeAttachments(serverID)
}

// DeleteVolumeAttachment deletes the volume attachment identifed by id
func (s *Stack) DeleteVolumeAttachment(serverID, vaID string) error {
	return s.Stack.DeleteVolumeAttachment(serverID, vaID)
}
