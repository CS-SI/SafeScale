/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

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

func (s stack) getVolumeType(speed volumespeed.Enum) string {
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

func (s stack) getVolumeSpeed(vType string) volumespeed.Enum {
	speed, ok := s.cfgOpts.VolumeSpeeds[vType]
	if ok {
		return speed
	}
	return volumespeed.HDD
}

// CreateVolume creates a block volume
func (s stack) CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
	nullAV := abstract.NewVolume()
	if s.IsNull() {
		return nullAV, fail.InvalidInstanceError()
	}

	volume, xerr := s.InspectVolume(request.Name)
	if xerr == nil && volume != nil {
		return nullAV, fail.DuplicateError("volume '%s' already exists", request.Name)
	}

	az, xerr := s.SelectedAvailabilityZone()
	if xerr != nil {
		return nil, xerr
	}
	opts := volumes.CreateOpts{
		AvailabilityZone: az,
		Name:             request.Name,
		Size:             request.Size,
		VolumeType:       s.getVolumeType(request.Speed),
	}
	var vol *volumes.Volume
	commRetryErr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			vol, innerErr = volumes.Create(s.Stack.VolumeClient, opts).Extract()
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return nullAV, commRetryErr
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

// InspectVolume returns the volume identified by id
func (s stack) InspectVolume(id string) (*abstract.Volume, fail.Error) {
	nullAV := abstract.NewVolume()
	if s.IsNull() {
		return nullAV, fail.InvalidInstanceError()
	}
	if id = strings.TrimSpace(id); id == "" {
		return nullAV, fail.InvalidParameterError("id", "cannot be empty string")
	}

	var vol *volumes.Volume
	commRetryErr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			vol, innerErr = volumes.Get(s.Stack.VolumeClient, id).Extract()
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		switch commRetryErr.(type) {
		case *fail.ErrNotFound:
			return nullAV, abstract.ResourceNotFoundError("volume", id)
		default:
			return nullAV, commRetryErr
		}
	}

	av := abstract.Volume{
		ID:    vol.ID,
		Name:  vol.Name,
		Size:  vol.Size,
		Speed: s.getVolumeSpeed(vol.VolumeType),
		State: toVolumeState(vol.Status),
	}
	return &av, nil
}

// ListVolumes lists volumes
func (s stack) ListVolumes() ([]abstract.Volume, fail.Error) {
	var emptySlice []abstract.Volume
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	var vs []abstract.Volume
	commRetryErr := stacks.RetryableRemoteCall(
		func() error {
			innerErr := volumes.List(s.Stack.VolumeClient, volumes.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
				list, err := volumes.ExtractVolumes(page)
				if err != nil {
					logrus.Errorf("Error listing volumes: volume extraction: %+v", err)
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
			})
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return emptySlice, commRetryErr
	}
	// VPL: empty list is not an abnormal situation, do not log or raise error
	// if len(vs) == 0 {
	//     logrus.Warnf("Complete volume list empty")
	// }
	return vs, nil
}
