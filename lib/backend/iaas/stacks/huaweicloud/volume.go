/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// toVolumeState converts a Volume status returned by the OpenStack driver into VolumeState enum
func toVolumeState(status string) volumestate.Enum {
	switch status {
	case "creating":
		return volumestate.Creating
	case "available":
		return volumestate.Available
	case "attaching":
		return volumestate.Attaching
	case "detaching":
		return volumestate.Detaching
	case "in-use":
		return volumestate.Used
	case "deleting":
		return volumestate.Deleting
	case "error", "error_deleting", "error_backing-up", "error_restoring", "error_extending":
		return volumestate.Error
	default:
		return volumestate.Unknown
	}
}

func (s stack) getVolumeType(speed volumespeed.Enum) string {
	for t, s := range s.cfgOpts.VolumeSpeeds {
		if s == speed {
			return t
		}
	}
	switch speed {
	case volumespeed.Ssd:
		return s.getVolumeType(volumespeed.Hdd)
	case volumespeed.Hdd:
		return s.getVolumeType(volumespeed.Cold)
	default:
		return ""
	}
}

func (s stack) getVolumeSpeed(vType string) volumespeed.Enum {
	speed, ok := s.cfgOpts.VolumeSpeeds[vType]
	if ok {
		return speed
	}

	return volumespeed.Hdd
}

// CreateVolume creates a block volume
func (s stack) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	volume, xerr := s.InspectVolume(ctx, request.Name)
	if xerr == nil && volume != nil {
		return nil, fail.DuplicateError("volume '%s' already exists", request.Name)
	}

	az, xerr := s.SelectedAvailabilityZone(ctx)
	if xerr != nil {
		return nil, xerr
	}
	opts := volumes.CreateOpts{
		AvailabilityZone: az,
		Name:             request.Name,
		Size:             request.Size,
		VolumeType:       strings.ToUpper(s.getVolumeType(request.Speed)),
	}
	var vol *volumes.Volume
	commRetryErr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			vol, innerErr = volumes.Create(s.VolumeClient, opts).Extract()
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return nil, commRetryErr
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
func (s stack) InspectVolume(ctx context.Context, id string) (*abstract.Volume, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id = strings.TrimSpace(id); id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	var vol *volumes.Volume
	commRetryErr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			vol, innerErr = volumes.Get(s.VolumeClient, id).Extract()
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		switch commRetryErr.(type) {
		case *fail.ErrNotFound:
			return nil, abstract.ResourceNotFoundError("volume", id)
		default:
			return nil, commRetryErr
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
func (s stack) ListVolumes(ctx context.Context) ([]*abstract.Volume, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	var vs []*abstract.Volume
	commRetryErr := stacks.RetryableRemoteCall(ctx,
		func() error {
			innerErr := volumes.List(s.VolumeClient, volumes.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
				list, err := volumes.ExtractVolumes(page)
				if err != nil {
					logrus.WithContext(ctx).Errorf("Error listing volumes: volume extraction: %+v", err)
					return false, err
				}
				for _, vol := range list {
					av := &abstract.Volume{
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
		return nil, commRetryErr
	}

	return vs, nil
}
