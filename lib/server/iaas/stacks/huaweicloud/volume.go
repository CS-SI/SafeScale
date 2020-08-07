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
    "strings"

    "github.com/sirupsen/logrus"

    "github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
    "github.com/gophercloud/gophercloud/pagination"

    "github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
    "github.com/CS-SI/SafeScale/lib/server/resources/abstract"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/volumestate"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
    netretry "github.com/CS-SI/SafeScale/lib/utils/net"
    "github.com/CS-SI/SafeScale/lib/utils/temporal"
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
func (s *Stack) CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }

    volume, xerr := s.GetVolume(request.Name)
    if xerr == nil && volume != nil {
        return nil, fail.DuplicateError("volume '%s' already exists", request.Name)
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
    commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() (innerErr error) {
            vol, innerErr = volumes.Create(s.Stack.VolumeClient, opts).Extract()
            return openstack.NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
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

// GetVolume returns the volume identified by id
// If volume not found, returns (nil, nil) - TODO: returns utils.ErrNotFound
func (s *Stack) GetVolume(id string) (*abstract.Volume, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }
    if id = strings.TrimSpace(id); id == "" {
        return nil, fail.InvalidParameterError("id", "cannot be empty string")
    }

    var vol *volumes.Volume
    commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() (innerErr error) {
            vol, innerErr = volumes.Get(s.Stack.VolumeClient, id).Extract()
            return openstack.NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
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
func (s *Stack) ListVolumes() ([]abstract.Volume, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }

    var vs []abstract.Volume
    commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
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
            return openstack.NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
    if commRetryErr != nil {
        return nil, commRetryErr
    }
    // VPL: empty list is not an abnormal situation, do not log or raise error
    // if len(vs) == 0 {
    //     logrus.Warnf("Complete volume list empty")
    // }
    return vs, nil
}

// // CreateVolumeAttachment attaches a volume to an host
// func (s *Stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
// 	return s.Stack.CreateVolumeAttachment(request)
// }
//
// // GetVolumeAttachment returns the volume attachment identified by id
// func (s *Stack) GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
// 	return s.Stack.GetVolumeAttachment(serverID, id)
// }
//
// // ListVolumeAttachments lists available volume attachment
// func (s *Stack) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, error) {
// 	return s.Stack.ListVolumeAttachments(serverID)
// }
//
// // DeleteVolumeAttachment deletes the volume attachment identifed by id
// func (s *Stack) DeleteVolumeAttachment(serverID, vaID string) error {
// 	return s.Stack.DeleteVolumeAttachment(serverID, vaID)
// }
