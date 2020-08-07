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

package openstack

import (
    "strings"

    "github.com/sirupsen/logrus"

    volumesv1 "github.com/gophercloud/gophercloud/openstack/blockstorage/v1/volumes"
    volumesv2 "github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
    "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"
    "github.com/gophercloud/gophercloud/pagination"

    "github.com/CS-SI/SafeScale/lib/server/resources/abstract"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/volumestate"
    "github.com/CS-SI/SafeScale/lib/utils/debug"
    "github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
    netretry "github.com/CS-SI/SafeScale/lib/utils/net"
    "github.com/CS-SI/SafeScale/lib/utils/retry"
    "github.com/CS-SI/SafeScale/lib/utils/temporal"
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
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s *Stack) CreateVolume(request abstract.VolumeRequest) (volume *abstract.Volume, xerr fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }
    if request.Name == "" {
        return nil, fail.InvalidParameterError("request.Name", "cannot be empty string")
    }

    defer debug.NewTracer(nil, tracing.ShouldTrace("stack.volume"), "(%s)", request.Name).WithStopwatch().Entering().Exiting()

    volume, xerr = s.GetVolume(request.Name)
    if xerr != nil {
        if _, ok := xerr.(*fail.ErrNotFound); !ok {
            return nil, xerr
        }
    }
    if volume != nil {
        return nil, abstract.ResourceDuplicateError("volume", request.Name)
    }

    az, xerr := s.SelectedAvailabilityZone()
    if xerr != nil {
        return nil, abstract.ResourceDuplicateError("volume", request.Name)
    }

    var v   abstract.Volume
    switch s.versions["volume"] {
    case "v1":
        var vol *volumesv1.Volume
        xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
            func() (innerErr error) {
                vol, innerErr = volumesv1.Create(s.VolumeClient, volumesv1.CreateOpts{
                    AvailabilityZone: az,
                    Name:             request.Name,
                    Size:             request.Size,
                    VolumeType:       s.getVolumeType(request.Speed),
                }).Extract()
                return NormalizeError(innerErr)
            },
            temporal.GetCommunicationTimeout(),
        )
        if xerr != nil {
            break
        }
        if vol == nil {
            xerr = fail.InconsistentError("volume creation seems to have succeeded, but returned nil value is unexpected")
            break
        }
        v = abstract.Volume{
            ID:    vol.ID,
            Name:  vol.Name,
            Size:  vol.Size,
            Speed: s.getVolumeSpeed(vol.VolumeType),
            State: toVolumeState(vol.Status),
        }
    case "v2":
        var vol *volumesv2.Volume
        xerr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
            func() (innerErr error) {
                vol, innerErr = volumesv2.Create(s.VolumeClient, volumesv2.CreateOpts{
                    AvailabilityZone: az,
                    Name:             request.Name,
                    Size:             request.Size,
                    VolumeType:       s.getVolumeType(request.Speed),
                }).Extract()
                return NormalizeError(innerErr)
            },
            temporal.GetCommunicationTimeout(),
        )
        if xerr != nil {
            break
        }
        if vol == nil {
            xerr = fail.InconsistentError("volume creation seems to have succeeded, but returned nil value is unexpected")
            break
        }
        v = abstract.Volume{
            ID:    vol.ID,
            Name:  vol.Name,
            Size:  vol.Size,
            Speed: s.getVolumeSpeed(vol.VolumeType),
            State: toVolumeState(vol.Status),
        }
    default:
        xerr = fail.NotImplementedError("unmanaged service 'volume' version '%s'", s.versions["volume"])
    }
    if xerr != nil {
        return nil, xerr
    }

    return &v, nil
}

// GetVolume returns the volume identified by id
func (s *Stack) GetVolume(id string) (*abstract.Volume, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }
    if id == "" {
        return nil, fail.InvalidParameterError("id", "cannot be empty string")
    }

    defer debug.NewTracer(nil, tracing.ShouldTrace("stack.volume"), "(%s)", id).WithStopwatch().Entering().Exiting()

    var vol *volumesv2.Volume
    xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() (innerErr error) {
            vol, innerErr = volumesv2.Get(s.VolumeClient, id).Extract()
            return NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
    if xerr != nil {
        switch xerr.(type) {
        case *fail.ErrNotFound:
            return nil, abstract.ResourceNotFoundError("volume", id)
        default:
            return nil, xerr
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

// ListVolumes returns the list of all volumes known on the current tenant
func (s *Stack) ListVolumes() ([]abstract.Volume, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }

    defer debug.NewTracer(nil, tracing.ShouldTrace("stack.volume"), "").WithStopwatch().Entering().Exiting()

    var vs []abstract.Volume
    xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            innerErr := volumesv2.List(s.VolumeClient, volumesv2.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
                list, err := volumesv2.ExtractVolumes(page)
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
            return NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
    if xerr != nil || len(vs) == 0 {
        return nil, xerr
    }
    // VPL: empty list is not an abnormal situation, do not log
    // if len(vs) == 0 {
    // logrus.Warnf("Complete volume list empty")
    // }

    return vs, nil
}

// DeleteVolume deletes the volume identified by id
func (s *Stack) DeleteVolume(id string) fail.Error {
    if s == nil {
        return fail.InvalidInstanceError()
    }
    if id = strings.TrimSpace(id); id == "" {
        return fail.InvalidParameterError("id", "cannot be empty string")
    }

    defer debug.NewTracer(nil, tracing.ShouldTrace("stack.volume"), "("+id+")").WithStopwatch().Entering().Exiting()

    var (
        timeout = temporal.GetBigDelay()
        commDelay = temporal.GetCommunicationTimeout()
    )

    return retry.WhileUnsuccessfulDelay5Seconds(
        func() error {
            innerXErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
                func() error {
                    innerErr := volumesv2.Delete(s.VolumeClient, id, nil).ExtractErr()
                    return NormalizeError(innerErr)
                },
                commDelay,
            )
            switch innerXErr.(type) {
            case *fail.ErrInvalidRequest:
                return fail.NotAvailableError("volume not in state 'available'")
            }
            return innerXErr
        },
        timeout,
    )
}

// CreateVolumeAttachment attaches a volume to an host
// - 'name' of the volume attachment
// - 'volume' to attach
// - 'host' on which the volume is attached
func (s *Stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
    if s == nil {
        return "", fail.InvalidInstanceError()
    }
    if request.Name = strings.TrimSpace(request.Name); request.Name == "" {
        return "", fail.InvalidParameterError("request.Name", "cannot be empty string")
    }

    defer debug.NewTracer(nil, tracing.ShouldTrace("stack.volume"), "("+request.Name+")").WithStopwatch().Entering().Exiting()

    // Creates the attachment
    var va *volumeattach.VolumeAttachment
    xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() (innerErr error) {
            va, innerErr = volumeattach.Create(s.ComputeClient, request.HostID, volumeattach.CreateOpts{
                VolumeID: request.VolumeID,
            }).Extract()
            return NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
    if xerr != nil {
        return "", xerr
    }
    return va.ID, nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *Stack) GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }
    if serverID = strings.TrimSpace(serverID); serverID == "" {
        return nil, fail.InvalidParameterError("serverID", "cannot be empty string")
    }
    if id = strings.TrimSpace(id); id == "" {
        return nil, fail.InvalidParameterError("id", "cannot be empty string")
    }

    defer debug.NewTracer(nil, tracing.ShouldTrace("stack.volume"), "('"+serverID+"', '"+id+"')").WithStopwatch().Entering().Exiting()

    var va *volumeattach.VolumeAttachment
    xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() (innerErr error) {
            va, innerErr = volumeattach.Get(s.ComputeClient, serverID, id).Extract()
            return NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
    if xerr != nil {
        return nil, xerr
    }
    return &abstract.VolumeAttachment{
        ID:       va.ID,
        ServerID: va.ServerID,
        VolumeID: va.VolumeID,
        Device:   va.Device,
    }, nil
}

// ListVolumeAttachments lists available volume attachment
func (s *Stack) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, fail.Error) {
    if s == nil {
        return nil, fail.InvalidInstanceError()
    }
    if serverID = strings.TrimSpace(serverID); serverID == "" {
        return nil, fail.InvalidParameterError("serverID", "cannot be empty string")
    }

    defer debug.NewTracer(nil, tracing.ShouldTrace("stack.volume"), "('"+serverID+"')").WithStopwatch().Entering().Exiting()

    var vs []abstract.VolumeAttachment
    xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            innerErr := volumeattach.List(s.ComputeClient, serverID).EachPage(func(page pagination.Page) (bool, error) {
                list, err := volumeattach.ExtractVolumeAttachments(page)
                if err != nil {
                    return false, err
                }
                for _, va := range list {
                    ava := abstract.VolumeAttachment{
                        ID:       va.ID,
                        ServerID: va.ServerID,
                        VolumeID: va.VolumeID,
                        Device:   va.Device,
                    }
                    vs = append(vs, ava)
                }
                return true, nil
            })
            return NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
    if xerr != nil {
        return []abstract.VolumeAttachment{}, xerr
    }
    return vs, nil
}

// DeleteVolumeAttachment deletes the volume attachment identified by id
func (s *Stack) DeleteVolumeAttachment(serverID, vaID string) fail.Error {
    if s == nil {
        return fail.InvalidInstanceError()
    }
    if serverID = strings.TrimSpace(serverID); serverID == "" {
        return fail.InvalidParameterError("serverID", "cannot be empty string")
    }
    if vaID = strings.TrimSpace(vaID); vaID == "" {
        return fail.InvalidParameterError("vaID", "cannot be empty string")
    }

    defer debug.NewTracer(nil, tracing.ShouldTrace("stack.volume"), "('"+serverID+"', '"+vaID+"')").WithStopwatch().Entering().Exiting()

    return netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            innerErr := volumeattach.Delete(s.ComputeClient, serverID, vaID).ExtractErr()
            return NormalizeError(innerErr)
        },
        temporal.GetCommunicationTimeout(),
    )
}
