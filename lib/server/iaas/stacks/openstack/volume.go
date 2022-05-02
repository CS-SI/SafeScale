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

package openstack

import (
	"context"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"

	volumesv1 "github.com/gophercloud/gophercloud/openstack/blockstorage/v1/volumes"
	volumesv2 "github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/v22/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
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
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s stack) CreateVolume(request abstract.VolumeRequest) (volume *abstract.Volume, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if request.Name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("request.Name")
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("stack.volume"), "(%s)", request.Name).WithStopwatch().Entering().Exiting()

	az, xerr := s.SelectedAvailabilityZone()
	if xerr != nil { // nolint
		return nil, abstract.ResourceDuplicateError("volume", request.Name)
	}

	var v abstract.Volume
	switch s.versions["volume"] {
	case "v1":
		var vol *volumesv1.Volume
		opts := volumesv1.CreateOpts{
			AvailabilityZone: az,
			Name:             request.Name,
			Size:             request.Size,
			VolumeType:       s.getVolumeType(request.Speed),
		}
		xerr = stacks.RetryableRemoteCall(
			func() (innerErr error) {
				vol, innerErr = volumesv1.Create(s.VolumeClient, opts).Extract()
				return innerErr
			},
			NormalizeError,
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
		opts := volumesv2.CreateOpts{
			AvailabilityZone: az,
			Name:             request.Name,
			Size:             request.Size,
			VolumeType:       s.getVolumeType(request.Speed),
		}
		var vol *volumesv2.Volume
		xerr = stacks.RetryableRemoteCall(
			func() (innerErr error) {
				vol, innerErr = volumesv2.Create(s.VolumeClient, opts).Extract()
				return innerErr
			},
			NormalizeError,
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

// InspectVolume returns the volume identified by id
func (s stack) InspectVolume(id string) (*abstract.Volume, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("stack.volume"), "(%s)", id).WithStopwatch().Entering().Exiting()

	var vol *volumesv2.Volume
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			vol, innerErr = volumesv2.Get(s.VolumeClient, id).Extract()
			return innerErr
		},
		NormalizeError,
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
func (s stack) ListVolumes() ([]*abstract.Volume, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("stack.volume"), "").WithStopwatch().Entering().Exiting()

	var vs []*abstract.Volume
	xerr := stacks.RetryableRemoteCall(
		func() error {
			vs = []*abstract.Volume{} // If call fails, need to restart list from 0...
			innerErr := volumesv2.List(s.VolumeClient, volumesv2.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
				list, err := volumesv2.ExtractVolumes(page)
				if err != nil {
					logrus.Errorf("Error listing volumes: volume extraction: %+v", err)
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
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil || len(vs) == 0 {
		return nil, xerr
	}

	return vs, nil
}

// DeleteVolume deletes the volume identified by id
func (s stack) DeleteVolume(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if id = strings.TrimSpace(id); id == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("stack.volume"), "("+id+")").WithStopwatch().Entering().Exiting()

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	var timeout = timings.OperationTimeout()
	xerr = retry.WhileUnsuccessful(
		func() error {
			innerXErr := stacks.RetryableRemoteCall(
				func() error {
					return volumesv2.Delete(s.VolumeClient, id, nil).ExtractErr()
				},
				NormalizeError,
			)
			switch innerXErr.(type) { // nolint
			case *fail.ErrInvalidRequest:
				return fail.NotAvailableError("volume not in state 'available'")
			case *fail.ErrNotFound:
				return retry.StopRetryError(innerXErr)
			}
			return innerXErr
		},
		timings.NormalDelay(),
		timeout,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return fail.Wrap(fail.Cause(xerr), "timeout")
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		default:
			return xerr
		}
	}
	return nil
}

// CreateVolumeAttachment attaches a volume to a host
// - 'name' of the volume attachment
// - 'volume' to attach
// - 'host' on which the volume is attached
func (s stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	if valid.IsNil(s) {
		return "", fail.InvalidInstanceError()
	}
	if request.Name = strings.TrimSpace(request.Name); request.Name == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("request.Name")
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("stack.volume"), "("+request.Name+")").WithStopwatch().Entering().Exiting()

	// Creates the attachment
	var va *volumeattach.VolumeAttachment
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			va, innerErr = volumeattach.Create(s.ComputeClient, request.HostID, volumeattach.CreateOpts{
				VolumeID: request.VolumeID,
			}).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return "", xerr
	}
	return va.ID, nil
}

// InspectVolumeAttachment returns the volume attachment identified by id
func (s stack) InspectVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	nilA := abstract.NewVolumeAttachment()
	if valid.IsNil(s) {
		return nilA, fail.InvalidInstanceError()
	}
	if serverID = strings.TrimSpace(serverID); serverID == "" {
		return nilA, fail.InvalidParameterCannotBeEmptyStringError("serverID")
	}
	if id = strings.TrimSpace(id); id == "" {
		return nilA, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("stack.volume"), "('"+serverID+"', '"+id+"')").WithStopwatch().Entering().Exiting()

	var va *volumeattach.VolumeAttachment
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			va, innerErr = volumeattach.Get(s.ComputeClient, serverID, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nilA, xerr
	}
	return &abstract.VolumeAttachment{
		ID:       va.ID,
		ServerID: va.ServerID,
		VolumeID: va.VolumeID,
		Device:   va.Device,
	}, nil
}

// ListVolumeAttachments lists available volume attachment
func (s stack) ListVolumeAttachments(serverID string) ([]*abstract.VolumeAttachment, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if serverID = strings.TrimSpace(serverID); serverID == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("serverID")
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("stack.volume"), "('"+serverID+"')").WithStopwatch().Entering().Exiting()

	var vs []*abstract.VolumeAttachment
	xerr := stacks.RetryableRemoteCall(
		func() error {
			vs = []*abstract.VolumeAttachment{} // If call fails, need to reset volume list to prevent duplicates
			return volumeattach.List(s.ComputeClient, serverID).EachPage(func(page pagination.Page) (bool, error) {
				list, err := volumeattach.ExtractVolumeAttachments(page)
				if err != nil {
					return false, err
				}
				for _, va := range list {
					ava := &abstract.VolumeAttachment{
						ID:       va.ID,
						ServerID: va.ServerID,
						VolumeID: va.VolumeID,
						Device:   va.Device,
					}
					vs = append(vs, ava)
				}
				return true, nil
			})
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	return vs, nil
}

func (s stack) Migrate(operation string, params map[string]interface{}) (ferr fail.Error) {
	return nil
}

// DeleteVolumeAttachment deletes the volume attachment identified by id
func (s stack) DeleteVolumeAttachment(serverID, vaID string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if serverID = strings.TrimSpace(serverID); serverID == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("serverID")
	}
	if vaID = strings.TrimSpace(vaID); vaID == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("vaID")
	}

	defer debug.NewTracer(context.Background(), tracing.ShouldTrace("stack.volume"), "('"+serverID+"', '"+vaID+"')").WithStopwatch().Entering().Exiting()

	return stacks.RetryableRemoteCall(
		func() error {
			return volumeattach.Delete(s.ComputeClient, serverID, vaID).ExtractErr()
		},
		NormalizeError,
	)
}
