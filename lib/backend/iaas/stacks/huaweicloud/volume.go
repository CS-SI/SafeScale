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

	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
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

func (instance *stack) getVolumeType(speed volumespeed.Enum) string {
	for t, s := range instance.cfgOpts.VolumeSpeeds {
		if s == speed {
			return t
		}
	}
	switch speed {
	case volumespeed.Ssd:
		return instance.getVolumeType(volumespeed.Hdd)
	case volumespeed.Hdd:
		return instance.getVolumeType(volumespeed.Cold)
	default:
		return ""
	}
}

func (instance *stack) getVolumeSpeed(vType string) volumespeed.Enum {
	speed, ok := instance.cfgOpts.VolumeSpeeds[vType]
	if ok {
		return speed
	}

	return volumespeed.Hdd
}

// CreateVolume creates a block volume
func (instance *stack) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	volume, xerr := instance.InspectVolume(ctx, request.Name)
	if xerr == nil && volume != nil {
		return nil, fail.DuplicateError("volume '%s' already exists", request.Name)
	}

	az, xerr := instance.SelectedAvailabilityZone(ctx)
	if xerr != nil {
		return nil, xerr
	}
	opts := volumes.CreateOpts{
		AvailabilityZone: az,
		Name:             request.Name,
		Size:             request.Size,
		VolumeType:       strings.ToUpper(instance.getVolumeType(request.Speed)),
	}
	var vol *volumes.Volume
	commRetryErr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			vol, innerErr = volumes.Create(instance.VolumeClient, opts).Extract()
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return nil, commRetryErr
	}

	v, _ := abstract.NewVolume(abstract.WithName(request.Name))
	v.ID = vol.ID
	v.Size = vol.Size
	v.Speed = instance.getVolumeSpeed(vol.VolumeType)
	v.State = toVolumeState(vol.Status)
	return v, nil
}

// InspectVolume returns the volume identified by id
func (instance *stack) InspectVolume(ctx context.Context, id string) (*abstract.Volume, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if id = strings.TrimSpace(id); id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	var vol *volumes.Volume
	commRetryErr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			vol, innerErr = volumes.Get(instance.VolumeClient, id).Extract()
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

	av, xerr := abstract.NewVolume(abstract.WithName(vol.Name))
	if xerr != nil {
		return nil, xerr
	}

	av.ID = vol.ID
	av.Size = vol.Size
	av.Speed = instance.getVolumeSpeed(vol.VolumeType)
	av.State = toVolumeState(vol.Status)
	return av, nil
}

// ListVolumes lists volumes
func (instance *stack) ListVolumes(ctx context.Context) ([]*abstract.Volume, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	var vs []*abstract.Volume
	commRetryErr := stacks.RetryableRemoteCall(ctx,
		func() error {
			innerErr := volumes.List(instance.VolumeClient, volumes.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
				list, err := volumes.ExtractVolumes(page)
				if err != nil {
					logrus.WithContext(ctx).Errorf("Error listing volumes: volume extraction: %+v", err)
					return false, err
				}
				for _, vol := range list {
					av, xerr := abstract.NewVolume(abstract.WithName(vol.Name))
					if xerr != nil {
						return false, xerr
					}

					av.ID = vol.ID
					av.Size = vol.Size
					av.Speed = instance.getVolumeSpeed(vol.VolumeType)
					av.State = toVolumeState(vol.Status)
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

// DeleteVolume deletes the volume identified by id
func (instance *stack) DeleteVolume(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if id = strings.TrimSpace(id); id == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.volume"), "("+id+")").WithStopwatch().Entering().Exiting()

	timings, xerr := instance.Timings()
	if xerr != nil {
		return xerr
	}

	timeout := timings.OperationTimeout()
	xerr = retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			innerXErr := stacks.RetryableRemoteCall(ctx,
				func() error {
					return volumes.Delete(instance.VolumeClient, id, nil).ExtractErr()
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
func (instance *stack) CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	if request.Name = strings.TrimSpace(request.Name); request.Name == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("request.Name")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.volume"), "("+request.Name+")").WithStopwatch().Entering().Exiting()

	// Creates the attachment
	var va *volumeattach.VolumeAttachment
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			va, innerErr = volumeattach.Create(instance.ComputeClient, request.HostID, volumeattach.CreateOpts{
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
func (instance *stack) InspectVolumeAttachment(ctx context.Context, serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if serverID = strings.TrimSpace(serverID); serverID == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("serverID")
	}
	if id = strings.TrimSpace(id); id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.volume"), "('"+serverID+"', '"+id+"')").WithStopwatch().Entering().Exiting()

	var va *volumeattach.VolumeAttachment
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			va, innerErr = volumeattach.Get(instance.ComputeClient, serverID, id).Extract()
			return innerErr
		},
		NormalizeError,
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
func (instance *stack) ListVolumeAttachments(ctx context.Context, serverID string) ([]*abstract.VolumeAttachment, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if serverID = strings.TrimSpace(serverID); serverID == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("serverID")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.volume"), "('"+serverID+"')").WithStopwatch().Entering().Exiting()

	var vs []*abstract.VolumeAttachment
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			vs = []*abstract.VolumeAttachment{} // If call fails, need to reset volume list to prevent duplicates
			return volumeattach.List(instance.ComputeClient, serverID).EachPage(func(page pagination.Page) (bool, error) {
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

// DeleteVolumeAttachment deletes the volume attachment identified by id
func (instance *stack) DeleteVolumeAttachment(ctx context.Context, serverID, vaID string) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if serverID = strings.TrimSpace(serverID); serverID == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("serverID")
	}
	if vaID = strings.TrimSpace(vaID); vaID == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("vaID")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.volume"), "('"+serverID+"', '"+vaID+"')").WithStopwatch().Entering().Exiting()

	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return volumeattach.Delete(instance.ComputeClient, serverID, vaID).ExtractErr()
		},
		NormalizeError,
	)
}
