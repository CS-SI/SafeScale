/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumestate"
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
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (instance *stack) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (volume *abstract.Volume, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if request.Name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("request.Name")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.volume"), "(%s)", request.Name).WithStopwatch().Entering().Exiting()

	az, xerr := instance.SelectedAvailabilityZone(ctx)
	if xerr != nil { // nolint
		return nil, abstract.ResourceDuplicateError("volume", request.Name)
	}

	v, xerr := abstract.NewVolume(abstract.WithName(request.Name))
	if xerr != nil {
		return nil, xerr
	}

	switch instance.versions["volume"] {
	case "v1":
		var vol *volumesv1.Volume
		opts := volumesv1.CreateOpts{
			AvailabilityZone: az,
			Name:             request.Name,
			Size:             request.Size,
			VolumeType:       instance.getVolumeType(request.Speed),
		}
		xerr = stacks.RetryableRemoteCall(ctx,
			func() (innerErr error) {
				vol, innerErr = volumesv1.Create(instance.VolumeClient, opts).Extract()
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

		v.ID = vol.ID
		v.Size = vol.Size
		v.Speed = instance.getVolumeSpeed(vol.VolumeType)
		v.State = toVolumeState(vol.Status)

	case "v2":
		opts := volumesv2.CreateOpts{
			AvailabilityZone: az,
			Name:             request.Name,
			Size:             request.Size,
			VolumeType:       instance.getVolumeType(request.Speed),
		}
		var vol *volumesv2.Volume
		xerr = stacks.RetryableRemoteCall(ctx,
			func() (innerErr error) {
				vol, innerErr = volumesv2.Create(instance.VolumeClient, opts).Extract()
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

		v.ID = vol.ID
		v.Size = vol.Size
		v.Speed = instance.getVolumeSpeed(vol.VolumeType)
		v.State = toVolumeState(vol.Status)

	default:
		xerr = fail.NotImplementedError("unmanaged service 'volume' version '%s'", instance.versions["volume"])
	}
	if xerr != nil {
		return nil, xerr
	}

	return v, nil
}

// InspectVolume returns the volume identified by id
func (instance *stack) InspectVolume(ctx context.Context, id string) (*abstract.Volume, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.volume"), "(%s)", id).WithStopwatch().Entering().Exiting()

	var vol *volumesv2.Volume
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			vol, innerErr = volumesv2.Get(instance.VolumeClient, id).Extract()
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

// ListVolumes returns the list of all volumes known on the current tenant
func (instance *stack) ListVolumes(ctx context.Context) ([]*abstract.Volume, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.volume"), "").WithStopwatch().Entering().Exiting()

	var vs []*abstract.Volume
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			vs = []*abstract.Volume{} // If call fails, need to restart list from 0...
			innerErr := volumesv2.List(instance.VolumeClient, volumesv2.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
				list, err := volumesv2.ExtractVolumes(page)
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

	var timeout = timings.OperationTimeout()
	xerr = retry.WhileUnsuccessful(
		func() error {
			innerXErr := stacks.RetryableRemoteCall(ctx,
				func() error {
					return volumesv2.Delete(instance.VolumeClient, id, nil).ExtractErr()
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
	nilA := abstract.NewVolumeAttachment()
	if valid.IsNil(instance) {
		return nilA, fail.InvalidInstanceError()
	}
	if serverID = strings.TrimSpace(serverID); serverID == "" {
		return nilA, fail.InvalidParameterCannotBeEmptyStringError("serverID")
	}
	if id = strings.TrimSpace(id); id == "" {
		return nilA, fail.InvalidParameterCannotBeEmptyStringError("id")
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

func (instance *stack) Migrate(ctx context.Context, operation string, params map[string]interface{}) (ferr fail.Error) {
	return nil
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
