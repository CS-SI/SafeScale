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

package aws

import (
	"context"
	"sort"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// CreateVolume ...
func (s stack) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (_ *abstract.Volume, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.volume"), "(%v)", request).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(ctx, &ferr)

	volumeType, minSize := fromAbstractVolumeSpeed(request.Speed)
	if request.Size < minSize {
		logrus.WithContext(ctx).Infof("AWS minimum size for requested volume type is %d (%d requested); using minimum size", minSize, request.Size)
		request.Size = 125
	}

	resp, xerr := s.rpcCreateVolume(ctx, aws.String(request.Name), int64(request.Size), volumeType)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := s.rpcDeleteVolume(context.Background(), resp.VolumeId); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Volume '%s'", request.Name))
			}
		}
	}()

	volume := abstract.Volume{
		ID:    aws.StringValue(resp.VolumeId),
		Name:  request.Name,
		Size:  int(aws.Int64Value(resp.Size)),
		Speed: toAbstractVolumeSpeed(resp.VolumeType),
		State: toAbstractVolumeState(resp.State),
	}
	return &volume, nil
}

// InspectVolume ...
func (s stack) InspectVolume(ctx context.Context, ref string) (_ *abstract.Volume, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if ref == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", ref).WithStopwatch().Entering().Exiting()
	// VPL: caller must log; sometimes InspectVolume() returned error is to be considered as an information, not a real error
	// defer fail.OnExitLogError(&xerr)

	var name string
	resp, xerr := s.rpcDescribeVolumeByName(ctx, aws.String(ref))
	if xerr != nil || resp == nil {
		switch xerr.(type) {
		case *fail.ErrNotFound, *fail.ErrInvalidRequest:
			resp, xerr = s.rpcDescribeVolumeByID(ctx, aws.String(ref))
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound, *fail.ErrInvalidRequest:
					return nil, fail.NotFoundError("failed to find Volume %s", ref)
				default:
					return nil, xerr
				}
			}
			if resp == nil {
				return nil, fail.NotFoundError("failed to find Volume %s", ref)
			}

			name = ref
		default:
			return nil, xerr
		}
	} else {
		for _, v := range resp.Tags {
			if aws.StringValue(v.Key) == tagNameLabel {
				name = aws.StringValue(v.Value)
				break
			}
		}
	}

	volume := abstract.Volume{
		ID:    aws.StringValue(resp.VolumeId),
		Name:  name,
		Size:  int(aws.Int64Value(resp.Size)),
		Speed: toAbstractVolumeSpeed(resp.VolumeType),
		State: toAbstractVolumeState(resp.State),
	}
	return &volume, nil
}

func fromAbstractVolumeSpeed(speed volumespeed.Enum) (string, int) {
	switch speed {
	case volumespeed.Cold:
		return "sc1", 125
	case volumespeed.Ssd:
		return "gp2", 1
	}
	return "st1", 125
}

func toAbstractVolumeSpeed(t *string) volumespeed.Enum {
	if t == nil {
		return volumespeed.Hdd
	}
	if *t == "sc1" {
		return volumespeed.Cold
	}
	if *t == "st1" {
		return volumespeed.Hdd
	}
	if *t == "gp2" {
		return volumespeed.Ssd
	}
	return volumespeed.Hdd
}

func toAbstractVolumeState(s *string) volumestate.Enum {
	// VolumeStateCreating = "creating"
	// VolumeStateAvailable = "available"
	// VolumeStateInUse = "in-use"
	// VolumeStateDeleting = "deleting"
	// VolumeStateDeleted = "deleted"
	// VolumeStateError = "error"
	if s == nil {
		return volumestate.Error
	}
	if *s == "creating" {
		return volumestate.Creating
	}
	if *s == "available" {
		return volumestate.Available
	}
	if *s == "in-use" {
		return volumestate.Used
	}
	if *s == "deleting" {
		return volumestate.Deleting
	}
	if *s == "deleted" {
		return volumestate.Deleting
	}
	if *s == "error" {
		return volumestate.Error
	}
	return volumestate.Unknown
}

// ListVolumes ...
func (s stack) ListVolumes(ctx context.Context) (_ []*abstract.Volume, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(ctx, &ferr)

	var resp *ec2.DescribeVolumesOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.DescribeVolumes(&ec2.DescribeVolumesInput{})
			return normalizeError(innerErr)
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	var volumes []*abstract.Volume
	for _, v := range resp.Volumes {
		volumeName := aws.StringValue(v.VolumeId)
		if len(v.Tags) > 0 {
			for _, tag := range v.Tags {
				if tag != nil {
					if aws.StringValue(tag.Key) == "Name" {
						volumeName = aws.StringValue(tag.Value)
					}
				}
			}
		}

		volume := abstract.Volume{
			ID:    aws.StringValue(v.VolumeId),
			Name:  volumeName,
			Size:  int(aws.Int64Value(v.Size)),
			Speed: toAbstractVolumeSpeed(v.VolumeType),
			State: toAbstractVolumeState(v.State),
		}
		volumes = append(volumes, &volume)
	}

	return volumes, nil
}

// DeleteVolume ...
func (s stack) DeleteVolume(ctx context.Context, id string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(ctx, &ferr)

	query := ec2.DeleteVolumeInput{
		VolumeId: aws.String(id),
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, innerErr := s.EC2Service.DeleteVolume(&query)
			return normalizeError(innerErr)
		},
		normalizeError,
	)
}

// CreateVolumeAttachment ...
func (s stack) CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (_ string, ferr fail.Error) {
	if valid.IsNil(s) {
		return "", fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%v)", request).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(ctx, &ferr)

	availableDevices := initAvailableDevices()
	var resp *ec2.VolumeAttachment
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			var (
				deviceName string
				innerXErr  fail.Error
			)
			deviceName, availableDevices, innerXErr = s.findNextAvailableDevice(ctx, request.HostID, availableDevices)
			if innerXErr != nil {
				return innerXErr
			}

			resp, innerErr = s.EC2Service.AttachVolume(&ec2.AttachVolumeInput{
				Device:     aws.String(deviceName), // aws.String(request.Name),
				InstanceId: aws.String(request.HostID),
				VolumeId:   aws.String(request.VolumeID),
			})
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return "", xerr
	}

	// In AWS, there is no volume attachment ID, the value returned is the volumeID alone
	return aws.StringValue(resp.VolumeId), nil
}

// initAvailableDevices inits a map with potentially usable device names
// For AWS, recommended names for EBS volume is /dev/sd[f-z], allowing 21 attached volumes on one Host
func initAvailableDevices() map[string]struct{} {
	// Initialize the map of possible slots
	availableSlots := make(map[string]struct{})
	for i := int('f'); i <= int('z'); i++ {
		availableSlots[string(byte(i))] = struct{}{}
	}
	return availableSlots
}

func (s stack) findNextAvailableDevice(ctx context.Context, hostID string, availableSlots map[string]struct{}) (string, map[string]struct{}, fail.Error) {
	instance, xerr := s.rpcDescribeInstanceByID(ctx, aws.String(hostID))
	if xerr != nil {
		return "", availableSlots, xerr
	}

	var sdCount, xvdCount uint
	// walk through all the devices already attached to the Host and remove from available slots the ones that
	// are already used
	for _, v := range instance.BlockDeviceMappings {
		var suffix string
		deviceName := aws.StringValue(v.DeviceName)
		if strings.HasPrefix(deviceName, "/dev/sd") { // nolint
			suffix = strings.TrimPrefix(deviceName, "/dev/sd")
			sdCount++
		} else if strings.HasPrefix(deviceName, "/dev/xvd") {
			suffix = strings.TrimPrefix(deviceName, "/dev/xvd")
			xvdCount++
		} else {
			continue
		}
		delete(availableSlots, suffix)
	}
	if len(availableSlots) == 0 {
		return "", availableSlots, fail.OverflowError(nil, 25, "no more devices available to attach a volume on Host %s", hostID)
	}

	// extract keys from availableSlots
	availableKeys := make([]string, 0, len(availableSlots))
	for k := range availableSlots {
		availableKeys = append(availableKeys, k)
	}
	sort.Strings(availableKeys)
	// The winner is the first entry in availableKeys

	// decide what prefix to use for device name
	var deviceName string
	if sdCount >= xvdCount {
		deviceName = "sd"
	} else {
		deviceName = "xvd"
	}
	deviceName += availableKeys[0]
	delete(availableSlots, availableKeys[0]) // selected, remove it from availableSlots for optional next rounds
	return deviceName, availableSlots, nil
}

// InspectVolumeAttachment returns information about a volume attachment
func (s stack) InspectVolumeAttachment(ctx context.Context, serverID, id string) (_ *abstract.VolumeAttachment, ferr fail.Error) {
	nilA := abstract.NewVolumeAttachment()
	if valid.IsNil(s) {
		return nilA, fail.InvalidInstanceError()
	}
	if serverID == "" {
		return nilA, fail.InvalidParameterError("serverID", "cannot be empty string")
	}
	if id == "" {
		return nilA, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()
	// VPL: caller MUST log; sometimes, InspectVolumeAttachment returned error may be considered as an information of non-existence, not a real error
	// defer fail.OnExitLogError(&xerr)

	query := ec2.DescribeVolumesInput{
		VolumeIds: []*string{aws.String(id)},
	}
	var resp *ec2.DescribeVolumesOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeVolumes(&query)
			return normalizeError(err)
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	v := resp.Volumes[0]
	for _, va := range v.Attachments {
		if *va.InstanceId == serverID {
			return &abstract.VolumeAttachment{
				Device:   aws.StringValue(va.Device),
				ServerID: aws.StringValue(va.InstanceId),
				VolumeID: aws.StringValue(va.VolumeId),
			}, nil
		}
	}
	return nil, fail.NotFoundError("volume attachment of volume %s on server %s does not exist", serverID, id)
}

// ListVolumeAttachments ...
func (s stack) ListVolumeAttachments(ctx context.Context, serverID string) (_ []*abstract.VolumeAttachment, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if serverID == "" {
		return nil, fail.InvalidParameterError("serverID", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", serverID).WithStopwatch().Entering().Exiting()

	query := ec2.DescribeVolumesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("attachment.instance-id"),
				Values: []*string{aws.String(serverID)},
			},
		},
	}
	var resp *ec2.DescribeVolumesOutput
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = s.EC2Service.DescribeVolumes(&query)
			return normalizeError(err)
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	var vas []*abstract.VolumeAttachment
	for _, v := range resp.Volumes {
		for _, va := range v.Attachments {
			va := va
			vas = append(vas, &abstract.VolumeAttachment{
				Device:   aws.StringValue(va.Device),
				ServerID: aws.StringValue(va.InstanceId),
				VolumeID: aws.StringValue(va.VolumeId),
			})
		}
	}
	return vas, nil
}

func (s stack) Migrate(ctx context.Context, operation string, params map[string]interface{}) (ferr fail.Error) {
	return nil
}

// DeleteVolumeAttachment detach from server 'serverID' the volume 'id'
func (s stack) DeleteVolumeAttachment(ctx context.Context, serverID, id string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if serverID == "" {
		return fail.InvalidParameterError("serverID", "cannot be empty string")
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s, %s)", serverID, id).WithStopwatch().Entering().Exiting()

	query := ec2.DetachVolumeInput{
		InstanceId: aws.String(serverID),
		VolumeId:   aws.String(id),
	}
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			_, err := s.EC2Service.DetachVolume(&query)
			return normalizeError(err)
		},
		normalizeError,
	)
}
