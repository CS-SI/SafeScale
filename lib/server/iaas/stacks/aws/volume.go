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

package aws

import (
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// CreateVolume ...
func (s stack) CreateVolume(request abstract.VolumeRequest) (_ *abstract.Volume, xerr fail.Error) {
	nullAV := abstract.NewVolume()
	if s.IsNull() {
		return nullAV, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.volume"), "(%v)", request).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	query := ec2.CreateVolumeInput{
		Size:             aws.Int64(int64(request.Size)),
		VolumeType:       aws.String(toVolumeType(request.Speed)),
		AvailabilityZone: aws.String(s.AwsConfig.Zone),
	}
	var resp *ec2.Volume
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.CreateVolume(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}

	// FIXME: Defer volume destruction
	defer func() {
		if xerr != nil {
			query := ec2.DeleteVolumeInput{
				VolumeId: resp.VolumeId,
			}
			derr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
				func() error {
					_, innerErr := s.EC2Service.DeleteVolume(&query)
					return normalizeError(innerErr)
				},
				temporal.GetCommunicationTimeout(),
			)
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Volume"))
			}
		}
	}()

	tagQuery := ec2.CreateTagsInput{
		Resources: []*string{resp.VolumeId},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String("Name"),
				Value: aws.String(request.Name),
			},
		},
	}
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.EC2Service.CreateTags(&tagQuery)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}

	volume := abstract.Volume{
		ID:    aws.StringValue(resp.VolumeId),
		Name:  request.Name,
		Size:  int(aws.Int64Value(resp.Size)),
		Speed: toVolumeSpeed(resp.VolumeType),
		State: toVolumeState(resp.State),
	}
	return &volume, nil
}

// InspectVolume ...
func (s stack) InspectVolume(id string) (_ *abstract.Volume, xerr fail.Error) {
	nullAV := abstract.NewVolume()
	if s.IsNull() {
		return nullAV, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAV, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	var resp *ec2.DescribeVolumesOutput
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.DescribeVolumes(&ec2.DescribeVolumesInput{
				VolumeIds: []*string{aws.String(id)},
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}

	if len(resp.Volumes) == 0 {
		return nullAV, abstract.ResourceNotFoundError("Volume", id)
	}

	v := resp.Volumes[0]
	volume := abstract.Volume{
		ID:    aws.StringValue(v.VolumeId),
		Name:  aws.StringValue(v.VolumeId), // FIXME: Append name as Tags
		Size:  int(aws.Int64Value(v.Size)),
		Speed: toVolumeSpeed(v.VolumeType),
		State: toVolumeState(v.State),
	}
	return &volume, nil
}

func toVolumeType(speed volumespeed.Enum) string {
	switch speed {
	case volumespeed.COLD:
		return "sc1"
	case volumespeed.HDD:
		return "st1"
	case volumespeed.SSD:
		return "gp2"
	}
	return "gp2"
}

func toVolumeSpeed(t *string) volumespeed.Enum {
	if t == nil {
		return volumespeed.HDD
	}
	if *t == "sc1" {
		return volumespeed.COLD
	}
	if *t == "st1" {
		return volumespeed.HDD
	}
	if *t == "gp2" {
		return volumespeed.SSD
	}
	return volumespeed.HDD
}

func toVolumeState(s *string) volumestate.Enum {
	// VolumeStateCreating = "creating"
	// VolumeStateAvailable = "available"
	// VolumeStateInUse = "in-use"
	// VolumeStateDeleting = "deleting"
	// VolumeStateDeleted = "deleted"
	// VolumeStateError = "error"
	if s == nil {
		return volumestate.ERROR
	}
	if *s == "creating" {
		return volumestate.CREATING
	}
	if *s == "available" {
		return volumestate.AVAILABLE
	}
	if *s == "in-use" {
		return volumestate.USED
	}
	if *s == "deleting" {
		return volumestate.DELETING
	}
	if *s == "deleted" {
		return volumestate.DELETING
	}
	if *s == "error" {
		return volumestate.ERROR
	}
	return volumestate.OTHER
}

// ListVolumes ...
func (s stack) ListVolumes() (_ []abstract.Volume, xerr fail.Error) {
	var emptySlice []abstract.Volume
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	var resp *ec2.DescribeVolumesOutput
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.DescribeVolumes(&ec2.DescribeVolumesInput{})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return emptySlice, xerr
	}

	var volumes []abstract.Volume
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
			Speed: toVolumeSpeed(v.VolumeType),
			State: toVolumeState(v.State),
		}
		volumes = append(volumes, volume)
	}

	return volumes, nil
}

// DeleteVolume ...
func (s stack) DeleteVolume(id string) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	query := ec2.DeleteVolumeInput{
		VolumeId: aws.String(id),
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.EC2Service.DeleteVolume(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

// CreateVolumeAttachment ...
func (s stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (_ string, xerr fail.Error) {
	if s.IsNull() {
		return "", fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%v)", request).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	var resp *ec2.VolumeAttachment
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.AttachVolume(&ec2.AttachVolumeInput{
				Device:     aws.String(request.Name),
				InstanceId: aws.String(request.HostID),
				VolumeId:   aws.String(request.VolumeID),
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return "", xerr
	}
	return aws.StringValue(resp.Device) + aws.StringValue(resp.VolumeId), nil
}

// InspectVolumeAttachment ...
func (s stack) InspectVolumeAttachment(serverID, id string) (_ *abstract.VolumeAttachment, xerr fail.Error) {
	nullAVA := abstract.NewVolumeAttachment()
	if s.IsNull() {
		return nullAVA, fail.InvalidInstanceError()
	}
	if serverID == "" {
		return nullAVA, fail.InvalidParameterError("serverID", "cannot be empty string")
	}
	if id == "" {
		return nullAVA, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	query := ec2.DescribeVolumesInput{
		VolumeIds: []*string{aws.String(id)},
	}
	var resp *ec2.DescribeVolumesOutput
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.DescribeVolumes(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
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
func (s stack) ListVolumeAttachments(serverID string) (_ []abstract.VolumeAttachment, xerr fail.Error) {
	var emptySlice []abstract.VolumeAttachment
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}
	if serverID == "" {
		return emptySlice, fail.InvalidParameterError("serverID", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s)", serverID).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	query := ec2.DescribeVolumesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("attachment.instance-id"), // FIXME: What ?
				Values: []*string{aws.String(serverID)},
			},
		},
	}
	var resp *ec2.DescribeVolumesOutput
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, innerErr = s.EC2Service.DescribeVolumes(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}

	var vas []abstract.VolumeAttachment
	for _, v := range resp.Volumes {
		for _, va := range v.Attachments {
			vas = append(vas, abstract.VolumeAttachment{
				Device:   aws.StringValue(va.Device),
				ServerID: aws.StringValue(va.InstanceId),
				VolumeID: aws.StringValue(va.VolumeId),
			})
		}
	}
	return vas, nil
}

// DeleteVolumeAttachment ...
func (s stack) DeleteVolumeAttachment(serverID, id string) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if serverID == "" {
		return fail.InvalidParameterError("serverID", "cannot be empty string")
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.network"), "(%s, %s)", serverID, id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	query := ec2.DetachVolumeInput{
		InstanceId: aws.String(serverID),
		VolumeId:   aws.String(id),
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.EC2Service.DetachVolume(&query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}
