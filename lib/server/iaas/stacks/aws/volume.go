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
	"fmt"

	"github.com/CS-SI/SafeScale/lib/utils/fail"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/volumestate"
)

func (s *Stack) CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, error) {
	v, err := s.EC2Service.CreateVolume(
		&ec2.CreateVolumeInput{
			Size:             aws.Int64(int64(request.Size)),
			VolumeType:       aws.String(toVolumeType(request.Speed)),
			AvailabilityZone: aws.String(s.AwsConfig.Zone),
		},
	)
	if err != nil {
		return nil, err
	}

	// FIXME: Defer volume destruction

	_, err = s.EC2Service.CreateTags(
		&ec2.CreateTagsInput{
			Resources: []*string{v.VolumeId},
			Tags: []*ec2.Tag{
				{
					Key:   aws.String("Name"),
					Value: aws.String(request.Name),
				},
			},
		},
	)
	if err != nil {
		// FIXME: Should we delete the volume if we cannot name it ?
		return nil, err
	}

	volume := abstract.Volume{
		ID:    aws.StringValue(v.VolumeId),
		Name:  request.Name,
		Size:  int(aws.Int64Value(v.Size)),
		Speed: toVolumeSpeed(v.VolumeType),
		State: toVolumeState(v.State),
	}
	return &volume, nil
}

func (s *Stack) GetVolume(id string) (*abstract.Volume, error) {
	out, err := s.EC2Service.DescribeVolumes(
		&ec2.DescribeVolumesInput{
			VolumeIds: []*string{aws.String(id)},
		},
	)
	if err != nil {
		return nil, err
	}

	if len(out.Volumes) == 0 {
		return nil, abstract.ResourceNotFoundError("Volume", id)
	}

	v := out.Volumes[0]
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

func (s *Stack) ListVolumes() ([]abstract.Volume, error) {
	out, err := s.EC2Service.DescribeVolumes(&ec2.DescribeVolumesInput{})
	if err != nil {
		return nil, err
	}
	volumes := []abstract.Volume{}
	for _, v := range out.Volumes {
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

func (s *Stack) DeleteVolume(id string) error {
	_, err := s.EC2Service.DeleteVolume(
		&ec2.DeleteVolumeInput{
			VolumeId: aws.String(id),
		},
	)
	return err
}

func (s *Stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, error) {
	va, err := s.EC2Service.AttachVolume(
		&ec2.AttachVolumeInput{
			Device:     aws.String(request.Name),
			InstanceId: aws.String(request.HostID),
			VolumeId:   aws.String(request.VolumeID),
		},
	)
	if err != nil {
		return "", err
	}
	return aws.StringValue(va.Device) + aws.StringValue(va.VolumeId), nil
}

func (s *Stack) GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, error) {
	out, err := s.EC2Service.DescribeVolumes(
		&ec2.DescribeVolumesInput{
			VolumeIds: []*string{aws.String(id)},
		},
	)
	if err != nil {
		return nil, err
	}
	v := out.Volumes[0]
	for _, va := range v.Attachments {
		if *va.InstanceId == serverID {
			return &abstract.VolumeAttachment{
				Device:   aws.StringValue(va.Device),
				ServerID: aws.StringValue(va.InstanceId),
				VolumeID: aws.StringValue(va.VolumeId),
			}, nil
		}
	}
	return nil, fail.Errorf(
		fmt.Sprintf("volume attachment of volume %s on server %s does not exist", serverID, id), nil,
	)
}

func (s *Stack) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, error) {
	out, err := s.EC2Service.DescribeVolumes(
		&ec2.DescribeVolumesInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   aws.String("attachment.instance-id"),
					Values: []*string{aws.String(serverID)},
				},
			},
		},
	)
	if err != nil {
		return nil, err
	}
	vas := []abstract.VolumeAttachment{}
	for _, v := range out.Volumes {
		for _, va := range v.Attachments {
			vas = append(
				vas, abstract.VolumeAttachment{
					Device:   aws.StringValue(va.Device),
					ServerID: aws.StringValue(va.InstanceId),
					VolumeID: aws.StringValue(va.VolumeId),
				},
			)
		}
	}
	return vas, nil
}

func (s *Stack) DeleteVolumeAttachment(serverID, id string) error {
	_, err := s.EC2Service.DetachVolume(
		&ec2.DetachVolumeInput{
			InstanceId: aws.String(serverID),
			VolumeId:   aws.String(id),
		},
	)
	return err
}
