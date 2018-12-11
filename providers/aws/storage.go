/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeState"
)

func toVolumeType(speed VolumeSpeed.Enum) string {
	switch speed {
	case VolumeSpeed.COLD:
		return "sc1"
	case VolumeSpeed.HDD:
		return "st1"
	case VolumeSpeed.SSD:
		return "gp2"
	}
	return "st1"
}

func toVolumeSpeed(t *string) VolumeSpeed.Enum {
	if t == nil {
		return VolumeSpeed.HDD
	}
	if *t == "sc1" {
		return VolumeSpeed.COLD
	}
	if *t == "st1" {
		return VolumeSpeed.HDD
	}
	if *t == "gp2" {
		return VolumeSpeed.SSD
	}
	return VolumeSpeed.HDD
}

func toVolumeState(s *string) VolumeState.Enum {
	// VolumeStateCreating = "creating"
	// VolumeStateAvailable = "available"
	// VolumeStateInUse = "in-use"
	// VolumeStateDeleting = "deleting"
	// VolumeStateDeleted = "deleted"
	// VolumeStateError = "error"
	if s == nil {
		return VolumeState.ERROR
	}
	if *s == "creating" {
		return VolumeState.CREATING
	}
	if *s == "available" {
		return VolumeState.AVAILABLE
	}
	if *s == "in-use" {
		return VolumeState.USED
	}
	if *s == "deleting" {
		return VolumeState.DELETING
	}
	if *s == "deleted" {
		return VolumeState.DELETING
	}
	if *s == "error" {
		return VolumeState.ERROR
	}
	return VolumeState.OTHER
}

// CreateVolume creates a block volume
//- name is the name of the volume
//- size is the size of the volume in GB
//- volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (c *Client) CreateVolume(request model.VolumeRequest) (*model.Volume, error) {
	// Check if a volume already exists with the same name
	volume, err := c.GetVolume(request.Name)
	if err != nil {
		return nil, err
	}
	if volume != nil {
		return nil, fmt.Errorf("Volume '%s' already exists", request.Name)
	}

	v, err := c.EC2.CreateVolume(&ec2.CreateVolumeInput{
		Size:       aws.Int64(int64(request.Size)),
		VolumeType: aws.String(toVolumeType(request.Speed)),
	})
	if err != nil {
		return nil, err
	}

	volume = model.NewVolume()
	volume.ID = pStr(v.VolumeId)
	volume.Name = request.Name
	volume.Size = int(*(v.Size))
	volume.Speed = toVolumeSpeed(v.VolumeType)
	volume.State = toVolumeState(v.State)

	return volume, nil
}

// GetVolume returns the volume identified by id
func (c *Client) GetVolume(id string) (*model.Volume, error) {
	out, err := c.EC2.DescribeVolumes(&ec2.DescribeVolumesInput{
		VolumeIds: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, err
	}
	v := out.Volumes[0]

	volume := model.Volume{
		ID: pStr(v.VolumeId),
		// Name:  name,
		Size:  int(*v.Size),
		Speed: toVolumeSpeed(v.VolumeType),
		State: toVolumeState(v.State),
	}
	return &volume, nil
}

// ListVolumes list available volumes
func (c *Client) ListVolumes() ([]model.Volume, error) {
	out, err := c.EC2.DescribeVolumes(&ec2.DescribeVolumesInput{})
	if err != nil {
		return nil, err
	}
	volumes := []model.Volume{}
	for _, v := range out.Volumes {
		// name, err := c.getVolumeName(*v.VolumeId)
		// if err != nil {
		// 	return nil, err
		// }
		volume := model.Volume{
			ID: pStr(v.VolumeId),
			// Name:  name,
			Size: int(*v.Size),
			// Name:  name,
			Speed: toVolumeSpeed(v.VolumeType),
			State: toVolumeState(v.State),
		}
		volumes = append(volumes, volume)
	}

	return volumes, nil
}

// DeleteVolume deletes the volume identified by id
func (c *Client) DeleteVolume(id string) error {
	_, err := c.EC2.DeleteVolume(&ec2.DeleteVolumeInput{
		VolumeId: aws.String(id),
	})
	return err
}

// CreateVolumeAttachment attaches a volume to an host
//- name the name of the volume attachment
//- volume the volume to attach
//- host on which the volume is attached
func (c *Client) CreateVolumeAttachment(request model.VolumeAttachmentRequest) (string, error) {
	va, err := c.EC2.AttachVolume(&ec2.AttachVolumeInput{
		InstanceId: aws.String(request.HostID),
		VolumeId:   aws.String(request.VolumeID),
	})
	if err != nil {
		return "", err
	}
	return *va.VolumeId, nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (c *Client) GetVolumeAttachment(hostID, vaID string) (*model.VolumeAttachment, error) {
	out, err := c.EC2.DescribeVolumes(&ec2.DescribeVolumesInput{
		VolumeIds: []*string{aws.String(vaID)},
	})
	if err != nil {
		return nil, err
	}
	v := out.Volumes[0]
	for _, va := range v.Attachments {
		if *va.InstanceId == hostID {
			return &model.VolumeAttachment{
				Device:   pStr(va.Device),
				ServerID: pStr(va.InstanceId),
				VolumeID: pStr(va.VolumeId),
			}, nil
		}
	}
	return nil, fmt.Errorf("Volume attachment of volume '%s' to host '%s' doesn't exist", hostID, vaID)
}

// ListVolumeAttachments lists existing volume attachments
func (c *Client) ListVolumeAttachments(serverID string) ([]model.VolumeAttachment, error) {
	out, err := c.EC2.DescribeVolumes(&ec2.DescribeVolumesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name:   aws.String("attachment.instance-id"),
				Values: []*string{aws.String(serverID)},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	vas := []model.VolumeAttachment{}
	for _, v := range out.Volumes {
		for _, va := range v.Attachments {
			vas = append(vas, model.VolumeAttachment{
				Device:   pStr(va.Device),
				ServerID: pStr(va.InstanceId),
				VolumeID: pStr(va.VolumeId),
			})
		}
	}
	return vas, nil
}

// DeleteVolumeAttachment deletes the volume attachment identifed by id
func (c *Client) DeleteVolumeAttachment(hostID, vaID string) error {
	_, err := c.EC2.DetachVolume(&ec2.DetachVolumeInput{
		InstanceId: aws.String(hostID),
		VolumeId:   aws.String(vaID),
	})
	return err
}
