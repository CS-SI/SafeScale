/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

	// log "github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeState"

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
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s *Stack) CreateVolume(request resources.VolumeRequest) (*resources.Volume, error) {
	panic("implement me")
}

// GetVolume returns the volume identified by id
func (s *Stack) GetVolume(id string) (*resources.Volume, error) {
	panic("implement me")
}

// ListVolumes list available volumes
func (s *Stack) ListVolumes() ([]resources.Volume, error) {
	panic("implement me")
}

// DeleteVolume deletes the volume identified by id
func (s *Stack) DeleteVolume(id string) error {
	panic("implement me")
}

// CreateVolumeAttachment attaches a volume to an host
// - 'name' the name of the volume attachment
// - 'volume' the volume to attach
// - 'host' on which the volume is attached
func (s *Stack) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (string, error) {
	panic("implement me")
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *Stack) GetVolumeAttachment(serverID, id string) (*resources.VolumeAttachment, error) {
	out, err := s.EC2.DescribeVolumes(&ec2.DescribeVolumesInput{
		VolumeIds: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, err
	}
	v := out.Volumes[0]
	for _, va := range v.Attachments {
		if *va.InstanceId == serverID {
			return &resources.VolumeAttachment{
				Device:   pStr(va.Device),
				ServerID: pStr(va.InstanceId),
				VolumeID: pStr(va.VolumeId),
			}, nil
		}
	}
	return nil, resources.ResourceNotAvailableError("volume", fmt.Sprintf("volume '%s' doesn't seem to be attached to host '%s'", id, serverID))
}

// ListVolumeAttachments lists available volume attachment
func (s *Stack) ListVolumeAttachments(serverID string) ([]resources.VolumeAttachment, error) {
	panic("implement me")

}

// DeleteVolumeAttachment deletes the volume attachment identifed by id
func (s *Stack) DeleteVolumeAttachment(serverID, id string) error {
	panic("implement me")
}
