package aws

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeState"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

func (s *Stack) CreateVolume(request resources.VolumeRequest) (*resources.Volume, error) {
	v, err := s.EC2Service.CreateVolume(&ec2.CreateVolumeInput{
		Size:             aws.Int64(int64(request.Size)),
		VolumeType:       aws.String(toVolumeType(request.Speed)),
		AvailabilityZone: aws.String(s.AwsConfig.Zone),
	})
	if err != nil {
		return nil, err
	}

	_, err = s.EC2Service.CreateTags(&ec2.CreateTagsInput{
		Resources: []*string{v.VolumeId},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String("Name"),
				Value: aws.String(request.Name),
			},
		},
	})
	if err != nil {
		// FIXME Should we delete the volume if we cannot name it ?
		return nil, err
	}

	volume := resources.Volume{
		ID:    aws.StringValue(v.VolumeId),
		Name:  request.Name, // FIXME Better check the tag is present in v
		Size:  int(aws.Int64Value(v.Size)),
		Speed: toVolumeSpeed(v.VolumeType),
		State: toVolumeState(v.State),
	}
	return &volume, nil
}

func (s *Stack) GetVolume(id string) (*resources.Volume, error) {
	out, err := s.EC2Service.DescribeVolumes(&ec2.DescribeVolumesInput{
		VolumeIds: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, err
	}

	if len(out.Volumes) == 0 {
		return nil, resources.ResourceNotFoundError("Volume", id)
	}

	v := out.Volumes[0]
	volume := resources.Volume{
		ID:    aws.StringValue(v.VolumeId),
		Name:  aws.StringValue(v.VolumeId), // FIXME Append name as Tags
		Size:  int(aws.Int64Value(v.Size)),
		Speed: toVolumeSpeed(v.VolumeType),
		State: toVolumeState(v.State),
	}
	return &volume, nil
}

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

func (s *Stack) ListVolumes() ([]resources.Volume, error) {
	out, err := s.EC2Service.DescribeVolumes(&ec2.DescribeVolumesInput{})
	if err != nil {
		return nil, err
	}
	volumes := []resources.Volume{}
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

		volume := resources.Volume{
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
	_, err := s.EC2Service.DeleteVolume(&ec2.DeleteVolumeInput{
		VolumeId: aws.String(id),
	})
	return err
}

func (s *Stack) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (string, error) {
	va, err := s.EC2Service.AttachVolume(&ec2.AttachVolumeInput{
		Device:     aws.String(request.Name),
		InstanceId: aws.String(request.HostID),
		VolumeId:   aws.String(request.VolumeID),
	})
	if err != nil {
		return "", err
	}
	return aws.StringValue(va.Device) + aws.StringValue(va.VolumeId), nil
}

func (s *Stack) GetVolumeAttachment(serverID, id string) (*resources.VolumeAttachment, error) {
	out, err := s.EC2Service.DescribeVolumes(&ec2.DescribeVolumesInput{
		VolumeIds: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, err
	}
	v := out.Volumes[0]
	for _, va := range v.Attachments {
		if *va.InstanceId == serverID {
			return &resources.VolumeAttachment{
				Device:   aws.StringValue(va.Device),
				ServerID: aws.StringValue(va.InstanceId),
				VolumeID: aws.StringValue(va.VolumeId),
			}, nil
		}
	}
	return nil, fmt.Errorf("volume attachment of volume %s on server %s does not exist", serverID, id)
}

func (s *Stack) ListVolumeAttachments(serverID string) ([]resources.VolumeAttachment, error) {
	out, err := s.EC2Service.DescribeVolumes(&ec2.DescribeVolumesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name:   aws.String("attachment.instance-id"), // FIXME What ?
				Values: []*string{aws.String(serverID)},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	vas := []resources.VolumeAttachment{}
	for _, v := range out.Volumes {
		for _, va := range v.Attachments {
			vas = append(vas, resources.VolumeAttachment{
				Device:   aws.StringValue(va.Device),
				ServerID: aws.StringValue(va.InstanceId),
				VolumeID: aws.StringValue(va.VolumeId),
			})
		}
	}
	return vas, nil
}

func (s *Stack) DeleteVolumeAttachment(serverID, id string) error {
	_, err := s.EC2Service.DetachVolume(&ec2.DetachVolumeInput{
		InstanceId: aws.String(serverID),
		VolumeId:   aws.String(id),
	})
	return err
}
