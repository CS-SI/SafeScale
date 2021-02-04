package outscale

import (
	"fmt"
	"time"

	"github.com/antihax/optional"
	"github.com/sirupsen/logrus"

	"github.com/outscale-dev/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/volumestate"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// CreateVolume creates a block volume
func (s *Stack) CreateVolume(request abstract.VolumeRequest) (_ *abstract.Volume, xerr fail.Error) {
	v, _ := s.GetVolumeByName(request.Name)
	if v != nil {
		return nil, abstract.ResourceDuplicateError("volume", request.Name)
	}
	IOPS := 0
	if request.Speed == volumespeed.SSD {
		IOPS = request.Size * 300
		if IOPS > 13000 {
			IOPS = 13000
		}
	}
	createVolumeRequest := osc.CreateVolumeRequest{
		DryRun:        false,
		Iops:          int32(IOPS),
		Size:          int32(request.Size),
		SnapshotId:    "",
		SubregionName: s.Options.Compute.Subregion,
		VolumeType:    s.volumeType(request.Speed),
	}
	res, _, err := s.client.VolumeApi.CreateVolume(
		s.auth, &osc.CreateVolumeOpts{
			CreateVolumeRequest: optional.NewInterface(createVolumeRequest),
		},
	)
	if err != nil {
		return nil, normalizeError(err)
	}

	ov := res.Volume

	defer func() {
		if xerr != nil {
			if !fail.ImplementsCauser(err) {
				xerr = fail.Wrap(xerr, "")
			}

			derr := s.DeleteVolume(ov.VolumeId)
			if derr != nil {
				err = fail.AddConsequence(xerr, derr)
			}
		}
	}()

	// FIXME: Add resource tags here
	tags := make(map[string]string)
	tags["name"] = request.Name

	tags["ManagedBy"] = "safescale"
	tags["DeclaredInBucket"] = s.configurationOptions.MetadataBucket
	tags["CreationDate"] = time.Now().Format(time.RFC3339)

	err = s.setResourceTags(
		res.Volume.VolumeId, tags,
	)
	if err != nil {
		return nil, err
	}
	err = s.WaitForVolumeState(ov.VolumeId, volumestate.AVAILABLE)
	if err != nil {
		return nil, err
	}
	volume := abstract.NewVolume()
	volume.ID = ov.VolumeId
	volume.Speed = s.volumeSpeed(ov.VolumeType)
	volume.Size = int(ov.Size)
	volume.State = volumestate.AVAILABLE
	volume.Name = request.Name

	tagged, _ := s.getResourceTags(res.Volume.VolumeId)
	volume.Tags["CreationDate"] = tagged["CreationDate"]
	volume.Tags["ManagedBy"] = tagged["ManagedBy"]
	volume.Tags["DeclaredInBucket"] = tagged["DeclaredInBucket"]
	return volume, nil
}

func (s *Stack) volumeSpeed(t string) volumespeed.Enum {
	if s, ok := s.configurationOptions.VolumeSpeeds[t]; ok {
		return s
	}
	return volumespeed.HDD
}

func (s *Stack) volumeType(speed volumespeed.Enum) string {
	for t, s := range s.configurationOptions.VolumeSpeeds {
		if s == speed {
			return t
		}
	}
	return s.volumeType(volumespeed.HDD)
}

func volumeState(state string) volumestate.Enum {
	if state == "creating" {
		return volumestate.CREATING
	}
	if state == "available" {
		return volumestate.AVAILABLE
	}
	if state == "in-use" {
		return volumestate.USED
	}
	if state == "deleting" {
		return volumestate.DELETING
	}
	if state == "error" {
		return volumestate.ERROR
	}
	return volumestate.OTHER
}

// WaitForVolumeState wait for volume to be in the specified state
func (s *Stack) WaitForVolumeState(volumeID string, state volumestate.Enum) error {
	err := retry.WhileUnsuccessfulDelay5SecondsTimeout(
		func() error {
			vol, err := s.GetVolume(volumeID)
			if err != nil {
				return fail.Errorf("", err)
			}
			if vol.State != state {
				return fail.Errorf("wrong state", nil)
			}
			return nil
		}, temporal.GetHostTimeout(),
	)
	return err
}

// GetVolume returns the volume identified by id
func (s *Stack) GetVolume(id string) (*abstract.Volume, fail.Error) {
	readVolumesRequest := osc.ReadVolumesRequest{
		Filters: osc.FiltersVolume{
			VolumeIds: []string{id},
		},
	}
	res, _, err := s.client.VolumeApi.ReadVolumes(
		s.auth, &osc.ReadVolumesOpts{
			ReadVolumesRequest: optional.NewInterface(readVolumesRequest),
		},
	)
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(res.Volumes) > 1 {
		return nil, fail.InconsistentError("Invalid provider response")
	}
	if len(res.Volumes) == 0 {
		return nil, nil
	}

	ov := res.Volumes[0]
	volume := abstract.NewVolume()
	volume.ID = ov.VolumeId
	volume.Speed = s.volumeSpeed(ov.VolumeType)
	volume.Size = int(ov.Size)
	volume.State = volumeState(ov.State)
	volume.Name = getResourceTag(ov.Tags, "name", "")

	tagged, _ := s.getResourceTags(ov.VolumeId)
	volume.Tags["CreationDate"] = tagged["CreationDate"]
	volume.Tags["ManagedBy"] = tagged["ManagedBy"]
	volume.Tags["DeclaredInBucket"] = tagged["DeclaredInBucket"]

	return volume, nil
}

// GetVolumeByName returns the volume with name name
func (s *Stack) GetVolumeByName(name string) (*abstract.Volume, fail.Error) {
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}
	subregion := s.Options.Compute.Subregion
	readVolumesRequest := osc.ReadVolumesRequest{
		Filters: osc.FiltersVolume{
			Tags:           []string{fmt.Sprintf("name=%s", name)},
			SubregionNames: []string{subregion},
		},
	}
	res, _, err := s.client.VolumeApi.ReadVolumes(
		s.auth, &osc.ReadVolumesOpts{
			ReadVolumesRequest: optional.NewInterface(readVolumesRequest),
		},
	)
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(res.Volumes) == 0 {
		return nil, fail.NotFoundError(fmt.Sprintf("No volume named %s", name))
	}

	if len(res.Volumes) > 1 {
		return nil, fail.InconsistentError(fmt.Sprintf("two volumes with name %s in subregion %s", name, subregion))
	}
	ov := res.Volumes[0]
	volume := abstract.NewVolume()
	volume.ID = ov.VolumeId
	volume.Speed = s.volumeSpeed(ov.VolumeType)
	volume.Size = int(ov.Size)
	volume.State = volumeState(ov.State)
	volume.Name = name

	tagged, _ := s.getResourceTags(ov.VolumeId)
	volume.Tags["CreationDate"] = tagged["CreationDate"]
	volume.Tags["ManagedBy"] = tagged["ManagedBy"]
	volume.Tags["DeclaredInBucket"] = tagged["DeclaredInBucket"]
	return volume, nil
}

// ListVolumes list available volumes
func (s *Stack) ListVolumes() ([]abstract.Volume, fail.Error) {
	subregion := s.Options.Compute.Subregion
	readVolumesRequest := osc.ReadVolumesRequest{
		Filters: osc.FiltersVolume{
			SubregionNames: []string{subregion},
		},
	}
	res, _, err := s.client.VolumeApi.ReadVolumes(
		s.auth, &osc.ReadVolumesOpts{
			ReadVolumesRequest: optional.NewInterface(readVolumesRequest),
		},
	)
	if err != nil {
		return nil, normalizeError(err)
	}

	var volumes []abstract.Volume
	for _, ov := range res.Volumes {
		volume := abstract.NewVolume()
		volume.ID = ov.VolumeId
		volume.Speed = s.volumeSpeed(ov.VolumeType)
		volume.Size = int(ov.Size)
		volume.State = volumeState(ov.State)
		volume.Name = getResourceTag(ov.Tags, "name", "")
		tagged, _ := s.getResourceTags(ov.VolumeId)
		volume.Tags["CreationDate"] = tagged["CreationDate"]
		volume.Tags["ManagedBy"] = tagged["ManagedBy"]
		volume.Tags["DeclaredInBucket"] = tagged["DeclaredInBucket"]
		volumes = append(volumes, *volume)
	}
	return volumes, nil
}

// DeleteVolume deletes the volume identified by id
func (s *Stack) DeleteVolume(id string) error {
	deleteVolumeRequest := osc.DeleteVolumeRequest{
		VolumeId: id,
	}
	_, _, err := s.client.VolumeApi.DeleteVolume(
		s.auth, &osc.DeleteVolumeOpts{
			DeleteVolumeRequest: optional.NewInterface(deleteVolumeRequest),
		},
	)
	return normalizeError(err)
}

func freeDevice(usedDevices []string, device string) bool {
	for _, usedDevice := range usedDevices {
		if device == usedDevice {
			return false
		}
	}
	return true
}

func (s *Stack) getFirstFreeDeviceName(serverID string) (string, fail.Error) {
	var usedDeviceNames []string
	atts, _ := s.ListVolumeAttachments(serverID)
	if atts == nil {
		if len(s.deviceNames) > 0 {
			return s.deviceNames[0], nil
		}
		return "", fail.InconsistentError("device names is empty")
	}
	for _, att := range atts {
		usedDeviceNames = append(usedDeviceNames, att.Device)
	}
	for _, deviceName := range s.deviceNames {
		if freeDevice(usedDeviceNames, deviceName) {
			return deviceName, nil
		}
	}
	return "", nil
}

// CreateVolumeAttachment attaches a volume to an host
func (s *Stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	firstDeviceName, err := s.getFirstFreeDeviceName(request.HostID)
	if err != nil {
		return "", normalizeError(err)
	}

	logrus.Warnf("Trying to attach a device with name %s", firstDeviceName)

	linkVolumeRequest := osc.LinkVolumeRequest{
		DeviceName: firstDeviceName,
		VmId:       request.HostID,
		VolumeId:   request.VolumeID,
	}
	_, _, err = s.client.VolumeApi.LinkVolume(
		s.auth, &osc.LinkVolumeOpts{
			LinkVolumeRequest: optional.NewInterface(linkVolumeRequest),
		},
	)
	if err != nil {
		return "", normalizeErrorWithReason("linking volume api", err)
	}
	return request.VolumeID, nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *Stack) GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	readVolumesRequest := osc.ReadVolumesRequest{
		Filters: osc.FiltersVolume{
			VolumeIds: []string{id},
		},
	}
	res, _, err := s.client.VolumeApi.ReadVolumes(
		s.auth, &osc.ReadVolumesOpts{
			ReadVolumesRequest: optional.NewInterface(readVolumesRequest),
		},
	)
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(res.Volumes) > 1 {
		return nil, fail.InconsistentError("Invalid provider response")
	}
	if len(res.Volumes) == 0 {
		return nil, nil
	}

	ov := res.Volumes[0]
	for _, lv := range ov.LinkedVolumes {
		if lv.VmId == serverID {
			return &abstract.VolumeAttachment{
				VolumeID:   id,
				ServerID:   serverID,
				Device:     lv.DeviceName,
				Name:       "",
				MountPoint: "",
				Format:     "",
				ID:         id,
			}, nil
		}
	}
	return nil, nil

}

// ListVolumeAttachments lists available volume attachment
func (s *Stack) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, fail.Error) {
	volumes, err := s.ListVolumes()
	if err != nil {
		return nil, err
	}
	var atts []abstract.VolumeAttachment
	for _, v := range volumes {
		att, _ := s.GetVolumeAttachment(serverID, v.ID)
		if att != nil {
			atts = append(atts, *att)
		}
	}
	return atts, nil
}

// DeleteVolumeAttachment deletes the volume attachment identified by id
func (s *Stack) DeleteVolumeAttachment(serverID, id string) error {
	unlinkVolumeRequest := osc.UnlinkVolumeRequest{
		VolumeId: id,
	}
	_, _, err := s.client.VolumeApi.UnlinkVolume(
		s.auth, &osc.UnlinkVolumeOpts{
			UnlinkVolumeRequest: optional.NewInterface(unlinkVolumeRequest),
		},
	)
	if err != nil {
		return normalizeError(err)
	}
	return s.WaitForVolumeState(id, volumestate.AVAILABLE)
}
