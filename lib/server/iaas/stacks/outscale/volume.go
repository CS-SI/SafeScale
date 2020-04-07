package outscale

import (
	"fmt"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
	"github.com/outscale/osc-sdk-go/oapi"
)

func (s *Stack) deleteVolumeOnError(err error, v *oapi.Volume) error {
	err2 := s.DeleteVolume(v.VolumeId)
	if err2 != nil {
		return scerr.Wrap(err, err2.Error())
	}
	return err
}

// CreateVolume creates a block volume
func (s *Stack) CreateVolume(request resources.VolumeRequest) (*resources.Volume, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if request.Name == "" {
		return nil, scerr.InvalidParameterError("volume name", "cannot be empty string")
	}
	v, _ := s.GetVolumeByName(request.Name)
	if v != nil {
		return nil, resources.ResourceDuplicateError("volume", request.Name)
	}
	iops := 0
	if request.Speed == volumespeed.SSD {
		iops = request.Size * 300
		if iops > 13000 {
			iops = 13000
		}
	}
	res, err := s.client.POST_CreateVolume(oapi.CreateVolumeRequest{
		Size:          int64(request.Size),
		VolumeType:    s.volumeType(request.Speed),
		SubregionName: s.Options.Compute.Subregion,
		Iops:          int64(iops),
	})
	if err != nil {
		return nil, err
	}
	if res == nil || res.OK == nil {
		return nil, scerr.InconsistentError("Invalid provider response")
	}

	ov := res.OK.Volume
	err = s.setResourceTags(res.OK.Volume.VolumeId, map[string]string{
		"name": request.Name,
	})
	if err != nil {
		return nil, s.deleteVolumeOnError(err, &ov)
	}
	err = s.WaitForVolumeState(ov.VolumeId, volumestate.AVAILABLE)
	if err != nil {
		return nil, s.deleteVolumeOnError(err, &ov)
	}
	volume := resources.NewVolume()
	volume.ID = ov.VolumeId
	volume.Speed = s.volumeSpeed(ov.VolumeType)
	volume.Size = int(ov.Size)
	volume.State = volumestate.AVAILABLE
	volume.Name = request.Name
	return volume, nil
}

func (s *Stack) volumeSpeed(t string) volumespeed.Enum {
	if s, ok := s.configrationOptions.VolumeSpeeds[t]; ok {
		return s
	}
	return volumespeed.HDD
}

func (s *Stack) volumeType(speed volumespeed.Enum) string {
	for t, s := range s.configrationOptions.VolumeSpeeds {
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

//WaitForVolumeState wait for volume to be in the specified state
func (s *Stack) WaitForVolumeState(volumeID string, state volumestate.Enum) error {
	err := retry.WhileUnsuccessfulDelay5SecondsTimeout(func() error {
		vol, err := s.GetVolume(volumeID)
		if err != nil {
			println("aborted")
			return scerr.AbortedError("", err)
		}
		println(vol.State.String())
		if vol.State != state {
			return fmt.Errorf("wrong state")
		}
		return nil
	}, temporal.GetHostTimeout())
	return err
}

// GetVolume returns the volume identified by id
func (s *Stack) GetVolume(id string) (*resources.Volume, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if id == "" {
		return nil, scerr.InvalidParameterError("id", "cannot be empty string")
	}
	res, err := s.client.POST_ReadVolumes(oapi.ReadVolumesRequest{
		Filters: oapi.FiltersVolume{
			VolumeIds: []string{id},
		},
	})
	if err != nil {
		return nil, err
	}
	if res == nil || res.OK == nil || len(res.OK.Volumes) > 1 {
		return nil, scerr.InconsistentError("Invalid provider response")
	}
	if len(res.OK.Volumes) == 0 {
		return nil, nil
	}

	ov := res.OK.Volumes[0]
	volume := resources.NewVolume()
	volume.ID = ov.VolumeId
	volume.Speed = s.volumeSpeed(ov.VolumeType)
	volume.Size = int(ov.Size)
	volume.State = volumeState(ov.State)
	volume.Name = getResourceTag(ov.Tags, "name", "")
	return volume, nil
}

//GetVolumeByName returns the volume with name name
func (s *Stack) GetVolumeByName(name string) (*resources.Volume, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}
	subregion := s.Options.Compute.Subregion
	res, err := s.client.POST_ReadVolumes(oapi.ReadVolumesRequest{
		Filters: oapi.FiltersVolume{
			Tags:           []string{fmt.Sprintf("name=%s", name)},
			SubregionNames: []string{subregion},
		},
	})
	if err != nil {
		return nil, err
	}
	if res == nil || res.OK == nil || len(res.OK.Volumes) == 0 {
		return nil, scerr.NotFoundError(fmt.Sprintf("No volume named %s", name))
	}
	if res == nil || res.OK == nil {
		return nil, scerr.InconsistentError("Invalid provider response")
	}
	if len(res.OK.Volumes) > 1 {
		return nil, scerr.InconsistentError(fmt.Sprintf("two volumes with name %s in subregion %s", name, subregion))
	}
	ov := res.OK.Volumes[0]
	volume := resources.NewVolume()
	volume.ID = ov.VolumeId
	volume.Speed = s.volumeSpeed(ov.VolumeType)
	volume.Size = int(ov.Size)
	volume.State = volumeState(ov.State)
	volume.Name = name
	return volume, nil
}

// ListVolumes list available volumes
func (s *Stack) ListVolumes() ([]resources.Volume, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	subregion := s.Options.Compute.Subregion
	res, err := s.client.POST_ReadVolumes(oapi.ReadVolumesRequest{
		Filters: oapi.FiltersVolume{
			SubregionNames: []string{subregion},
		},
	})
	if err != nil {
		return nil, err
	}
	if res == nil || res.OK == nil {
		return nil, scerr.InconsistentError("Invalid provider response")
	}
	var volumes []resources.Volume
	for _, ov := range res.OK.Volumes {
		volume := resources.NewVolume()
		volume.ID = ov.VolumeId
		volume.Speed = s.volumeSpeed(ov.VolumeType)
		volume.Size = int(ov.Size)
		volume.State = volumeState(ov.State)
		volume.Name = getResourceTag(ov.Tags, "name", "")
		volumes = append(volumes, *volume)
	}
	return volumes, nil
}

// DeleteVolume deletes the volume identified by id
func (s *Stack) DeleteVolume(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty string")
	}
	_, err := s.client.POST_DeleteVolume(oapi.DeleteVolumeRequest{
		VolumeId: id,
	})
	return err
}

func freeDevice(usedDevices []string, device string) bool {
	for _, usedDevice := range usedDevices {
		if device == usedDevice {
			return false
		}
	}
	return true
}

func (s *Stack) getFirstFreeDeviceName(serverID string) string {
	var usedDeviceNames []string
	atts, _ := s.ListVolumeAttachments(serverID)
	if atts == nil {
		return s.deviceNames[0]
	}
	for _, att := range atts {
		usedDeviceNames = append(usedDeviceNames, att.Device)
	}
	for _, deviceName := range s.deviceNames {
		if freeDevice(usedDeviceNames, deviceName) {
			return deviceName
		}
	}
	return ""
}

// CreateVolumeAttachment attaches a volume to an host
func (s *Stack) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (string, error) {
	if s == nil {
		return "", scerr.InvalidInstanceError()
	}
	if request.HostID == "" {
		return "", scerr.InvalidParameterError("HostID", "cannot be empty string")
	}
	if request.VolumeID == "" {
		return "", scerr.InvalidParameterError("VolumeID", "cannot be empty string")
	}

	_, err := s.client.POST_LinkVolume(oapi.LinkVolumeRequest{
		DeviceName: s.getFirstFreeDeviceName(request.HostID),
		VmId:       request.HostID,
		VolumeId:   request.VolumeID,
	})
	if err != nil {
		return "", err
	}
	return request.VolumeID, nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *Stack) GetVolumeAttachment(serverID, id string) (*resources.VolumeAttachment, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if serverID == "" {
		return nil, scerr.InvalidParameterError("serverID", "cannot be empty string")
	}
	if id == "" {
		return nil, scerr.InvalidParameterError("id", "cannot be empty string")
	}
	res, err := s.client.POST_ReadVolumes(oapi.ReadVolumesRequest{
		Filters: oapi.FiltersVolume{
			VolumeIds: []string{id},
		},
	})
	if err != nil {
		return nil, err
	}
	if res == nil || res.OK == nil || len(res.OK.Volumes) > 1 {
		return nil, scerr.InconsistentError("Invalid provider response")
	}
	if len(res.OK.Volumes) == 0 {
		return nil, nil
	}

	ov := res.OK.Volumes[0]
	for _, lv := range ov.LinkedVolumes {
		if lv.VmId == serverID {
			return &resources.VolumeAttachment{
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
func (s *Stack) ListVolumeAttachments(serverID string) ([]resources.VolumeAttachment, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if serverID == "" {
		return nil, scerr.InvalidParameterError("serverID", "cannot be empty string")
	}
	volumes, err := s.ListVolumes()
	if err != nil {
		return nil, err
	}
	var atts []resources.VolumeAttachment
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
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if serverID == "" {
		return scerr.InvalidParameterError("serverID", "cannot be empty string")
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty string")
	}
	_, err := s.client.POST_UnlinkVolume(oapi.UnlinkVolumeRequest{
		VolumeId: id,
	})
	if err != nil {
		return err
	}
	return s.WaitForVolumeState(id, volumestate.AVAILABLE)
}

func toVolumeSpeed(s string) volumespeed.Enum {
	if s == "COLD" {
		return volumespeed.COLD
	}
	if s == "HDD" {
		return volumespeed.HDD
	}
	if s == "SSD" {
		return volumespeed.SSD
	}
	return volumespeed.HDD
}
