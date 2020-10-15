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

package outscale

import (
	"fmt"

	"github.com/antihax/optional"
	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// CreateVolume creates a block volume
func (s *Stack) CreateVolume(request abstract.VolumeRequest) (_ *abstract.Volume, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if request.Name == "" {
		return nil, fail.InvalidParameterError("volume name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%v)", request).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	v, _ := s.InspectVolumeByName(request.Name)
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
	res, _, err := s.client.VolumeApi.CreateVolume(s.auth, &osc.CreateVolumeOpts{
		CreateVolumeRequest: optional.NewInterface(createVolumeRequest),
	})
	if err != nil {
		return nil, normalizeError(err)
	}

	ov := res.Volume

	defer func() {
		if xerr != nil {
			derr := s.DeleteVolume(ov.VolumeId)
			_ = xerr.AddConsequence(derr)
		}
	}()

	xerr = s.setResourceTags(res.Volume.VolumeId, map[string]string{
		"name": request.Name,
	})
	if xerr != nil {
		return nil, xerr
	}
	xerr = s.WaitForVolumeState(ov.VolumeId, volumestate.AVAILABLE)
	if xerr != nil {
		return nil, xerr
	}
	volume := abstract.NewVolume()
	volume.ID = ov.VolumeId
	volume.Speed = s.volumeSpeed(ov.VolumeType)
	volume.Size = int(ov.Size)
	volume.State = volumestate.AVAILABLE
	volume.Name = request.Name
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
func (s *Stack) WaitForVolumeState(volumeID string, state volumestate.Enum) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", volumeID).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	return retry.WhileUnsuccessfulDelay5SecondsTimeout(
		func() error {
			vol, innerErr := s.InspectVolume(volumeID)
			if innerErr != nil {
				return innerErr
			}
			if vol.State != state {
				return fail.NewError("wrong state")
			}
			return nil
		},
		temporal.GetHostTimeout(),
	)
}

// InspectVolume returns the volume identified by id
func (s *Stack) InspectVolume(id string) (av *abstract.Volume, xerr fail.Error) {
	nullAv := abstract.NewVolume()
	if s == nil {
		return nullAv, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAv, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	readVolumesRequest := osc.ReadVolumesRequest{
		Filters: osc.FiltersVolume{
			VolumeIds: []string{id},
		},
	}
	res, _, err := s.client.VolumeApi.ReadVolumes(s.auth, &osc.ReadVolumesOpts{
		ReadVolumesRequest: optional.NewInterface(readVolumesRequest),
	})
	if err != nil {
		return nullAv, normalizeError(err)
	}
	if len(res.Volumes) > 1 {
		return nil, fail.InconsistentError("Invalid provider response")
	}
	if len(res.Volumes) == 0 {
		return nullAv, fail.NotFoundError("failed to find a volume '%s'", id)
	}

	ov := res.Volumes[0]
	av = abstract.NewVolume()
	av.ID = ov.VolumeId
	av.Speed = s.volumeSpeed(ov.VolumeType)
	av.Size = int(ov.Size)
	av.State = volumeState(ov.State)
	av.Name = getResourceTag(ov.Tags, "name", "")
	return av, nil
}

// InspectVolumeByName returns the volume with name name
func (s *Stack) InspectVolumeByName(name string) (av *abstract.Volume, xerr fail.Error) {
	nullAv := abstract.NewVolume()
	if s == nil {
		return nullAv, fail.InvalidInstanceError()
	}
	if name == "" {
		return nullAv, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	subregion := s.Options.Compute.Subregion
	readVolumesRequest := osc.ReadVolumesRequest{
		Filters: osc.FiltersVolume{
			Tags:           []string{fmt.Sprintf("name=%s", name)},
			SubregionNames: []string{subregion},
		},
	}
	res, _, err := s.client.VolumeApi.ReadVolumes(s.auth, &osc.ReadVolumesOpts{
		ReadVolumesRequest: optional.NewInterface(readVolumesRequest),
	})
	if err != nil {
		return nullAv, normalizeError(err)
	}
	if len(res.Volumes) == 0 {
		return nullAv, fail.NotFoundError("failed to find volume '%s'", name)
	}

	if len(res.Volumes) > 1 {
		return nullAv, fail.InconsistentError(fmt.Sprintf("two volumes with name %s in subregion %s", name, subregion))
	}
	ov := res.Volumes[0]
	av = abstract.NewVolume()
	av.ID = ov.VolumeId
	av.Speed = s.volumeSpeed(ov.VolumeType)
	av.Size = int(ov.Size)
	av.State = volumeState(ov.State)
	av.Name = name
	return av, nil
}

// ListVolumes list available volumes
func (s *Stack) ListVolumes() (_ []abstract.Volume, xerr fail.Error) {
	emptySlice := make([]abstract.Volume, 0)
	if s == nil {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	subregion := s.Options.Compute.Subregion
	readVolumesRequest := osc.ReadVolumesRequest{
		Filters: osc.FiltersVolume{
			SubregionNames: []string{subregion},
		},
	}
	res, _, err := s.client.VolumeApi.ReadVolumes(s.auth, &osc.ReadVolumesOpts{
		ReadVolumesRequest: optional.NewInterface(readVolumesRequest),
	})
	if err != nil {
		return emptySlice, normalizeError(err)
	}

	volumes := make([]abstract.Volume, 0, len(res.Volumes))
	for _, ov := range res.Volumes {
		volume := abstract.NewVolume()
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
func (s *Stack) DeleteVolume(id string) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	deleteVolumeRequest := osc.DeleteVolumeRequest{
		VolumeId: id,
	}
	_, _, err := s.client.VolumeApi.DeleteVolume(s.auth, &osc.DeleteVolumeOpts{
		DeleteVolumeRequest: optional.NewInterface(deleteVolumeRequest),
	})
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

// CreateVolumeAttachment attaches a volume to a host
func (s *Stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (_ string, xerr fail.Error) {
	if s == nil {
		return "", fail.InvalidInstanceError()
	}
	if request.HostID == "" {
		return "", fail.InvalidParameterError("HostID", "cannot be empty string")
	}
	if request.VolumeID == "" {
		return "", fail.InvalidParameterError("VolumeID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%v)", request).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	firstDeviceName, xerr := s.getFirstFreeDeviceName(request.HostID)
	if xerr != nil {
		return "", xerr
	}

	linkVolumeRequest := osc.LinkVolumeRequest{
		DeviceName: firstDeviceName,
		VmId:       request.HostID,
		VolumeId:   request.VolumeID,
	}
	_, _, err := s.client.VolumeApi.LinkVolume(s.auth, &osc.LinkVolumeOpts{
		LinkVolumeRequest: optional.NewInterface(linkVolumeRequest),
	})
	if err != nil {
		return "", normalizeError(err)
	}
	return request.VolumeID, nil
}

// GetVolumeAttachment returns the volume attachment identified by volumeID
func (s *Stack) InspectVolumeAttachment(serverID, volumeID string) (_ *abstract.VolumeAttachment, xerr fail.Error) {
	nullVa := abstract.NewVolumeAttachment()
	if s == nil {
		return nullVa, fail.InvalidInstanceError()
	}
	if serverID == "" {
		return nullVa, fail.InvalidParameterError("serverID", "cannot be empty string")
	}
	if volumeID == "" {
		return nullVa, fail.InvalidParameterError("volumeID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s, %s)", serverID, volumeID).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	readVolumesRequest := osc.ReadVolumesRequest{
		Filters: osc.FiltersVolume{
			VolumeIds: []string{volumeID},
		},
	}
	res, _, err := s.client.VolumeApi.ReadVolumes(s.auth, &osc.ReadVolumesOpts{
		ReadVolumesRequest: optional.NewInterface(readVolumesRequest),
	})
	if err != nil {
		return nullVa, normalizeError(err)
	}
	if len(res.Volumes) > 1 {
		return nullVa, fail.InconsistentError("Invalid provider response")
	}
	if len(res.Volumes) == 0 {
		return nullVa, nil
	}

	ov := res.Volumes[0]
	for _, lv := range ov.LinkedVolumes {
		if lv.VmId == serverID {
			return &abstract.VolumeAttachment{
				VolumeID:   volumeID,
				ServerID:   serverID,
				Device:     lv.DeviceName,
				Name:       "",
				MountPoint: "",
				Format:     "",
				ID:         volumeID,
			}, nil
		}
	}

	return nil, fail.NotFoundError("failed to find an attachment of volume '%s' on host '%s'", volumeID, serverID)
}

// ListVolumeAttachments lists available volume attachment
func (s *Stack) ListVolumeAttachments(serverID string) (_ []abstract.VolumeAttachment, xerr fail.Error) {
	emptySlice := make([]abstract.VolumeAttachment, 0)
	if s == nil {
		return emptySlice, fail.InvalidInstanceError()
	}
	if serverID == "" {
		return emptySlice, fail.InvalidParameterError("serverID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", serverID).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	volumes, err := s.ListVolumes()
	if err != nil {
		return nil, err
	}
	atts := make([]abstract.VolumeAttachment, 0, len(volumes))
	for _, v := range volumes {
		att, _ := s.InspectVolumeAttachment(serverID, v.ID)
		if att != nil {
			atts = append(atts, *att)
		}
	}
	return atts, nil
}

// DeleteVolumeAttachment deletes the volume attachment identified by id
func (s *Stack) DeleteVolumeAttachment(serverID, volumeID string) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if serverID == "" {
		return fail.InvalidParameterError("serverID", "cannot be empty string")
	}
	if volumeID == "" {
		return fail.InvalidParameterError("volumeID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s, %s)", serverID, volumeID).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(tracer.TraceMessage(), &xerr)

	unlinkVolumeRequest := osc.UnlinkVolumeRequest{
		VolumeId: volumeID,
	}
	_, _, err := s.client.VolumeApi.UnlinkVolume(s.auth, &osc.UnlinkVolumeOpts{
		UnlinkVolumeRequest: optional.NewInterface(unlinkVolumeRequest),
	})
	if err != nil {
		return normalizeError(err)
	}
	return s.WaitForVolumeState(volumeID, volumestate.AVAILABLE)
}

// func toVolumeSpeed(s string) volumespeed.Enum {
//	if s == "COLD" {
//		return volumespeed.COLD
//	}
//	if s == "HDD" {
//		return volumespeed.HDD
//	}
//	if s == "SSD" {
//		return volumespeed.SSD
//	}
//	return volumespeed.HDD
// }
