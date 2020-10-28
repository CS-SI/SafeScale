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
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// CreateVolume creates a block volume
func (s stack) CreateVolume(request abstract.VolumeRequest) (_ *abstract.Volume, xerr fail.Error) {
	nullAV := abstract.NewVolume()
	if s.IsNull() {
		return nullAV, fail.InvalidInstanceError()
	}
	if request.Name == "" {
		return nil, fail.InvalidParameterError("volume name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%v)", request).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	v, _ := s.InspectVolumeByName(request.Name)
	if v != nil {
		return nullAV, abstract.ResourceDuplicateError("volume", request.Name)
	}
	IOPS := 0
	if request.Speed == volumespeed.SSD {
		IOPS = request.Size * 300
		if IOPS > 13000 {
			IOPS = 13000
		}
	}
	createVolumeOpts := osc.CreateVolumeOpts{
		CreateVolumeRequest: optional.NewInterface(osc.CreateVolumeRequest{
			DryRun:        false,
			Iops:          int32(IOPS),
			Size:          int32(request.Size),
			SnapshotId:    "",
			SubregionName: s.Options.Compute.Subregion,
			VolumeType:    s.volumeType(request.Speed),
		}),
	}
	var resp osc.CreateVolumeResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.VolumeApi.CreateVolume(s.auth, &createVolumeOpts)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nullAV, xerr
	}

	ov := resp.Volume

	defer func() {
		if xerr != nil {
			if derr := s.DeleteVolume(ov.VolumeId); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Volume"))
			}
		}
	}()

	_, xerr = s.rpcCreateTags(ov.VolumeId, map[string]string{
		"name": request.Name,
	})
	if xerr != nil {
		return nullAV, xerr
	}
	xerr = s.WaitForVolumeState(ov.VolumeId, volumestate.AVAILABLE)
	if xerr != nil {
		return nullAV, xerr
	}

	volume := abstract.NewVolume()
	volume.ID = ov.VolumeId
	volume.Speed = s.volumeSpeed(ov.VolumeType)
	volume.Size = int(ov.Size)
	volume.State = volumestate.AVAILABLE
	volume.Name = request.Name
	return volume, nil
}

func (s stack) volumeSpeed(t string) volumespeed.Enum {
	if s, ok := s.configurationOptions.VolumeSpeeds[t]; ok {
		return s
	}
	return volumespeed.HDD
}

func (s stack) volumeType(speed volumespeed.Enum) string {
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
func (s stack) WaitForVolumeState(volumeID string, state volumestate.Enum) (xerr fail.Error) {
	if s.IsNull() {
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
func (s stack) InspectVolume(id string) (av *abstract.Volume, xerr fail.Error) {
	nullAV := abstract.NewVolume()
	if s.IsNull() {
		return nullAV, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAV, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	readVolumesOpts := osc.ReadVolumesOpts{
		ReadVolumesRequest: optional.NewInterface(osc.ReadVolumesRequest{
			Filters: osc.FiltersVolume{
				VolumeIds: []string{id},
			},
		}),
	}
	var resp osc.ReadVolumesResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.VolumeApi.ReadVolumes(s.auth, &readVolumesOpts)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nullAV, xerr
	}
	if len(resp.Volumes) > 1 {
		return nil, fail.InconsistentError("Invalid provider response")
	}
	if len(resp.Volumes) == 0 {
		return nullAV, fail.NotFoundError("failed to find a volume '%s'", id)
	}

	ov := resp.Volumes[0]
	av = abstract.NewVolume()
	av.ID = ov.VolumeId
	av.Speed = s.volumeSpeed(ov.VolumeType)
	av.Size = int(ov.Size)
	av.State = volumeState(ov.State)
	av.Name = getResourceTag(ov.Tags, "name", "")
	return av, nil
}

// InspectVolumeByName returns the volume with name name
func (s stack) InspectVolumeByName(name string) (av *abstract.Volume, xerr fail.Error) {
	nullAV := abstract.NewVolume()
	if s.IsNull() {
		return nullAV, fail.InvalidInstanceError()
	}
	if name == "" {
		return nullAV, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	subregion := s.Options.Compute.Subregion
	readVolumesOpts := osc.ReadVolumesOpts{
		ReadVolumesRequest: optional.NewInterface(osc.ReadVolumesRequest{
			Filters: osc.FiltersVolume{
				Tags:           []string{fmt.Sprintf("name=%s", name)},
				SubregionNames: []string{subregion},
			},
		}),
	}
	var resp osc.ReadVolumesResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.VolumeApi.ReadVolumes(s.auth, &readVolumesOpts)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nullAV, xerr
	}
	if len(resp.Volumes) == 0 {
		return nullAV, fail.NotFoundError("failed to find volume '%s'", name)
	}

	if len(resp.Volumes) > 1 {
		return nullAV, fail.InconsistentError(fmt.Sprintf("two volumes with name %s in subregion %s", name, subregion))
	}
	ov := resp.Volumes[0]
	av = abstract.NewVolume()
	av.ID = ov.VolumeId
	av.Speed = s.volumeSpeed(ov.VolumeType)
	av.Size = int(ov.Size)
	av.State = volumeState(ov.State)
	av.Name = name
	return av, nil
}

// ListVolumes list available volumes
func (s stack) ListVolumes() (_ []abstract.Volume, xerr fail.Error) {
	var emptySlice []abstract.Volume
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	subregion := s.Options.Compute.Subregion
	readVolumesOpts := osc.ReadVolumesOpts{
		ReadVolumesRequest: optional.NewInterface(osc.ReadVolumesRequest{
			Filters: osc.FiltersVolume{
				SubregionNames: []string{subregion},
			},
		}),
	}
	var resp osc.ReadVolumesResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.VolumeApi.ReadVolumes(s.auth, &readVolumesOpts)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return emptySlice, xerr
	}

	volumes := make([]abstract.Volume, 0, len(resp.Volumes))
	for _, ov := range resp.Volumes {
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
func (s stack) DeleteVolume(id string) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	deleteVolumeOpts := osc.DeleteVolumeOpts{
		DeleteVolumeRequest: optional.NewInterface(osc.DeleteVolumeRequest{
			VolumeId: id,
		}),
	}
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, _, err := s.client.VolumeApi.DeleteVolume(s.auth, &deleteVolumeOpts)
			return normalizeError(err)
		},
		temporal.GetCommunicationTimeout(),
	)
}

func freeDevice(usedDevices []string, device string) bool {
	for _, usedDevice := range usedDevices {
		if device == usedDevice {
			return false
		}
	}
	return true
}

func (s stack) getFirstFreeDeviceName(serverID string) (string, fail.Error) {
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
func (s stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (_ string, xerr fail.Error) {
	if s.IsNull() {
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

	linkVolumeOpts := osc.LinkVolumeOpts{
		LinkVolumeRequest: optional.NewInterface(osc.LinkVolumeRequest{
			DeviceName: firstDeviceName,
			VmId:       request.HostID,
			VolumeId:   request.VolumeID,
		}),
	}
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, _, innerErr := s.client.VolumeApi.LinkVolume(s.auth, &linkVolumeOpts)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return "", xerr
	}
	return request.VolumeID, nil
}

// InspectVolumeAttachment returns the volume attachment identified by volumeID
func (s stack) InspectVolumeAttachment(serverID, volumeID string) (_ *abstract.VolumeAttachment, xerr fail.Error) {
	nullVA := abstract.NewVolumeAttachment()
	if s.IsNull() {
		return nullVA, fail.InvalidInstanceError()
	}
	if serverID == "" {
		return nullVA, fail.InvalidParameterError("serverID", "cannot be empty string")
	}
	if volumeID == "" {
		return nullVA, fail.InvalidParameterError("volumeID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s, %s)", serverID, volumeID).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	readVolumesOpts := osc.ReadVolumesOpts{
		ReadVolumesRequest: optional.NewInterface(osc.ReadVolumesRequest{
			Filters: osc.FiltersVolume{
				VolumeIds: []string{volumeID},
			},
		}),
	}
	var resp osc.ReadVolumesResponse
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.VolumeApi.ReadVolumes(s.auth, &readVolumesOpts)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nullVA, xerr
	}
	if len(resp.Volumes) > 1 {
		return nullVA, fail.InconsistentError("Invalid provider response")
	}
	if len(resp.Volumes) == 0 {
		return nullVA, nil
	}

	ov := resp.Volumes[0]
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
func (s stack) ListVolumeAttachments(serverID string) (_ []abstract.VolumeAttachment, xerr fail.Error) {
	emptySlice := make([]abstract.VolumeAttachment, 0)
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}
	if serverID == "" {
		return emptySlice, fail.InvalidParameterError("serverID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.outscale"), "(%s)", serverID).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

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
func (s stack) DeleteVolumeAttachment(serverID, volumeID string) (xerr fail.Error) {
	if s.IsNull() {
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
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	unlinkVolumeOpts := osc.UnlinkVolumeOpts{
		UnlinkVolumeRequest: optional.NewInterface(osc.UnlinkVolumeRequest{
			VolumeId: volumeID,
		}),
	}
	xerr = netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, _, innerErr := s.client.VolumeApi.UnlinkVolume(s.auth, &unlinkVolumeOpts)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return xerr
	}
	return s.WaitForVolumeState(volumeID, volumestate.AVAILABLE)
}
