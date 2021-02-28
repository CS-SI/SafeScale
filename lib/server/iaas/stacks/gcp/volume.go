/*
 * Copyright 2018, CS Systemes d'Information, http://csgroup.eu
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

package gcp

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"

	"google.golang.org/api/compute/v1"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// -------------Volumes Management---------------------------------------------------------------------------------------

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s stack) CreateVolume(request abstract.VolumeRequest) (_ *abstract.Volume, xerr fail.Error) {
	nullAV := abstract.NewVolume()
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if request.Name == "" {
		return nullAV, fail.InvalidParameterCannotBeEmptyStringError("request.Name")
	}
	if request.Size <= 0 {
		return nullAV, fail.InvalidParameterError("request.Size", "cannot be negative integer or 0")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp")).WithStopwatch().Entering()
	defer tracer.Exiting()

	// TODO: validate content of request

	selectedType := fmt.Sprintf("projects/%s/zones/%s/diskTypes/pd-standard", s.GcpConfig.ProjectID, s.GcpConfig.Zone)
	if request.Speed == volumespeed.SSD {
		selectedType = fmt.Sprintf("projects/%s/zones/%s/diskTypes/pd-ssd", s.GcpConfig.ProjectID, s.GcpConfig.Zone)
	}

	resp, xerr := s.rpcCreateDisk(request.Name, selectedType, int64(request.Size))
	if xerr != nil {
		return nullAV, xerr
	}

	out, xerr := toAbstractVolume(*resp)
	if xerr != nil {
		return nullAV, xerr
	}
	return out, nil
}

func toAbstractVolume(in compute.Disk) (out *abstract.Volume, xerr fail.Error) {
	out = abstract.NewVolume()
	out.Name = in.Name
	if strings.Contains(in.Type, "pd-ssd") {
		out.Speed = volumespeed.SSD
	} else {
		out.Speed = volumespeed.HDD
	}
	out.Size = int(in.SizeGb)
	out.ID = strconv.FormatUint(in.Id, 10)
	if out.State, xerr = toAbstractVolumeState(in.Status); xerr != nil {
		return abstract.NewVolume(), xerr
	}
	return out, nil
}

// InspectVolume returns the volume identified by id
func (s stack) InspectVolume(ref string) (_ *abstract.Volume, xerr fail.Error) {
	nullAV := abstract.NewVolume()
	if s.IsNull() {
		return nullAV, fail.InvalidInstanceError()
	}
	if ref == "" {
		return nullAV, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcGetDisk(ref)
	if xerr != nil {
		return nullAV, xerr
	}

	out, xerr := toAbstractVolume(*resp)
	if xerr != nil {
		return nullAV, xerr
	}
	return out, nil
}

func toAbstractVolumeState(in string) (volumestate.Enum, fail.Error) {
	switch in {
	case "CREATING":
		return volumestate.CREATING, nil
	case "DELETING":
		return volumestate.DELETING, nil
	case "FAILED":
		return volumestate.ERROR, nil
	case "READY":
		return volumestate.AVAILABLE, nil
	case "RESTORING":
		return volumestate.CREATING, nil
	default:
		return -1, fail.NewError("unexpected volume status '%s'", in)
	}
}

// ListVolumes return the list of all volume known on the current tenant
func (s stack) ListVolumes() ([]abstract.Volume, fail.Error) {
	var emptySlice []abstract.Volume
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp")).WithStopwatch().Entering()
	defer tracer.Exiting()

	var out []abstract.Volume
	resp, xerr := s.rpcListDisks()
	if xerr != nil {
		return emptySlice, xerr
	}
	for _, v := range resp {
		item, xerr := toAbstractVolume(*v)
		if xerr != nil {
			return emptySlice, xerr
		}
		out = append(out, *item)
	}
	return out, nil
}

func (s stack) rpcListDisks() ([]*compute.Disk, fail.Error) {
	var (
		emptySlice, out []*compute.Disk
		resp            *compute.DiskList
	)
	for token := ""; ; {
		xerr := stacks.RetryableRemoteCall(
			func() (err error) {
				resp, err = s.ComputeService.Disks.List(s.GcpConfig.ProjectID, s.GcpConfig.Zone).PageToken(token).Do()
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			return emptySlice, xerr
		}
		if resp != nil && len(resp.Items) > 0 {
			out = append(out, resp.Items...)
		}
		if token = resp.NextPageToken; token == "" {
			break
		}
	}
	return out, nil
}

// DeleteVolume deletes the volume identified by id
func (s stack) DeleteVolume(ref string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ref == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()

	return s.rpcDeleteDisk(ref)
}

// CreateVolumeAttachment attaches a volume to an host
func (s stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	if s.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if request.VolumeID == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("request.VolumeID")
	}
	if request.HostID == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("request.HostID")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp"), "('%s')", request.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcCreateDiskAttachment(request.VolumeID, request.HostID)
	if xerr != nil {
		return "", xerr
	}
	return resp, nil
}

// InspectVolumeAttachment returns the volume attachment identified by id
func (s stack) InspectVolumeAttachment(hostRef, vaID string) (*abstract.VolumeAttachment, fail.Error) {
	nullAVA := abstract.NewVolumeAttachment()
	if s.IsNull() {
		return nullAVA, fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return nullAVA, fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if vaID == "" {
		return nullAVA, fail.InvalidParameterCannotBeEmptyStringError("vaID")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp"), "(%s, %s)", hostRef, vaID).WithStopwatch().Entering()
	defer tracer.Exiting()

	serverID, diskID := extractFromAttachmentID(vaID)
	instance, xerr := s.rpcGetInstance(serverID)
	if xerr != nil {
		return nullAVA, xerr
	}

	disk, xerr := s.rpcGetDisk(diskID)
	if xerr != nil {
		return nullAVA, xerr
	}

	for _, v := range instance.Disks {
		if v != nil {
			if v.DeviceName == disk.Name {
				ava := toAbstractVolumeAttachment(instance.Name, disk.Name)
				return &ava, nil
			}
		}
	}

	return nil, abstract.ResourceNotFoundError("attachment", vaID)
}

// DeleteVolumeAttachment ...
func (s stack) DeleteVolumeAttachment(serverRef, vaID string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if vaID == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("vaID")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp"), "(%s, %s)", serverRef, vaID).WithStopwatch().Entering()
	defer tracer.Exiting()

	return s.rpcDeleteDiskAttachment(vaID)
}

// ListVolumeAttachments lists available volume attachment
func (s stack) ListVolumeAttachments(serverRef string) ([]abstract.VolumeAttachment, fail.Error) {
	var emptySlice []abstract.VolumeAttachment
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}
	if serverRef == "" {
		return emptySlice, fail.InvalidParameterCannotBeEmptyStringError("serverRef")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp"), "(%s)", serverRef).WithStopwatch().Entering()
	defer tracer.Exiting()

	var vats []abstract.VolumeAttachment

	instance, xerr := s.rpcGetInstance(serverRef)
	if xerr != nil {
		return emptySlice, xerr
	}

	for _, disk := range instance.Disks {
		if disk != nil {
			vats = append(vats, toAbstractVolumeAttachment(instance.Name, disk.DeviceName))
		}
	}

	return vats, nil
}

func toAbstractVolumeAttachment(serverName, diskName string) abstract.VolumeAttachment {
	id := generateDiskAttachmentID(serverName, diskName)
	return abstract.VolumeAttachment{
		ID:       id,
		Name:     id,
		VolumeID: diskName,
		ServerID: serverName,
	}
}

//type gcpDiskAttachment struct {
//	attachmentID string
//	hostName     string
//	diskName     string
//}

//func newGcpDiskAttachment(hostName string, diskName string) gcpDiskAttachment {
//	return gcpDiskAttachment{
//		hostName:     hostName,
//		diskName:     diskName,
//		attachmentID: generateDiskAttachmentID(hostName, diskName),
//	}
//}

const attachmentIDSeparator = "---"

func generateDiskAttachmentID(hostName string, diskName string) string {
	return fmt.Sprintf("%s%s%s", hostName, attachmentIDSeparator, diskName)
}

func extractFromAttachmentID(theID string) (serverName, diskName string) {
	if strings.Contains(theID, attachmentIDSeparator) {
		splitted := strings.Split(theID, attachmentIDSeparator)
		server := splitted[0]
		disk := splitted[1]
		return server, disk
	}
	return "", ""
}

//
//func newGcpDiskAttachmentFromID(theID string) gcpDiskAttachment {
//	sep := "---"
//	if strings.Contains(theID, sep) {
//		host := strings.Split(theID, sep)[0]
//		drive := strings.Split(theID, sep)[1]
//		return newGcpDiskAttachment(host, drive)
//	}
//	return gcpDiskAttachment{}
//}
