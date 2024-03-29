/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/api/compute/v1"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// -------------Volumes Management---------------------------------------------------------------------------------------

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s stack) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (_ *abstract.Volume, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if request.Name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("request.Name")
	}
	if request.Size <= 0 {
		return nil, fail.InvalidParameterError("request.Size", "cannot be negative integer or 0")
	}

	// TODO: validate content of request

	selectedType := fmt.Sprintf("projects/%s/zones/%s/diskTypes/pd-standard", s.GcpConfig.ProjectID, s.GcpConfig.Zone)
	if request.Speed == volumespeed.Ssd {
		selectedType = fmt.Sprintf("projects/%s/zones/%s/diskTypes/pd-ssd", s.GcpConfig.ProjectID, s.GcpConfig.Zone)
	}

	resp, xerr := s.rpcCreateDisk(ctx, request.Name, selectedType, int64(request.Size))
	if xerr != nil {
		return nil, xerr
	}

	out, xerr := toAbstractVolume(*resp)
	if xerr != nil {
		return nil, xerr
	}
	return out, nil
}

func toAbstractVolume(in compute.Disk) (out *abstract.Volume, ferr fail.Error) {
	out = abstract.NewVolume()
	out.Name = in.Name
	if strings.Contains(in.Type, "pd-ssd") {
		out.Speed = volumespeed.Ssd
	} else {
		out.Speed = volumespeed.Hdd
	}
	out.Size = int(in.SizeGb)
	out.ID = strconv.FormatUint(in.Id, 10)

	var xerr fail.Error
	if out.State, xerr = toAbstractVolumeState(in.Status); xerr != nil {
		return abstract.NewVolume(), xerr
	}
	return out, nil
}

// InspectVolume returns the volume identified by id
func (s stack) InspectVolume(ctx context.Context, ref string) (_ *abstract.Volume, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if ref == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	resp, xerr := s.rpcGetDisk(ctx, ref)
	if xerr != nil {
		return nil, xerr
	}

	out, xerr := toAbstractVolume(*resp)
	if xerr != nil {
		return nil, xerr
	}
	return out, nil
}

func toAbstractVolumeState(in string) (volumestate.Enum, fail.Error) {
	switch in {
	case "Creating":
		return volumestate.Creating, nil
	case "Deleting":
		return volumestate.Deleting, nil
	case "FAILED":
		return volumestate.Error, nil
	case "READY":
		return volumestate.Available, nil
	case "RESTORING":
		return volumestate.Creating, nil
	default:
		return -1, fail.NewError("unexpected volume status '%s'", in)
	}
}

// ListVolumes return the list of all volume known on the current tenant
func (s stack) ListVolumes(ctx context.Context) ([]*abstract.Volume, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	var out []*abstract.Volume
	resp, xerr := s.rpcListDisks(ctx)
	if xerr != nil {
		return nil, xerr
	}
	for _, v := range resp {
		item, xerr := toAbstractVolume(*v)
		if xerr != nil {
			return nil, xerr
		}
		out = append(out, item)
	}
	return out, nil
}

func (s stack) rpcListDisks(ctx context.Context) ([]*compute.Disk, fail.Error) {
	var (
		out  []*compute.Disk
		resp *compute.DiskList
	)
	for token := ""; ; {
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (err error) {
				resp, err = s.ComputeService.Disks.List(s.GcpConfig.ProjectID, s.GcpConfig.Zone).PageToken(token).Do()
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			return nil, xerr
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
func (s stack) DeleteVolume(ctx context.Context, ref string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if ref == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	return s.rpcDeleteDisk(ctx, ref)
}

// CreateVolumeAttachment attaches a volume to a host
func (s stack) CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	if valid.IsNil(s) {
		return "", fail.InvalidInstanceError()
	}
	if request.VolumeID == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("request.VolumeID")
	}
	if request.HostID == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("request.HostID")
	}

	resp, xerr := s.rpcCreateDiskAttachment(ctx, request.VolumeID, request.HostID)
	if xerr != nil {
		return "", xerr
	}
	return resp, nil
}

// InspectVolumeAttachment returns the volume attachment identified by id
func (s stack) InspectVolumeAttachment(ctx context.Context, hostRef, vaID string) (*abstract.VolumeAttachment, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if vaID == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("vaID")
	}

	serverID, diskID := extractFromAttachmentID(vaID)
	instance, xerr := s.rpcGetInstance(ctx, serverID)
	if xerr != nil {
		return nil, xerr
	}

	disk, xerr := s.rpcGetDisk(ctx, diskID)
	if xerr != nil {
		return nil, xerr
	}

	for _, v := range instance.Disks {
		if v != nil {
			if v.DeviceName == disk.Name {
				ava := toAbstractVolumeAttachment(instance.Name, disk.Name)
				return ava, nil
			}
		}
	}

	return nil, abstract.ResourceNotFoundError("attachment", vaID)
}

// DeleteVolumeAttachment ...
func (s stack) DeleteVolumeAttachment(ctx context.Context, serverRef, vaID string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vaID == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("vaID")
	}

	return s.rpcDeleteDiskAttachment(ctx, vaID)
}

// ListVolumeAttachments lists available volume attachment
func (s stack) ListVolumeAttachments(ctx context.Context, serverRef string) ([]*abstract.VolumeAttachment, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if serverRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("serverRef")
	}

	var vats []*abstract.VolumeAttachment

	instance, xerr := s.rpcGetInstance(ctx, serverRef)
	if xerr != nil {
		return nil, xerr
	}

	for _, disk := range instance.Disks {
		if disk != nil {
			vats = append(vats, toAbstractVolumeAttachment(instance.Name, disk.DeviceName))
		}
	}

	return vats, nil
}

func toAbstractVolumeAttachment(serverName, diskName string) *abstract.VolumeAttachment {
	id := generateDiskAttachmentID(serverName, diskName)
	return &abstract.VolumeAttachment{
		ID:       id,
		Name:     id,
		VolumeID: diskName,
		ServerID: serverName,
	}
}

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
