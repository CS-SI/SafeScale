/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/v22/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// -------------Volumes Management---------------------------------------------------------------------------------------

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s stack) CreateVolume(request abstract.VolumeRequest) (_ *abstract.Volume, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if request.Name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("request.Name")
	}
	if request.Size <= 0 {
		return nil, fail.InvalidParameterError("request.Size", "cannot be negative integer or 0")
	}

	tracer := debug.NewTracer(context.Background(), tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp")).WithStopwatch().Entering()
	defer tracer.Exiting()

	// TODO: validate content of request

	selectedType := fmt.Sprintf("projects/%s/zones/%s/diskTypes/pd-standard", s.GcpConfig.ProjectID, s.GcpConfig.Zone)
	if request.Speed == volumespeed.Ssd {
		selectedType = fmt.Sprintf("projects/%s/zones/%s/diskTypes/pd-ssd", s.GcpConfig.ProjectID, s.GcpConfig.Zone)
	}

	resp, xerr := s.rpcCreateDisk(request.Name, selectedType, int64(request.Size))
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
func (s stack) InspectVolume(ref string) (_ *abstract.Volume, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if ref == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	tracer := debug.NewTracer(context.Background(), tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcGetDisk(ref)
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
func (s stack) ListVolumes() ([]*abstract.Volume, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(context.Background(), tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp")).WithStopwatch().Entering()
	defer tracer.Exiting()

	var out []*abstract.Volume
	resp, xerr := s.rpcListDisks()
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

func (s stack) rpcListDisks() ([]*compute.Disk, fail.Error) {
	var (
		out  []*compute.Disk
		resp *compute.DiskList
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
func (s stack) DeleteVolume(ref string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if ref == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	tracer := debug.NewTracer(context.Background(), tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp"), "(%s)", ref).WithStopwatch().Entering()
	defer tracer.Exiting()

	return s.rpcDeleteDisk(ref)
}

// CreateVolumeAttachment attaches a volume to a host
func (s stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	if valid.IsNil(s) {
		return "", fail.InvalidInstanceError()
	}
	if request.VolumeID == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("request.VolumeID")
	}
	if request.HostID == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("request.HostID")
	}

	tracer := debug.NewTracer(context.Background(), tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp"), "('%s')", request.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, xerr := s.rpcCreateDiskAttachment(request.VolumeID, request.HostID)
	if xerr != nil {
		return "", xerr
	}
	return resp, nil
}

// InspectVolumeAttachment returns the volume attachment identified by id
func (s stack) InspectVolumeAttachment(hostRef, vaID string) (*abstract.VolumeAttachment, fail.Error) {
	nilA := abstract.NewVolumeAttachment()
	if valid.IsNil(s) {
		return nilA, fail.InvalidInstanceError()
	}
	if hostRef == "" {
		return nilA, fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if vaID == "" {
		return nilA, fail.InvalidParameterCannotBeEmptyStringError("vaID")
	}

	tracer := debug.NewTracer(context.Background(), tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp"), "(%s, %s)", hostRef, vaID).WithStopwatch().Entering()
	defer tracer.Exiting()

	serverID, diskID := extractFromAttachmentID(vaID)
	instance, xerr := s.rpcGetInstance(serverID)
	if xerr != nil {
		return nilA, xerr
	}

	disk, xerr := s.rpcGetDisk(diskID)
	if xerr != nil {
		return nilA, xerr
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

func (s stack) Migrate(operation string, params map[string]interface{}) (ferr fail.Error) {
	defer fail.OnPanic(&ferr) // too many unchecked casts

	if operation == "tags" {
		// delete current nat route (is it really necessary ?)
		routeName := params["subnetName"].(string) + "-nat-allowed"
		xerr := s.rpcDeleteRoute(routeName)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				break
			default:
				return xerr
			}
		}

		// create new nat route
		_, xerr = s.rpcCreateRoute(params["networkName"].(string), params["subnetID"].(string), params["subnetName"].(string))
		if xerr != nil {
			return xerr
		}

		return nil
	}

	if operation == "removetag" {
		subnetInstance, ok := params["subnetInstance"].(resources.Subnet)
		if !ok {
			return fail.InvalidParameterError("subnetInstance", "should be resources.Subnet")
		}
		instance, ok := params["instance"].(*operations.Host)
		if !ok {
			return fail.InvalidParameterError("instance", "should be *operations.Host")
		}

		networkInstance, xerr := subnetInstance.InspectNetwork(context.Background())
		if xerr != nil {
			return xerr
		}

		// remove old nat route tag
		xerr = s.rpcRemoveTagsFromInstance(instance.GetID(), []string{"no-ip-" + subnetInstance.GetName()})
		if xerr != nil {
			return xerr
		}

		// add new nat route tag
		xerr = s.rpcAddTagsToInstance(instance.GetID(), []string{fmt.Sprintf(NATRouteTagFormat, networkInstance.GetID())})
		if xerr != nil {
			return xerr
		}

		return nil
	}

	return nil
}

// DeleteVolumeAttachment ...
func (s stack) DeleteVolumeAttachment(serverRef, vaID string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vaID == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("vaID")
	}

	tracer := debug.NewTracer(context.Background(), tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp"), "(%s, %s)", serverRef, vaID).WithStopwatch().Entering()
	defer tracer.Exiting()

	return s.rpcDeleteDiskAttachment(vaID)
}

// ListVolumeAttachments lists available volume attachment
func (s stack) ListVolumeAttachments(serverRef string) ([]*abstract.VolumeAttachment, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if serverRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("serverRef")
	}

	tracer := debug.NewTracer(context.Background(), tracing.ShouldTrace("stacks.volume") || tracing.ShouldTrace("stack.gcp"), "(%s)", serverRef).WithStopwatch().Entering()
	defer tracer.Exiting()

	var vats []*abstract.VolumeAttachment

	instance, xerr := s.rpcGetInstance(serverRef)
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
