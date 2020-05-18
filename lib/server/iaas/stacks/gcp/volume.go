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

package gcp

import (
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/api/compute/v1"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// -------------Volumes Management---------------------------------------------------------------------------------------

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s *Stack) CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	selectedType := fmt.Sprintf("projects/%s/zones/%s/diskTypes/pd-standard", s.GcpConfig.ProjectID, s.GcpConfig.Zone)
	if request.Speed == volumespeed.SSD {
		selectedType = fmt.Sprintf("projects/%s/zones/%s/diskTypes/pd-ssd", s.GcpConfig.ProjectID, s.GcpConfig.Zone)
	}

	newDisk := &compute.Disk{
		Name:   request.Name,
		Region: s.GcpConfig.Region,
		SizeGb: int64(request.Size),
		Type:   selectedType,
		Zone:   s.GcpConfig.Zone,
	}

	service := s.ComputeService

	op, err := s.ComputeService.Disks.Insert(s.GcpConfig.ProjectID, s.GcpConfig.Zone, newDisk).Do()
	if err != nil {
		return nil, fail.ToError(err)
	}

	oco := OpContext{
		Operation:    op,
		ProjectID:    s.GcpConfig.ProjectID,
		Service:      service,
		DesiredState: "DONE",
	}

	xerr := waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
	if xerr != nil {
		return nil, xerr
	}

	gcpDisk, err := s.ComputeService.Disks.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, request.Name).Do()
	if err != nil {
		return nil, fail.ToError(err)
	}

	nvol := abstract.NewVolume()
	nvol.Name = gcpDisk.Name
	if strings.Contains(gcpDisk.Type, "pd-ssd") {
		nvol.Speed = volumespeed.SSD
	} else {
		nvol.Speed = volumespeed.HDD
	}
	nvol.Size = int(gcpDisk.SizeGb)
	nvol.ID = strconv.FormatUint(gcpDisk.Id, 10)
	nvol.State, xerr = volumeStateConvert(gcpDisk.Status)
	if xerr != nil {
		return nil, xerr
	}

	return nvol, nil
}

// GetVolume returns the volume identified by id
func (s *Stack) GetVolume(ref string) (_ *abstract.Volume, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	gcpDisk, err := s.ComputeService.Disks.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ref).Do()
	if err != nil {
		return nil, fail.ToError(err)
	}

	nvol := abstract.NewVolume()
	nvol.State, xerr = volumeStateConvert(gcpDisk.Status)
	if xerr != nil {
		return nil, xerr
	}
	nvol.Name = gcpDisk.Name
	if strings.Contains(gcpDisk.Type, "pd-ssd") {
		nvol.Speed = volumespeed.SSD
	} else {
		nvol.Speed = volumespeed.HDD
	}
	nvol.Size = int(gcpDisk.SizeGb)
	nvol.ID = strconv.FormatUint(gcpDisk.Id, 10)

	return nvol, nil
}

func volumeStateConvert(gcpDriveStatus string) (volumestate.Enum, fail.Error) {
	switch gcpDriveStatus {
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
		return -1, fail.NewError("unexpected volume status '%s'", gcpDriveStatus)
	}
}

// ListVolumes return the list of all volume known on the current tenant
func (s *Stack) ListVolumes() ([]abstract.Volume, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	var volumes []abstract.Volume

	compuService := s.ComputeService

	token := ""
	for paginate := true; paginate; {
		resp, err := compuService.Disks.List(s.GcpConfig.ProjectID, s.GcpConfig.Zone).PageToken(token).Do()
		if err != nil {
			return volumes, fail.Wrap(err, "cannot list volumes")
		}
		for _, instance := range resp.Items {
			nvolume := abstract.NewVolume()
			nvolume.ID = strconv.FormatUint(instance.Id, 10)
			nvolume.Name = instance.Name
			nvolume.Size = int(instance.SizeGb)
			nvolume.State, _ = volumeStateConvert(instance.Status)
			if strings.Contains(instance.Type, "pd-ssd") {
				nvolume.Speed = volumespeed.SSD
			} else {
				nvolume.Speed = volumespeed.HDD
			}
			volumes = append(volumes, *nvolume)
		}
		token := resp.NextPageToken
		paginate = token != ""
	}

	return volumes, nil
}

// DeleteVolume deletes the volume identified by id
func (s *Stack) DeleteVolume(ref string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	service := s.ComputeService
	op, err := s.ComputeService.Disks.Delete(s.GcpConfig.ProjectID, s.GcpConfig.Zone, ref).Do()
	if err != nil {
		return fail.ToError(err)
	}

	oco := OpContext{
		Operation:    op,
		ProjectID:    s.GcpConfig.ProjectID,
		Service:      service,
		DesiredState: "DONE",
	}

	return waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
}

// CreateVolumeAttachment attaches a volume to an host
// - 'name' of the volume attachment
// - 'volume' to attach
// - 'host' on which the volume is attached
func (s *Stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	if s == nil {
		return "", fail.InvalidInstanceError()
	}

	service := s.ComputeService

	gcpInstance, err := s.ComputeService.Instances.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, request.HostID).Do()
	if err != nil {
		return "", fail.ToError(err)
	}

	gcpDisk, err := s.ComputeService.Disks.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, request.VolumeID).Do()
	if err != nil {
		return "", fail.ToError(err)
	}

	cad := &compute.AttachedDisk{
		DeviceName: gcpDisk.Name,
		Source:     gcpDisk.SelfLink,
	}

	op, err := s.ComputeService.Instances.AttachDisk(s.GcpConfig.ProjectID, s.GcpConfig.Zone, gcpInstance.Name, cad).Do()
	if err != nil {
		return "", fail.ToError(err)
	}

	oco := OpContext{
		Operation:    op,
		ProjectID:    s.GcpConfig.ProjectID,
		Service:      service,
		DesiredState: "DONE",
	}

	xerr := waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
	if xerr != nil {
		return "", xerr
	}

	return newGcpDiskAttachment(gcpInstance.Name, gcpDisk.Name).attachmentID, nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *Stack) GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	dat := newGcpDiskAttachmentFromID(id)

	gcpInstance, err := s.ComputeService.Instances.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, dat.hostName).Do()
	if err != nil {
		return nil, fail.ToError(err)
	}

	favoriteSlave := dat.diskName

	for _, disk := range gcpInstance.Disks {
		if disk != nil {
			if disk.DeviceName == favoriteSlave {
				vat := &abstract.VolumeAttachment{
					ID:       id,
					Name:     dat.diskName,
					VolumeID: dat.diskName,
					ServerID: dat.hostName,
				}
				return vat, nil
			}
		}
	}

	return nil, abstract.ResourceNotFoundError("attachment", id)
}

// DeleteVolumeAttachment ...
func (s *Stack) DeleteVolumeAttachment(serverID, id string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	service := s.ComputeService

	gcpInstance, err := s.ComputeService.Instances.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, serverID).Do()
	if err != nil {
		return fail.ToError(err)
	}

	diskName := newGcpDiskAttachmentFromID(id).diskName
	gcpDisk, err := s.ComputeService.Disks.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, diskName).Do()
	if err != nil {
		return fail.ToError(err)
	}

	op, err := s.ComputeService.Instances.DetachDisk(s.GcpConfig.ProjectID, s.GcpConfig.Zone, gcpInstance.Name, gcpDisk.Name).Do()
	if err != nil {
		return fail.ToError(err)
	}

	oco := OpContext{
		Operation:    op,
		ProjectID:    s.GcpConfig.ProjectID,
		Service:      service,
		DesiredState: "DONE",
	}

	return waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
}

// ListVolumeAttachments lists available volume attachment
func (s *Stack) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	var vats []abstract.VolumeAttachment

	gcpInstance, err := s.ComputeService.Instances.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, serverID).Do()
	if err != nil {
		return nil, fail.ToError(err)
	}

	for _, disk := range gcpInstance.Disks {
		if disk != nil {
			vat := abstract.VolumeAttachment{
				ID:       newGcpDiskAttachment(gcpInstance.Name, disk.DeviceName).attachmentID,
				Name:     disk.DeviceName,
				VolumeID: disk.DeviceName,
				ServerID: serverID,
			}
			vats = append(vats, vat)
		}
	}

	return vats, nil
}

type gcpDiskAttachment struct {
	attachmentID string
	hostName     string
	diskName     string
}

func newGcpDiskAttachment(hostName string, diskName string) *gcpDiskAttachment {
	return &gcpDiskAttachment{hostName: hostName, diskName: diskName, attachmentID: fmt.Sprintf("%s---%s", hostName, diskName)}
}

func newGcpDiskAttachmentFromID(theID string) *gcpDiskAttachment {
	sep := "---"
	if strings.Contains(theID, sep) {
		host := strings.Split(theID, sep)[0]
		drive := strings.Split(theID, sep)[1]
		return newGcpDiskAttachment(host, drive)
	}
	return nil
}
