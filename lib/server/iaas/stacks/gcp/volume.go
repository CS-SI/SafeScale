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
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeState"
	"github.com/CS-SI/SafeScale/lib/utils"
	"google.golang.org/api/compute/v1"
	"strconv"
	"strings"
)

//-------------Volumes Management---------------------------------------------------------------------------------------

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s *Stack) CreateVolume(request resources.VolumeRequest) (*resources.Volume, error) {
	selectedType := fmt.Sprintf("projects/%s/zones/%s/diskTypes/pd-standard", s.GcpConfig.ProjectId, s.GcpConfig.Zone)
	if request.Speed == VolumeSpeed.SSD {
		selectedType = fmt.Sprintf("projects/%s/zones/%s/diskTypes/pd-ssd", s.GcpConfig.ProjectId, s.GcpConfig.Zone)
	}

	newDisk := &compute.Disk{
		Name:   request.Name,
		Region: s.GcpConfig.Region,
		SizeGb: int64(request.Size),
		Type:   selectedType,
		Zone:   s.GcpConfig.Zone,
	}

	service := s.ComputeService

	op, err := s.ComputeService.Disks.Insert(s.GcpConfig.ProjectId, s.GcpConfig.Zone, newDisk).Do()
	if err != nil {
		return nil, err
	}

	oco := OpContext{
		Operation:    op,
		ProjectId:    s.GcpConfig.ProjectId,
		Service:      service,
		DesiredState: "DONE",
	}

	err = waitUntilOperationIsSuccessfulOrTimeout(oco, utils.GetMinDelay(), utils.GetHostTimeout())
	if err != nil {
		return nil, err
	}

	gcpDisk, err := s.ComputeService.Disks.Get(s.GcpConfig.ProjectId, s.GcpConfig.Zone, request.Name).Do()
	if err != nil {
		return nil, err
	}

	nvol := resources.NewVolume()
	nvol.Name = gcpDisk.Name
	if strings.Contains(gcpDisk.Type, "pd-ssd") {
		nvol.Speed = VolumeSpeed.SSD
	} else {
		nvol.Speed = VolumeSpeed.HDD
	}
	nvol.Size = int(gcpDisk.SizeGb)
	nvol.ID = strconv.FormatUint(gcpDisk.Id, 10)
	nvol.State = volumeStateConvert(gcpDisk.Status)

	return nvol, nil
}

// GetVolume returns the volume identified by id
func (s *Stack) GetVolume(ref string) (*resources.Volume, error) {
	gcpDisk, err := s.ComputeService.Disks.Get(s.GcpConfig.ProjectId, s.GcpConfig.Zone, ref).Do()
	if err != nil {
		return nil, err
	}

	nvol := resources.NewVolume()
	nvol.Name = gcpDisk.Name
	if strings.Contains(gcpDisk.Type, "pd-ssd") {
		nvol.Speed = VolumeSpeed.SSD
	} else {
		nvol.Speed = VolumeSpeed.HDD
	}
	nvol.Size = int(gcpDisk.SizeGb)
	nvol.ID = strconv.FormatUint(gcpDisk.Id, 10)
	nvol.State = volumeStateConvert(gcpDisk.Status)

	return nvol, nil
}

func volumeStateConvert(gcpDriveStatus string) VolumeState.Enum {
	switch gcpDriveStatus {
	case "CREATING":
		return VolumeState.CREATING
	case "DELETING":
		return VolumeState.DELETING
	case "FAILED":
		return VolumeState.ERROR
	case "READY":
		return VolumeState.AVAILABLE
	case "RESTORING":
		return VolumeState.CREATING
	default:
		panic(fmt.Sprintf("Unexpected volume status: [%s]", gcpDriveStatus))
	}
}

//ListVolumes return the list of all volume known on the current tenant
func (s *Stack) ListVolumes() ([]resources.Volume, error) {
	var volumes []resources.Volume

	compuService := s.ComputeService

	token := ""
	for paginate := true; paginate; {
		resp, err := compuService.Disks.List(s.GcpConfig.ProjectId, s.GcpConfig.Zone).PageToken(token).Do()
		if err != nil {
			return volumes, fmt.Errorf("cannot list volumes: %v", err)
		} else {
			for _, instance := range resp.Items {
				nvolume := resources.NewVolume()
				nvolume.ID = strconv.FormatUint(instance.Id, 10)
				nvolume.Name = instance.Name
				nvolume.Size = int(instance.SizeGb)
				nvolume.State = volumeStateConvert(instance.Status)
				if strings.Contains(instance.Type, "pd-ssd") {
					nvolume.Speed = VolumeSpeed.SSD
				} else {
					nvolume.Speed = VolumeSpeed.HDD
				}
				volumes = append(volumes, *nvolume)
			}
		}
		token := resp.NextPageToken
		paginate = token != ""
	}

	return volumes, nil
}

// DeleteVolume deletes the volume identified by id
func (s *Stack) DeleteVolume(ref string) error {
	service := s.ComputeService
	op, err := s.ComputeService.Disks.Delete(s.GcpConfig.ProjectId, s.GcpConfig.Zone, ref).Do()
	if err != nil {
		return err
	}

	oco := OpContext{
		Operation:    op,
		ProjectId:    s.GcpConfig.ProjectId,
		Service:      service,
		DesiredState: "DONE",
	}

	err = waitUntilOperationIsSuccessfulOrTimeout(oco, utils.GetMinDelay(), utils.GetHostTimeout())
	return err
}

// CreateVolumeAttachment attaches a volume to an host
// - 'name' of the volume attachment
// - 'volume' to attach
// - 'host' on which the volume is attached
func (s *Stack) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (string, error) {
	service := s.ComputeService

	gcpInstance, err := s.ComputeService.Instances.Get(s.GcpConfig.ProjectId, s.GcpConfig.Zone, request.HostID).Do()
	if err != nil {
		return "", err
	}

	gcpDisk, err := s.ComputeService.Disks.Get(s.GcpConfig.ProjectId, s.GcpConfig.Zone, request.VolumeID).Do()
	if err != nil {
		return "", err
	}

	cad := &compute.AttachedDisk{
		DeviceName: gcpDisk.Name,
		Source:     gcpDisk.SelfLink,
	}

	op, err := s.ComputeService.Instances.AttachDisk(s.GcpConfig.ProjectId, s.GcpConfig.Zone, gcpInstance.Name, cad).Do()
	if err != nil {
		return "", err
	}

	oco := OpContext{
		Operation:    op,
		ProjectId:    s.GcpConfig.ProjectId,
		Service:      service,
		DesiredState: "DONE",
	}

	err = waitUntilOperationIsSuccessfulOrTimeout(oco, utils.GetMinDelay(), utils.GetHostTimeout())
	if err != nil {
		return "", err
	}

	return newGcpDiskAttachment(gcpInstance.Name, gcpDisk.Name).attachmentId, nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *Stack) GetVolumeAttachment(serverID, id string) (*resources.VolumeAttachment, error) {
	dat := NewGcpDiskAttachmentFromId(id)

	gcpInstance, err := s.ComputeService.Instances.Get(s.GcpConfig.ProjectId, s.GcpConfig.Zone, dat.hostName).Do()
	if err != nil {
		return nil, err
	}

	favoriteSlave := dat.diskName

	for _, disk := range gcpInstance.Disks {
		if disk != nil {
			if disk.DeviceName == favoriteSlave {
				vat := &resources.VolumeAttachment{
					ID:       id,
					Name:     dat.diskName,
					VolumeID: dat.diskName,
					ServerID: dat.hostName,
				}
				return vat, nil
			}
		}
	}

	return nil, resources.ResourceNotFoundError("attachment", id)
}

// DeleteVolumeAttachment ...
func (s *Stack) DeleteVolumeAttachment(serverID, id string) error {
	service := s.ComputeService

	gcpInstance, err := s.ComputeService.Instances.Get(s.GcpConfig.ProjectId, s.GcpConfig.Zone, serverID).Do()
	if err != nil {
		return err
	}

	diskName := NewGcpDiskAttachmentFromId(id).diskName
	gcpDisk, err := s.ComputeService.Disks.Get(s.GcpConfig.ProjectId, s.GcpConfig.Zone, diskName).Do()
	if err != nil {
		return err
	}

	op, err := s.ComputeService.Instances.DetachDisk(s.GcpConfig.ProjectId, s.GcpConfig.Zone, gcpInstance.Name, gcpDisk.Name).Do()
	if err != nil {
		return err
	}

	oco := OpContext{
		Operation:    op,
		ProjectId:    s.GcpConfig.ProjectId,
		Service:      service,
		DesiredState: "DONE",
	}

	err = waitUntilOperationIsSuccessfulOrTimeout(oco, utils.GetMinDelay(), utils.GetHostTimeout())
	if err != nil {
		return err
	}

	return err
}

// ListVolumeAttachments lists available volume attachment
func (s *Stack) ListVolumeAttachments(serverID string) ([]resources.VolumeAttachment, error) {
	var vats []resources.VolumeAttachment

	gcpInstance, err := s.ComputeService.Instances.Get(s.GcpConfig.ProjectId, s.GcpConfig.Zone, serverID).Do()
	if err != nil {
		return nil, err
	}

	for _, disk := range gcpInstance.Disks {
		if disk != nil {
			vat := resources.VolumeAttachment{
				ID:       newGcpDiskAttachment(gcpInstance.Name, disk.DeviceName).attachmentId,
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
	attachmentId string
	hostName     string
	diskName     string
}

func newGcpDiskAttachment(hostName string, diskName string) *gcpDiskAttachment {
	return &gcpDiskAttachment{hostName: hostName, diskName: diskName, attachmentId: fmt.Sprintf("%s---%s", hostName, diskName)}
}

func NewGcpDiskAttachmentFromId(theId string) *gcpDiskAttachment {
	sep := "---"
	if strings.Contains(theId, sep) {
		host := strings.Split(theId, sep)[0]
		drive := strings.Split(theId, sep)[1]
		return newGcpDiskAttachment(host, drive)
	}
	return nil
}
