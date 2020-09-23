/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package ebrc

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vmware/go-vcloud-director/types/v56"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// -------------Volumes Management---------------------------------------------------------------------------------------

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s *StackEbrc) CreateVolume(request resources.VolumeRequest) (*resources.Volume, error) {
	diskCreateParams := &types.DiskCreateParams{
		Disk: &types.Disk{
			Name:       request.Name,
			Size:       int(request.Size * 1024 * 1024 * 1024),
			BusType:    "6",
			BusSubType: "lsilogicsas",
		},
	}

	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return nil, scerr.Wrap(err, fmt.Sprintf("Error creating volume"))
	}

	storageProfileValue := ""
	for _, sps := range vdc.Vdc.VdcStorageProfiles {
		for _, sp := range sps.VdcStorageProfile {
			storageProfileValue = sp.Name
		}
	}

	var storageReference types.Reference
	if storageProfileValue != "" {
		storageReference, err = vdc.FindStorageProfileReference(storageProfileValue)
		if err != nil {
			return nil, scerr.Errorf(fmt.Sprintf("error finding storage profile %s", storageProfileValue), err)
		}
		diskCreateParams.Disk.StorageProfile = &types.Reference{HREF: storageReference.HREF}
	}

	task, err := vdc.CreateDisk(diskCreateParams)
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("error creating independent disk: %s", err), err)
	}

	err = task.WaitTaskCompletion()
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("error waiting to finish creation of independent disk: %s", err), err)
	}

	drec, err := vdc.QueryDisk(request.Name)
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("error creating independent disk: %s", err), err)
	}
	disk, err := vdc.FindDiskByHREF(drec.Disk.HREF)
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("unable to find disk by reference: %s", err), err)
	}

	revol := &resources.Volume{
		ID:   disk.Disk.Id,
		Name: disk.Disk.Name,
		Size: disk.Disk.Size,
	}

	return revol, nil
}

// GetVolume returns the volume identified by id
func (s *StackEbrc) GetVolume(ref string) (*resources.Volume, error) {
	logrus.Debug("ebrc.Client.GetVolume() called")
	defer logrus.Debug("ebrc.Client.GetVolume() done")

	var volume resources.Volume

	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return nil, scerr.Wrap(err, fmt.Sprintf("Error listing volumes"))
	}

	// FIXME: Add data
	dr, err := vdc.QueryDisk(ref)
	if err == nil {
		thed, err := vdc.FindDiskByHREF(dr.Disk.HREF)
		if err == nil {
			volume = resources.Volume{
				Name: thed.Disk.Name,
				Size: thed.Disk.Size,
				ID:   thed.Disk.Id,
			}
		}
	}

	if err != nil {
		return nil, err
	}

	return &volume, nil
}

// ListVolumes return the list of all volume known on the current tenant
func (s *StackEbrc) ListVolumes() ([]resources.Volume, error) {
	logrus.Debug("ebrc.Client.ListVolumes() called")
	defer logrus.Debug("ebrc.Client.ListVolumes() done")

	var volumes []resources.Volume

	org, vdc, err := s.getOrgVdc()
	if err != nil {
		return volumes, scerr.Wrap(err, fmt.Sprintf("Error listing volumes"))
	}

	// Check if network is already there
	refs, err := getLinks(org, "vnd.vmware.vcloud.disk+xml")
	if err != nil {
		return nil, scerr.Wrap(err, fmt.Sprintf("Error recovering network information"))
	}
	for _, ref := range refs {
		// FIXME: Add data
		dr, err := vdc.QueryDisk(ref.Name)
		if err == nil {
			thed, err := vdc.FindDiskByHREF(dr.Disk.HREF)
			if err == nil {
				volumes = append(volumes, resources.Volume{Name: ref.Name, ID: ref.ID, Size: thed.Disk.Size})
			}
		}
	}

	return volumes, nil
}

// DeleteVolume deletes the volume identified by id
func (s *StackEbrc) DeleteVolume(ref string) error {
	logrus.Debugf("ebrc.Client.DeleteVolume(%s) called", ref)
	defer logrus.Debugf("ebrc.Client.DeleteVolume(%s) done", ref)

	thed, err := s.findDiskByID(ref)
	if err != nil {
		return err
	}

	deltask, err := thed.Delete()
	if err != nil {
		return err
	}
	err = deltask.WaitTaskCompletion()
	return err
}

func hash(s string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return strconv.Itoa(int(h.Sum32()))
}

func getAttachmentID(volume string, domain string) string {
	return volume + ":" + domain
}

// CreateVolumeAttachment attaches a volume to an host
// - 'name' of the volume attachment
// - 'volume' to attach
// - 'host' on which the volume is attached
func (s *StackEbrc) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (string, error) {
	logrus.Debugf(">>> stacks.ebrc::CreateVolumeAttachment(%s)", request.Name)
	defer logrus.Debugf("<<< stacks.ebrc::CreateVolumeAttachment(%s)", request.Name)

	vm, err := s.findVMByID(request.HostID)
	if err != nil || utils.IsEmpty(vm) {
		return "", scerr.Wrap(err, fmt.Sprintf("Error creating attachment, vm empty"))
	}

	disk, err := s.findDiskByID(request.VolumeID)
	if err != nil || utils.IsEmpty(disk) {
		return "", scerr.Wrap(err, fmt.Sprintf("Error creating attachment, disk empty"))
	}

	attask, err := vm.AttachDisk(&types.DiskAttachOrDetachParams{Disk: &types.Reference{HREF: disk.Disk.HREF}})
	if err != nil {
		return "", scerr.Wrap(err, fmt.Sprintf("Error creating attachment"))
	}

	err = attask.WaitTaskCompletion()
	if err != nil {
		return "", scerr.Wrap(err, fmt.Sprintf("Error creating attachment"))
	}

	return getAttachmentID(request.HostID, request.VolumeID), nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *StackEbrc) GetVolumeAttachment(serverID, id string) (*resources.VolumeAttachment, error) {
	logrus.Debugf(">>> stacks.ebrc::GetVolumeAttachment(%s)", id)
	defer logrus.Debugf("<<< stacks.ebrc::GetVolumeAttachment(%s)", id)

	vats, err := s.ListVolumeAttachments(serverID)
	if err != nil {
		return nil, scerr.Wrap(err, fmt.Sprintf("Error getting attachment"))
	}

	for _, vat := range vats {
		if vat.ID == id && vat.ServerID == serverID {
			return &vat, nil
		}
	}

	return nil, scerr.Errorf(fmt.Sprintf("Attachment [%s] to [%s] not found", id, serverID), nil)
}

// DeleteVolumeAttachment ...
func (s *StackEbrc) DeleteVolumeAttachment(serverID, id string) error {
	logrus.Debugf(">>> stacks.ebrc::DeleteVolumeAttachment(%s)", id)
	defer logrus.Debugf("<<< stacks.ebrc::DeleteVolumeAttachment(%s)", id)

	vm, err := s.findVMByID(serverID)
	if err != nil {
		return scerr.Wrap(err, fmt.Sprintf("Error deleting attachment"))
	}

	splitted := strings.Split(id, ":")

	diskId := strings.Join(splitted[len(splitted)/2:], ":")
	disk, err := s.findDiskByID(diskId)
	if err != nil {
		return scerr.Wrap(err, fmt.Sprintf("Error deleting attachment"))
	}

	attask, err := vm.DetachDisk(&types.DiskAttachOrDetachParams{Disk: &types.Reference{HREF: disk.Disk.HREF}})
	if err != nil {
		return scerr.Wrap(err, fmt.Sprintf("Error deleting attachment"))
	}

	err = attask.WaitTaskCompletion()
	if err != nil {
		return scerr.Wrap(err, fmt.Sprintf("Error creating attachment"))
	}

	return nil
}

// ListVolumeAttachments lists available volume attachments
func (s *StackEbrc) ListVolumeAttachments(serverID string) ([]resources.VolumeAttachment, error) {
	vms, err := s.findVmNames()
	if err != nil {
		return []resources.VolumeAttachment{}, err
	}

	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return []resources.VolumeAttachment{}, scerr.Wrap(err, fmt.Sprintf("Error deleting volume"))
	}

	var attachments []resources.VolumeAttachment

	for _, vmname := range vms {
		vm, err := s.findVMByName(vmname)
		if err != nil {
			continue
		}

		for _, ittem := range vm.VM.VirtualHardwareSection.Item {
			if ittem != nil {
				if ittem.ResourceType == 17 {
					dadr := ittem.HostResource[0].Disk
					thedi, err := vdc.FindDiskByHREF(dadr)
					if err != nil {
						continue
					}

					reid := resources.VolumeAttachment{
						ID:       serverID + ":" + thedi.Disk.Id,
						VolumeID: thedi.Disk.Id,
						ServerID: serverID,
					}

					attachments = append(attachments, reid)
				}
			}
		}
	}

	return attachments, nil
}
