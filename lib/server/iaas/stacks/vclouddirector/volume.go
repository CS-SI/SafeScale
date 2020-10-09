// +build ignore
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

package vclouddirector

import (
	"hash/fnv"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/vmware/go-vcloud-director/types/v56"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
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

	diskCreateParams := &types.DiskCreateParams{Disk: &types.Disk{
		Name:       request.Name,
		Size:       int(request.Size * 1024 * 1024 * 1024),
		BusType:    "6",
		BusSubType: "lsilogicsas",
	}}

	_, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return nil, xerr
	}

	storageProfileValue := ""
	for _, sps := range vdc.Vdc.VdcStorageProfiles {
		for _, sp := range sps.VdcStorageProfile {
			storageProfileValue = sp.Name
		}
	}

	var (
		storageReference types.Reference
		err              error
	)
	if storageProfileValue != "" {
		storageReference, err = vdc.FindStorageProfileReference(storageProfileValue)
		if err != nil {
			return nil, fail.Wrap(normalizeError(err), "error finding storage profile '%s'", storageProfileValue)
		}
		diskCreateParams.Disk.StorageProfile = &types.Reference{HREF: storageReference.HREF}
	}

	task, err := vdc.CreateDisk(diskCreateParams)
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), "error creating independent disk")
	}

	err = task.WaitTaskCompletion()
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), "error waiting to finish creation of independent disk")
	}

	drec, err := vdc.QueryDisk(request.Name)
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), "error creating independent disk")
	}
	disk, err := vdc.FindDiskByHREF(drec.Disk.HREF)
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), "unable to find disk by reference")
	}

	revol := &abstract.Volume{
		ID:   disk.Disk.Id,
		Name: disk.Disk.Name,
		Size: disk.Disk.Size,
	}
	return revol, nil
}

// InspectVolume returns the volume identified by id
func (s *Stack) InspectVolume(ref string) (*abstract.Volume, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debug("vclouddirector.Client.InspectVolume() called")
	defer logrus.Debug("vclouddirector.Client.InspectVolume() done")

	var volume abstract.Volume

	_, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return nil, xerr
	}

	// FIXME Add data
	dr, err := vdc.QueryDisk(ref)
	if err == nil {
		thed, err := vdc.FindDiskByHREF(dr.Disk.HREF)
		if err == nil {
			volume = abstract.Volume{
				Name: thed.Disk.Name,
				Size: thed.Disk.Size,
				ID:   thed.Disk.Id,
			}
		}
	}
	if err != nil {
		return nil, normalizeError(err)
	}

	return &volume, nil
}

// ListVolumes return the list of all volume known on the current tenant
func (s *Stack) ListVolumes() ([]abstract.Volume, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debug("vclouddirector.Client.ListVolumes() called")
	defer logrus.Debug("vclouddirector.Client.ListVolumes() done")

	var volumes []abstract.Volume

	org, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return volumes, xerr
	}

	// Check if network is already there
	refs, xerr := getLinks(org, "vnd.vmware.vcloud.disk+xml")
	if xerr != nil {
		return nil, xerr
	}
	for _, ref := range refs {
		// FIXME: Add data
		// FIXME: handle errors
		dr, err := vdc.QueryDisk(ref.Name)
		if err == nil {
			thed, err := vdc.FindDiskByHREF(dr.Disk.HREF)
			if err == nil {
				volumes = append(volumes, abstract.Volume{Name: ref.Name, ID: ref.ID, Size: thed.Disk.Size})
			}
		}
	}

	return volumes, nil
}

// DeleteVolume deletes the volume identified by id
func (s *Stack) DeleteVolume(ref string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debugf("vclouddirector.Client.DeleteVolume(%s) called", ref)
	defer logrus.Debugf("vclouddirector.Client.DeleteVolume(%s) done", ref)

	thed, xerr := s.findDiskByID(ref)
	if xerr != nil {
		return xerr
	}

	deltask, err := thed.Delete()
	if err != nil {
		return normalizeError(err)
	}
	err = deltask.WaitTaskCompletion()
	return normalizeError(err)
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
func (s *Stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	if s == nil {
		return "", fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debugf(">>> stacks.vclouddirector::CreateVolumeAttachment(%s)", request.Name)
	defer logrus.Debugf("<<< stacks.vclouddirector::CreateVolumeAttachment(%s)", request.Name)

	vm, xerr := s.findVMByID(request.HostID)
	if xerr != nil || utils.IsEmpty(vm) {
		return "", xerr
	}

	disk, err := s.findDiskByID(request.VolumeID)
	if err != nil {
		return "", normalizeError(err)
	}
	if utils.IsEmpty(disk) {
		return "", fail.NewError("failed to find disk '%s'", request.VolumeID)
	}

	attask, err := vm.AttachDisk(&types.DiskAttachOrDetachParams{Disk: &types.Reference{HREF: disk.Disk.HREF}})
	if err != nil {
		return "", normalizeError(err)
	}

	err = attask.WaitTaskCompletion()
	if err != nil {
		return "", normalizeError(err)
	}

	return getAttachmentID(request.HostID, request.VolumeID), nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *Stack) GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debugf(">>> stacks.vclouddirector::InspectVolumeAttachment(%s)", id)
	defer logrus.Debugf("<<< stacks.vclouddirector::InspectVolumeAttachment(%s)", id)

	vats, xerr := s.ListVolumeAttachments(serverID)
	if xerr != nil {
		return nil, xerr
	}

	for _, vat := range vats {
		if vat.ID == id && vat.ServerID == serverID {
			return &vat, nil
		}
	}

	return nil, fail.NotFoundError("failed to find attachment '%' to server '%s'", id, serverID)
}

// DeleteVolumeAttachment ...
func (s *Stack) DeleteVolumeAttachment(serverID, id string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debugf(">>> stacks.vclouddirector::DeleteVolumeAttachment(%s)", id)
	defer logrus.Debugf("<<< stacks.vclouddirector::DeleteVolumeAttachment(%s)", id)

	vm, xerr := s.findVMByID(serverID)
	if xerr != nil {
		return xerr
	}

	splitted := strings.Split(id, ":")

	diskId := strings.Join(splitted[len(splitted)/2:], ":")
	disk, err := s.findDiskByID(diskId)
	if err != nil {
		return normalizeError(err)
	}

	attask, err := vm.DetachDisk(&types.DiskAttachOrDetachParams{Disk: &types.Reference{HREF: disk.Disk.HREF}})
	if err != nil {
		return normalizeError(err)
	}

	err = attask.WaitTaskCompletion()
	return normalizeError(err)
}

// ListVolumeAttachments lists available volume attachments
func (s *Stack) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer

	vms, xerr := s.findVmNames()
	if xerr != nil {
		return []abstract.VolumeAttachment{}, xerr
	}

	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return []abstract.VolumeAttachment{}, normalizeError(err)
	}

	var attachments []abstract.VolumeAttachment

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

					reid := abstract.VolumeAttachment{
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
