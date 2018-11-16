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

package services

import (
	"fmt"
	"strings"
	"time"

	"github.com/deckarep/golang-set"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeProperty"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/system/nfs"
	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/retry"
)

//go:generate mockgen -destination=../mocks/mock_volumeapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/services VolumeAPI

// VolumeAPI defines API to manipulate hosts
type VolumeAPI interface {
	Delete(ref string) error
	Get(ref string) (*model.Volume, error)
	Inspect(ref string) (*model.Volume, map[string]propsv1.HostLocalMount, error)
	List(all bool) ([]model.Volume, error)
	Create(name string, size int, speed VolumeSpeed.Enum) (*model.Volume, error)
	Attach(volume string, host string, path string, format string) error
	Detach(volume string, host string) error
}

// VolumeService volume service
type VolumeService struct {
	provider *providers.Service
}

// NewVolumeService creates a Volume service
func NewVolumeService(api *providers.Service) VolumeAPI {
	return &VolumeService{
		provider: providers.FromClient(api),
	}
}

// List returns the network list
func (svc *VolumeService) List(all bool) ([]model.Volume, error) {
	return svc.provider.ListVolumes(all)
}

// Delete deletes volume referenced by ref
func (svc *VolumeService) Delete(ref string) error {
	vol, err := svc.Get(ref)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}
	if vol == nil {
		return fmt.Errorf("volume doesn't exist")
	}

	vpAttachmentsV1 := propsv1.VolumeAttachments{}
	err = vol.Properties.Get(VolumeProperty.AttachedV1, &vpAttachmentsV1)
	if err != nil {
		return err
	}

	nbAttach := len(vpAttachmentsV1.HostIDs)
	if nbAttach > 0 {
		return fmt.Errorf("still attached on %d host%s", nbAttach, utils.Plural(nbAttach))
	}
	return svc.provider.DeleteVolume(vol.ID)
}

// Get returns the volume identified by ref, ref can be the name or the id
func (svc *VolumeService) Get(ref string) (*model.Volume, error) {
	mv, err := metadata.LoadVolume(svc.provider, ref)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	if mv == nil {
		return nil, nil
	}
	return mv.Get(), nil
}

// Inspect returns the volume identified by ref and its attachment (if any)
func (svc *VolumeService) Inspect(ref string) (*model.Volume, map[string]propsv1.HostLocalMount, error) {
	mv, err := metadata.LoadVolume(svc.provider, ref)
	if err != nil {
		return nil, nil, err
	}
	if mv == nil {
		return nil, nil, nil
	}
	volume := mv.Get()

	mounts := map[string]propsv1.HostLocalMount{}
	vpAttachedV1 := propsv1.BlankVolumeAttachments
	err = volume.Properties.Get(VolumeProperty.AttachedV1, &vpAttachedV1)
	if err == nil && len(vpAttachedV1.HostIDs) > 0 {
		for _, id := range vpAttachedV1.HostIDs {
			mh, err := metadata.LoadHost(svc.provider, id)
			if err != nil {
				continue
			}
			host := mh.Get()
			hostVolumesV1 := propsv1.BlankHostVolumes
			err = host.Properties.Get(HostProperty.VolumesV1, &hostVolumesV1)
			if err != nil {
				continue
			}
			hostMountsV1 := propsv1.BlankHostMounts
			err = host.Properties.Get(HostProperty.MountsV1, &hostMountsV1)
			if err != nil {
				continue
			}
			if volumeAttachment, found := hostVolumesV1.VolumesByID[volume.ID]; found {
				if mount, ok := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[volumeAttachment.Device]]; ok {
					mounts[host.Name] = mount
				} else {
					mounts[host.Name] = propsv1.BlankHostLocalMount
				}
			}
		}
	}
	return volume, mounts, nil
}

// Create a volume
func (svc *VolumeService) Create(name string, size int, speed VolumeSpeed.Enum) (*model.Volume, error) {
	return svc.provider.CreateVolume(model.VolumeRequest{
		Name:  name,
		Size:  size,
		Speed: speed,
	})
}

// Attach a volume to an host
func (svc *VolumeService) Attach(volumeName, hostName, path, format string) error {
	// Get volume ID
	volume, err := svc.Get(volumeName)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}
	if volume == nil {
		return errors.Wrap(model.ResourceNotFoundError("volume", volumeName), "Can't attach volume")
	}
	volumeAttachedV1 := propsv1.BlankVolumeAttachments
	err = volume.Properties.Get(VolumeProperty.AttachedV1, &volumeAttachedV1)
	if err != nil {
		return errors.Wrap(err, "Can't attach volume")
	}

	// Get Host
	hostService := NewHostService(svc.provider)
	host, err := hostService.Get(hostName)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}
	if host == nil {
		return errors.Wrap(model.ResourceNotFoundError("host", hostName), "Cannot attach volume")
	}
	// If volume already attached to host, do nothing
	if len(volumeAttachedV1.HostIDs) > 0 {
		if host.ID == volumeAttachedV1.HostIDs[0] {
			return nil
		}
		// For now, allows only one attachment...
		return errors.Wrap(model.ResourceNotAvailableError("volume", volumeName), "Can't attach volume")
	}

	// Checks if there is no other device mounted in the path (or in subpath)
	hostMountsV1 := propsv1.BlankHostMounts
	err = host.Properties.Get(HostProperty.MountsV1, &hostMountsV1)
	if err != nil {
		return err
	}
	for _, i := range hostMountsV1.LocalMountsByPath {
		if strings.Index(i.Path, path) == 0 {
			return fmt.Errorf("Can't attach volume '%s' to host '%s': there is already a volume in path '%s'", volume.Name, host.Name, path)
		}
	}
	for _, i := range hostMountsV1.RemoteMountsByPath {
		if strings.Index(i.Path, path) == 0 {
			return fmt.Errorf("Can't attach volume '%s' to host '%s': there is a share mounted in path '%s[/...]'", volume.Name, host.Name, path)
		}
	}

	// Note: most providers are not able to tell the real device name the volume
	//       will have on the host, so we have to use a way that can work everywhere
	// Get list of disks before attachment
	oldDiskSet, err := svc.listAttachedDevices(host)
	if err != nil {
		return fmt.Errorf("failed to get list of connected disks: %s", err)
	}
	vaID, err := svc.provider.CreateVolumeAttachment(model.VolumeAttachmentRequest{
		Name:     fmt.Sprintf("%s-%s", volume.Name, host.Name),
		HostID:   host.ID,
		VolumeID: volume.ID,
	})
	if err != nil {
		return fmt.Errorf("failed to create host-volume attachment: %v", err)
	}

	// Starting from here, remove volume attachment if exit with error
	defer func() {
		if err != nil {
			derr := svc.provider.DeleteVolumeAttachment(host.ID, vaID)
			if err != nil {
				log.Errorf("failed to detach volume '%s' from host '%s': %v", volume.Name, host.Name, derr)
			}
		}
	}()

	// Updates volume properties
	volumeAttachedV1.HostIDs = append(volumeAttachedV1.HostIDs, host.ID)
	err = volume.Properties.Set(VolumeProperty.AttachedV1, &volumeAttachedV1)
	if err != nil {
		return err
	}

	// Retries to acknowledge the volume is really attached to host
	var newDisk mapset.Set
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			// Get new of disk after attachment
			newDiskSet, err := svc.listAttachedDevices(host)
			if err != nil {
				return fmt.Errorf("failed to get list of connected disks: %s", err)
			}
			// Isolate the new device
			newDisk = newDiskSet.Difference(oldDiskSet)
			if newDisk.Cardinality() == 0 {
				return fmt.Errorf("disk not yet attached, retrying")
			}
			return nil
		},
		2*time.Minute,
	)
	if retryErr != nil {
		return fmt.Errorf("failed to acknowledge the disk attachment after %s", 2*time.Minute)
	}

	// Recovers real device name from the system
	deviceName := "/dev/" + newDisk.ToSlice()[0].(string)

	// Saves volume information in property
	hpVolumesV1 := propsv1.BlankHostVolumes
	err = host.Properties.Get(HostProperty.VolumesV1, &hpVolumesV1)
	if err != nil {
		return err
	}
	hpVolumesV1.VolumesByID[volume.ID] = propsv1.HostVolume{
		AttachID: vaID,
		Device:   deviceName,
	}
	hpVolumesV1.VolumesByName[volume.Name] = volume.ID
	hpVolumesV1.VolumesByDevice[deviceName] = volume.ID
	hpVolumesV1.DevicesByID[volume.ID] = deviceName
	err = host.Properties.Set(HostProperty.VolumesV1, &hpVolumesV1)
	if err != nil {
		return err
	}

	// Create mount point
	mountPoint := path
	if path == model.DefaultVolumeMountPoint {
		mountPoint = model.DefaultVolumeMountPoint + volume.Name
	}

	sshSvc := NewSSHService(svc.provider)
	sshConfig, err := sshSvc.GetConfig(host.ID)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}

	server, err := nfs.NewServer(sshConfig)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}
	err = server.MountBlockDevice(deviceName, mountPoint, format)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}

	// Starting from here, unmount block device if exit with error
	defer func() {
		if err != nil {
			derr := server.UnmountBlockDevice(deviceName)
			if derr != nil {
				log.Errorf("failed to unmount volume '%s' from host '%s': %v", volume.Name, host.Name, derr)
			}
		}
	}()

	// Updates host properties
	hostMountsV1.LocalMountsByPath[mountPoint] = propsv1.HostLocalMount{
		Device:     deviceName,
		Path:       mountPoint,
		FileSystem: "nfs",
	}
	hostMountsV1.LocalMountsByDevice[deviceName] = mountPoint
	err = host.Properties.Set(HostProperty.MountsV1, &hostMountsV1)
	if err != nil {
		return err
	}

	err = metadata.SaveVolume(svc.provider, volume)
	if err != nil {
		return err
	}
	err = metadata.SaveHost(svc.provider, host)
	if err != nil {
		return err
	}

	log.Infof("Volume '%s' successfully attached to host '%s' as device '%s'", volume.Name, host.Name, deviceName)
	return nil
}

func (svc *VolumeService) listAttachedDevices(host *model.Host) (mapset.Set, error) {
	var (
		retcode        int
		stdout, stderr string
		err            error
	)
	cmd := "sudo lsblk -l -o NAME,TYPE | grep disk | cut -d' ' -f1"
	sshSvc := NewSSHService(svc.provider)
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			retcode, stdout, stderr, err = sshSvc.Run(host.ID, cmd)
			if err != nil {
				tbr := errors.Wrap(err, "")
				log.Errorf("%+v", tbr)
				return tbr
			}
			if retcode != 0 {
				if retcode == 255 {
					return fmt.Errorf("failed to reach SSH service of host '%s', retrying", host.Name)
				}
				return fmt.Errorf(stderr)
			}
			return nil
		},
		2*time.Minute,
	)
	if retryErr != nil {
		return nil, fmt.Errorf("failed to get list of connected disks after %s: %s", 2*time.Minute, retryErr.Error())
	}
	disks := strings.Split(stdout, "\n")
	set := mapset.NewThreadUnsafeSet()
	for _, k := range disks {
		set.Add(k)
	}
	return set, nil
}

// Detach detach the volume identified by ref, ref can be the name or the id
func (svc *VolumeService) Detach(volumename, hostName string) error {
	mv, err := metadata.LoadVolume(svc.provider, volumename)
	if err != nil {
		return errors.Wrap(model.ResourceNotFoundError("volume", volumename), "Can't detach volume")
	}
	if mv == nil {
		return errors.Wrap(model.ResourceNotFoundError("volume", volumename), "Can't detach volume")
	}
	volume := mv.Get()

	// Get Host ID
	mh, err := metadata.LoadHost(svc.provider, hostName)
	if err != nil {
		return errors.Wrap(model.ResourceNotFoundError("host", hostName), "Can't detach volume")
	}
	host := mh.Get()

	hpVolumesV1 := propsv1.BlankHostVolumes
	err = host.Properties.Get(HostProperty.VolumesV1, &hpVolumesV1)
	if err != nil {
		return err
	}
	volProp, found := hpVolumesV1.VolumesByID[volume.ID]
	if !found {
		return fmt.Errorf("Can't detach volume '%s': not attached to host '%s'", volumename, host.Name)
	}

	sshSvc := NewSSHService(svc.provider)
	sshConfig, err := sshSvc.GetConfig(host.ID)
	if err != nil {
		tbr := errors.Wrap(err, "error getting ssh config")
		log.Errorf("%+v", tbr)
		return tbr
	}

	// Unmount the Block Device (using nfs.Server...)
	server, err := nfs.NewServer(sshConfig)
	if err != nil {
		tbr := errors.Wrap(err, "error creating nfs service")
		log.Errorf("%+v", tbr)
		return tbr
	}
	err = server.UnmountBlockDevice(volProp.Device)
	if err != nil {
		tbr := errors.Wrap(err, "error unmounting block device")
		log.Errorf("%+v", tbr)
		return tbr
	}

	// ... then detach
	err = svc.provider.DeleteVolumeAttachment(host.ID, volProp.AttachID)
	if err != nil {
		return err
	}

	// Updates host property propsv1.VolumesV1
	delete(hpVolumesV1.VolumesByID, volume.ID)
	delete(hpVolumesV1.VolumesByName, volume.Name)
	delete(hpVolumesV1.VolumesByDevice, volProp.Device)
	delete(hpVolumesV1.DevicesByID, volume.ID)
	err = host.Properties.Set(HostProperty.VolumesV1, &hpVolumesV1)
	if err != nil {
		return err
	}
	// Updates host property propsv1.MountsV1
	hostMountsV1 := propsv1.BlankHostMounts
	err = host.Properties.Get(HostProperty.MountsV1, &hostMountsV1)
	if err != nil {
		return err
	}
	mountProp := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[volProp.Device]]
	delete(hostMountsV1.LocalMountsByDevice, mountProp.Device)
	delete(hostMountsV1.LocalMountsByPath, mountProp.Path)
	err = host.Properties.Set(HostProperty.MountsV1, &hostMountsV1)
	if err != nil {
		return err
	}

	// Updates volume property propsv1.VolumeAttachments
	vpAttachedV1 := propsv1.BlankVolumeAttachments
	err = volume.Properties.Get(VolumeProperty.AttachedV1, &vpAttachedV1)
	if err != nil {
		return err
	}

	i := ""
	k := 0
	found = false
	for k, i = range vpAttachedV1.HostIDs {
		if i == host.ID {
			found = true
			break
		}
	}
	if found {
		vpAttachedV1.HostIDs = append(vpAttachedV1.HostIDs[:k], vpAttachedV1.HostIDs[k+1:]...)
	}
	// If not found, continue as if the job has been done... because it is indeed done :-)
	err = volume.Properties.Set(VolumeProperty.AttachedV1, &vpAttachedV1)
	if err != nil {
		return err
	}

	// Updates metadata
	err = metadata.SaveHost(svc.provider, host)
	if err != nil {
		return err
	}
	return metadata.SaveVolume(svc.provider, volume)
}
