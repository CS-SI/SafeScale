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
	Inspect(ref string) (*model.Volume, map[string]*propsv1.HostLocalMount, error)
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
		provider: api,
	}
}

// List returns the network list
func (svc *VolumeService) List(all bool) ([]model.Volume, error) {
	if all {
		volumes, err := svc.provider.ListVolumes()
		return volumes, infraErr(err)
	}

	var volumes []model.Volume
	mv := metadata.NewVolume(svc.provider)
	err := mv.Browse(func(volume *model.Volume) error {
		volumes = append(volumes, *volume)
		return nil
	})
	if err != nil {
		return nil, infraErrf(err, "Error listing volumes")
	}
	return volumes, nil
}

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// Delete deletes volume referenced by ref
func (svc *VolumeService) Delete(ref string) error {
	mv, err := metadata.LoadVolume(svc.provider, ref)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
			return err
		default:
			log.Debugf("Failed to delete volume: %+v", err)
			return infraErrf(err, "failed to delete volume")
		}
	}
	volume := mv.Get()

	volumeAttachmentsV1 := propsv1.NewVolumeAttachments()
	err = volume.Properties.Get(VolumeProperty.AttachedV1, volumeAttachmentsV1)
	if err != nil {
		err := infraErr(err)
		return err
	}

	nbAttach := len(volumeAttachmentsV1.Hosts)
	if nbAttach > 0 {
		var list []string
		for _, v := range volumeAttachmentsV1.Hosts {
			list = append(list, v)
		}
		return logicErr(fmt.Errorf("still attached to %d host%s: %s", nbAttach, utils.Plural(nbAttach), strings.Join(list, ", ")))
	}

	err = svc.provider.DeleteVolume(volume.ID)
	if err != nil {
		return infraErr(err)
	}

	delErr := mv.Delete()
	return infraErr(delErr)
}

// Get returns the volume identified by ref, ref can be the name or the id
func (svc *VolumeService) Get(ref string) (*model.Volume, error) {
	mv, err := metadata.LoadVolume(svc.provider, ref)
	if err != nil {
		err := infraErr(err)
		return nil, err
	}
	if mv == nil {
		return nil, logicErr(model.ResourceNotFoundError("volume", ref))
	}

	return mv.Get(), nil
}

// Inspect returns the volume identified by ref and its attachment (if any)
func (svc *VolumeService) Inspect(ref string) (*model.Volume, map[string]*propsv1.HostLocalMount, error) {
	volume, err := svc.Get(ref)
	if err != nil {
		err := infraErr(err)
		return nil, nil, err
	}

	if volume == nil {
		return nil, nil, infraErr(errors.Errorf("Volume '%s' not found !", ref))
	}

	mounts := map[string]*propsv1.HostLocalMount{}
	hostSvc := NewHostService(svc.provider)

	volumeAttachedV1 := propsv1.NewVolumeAttachments()
	err = volume.Properties.Get(VolumeProperty.AttachedV1, volumeAttachedV1)
	if err == nil && len(volumeAttachedV1.Hosts) > 0 {
		for id := range volumeAttachedV1.Hosts {
			host, err := hostSvc.Inspect(id)
			if err != nil || host == nil {
				continue
			}
			hostVolumesV1 := propsv1.NewHostVolumes()
			err = host.Properties.Get(HostProperty.VolumesV1, hostVolumesV1)
			if err != nil {
				continue
			}
			hostMountsV1 := propsv1.NewHostMounts()
			err = host.Properties.Get(HostProperty.MountsV1, hostMountsV1)
			if err != nil {
				continue
			}
			if volumeAttachment, found := hostVolumesV1.VolumesByID[volume.ID]; found {
				if mount, ok := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[volumeAttachment.Device]]; ok {
					mounts[host.Name] = mount
				} else {
					mounts[host.Name] = propsv1.NewHostLocalMount()
				}
			}
		}
	}
	return volume, mounts, nil
}

// Create a volume
func (svc *VolumeService) Create(name string, size int, speed VolumeSpeed.Enum) (*model.Volume, error) {
	volume, err := svc.provider.CreateVolume(model.VolumeRequest{
		Name:  name,
		Size:  size,
		Speed: speed,
	})
	if err != nil {
		return nil, infraErr(err)
	}

	defer func() {
		if err != nil {
			derr := svc.provider.DeleteVolume(volume.ID)
			if derr != nil {
				log.Debugf("failed to delete volume '%': %v", volume.Name, derr)
			}
		}
	}()

	err = metadata.SaveVolume(svc.provider, volume)
	if err != nil {
		log.Debugf("Error creating volume: saving volume metadata: %+v", err)
		return nil, infraErrf(err, "Error creating volume '%s' saving its volume metadata", name)
	}
	return volume, nil
}

// Attach a volume to an host
func (svc *VolumeService) Attach(volumeName, hostName, path, format string) error {
	// Get volume data
	volume, err := svc.Get(volumeName)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
			return infraErr(err)
		default:
			return infraErr(err)
		}
	}

	volumeAttachedV1 := propsv1.NewVolumeAttachments()
	err = volume.Properties.Get(VolumeProperty.AttachedV1, volumeAttachedV1)
	if err != nil {
		return infraErrf(err, "can't attach volume")
	}

	mountPoint := path
	if path == model.DefaultVolumeMountPoint {
		mountPoint = model.DefaultVolumeMountPoint + volume.Name
	}

	// Get Host data
	hostSvc := NewHostService(svc.provider)
	host, err := hostSvc.ForceInspect(hostName)
	if err != nil {
		return throwErr(err)
	}

	// For now, allows only one attachment...
	if len(volumeAttachedV1.Hosts) > 0 {
		for id := range volumeAttachedV1.Hosts {
			if id != host.ID {
				return model.ResourceNotAvailableError("volume", volumeName)
			}
			break
		}
	}

	hostVolumesV1 := propsv1.NewHostVolumes()
	err = host.Properties.Get(HostProperty.VolumesV1, hostVolumesV1)
	if err != nil {
		return infraErrf(err, "can't attach volume")
	}
	hostMountsV1 := propsv1.NewHostMounts()
	err = host.Properties.Get(HostProperty.MountsV1, hostMountsV1)
	if err != nil {
		return infraErrf(err, "can't attach volume")
	}
	// Check if the volume is already mounted elsewhere
	if device, found := hostVolumesV1.DevicesByID[volume.ID]; found {
		path := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[device]].Path
		if path != mountPoint {
			return logicErr(fmt.Errorf("volume '%s' is already attached in '%s:%s'", volume.Name, host.Name, path))
		}
		return nil
	}

	// Check if there is no other device mounted in the path (or in subpath)
	for _, i := range hostMountsV1.LocalMountsByPath {
		if strings.Index(i.Path, mountPoint) == 0 {
			return logicErr(fmt.Errorf("Can't attach volume '%s' to '%s:%s': there is already a volume mounted in '%s:%s'", volume.Name, host.Name, mountPoint, host.Name, i.Path))
		}
	}
	for _, i := range hostMountsV1.RemoteMountsByPath {
		if strings.Index(i.Path, mountPoint) == 0 {
			return logicErr(fmt.Errorf("Can't attach volume '%s' to '%s:%s': there is a share mounted in path '%s:%s[/...]'", volume.Name, host.Name, mountPoint, host.Name, i.Path))
		}
	}

	// Note: most providers are not able to tell the real device name the volume
	//       will have on the host, so we have to use a way that can work everywhere
	// Get list of disks before attachment
	oldDiskSet, err := svc.listAttachedDevices(host)
	if err != nil {
		err := logicErrf(err, "Failed to get list of connected disks")
		return err
	}
	vaID, err := svc.provider.CreateVolumeAttachment(model.VolumeAttachmentRequest{
		Name:     fmt.Sprintf("%s-%s", volume.Name, host.Name),
		HostID:   host.ID,
		VolumeID: volume.ID,
	})
	if err != nil {
		return infraErrf(err, "can't attach volume '%s'", volumeName)
	}

	// Starting from here, remove volume attachment if exit with error
	defer func() {
		if err != nil {
			derr := svc.provider.DeleteVolumeAttachment(host.ID, vaID)
			if derr != nil {
				log.Errorf("failed to detach volume '%s' from host '%s': %v", volume.Name, host.Name, derr)
			}
		}
	}()

	// Updates volume properties
	volumeAttachedV1.Hosts[host.ID] = host.Name
	err = volume.Properties.Set(VolumeProperty.AttachedV1, volumeAttachedV1)
	if err != nil {
		return infraErrf(err, "can't attach volume")
	}

	// Retries to acknowledge the volume is really attached to host
	var newDisk mapset.Set
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			// Get new of disk after attachment
			newDiskSet, err := svc.listAttachedDevices(host)
			if err != nil {
				err := logicErrf(err, "failed to get list of connected disks")
				return err
			}
			// Isolate the new device
			newDisk = newDiskSet.Difference(oldDiskSet)
			if newDisk.Cardinality() == 0 {
				return logicErr(fmt.Errorf("disk not yet attached, retrying"))
			}
			return nil
		},
		2*time.Minute,
	)
	if retryErr != nil {
		return logicErr(fmt.Errorf("failed to confirm the disk attachment after %s", 2*time.Minute))
	}

	// Recovers real device name from the system
	deviceName := "/dev/" + newDisk.ToSlice()[0].(string)

	// Saves volume information in property
	hostVolumesV1.VolumesByID[volume.ID] = &propsv1.HostVolume{
		AttachID: vaID,
		Device:   deviceName,
	}
	hostVolumesV1.VolumesByName[volume.Name] = volume.ID
	hostVolumesV1.VolumesByDevice[deviceName] = volume.ID
	hostVolumesV1.DevicesByID[volume.ID] = deviceName
	err = host.Properties.Set(HostProperty.VolumesV1, hostVolumesV1)
	if err != nil {
		return infraErrf(err, "can't attach volume")
	}

	// Create mount point
	sshSvc := NewSSHService(svc.provider)
	sshConfig, err := sshSvc.GetConfig(host.ID)
	if err != nil {
		err = infraErr(err)
		return err
	}

	server, err := nfs.NewServer(sshConfig)
	if err != nil {
		err = infraErr(err)
		return err
	}
	err = server.MountBlockDevice(deviceName, mountPoint, format)
	if err != nil {
		err = infraErr(err)
		return err
	}

	// Starting from here, unmount block device if exiting with error
	defer func() {
		if err != nil {
			derr := server.UnmountBlockDevice(deviceName)
			if derr != nil {
				log.Errorf("failed to unmount volume '%s' from host '%s': %v", volume.Name, host.Name, derr)
			}
		}
	}()

	// Updates host properties
	hostMountsV1.LocalMountsByPath[mountPoint] = &propsv1.HostLocalMount{
		Device:     deviceName,
		Path:       mountPoint,
		FileSystem: "nfs",
	}
	hostMountsV1.LocalMountsByDevice[deviceName] = mountPoint
	err = host.Properties.Set(HostProperty.MountsV1, hostMountsV1)
	if err != nil {
		return infraErrf(err, "can't attach volume")
	}

	err = metadata.SaveVolume(svc.provider, volume)
	if err != nil {
		return infraErrf(err, "can't attach volume")
	}
	err = metadata.SaveHost(svc.provider, host)
	if err != nil {
		return infraErrf(err, "can't attach volume")
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
				err = infraErr(err)
				return err
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
		return nil, logicErrf(retryErr, fmt.Sprintf("failed to get list of connected disks after %s", 2*time.Minute))
	}
	disks := strings.Split(stdout, "\n")
	set := mapset.NewThreadUnsafeSet()
	for _, k := range disks {
		set.Add(k)
	}
	return set, nil
}

// Detach detach the volume identified by ref, ref can be the name or the id
func (svc *VolumeService) Detach(volumeName, hostName string) error {
	// Load volume data
	volume, err := svc.Get(volumeName)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
			return infraErr(err)
		default:
			return infraErr(model.ResourceNotFoundError("volume", volumeName))
		}
	}
	if volume == nil {

	}
	// Load host data
	hostSvc := NewHostService(svc.provider)
	host, err := hostSvc.ForceInspect(hostName)
	if err != nil {
		return throwErr(err)
	}

	// Obtain volume attachment ID
	hostVolumesV1 := propsv1.NewHostVolumes()
	err = host.Properties.Get(HostProperty.VolumesV1, hostVolumesV1)
	if err != nil {
		err = infraErr(err)
		return err
	}

	// Check the volume is effectively attached
	attachment, found := hostVolumesV1.VolumesByID[volume.ID]
	if !found {
		return logicErr(fmt.Errorf("Can't detach volume '%s': not attached to host '%s'", volumeName, host.Name))
	}

	// Obtain mounts information
	hostMountsV1 := propsv1.NewHostMounts()
	err = host.Properties.Get(HostProperty.MountsV1, hostMountsV1)
	if err != nil {
		err = infraErr(err)
		return err
	}

	device := attachment.Device
	path := hostMountsV1.LocalMountsByDevice[device]
	mount := hostMountsV1.LocalMountsByPath[path]
	if mount == nil {
		return logicErr(errors.Wrap(fmt.Errorf("metadata inconsistency: no mount corresponding to volume attachment"), ""))
	}

	// Check if volume has other mount(s) inside it
	for p, i := range hostMountsV1.LocalMountsByPath {
		if i.Device == device {
			continue
		}
		if strings.Index(p, mount.Path) == 0 {
			return logicErr(fmt.Errorf("can't detach volume '%s' from '%s:%s', there is a volume mounted in '%s:%s'",
				volume.Name, host.Name, mount.Path, host.Name, p))
		}
	}
	for p := range hostMountsV1.RemoteMountsByPath {
		if strings.Index(p, mount.Path) == 0 {
			return logicErr(fmt.Errorf("can't detach volume '%s' from '%s:%s', there is a share mounted in '%s:%s'",
				volume.Name, host.Name, mount.Path, host.Name, p))
		}
	}

	// Check if volume (or a subdir in volume) is shared
	hostSharesV1 := propsv1.NewHostShares()
	err = host.Properties.Get(HostProperty.SharesV1, hostSharesV1)
	if err != nil {
		return infraErrf(err, "failed to check if volume is shared")
	}
	for _, v := range hostSharesV1.ByID {
		if strings.Index(v.Path, mount.Path) == 0 {
			return logicErr(fmt.Errorf("can't detach volume '%s' from '%s:%s', '%s:%s' is shared",
				volume.Name, host.Name, mount.Path, host.Name, v.Path))
		}
	}

	// Unmount the Block Device ...
	sshSvc := NewSSHService(svc.provider)
	sshConfig, err := sshSvc.GetConfig(host.ID)
	if err != nil {
		err = logicErrf(err, "error getting ssh config")
		return err
	}
	nfsServer, err := nfs.NewServer(sshConfig)
	if err != nil {
		err = logicErrf(err, "error creating nfs service")
		return err
	}
	err = nfsServer.UnmountBlockDevice(attachment.Device)
	if err != nil {
		err = logicErrf(err, "error unmounting block device")
		return err
	}

	// ... then detach volume
	err = svc.provider.DeleteVolumeAttachment(host.ID, attachment.AttachID)
	if err != nil {
		err = infraErr(err)
		return err
	}

	// Updates host property propsv1.VolumesV1
	delete(hostVolumesV1.VolumesByID, volume.ID)
	delete(hostVolumesV1.VolumesByName, volume.Name)
	delete(hostVolumesV1.VolumesByDevice, attachment.Device)
	delete(hostVolumesV1.DevicesByID, volume.ID)
	err = host.Properties.Set(HostProperty.VolumesV1, hostVolumesV1)
	if err != nil {
		err = infraErr(err)
		return err
	}

	// Updates host property propsv1.MountsV1
	delete(hostMountsV1.LocalMountsByDevice, mount.Device)
	delete(hostMountsV1.LocalMountsByPath, mount.Path)
	err = host.Properties.Set(HostProperty.MountsV1, hostMountsV1)
	if err != nil {
		err = infraErr(err)
		return err
	}

	// Updates volume property propsv1.VolumeAttachments
	volumeAttachedV1 := propsv1.NewVolumeAttachments()
	err = volume.Properties.Get(VolumeProperty.AttachedV1, volumeAttachedV1)
	if err != nil {
		err = infraErr(err)
		return err
	}
	delete(volumeAttachedV1.Hosts, host.ID)
	err = volume.Properties.Set(VolumeProperty.AttachedV1, volumeAttachedV1)
	if err != nil {
		err = infraErr(err)
		return err
	}

	// Updates metadata
	err = metadata.SaveHost(svc.provider, host)
	if err != nil {
		err = infraErr(err)
		return err
	}
	return metadata.SaveVolume(svc.provider, volume)
}
