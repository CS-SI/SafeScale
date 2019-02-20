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

package handlers

import (
	"fmt"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/broker/server/metadata"
	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/iaas/resources/enums/HostProperty"
	"github.com/CS-SI/SafeScale/iaas/resources/enums/VolumeProperty"
	"github.com/CS-SI/SafeScale/iaas/resources/enums/VolumeSpeed"
	propsv1 "github.com/CS-SI/SafeScale/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/system/nfs"
	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/retry"
)

//go:generate mockgen -destination=../mocks/mock_volumeapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/handlers VolumeAPI

// VolumeAPI defines API to manipulate hosts
type VolumeAPI interface {
	Delete(ref string) error
	Inspect(ref string) (*resources.Volume, map[string]*propsv1.HostLocalMount, error)
	List(all bool) ([]resources.Volume, error)
	Create(name string, size int, speed VolumeSpeed.Enum) (*resources.Volume, error)
	Attach(volume string, host string, path string, format string, doNotFormat bool) error
	Detach(volume string, host string) error
}

// VolumeHandler volume service
type VolumeHandler struct {
	service *iaas.Service
}

// NewVolumeHandler creates a Volume service
func NewVolumeHandler(svc *iaas.Service) VolumeAPI {
	return &VolumeHandler{
		service: svc,
	}
}

// List returns the network list
func (handler *VolumeHandler) List(all bool) ([]resources.Volume, error) {
	if all {
		volumes, err := handler.service.ListVolumes()
		return volumes, infraErr(err)
	}

	var volumes []resources.Volume
	mv := metadata.NewVolume(handler.service)
	err := mv.Browse(func(volume *resources.Volume) error {
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
func (handler *VolumeHandler) Delete(ref string) error {
	mv, err := metadata.LoadVolume(handler.service, ref)
	if err != nil {
		switch err.(type) {
		case utils.ErrNotFound:
			return resources.ResourceNotFoundError("volume", ref)
		default:
			log.Debugf("Failed to delete volume: %+v", err)
			return infraErrf(err, "failed to delete volume")
		}
	}
	volume := mv.Get()

	err = volume.Properties.LockForRead(VolumeProperty.AttachedV1).ThenUse(func(v interface{}) error {
		volumeAttachmentsV1 := v.(*propsv1.VolumeAttachments)
		nbAttach := len(volumeAttachmentsV1.Hosts)
		if nbAttach > 0 {
			var list []string
			for _, v := range volumeAttachmentsV1.Hosts {
				list = append(list, v)
			}
			return logicErr(fmt.Errorf("still attached to %d host%s: %s", nbAttach, utils.Plural(nbAttach), strings.Join(list, ", ")))
		}
		return nil
	})
	if err != nil {
		return err
	}

	err = handler.service.DeleteVolume(volume.ID)
	if err != nil {
		return infraErr(err)
	}

	delErr := mv.Delete()
	return infraErr(delErr)
}

// Inspect returns the volume identified by ref and its attachment (if any)
func (handler *VolumeHandler) Inspect(ref string) (*resources.Volume, map[string]*propsv1.HostLocalMount, error) {
	mv, err := metadata.LoadVolume(handler.service, ref)
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); ok {
			return nil, nil, logicErr(resources.ResourceNotFoundError("volume", ref))
		}
		err := infraErr(err)
		return nil, nil, err
	}
	volume := mv.Get()

	mounts := map[string]*propsv1.HostLocalMount{}
	hostSvc := NewHostHandler(handler.service)

	err = volume.Properties.LockForRead(VolumeProperty.AttachedV1).ThenUse(func(v interface{}) error {
		volumeAttachedV1 := v.(*propsv1.VolumeAttachments)
		if len(volumeAttachedV1.Hosts) > 0 {
			for id := range volumeAttachedV1.Hosts {
				host, err := hostSvc.Inspect(id)
				if err != nil {
					continue
				}
				err = host.Properties.LockForRead(HostProperty.VolumesV1).ThenUse(func(v interface{}) error {
					hostVolumesV1 := v.(*propsv1.HostVolumes)
					if volumeAttachment, found := hostVolumesV1.VolumesByID[volume.ID]; found {
						err = host.Properties.LockForRead(HostProperty.MountsV1).ThenUse(func(v interface{}) error {
							hostMountsV1 := v.(*propsv1.HostMounts)
							if mount, ok := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[volumeAttachment.Device]]; ok {
								mounts[host.Name] = mount
							} else {
								mounts[host.Name] = propsv1.NewHostLocalMount()
							}
							return nil
						})
						if err != nil {
							return err
						}
					}
					return nil
				})
				if err != nil {
					continue
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return volume, mounts, nil
}

// Create a volume
func (handler *VolumeHandler) Create(name string, size int, speed VolumeSpeed.Enum) (*resources.Volume, error) {
	volume, err := handler.service.CreateVolume(resources.VolumeRequest{
		Name:  name,
		Size:  size,
		Speed: speed,
	})
	if err != nil {
		return nil, infraErr(err)
	}

	defer func() {
		if err != nil {
			derr := handler.service.DeleteVolume(volume.ID)
			if derr != nil {
				log.Debugf("failed to delete volume '%s': %v", volume.Name, derr)
			}
		}
	}()

	err = metadata.SaveVolume(handler.service, volume)
	if err != nil {
		log.Debugf("Error creating volume: saving volume metadata: %+v", err)
		return nil, infraErrf(err, "Error creating volume '%s' saving its volume metadata", name)
	}
	return volume, nil
}

// Attach a volume to an host
func (handler *VolumeHandler) Attach(volumeName, hostName, path, format string, doNotFormat bool) error {
	// Get volume data
	volume, _, err := handler.Inspect(volumeName)
	if err != nil {
		switch err.(type) {
		case resources.ErrResourceNotFound:
			return infraErr(err)
		default:
			return infraErr(err)
		}
	}

	// Get Host data
	hostSvc := NewHostHandler(handler.service)
	host, err := hostSvc.ForceInspect(hostName)
	if err != nil {
		return throwErr(err)
	}

	var (
		deviceName string
		volumeUUID string
		mountPoint string
	)

	err = volume.Properties.LockForWrite(VolumeProperty.AttachedV1).ThenUse(func(v interface{}) error {
		volumeAttachedV1 := v.(*propsv1.VolumeAttachments)

		mountPoint = path
		if path == resources.DefaultVolumeMountPoint {
			mountPoint = resources.DefaultVolumeMountPoint + volume.Name
		}

		// For now, allows only one attachment...
		if len(volumeAttachedV1.Hosts) > 0 {
			for id := range volumeAttachedV1.Hosts {
				if id != host.ID {
					return resources.ResourceNotAvailableError("volume", volumeName)
				}
				break
			}
		}

		return host.Properties.LockForWrite(HostProperty.VolumesV1).ThenUse(func(v interface{}) error {
			hostVolumesV1 := v.(*propsv1.HostVolumes)
			return host.Properties.LockForWrite(HostProperty.MountsV1).ThenUse(func(v interface{}) error {
				hostMountsV1 := v.(*propsv1.HostMounts)
				// Check if the volume is already mounted elsewhere
				if device, found := hostVolumesV1.DevicesByID[volume.ID]; found {
					mount, ok := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[device]]
					if !ok {
						return logicErr(fmt.Errorf("metadata inconsistency for volume '%s' attached to host '%s'", volume.Name, host.Name))
					}
					path := mount.Path
					if path != mountPoint {
						return logicErr(fmt.Errorf("volume '%s' is already attached in '%s:%s'", volume.Name, host.Name, path))
					}
					return nil
				}

				// Check if there is no other device mounted in the path (or in subpath)
				for _, i := range hostMountsV1.LocalMountsByPath {
					if strings.Index(i.Path, mountPoint) == 0 {
						return logicErr(fmt.Errorf("can't attach volume '%s' to '%s:%s': there is already a volume mounted in '%s:%s'", volume.Name, host.Name, mountPoint, host.Name, i.Path))
					}
				}
				for _, i := range hostMountsV1.RemoteMountsByPath {
					if strings.Index(i.Path, mountPoint) == 0 {
						return logicErr(fmt.Errorf("can't attach volume '%s' to '%s:%s': there is a share mounted in path '%s:%s[/...]'", volume.Name, host.Name, mountPoint, host.Name, i.Path))
					}
				}

				// Note: most providers are not able to tell the real device name the volume
				//       will have on the host, so we have to use a way that can work everywhere
				// Get list of disks before attachment
				oldDiskSet, err := handler.listAttachedDevices(host)
				if err != nil {
					err := logicErrf(err, "failed to get list of connected disks")
					return err
				}
				vaID, err := handler.service.CreateVolumeAttachment(resources.VolumeAttachmentRequest{
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
						derr := handler.service.DeleteVolumeAttachment(host.ID, vaID)
						if derr != nil {
							log.Errorf("failed to detach volume '%s' from host '%s': %v", volume.Name, host.Name, derr)
						}
					}
				}()

				// Updates volume properties
				volumeAttachedV1.Hosts[host.ID] = host.Name

				// Retries to acknowledge the volume is really attached to host
				var newDisk mapset.Set
				retryErr := retry.WhileUnsuccessfulDelay1Second(
					func() error {
						// Get new of disk after attachment
						newDiskSet, err := handler.listAttachedDevices(host)
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
				deviceName = "/dev/" + newDisk.ToSlice()[0].(string)

				// Create mount point
				sshHandler := NewSSHHandler(handler.service)
				sshConfig, err := sshHandler.GetConfig(host.ID)
				if err != nil {
					err = infraErr(err)
					return err
				}

				server, err := nfs.NewServer(sshConfig)
				if err != nil {
					return infraErr(err)
				}
				volumeUUID, err = server.MountBlockDevice(deviceName, mountPoint, format, doNotFormat)
				if err != nil {
					err = infraErr(err)
					return err
				}

				// Saves volume information in property
				hostVolumesV1.VolumesByID[volume.ID] = &propsv1.HostVolume{
					AttachID: vaID,
					Device:   volumeUUID,
				}
				hostVolumesV1.VolumesByName[volume.Name] = volume.ID
				hostVolumesV1.VolumesByDevice[volumeUUID] = volume.ID
				hostVolumesV1.DevicesByID[volume.ID] = volumeUUID

				// Starting from here, unmount block device if exiting with error
				defer func() {
					if err != nil {
						derr := server.UnmountBlockDevice(volumeUUID)
						if derr != nil {
							log.Errorf("failed to unmount volume '%s' from host '%s': %v", volume.Name, host.Name, derr)
						}
					}
				}()

				// Updates host properties
				hostMountsV1.LocalMountsByPath[mountPoint] = &propsv1.HostLocalMount{
					Device:     volumeUUID,
					Path:       mountPoint,
					FileSystem: "nfs",
				}
				hostMountsV1.LocalMountsByDevice[volumeUUID] = mountPoint

				return nil
			})
		})
	})
	if err != nil {
		return infraErrf(err, "can't attach volume")
	}

	err = metadata.SaveVolume(handler.service, volume)
	if err != nil {
		return infraErrf(err, "can't attach volume")
	}
	err = metadata.SaveHost(handler.service, host)
	if err != nil {
		return infraErrf(err, "can't attach volume")
	}

	log.Infof("Volume '%s' successfully attached to host '%s' and mounted in '%s'", volume.Name, host.Name, mountPoint)
	return nil
}

func (handler *VolumeHandler) listAttachedDevices(host *resources.Host) (mapset.Set, error) {
	var (
		retcode        int
		stdout, stderr string
		err            error
	)
	cmd := "sudo lsblk -l -o NAME,TYPE | grep disk | cut -d' ' -f1"
	sshHandler := NewSSHHandler(handler.service)
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			retcode, stdout, stderr, err = sshHandler.Run(host.ID, cmd)
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
func (handler *VolumeHandler) Detach(volumeName, hostName string) error {
	// Load volume data
	volume, _, err := handler.Inspect(volumeName)
	if err != nil {
		switch err.(type) {
		case resources.ErrResourceNotFound:
			return infraErr(err)
		default:
			return infraErr(resources.ResourceNotFoundError("volume", volumeName))
		}
	}

	// Load host data
	hostSvc := NewHostHandler(handler.service)
	host, err := hostSvc.ForceInspect(hostName)
	if err != nil {
		return throwErr(err)
	}

	// Obtain volume attachment ID
	err = host.Properties.LockForWrite(HostProperty.VolumesV1).ThenUse(func(v interface{}) error {
		hostVolumesV1 := v.(*propsv1.HostVolumes)

		// Check the volume is effectively attached
		attachment, found := hostVolumesV1.VolumesByID[volume.ID]
		if !found {
			return logicErr(fmt.Errorf("Can't detach volume '%s': not attached to host '%s'", volumeName, host.Name))
		}

		// Obtain mounts information
		return host.Properties.LockForWrite(HostProperty.MountsV1).ThenUse(func(v interface{}) error {
			hostMountsV1 := v.(*propsv1.HostMounts)
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
			return host.Properties.LockForWrite(HostProperty.SharesV1).ThenUse(func(v interface{}) error {
				hostSharesV1 := v.(*propsv1.HostShares)

				for _, v := range hostSharesV1.ByID {
					if strings.Index(v.Path, mount.Path) == 0 {
						return logicErr(fmt.Errorf("can't detach volume '%s' from '%s:%s', '%s:%s' is shared",
							volume.Name, host.Name, mount.Path, host.Name, v.Path))
					}
				}

				// Unmount the Block Device ...
				sshHandler := NewSSHHandler(handler.service)
				sshConfig, err := sshHandler.GetConfig(host.ID)
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
				err = handler.service.DeleteVolumeAttachment(host.ID, attachment.AttachID)
				if err != nil {
					err = infraErr(err)
					return err
				}

				// Updates host property propsv1.VolumesV1
				delete(hostVolumesV1.VolumesByID, volume.ID)
				delete(hostVolumesV1.VolumesByName, volume.Name)
				delete(hostVolumesV1.VolumesByDevice, attachment.Device)
				delete(hostVolumesV1.DevicesByID, volume.ID)

				// Updates host property propsv1.MountsV1
				delete(hostMountsV1.LocalMountsByDevice, mount.Device)
				delete(hostMountsV1.LocalMountsByPath, mount.Path)

				// Updates volume property propsv1.VolumeAttachments
				return volume.Properties.LockForWrite(VolumeProperty.AttachedV1).ThenUse(func(v interface{}) error {
					volumeAttachedV1 := v.(*propsv1.VolumeAttachments)
					delete(volumeAttachedV1.Hosts, host.ID)
					return nil
				})
			})
		})
	})
	if err != nil {
		return err
	}

	// Updates metadata
	err = metadata.SaveHost(handler.service, host)
	if err != nil {
		return infraErr(err)
	}
	err = metadata.SaveVolume(handler.service, volume)
	if err != nil {
		return infraErr(err)
	}
	return nil
}
