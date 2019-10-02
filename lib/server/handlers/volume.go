/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"context"
	"fmt"
	"strings"

	mapset "github.com/deckarep/golang-set"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostProperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeProperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeSpeed"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/metadata"
	"github.com/CS-SI/SafeScale/lib/system/nfs"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

//go:generate mockgen -destination=../mocks/mock_volumeapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers VolumeAPI

// VolumeAPI defines API to manipulate hosts
type VolumeAPI interface {
	Delete(ctx context.Context, ref string) error
	List(ctx context.Context, all bool) ([]resources.Volume, error)
	Inspect(ctx context.Context, ref string) (*resources.Volume, map[string]*propsv1.HostLocalMount, error)
	Create(ctx context.Context, name string, size int, speed VolumeSpeed.Enum) (*resources.Volume, error)
	Attach(ctx context.Context, volume string, host string, path string, format string, doNotFormat bool) error
	Detach(ctx context.Context, volume string, host string) error
}

// VolumeHandler volume service
type VolumeHandler struct {
	service iaas.Service
}

// NewVolumeHandler creates a Volume service
func NewVolumeHandler(svc iaas.Service) VolumeAPI {
	return &VolumeHandler{
		service: svc,
	}
}

// List returns the network list
func (handler *VolumeHandler) List(ctx context.Context, all bool) (volumes []resources.Volume, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	//FIXME: validate parameters

	tracer := concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if all {
		volumes, err := handler.service.ListVolumes()
		return volumes, err
	}

	mv := metadata.NewVolume(handler.service)
	err = mv.Browse(func(volume *resources.Volume) error {
		volumes = append(volumes, *volume)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return volumes, nil
}

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// Delete deletes volume referenced by ref
func (handler *VolumeHandler) Delete(ctx context.Context, ref string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	// FIXME: validate parameters

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("(%s)", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mv, err := metadata.LoadVolume(handler.service, ref)
	if err != nil {
		switch err.(type) {
		case scerr.ErrNotFound:
			return resources.ResourceNotFoundError("volume", ref)
		default:
			logrus.Debugf("Failed to delete volume: %+v", err)
			return err
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
			return fmt.Errorf("still attached to %d host%s: %s", nbAttach, utils.Plural(nbAttach), strings.Join(list, ", "))
		}
		return nil
	})
	if err != nil {
		return err
	}

	err = handler.service.DeleteVolume(volume.ID)
	if err != nil {
		switch err.(type) {
		case scerr.ErrNotFound:
			logrus.Warnf("Unable to find the volume on provider side, cleaning up metadata")
		case scerr.ErrInvalidRequest, scerr.ErrTimeout:
			return err
		default:
			return err
		}
	}
	err = mv.Delete()
	if err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		logrus.Warnf("Volume deletion cancelled by user")
		volumeBis, err := handler.Create(context.Background(), volume.Name, volume.Size, volume.Speed)
		if err != nil {
			return fmt.Errorf("failed to stop volume deletion")
		}
		buf, err := volumeBis.Serialize()
		if err != nil {
			return fmt.Errorf("failed to recreate deleted volume")
		}
		return fmt.Errorf("deleted volume recreated by safescale : %s", buf)
	default:
	}

	return nil
}

// Inspect returns the volume identified by ref and its attachment (if any)
func (handler *VolumeHandler) Inspect(
	ctx context.Context,
	ref string,
) (volume *resources.Volume, mounts map[string]*propsv1.HostLocalMount, err error) {

	if handler == nil {
		return nil, nil, scerr.InvalidInstanceError()
	}
	// FIXME: validate parameters

	tracer := concurrency.NewTracer(nil, "('"+ref+"')", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mv, err := metadata.LoadVolume(handler.service, ref)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			return nil, nil, resources.ResourceNotFoundError("volume", ref)
		}
		return nil, nil, err
	}
	volume = mv.Get()

	mounts = map[string]*propsv1.HostLocalMount{}
	hostSvc := NewHostHandler(handler.service)

	err = volume.Properties.LockForRead(VolumeProperty.AttachedV1).ThenUse(func(v interface{}) error {
		volumeAttachedV1 := v.(*propsv1.VolumeAttachments)
		if len(volumeAttachedV1.Hosts) > 0 {
			for id := range volumeAttachedV1.Hosts {
				host, err := hostSvc.Inspect(ctx, id)
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
func (handler *VolumeHandler) Create(ctx context.Context, name string, size int, speed VolumeSpeed.Enum) (volume *resources.Volume, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	// FIXME: validate parameters

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', %d, %s)", name, size, speed.String()), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	volume, err = handler.service.CreateVolume(resources.VolumeRequest{
		Name:  name,
		Size:  size,
		Speed: speed,
	})
	if err != nil {
		switch err.(type) {
		case scerr.ErrNotFound, scerr.ErrInvalidRequest, scerr.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	}

	// starting from here delete volume if function ends with failure
	newVolume := volume
	defer func() {
		if err != nil {
			derr := handler.service.DeleteVolume(newVolume.ID)
			if derr != nil {
				switch derr.(type) {
				case scerr.ErrNotFound:
					logrus.Errorf("Cleaning up on failure, failed to delete volume '%s': %v", newVolume.Name, derr)
				case scerr.ErrTimeout:
					logrus.Errorf("Cleaning up on failure, failed to delete volume '%s': %v", newVolume.Name, derr)
				default:
					logrus.Errorf("Cleaning up on failure, failed to delete volume '%s': %v", newVolume.Name, derr)
				}
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	md, err := metadata.SaveVolume(handler.service, volume)
	if err != nil {
		logrus.Debugf("Error creating volume: saving volume metadata: %+v", err)
		return nil, err
	}

	// starting from here delete volume if function ends with failure
	defer func() {
		if err != nil {
			derr := md.Delete()
			if derr != nil {
				logrus.Warnf("Failed to delete metadata of volume '%s'", newVolume.Name)
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	select {
	case <-ctx.Done():
		logrus.Warnf("Volume creation cancelled by user")
		err = fmt.Errorf("volume creation cancelled by user")
		return nil, err
	default:
	}

	return volume, nil
}

// Attach a volume to an host
func (handler *VolumeHandler) Attach(ctx context.Context, volumeName, hostName, path, format string, doNotFormat bool) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	// FIXME: validate parameters
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s', '%s', '%s', %v)", volumeName, hostName, path, format, doNotFormat), true)
	defer tracer.WithStopwatch().GoingIn().OnExitTrace()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Get volume data
	volume, _, err := handler.Inspect(ctx, volumeName)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			return err
		}
		return err
	}

	// Get Host data
	hostSvc := NewHostHandler(handler.service)
	host, err := hostSvc.ForceInspect(ctx, hostName)
	if err != nil {
		return err
	}

	var (
		deviceName string
		volumeUUID string
		mountPoint string
		vaID       string
		server     *nfs.Server
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
						return fmt.Errorf("metadata inconsistency for volume '%s' attached to host '%s'", volume.Name, host.Name)
					}
					path := mount.Path
					if path != mountPoint {
						return fmt.Errorf("volume '%s' is already attached in '%s:%s'", volume.Name, host.Name, path)
					}
					return nil
				}

				// Check if there is no other device mounted in the path (or in subpath)
				for _, i := range hostMountsV1.LocalMountsByPath {
					if strings.Index(i.Path, mountPoint) == 0 {
						return fmt.Errorf("can't attach volume '%s' to '%s:%s': there is already a volume mounted in '%s:%s'", volume.Name, host.Name, mountPoint, host.Name, i.Path)
					}
				}
				for _, i := range hostMountsV1.RemoteMountsByPath {
					if strings.Index(i.Path, mountPoint) == 0 {
						return fmt.Errorf("can't attach volume '%s' to '%s:%s': there is a share mounted in path '%s:%s[/...]'", volume.Name, host.Name, mountPoint, host.Name, i.Path)
					}
				}

				// Note: most providers are not able to tell the real device name the volume
				//       will have on the host, so we have to use a way that can work everywhere
				// Get list of disks before attachment
				oldDiskSet, err := handler.listAttachedDevices(ctx, host)
				if err != nil {
					return err
				}
				vaID, err := handler.service.CreateVolumeAttachment(resources.VolumeAttachmentRequest{
					Name:     fmt.Sprintf("%s-%s", volume.Name, host.Name),
					HostID:   host.ID,
					VolumeID: volume.ID,
				})
				if err != nil {
					switch err.(type) {
					case scerr.ErrNotFound, scerr.ErrInvalidRequest, scerr.ErrTimeout:
						return err
					default:
						return err
					}
				}
				// Starting from here, remove volume attachment if exit with error
				defer func() {
					if err != nil {
						derr := handler.service.DeleteVolumeAttachment(host.ID, vaID)
						if derr != nil {
							switch derr.(type) {
							case scerr.ErrNotFound:
								logrus.Errorf("Cleaning up on failure, failed to detach volume '%s' from host '%s': %v", volume.Name, host.Name, derr)
							case scerr.ErrTimeout:
								logrus.Errorf("Cleaning up on failure, failed to detach volume '%s' from host '%s': %v", volume.Name, host.Name, derr)
							default:
								logrus.Errorf("Cleaning up on failure, failed to detach volume '%s' from host '%s': %v", volume.Name, host.Name, derr)
							}
							err = scerr.AddConsequence(err, derr)
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
						newDiskSet, err := handler.listAttachedDevices(ctx, host)
						if err != nil {
							return err
						}
						// Isolate the new device
						newDisk = newDiskSet.Difference(oldDiskSet)
						if newDisk.Cardinality() == 0 {
							return fmt.Errorf("disk not yet attached, retrying")
						}
						return nil
					},
					temporal.GetContextTimeout(),
				)
				if retryErr != nil {
					return fmt.Errorf("failed to confirm the disk attachment after %s", temporal.GetContextTimeout())
				}

				// Recovers real device name from the system
				deviceName = "/dev/" + newDisk.ToSlice()[0].(string)

				// Create mount point
				sshHandler := NewSSHHandler(handler.service)
				sshConfig, err := sshHandler.GetConfig(ctx, host.ID)
				if err != nil {
					return err
				}

				server, err = nfs.NewServer(sshConfig)
				if err != nil {
					return err
				}
				volumeUUID, err = server.MountBlockDevice(deviceName, mountPoint, format, doNotFormat)
				if err != nil {
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
							logrus.Errorf("failed to unmount volume '%s' from host '%s': %v", volume.Name, host.Name, derr)
							err = scerr.AddConsequence(err, derr)
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
		return err
	}

	defer func() {
		if err != nil {
			derr := server.UnmountBlockDevice(volumeUUID)
			if derr != nil {
				logrus.Errorf("failed to unmount volume '%s' from host '%s': %v", volume.Name, host.Name, derr)
				err = scerr.AddConsequence(err, derr)
			}
			derr = handler.service.DeleteVolumeAttachment(host.ID, vaID)
			if derr != nil {
				switch derr.(type) {
				case scerr.ErrNotFound:
					logrus.Errorf("Cleaning up on failure, failed to detach volume '%s' from host '%s': %v", volume.Name, host.Name, derr)
				case scerr.ErrTimeout:
					logrus.Errorf("Cleaning up on failure, failed to detach volume '%s' from host '%s': %v", volume.Name, host.Name, derr)
				default:
					logrus.Errorf("Cleaning up on failure, failed to detach volume '%s' from host '%s': %v", volume.Name, host.Name, derr)
				}
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	_, err = metadata.SaveVolume(handler.service, volume)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			err2 := volume.Properties.LockForWrite(VolumeProperty.AttachedV1).ThenUse(func(v interface{}) error {
				volumeAttachedV1 := v.(*propsv1.VolumeAttachments)
				delete(volumeAttachedV1.Hosts, host.ID)
				return nil
			})
			if err2 != nil {
				logrus.Warnf("Failed to set volume %s metadatas", volumeName)
				err = scerr.AddConsequence(err, err2)
			}
			_, err2 = metadata.SaveVolume(handler.service, volume)
			if err2 != nil {
				logrus.Warnf("Failed to save volume %s metadatas", volumeName)
				err = scerr.AddConsequence(err, err2)
			}
		}
	}()

	mh, err := metadata.SaveHost(handler.service, host)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			err2 := host.Properties.LockForWrite(HostProperty.VolumesV1).ThenUse(func(v interface{}) error {
				hostVolumesV1 := v.(*propsv1.HostVolumes)
				delete(hostVolumesV1.VolumesByID, volume.ID)
				delete(hostVolumesV1.VolumesByName, volume.Name)
				delete(hostVolumesV1.VolumesByDevice, volumeUUID)
				delete(hostVolumesV1.DevicesByID, volume.ID)
				return nil
			})
			if err2 != nil {
				logrus.Warnf("Failed to set host '%s' metadata about volumes", volumeName)
				err = scerr.AddConsequence(err, err2)
			}
			err2 = host.Properties.LockForWrite(HostProperty.MountsV1).ThenUse(func(v interface{}) error {
				hostMountsV1 := v.(*propsv1.HostMounts)
				delete(hostMountsV1.LocalMountsByDevice, volumeUUID)
				delete(hostMountsV1.LocalMountsByPath, mountPoint)
				return nil
			})
			if err2 != nil {
				logrus.Warnf("Failed to set host '%s' metadata about mounts", volumeName)
				err = scerr.AddConsequence(err, err2)

			}
			err2 = mh.Write()
			if err2 != nil {
				logrus.Warnf("Failed to save host '%s' metadata", volumeName)
				err = scerr.AddConsequence(err, err2)
			}
		}
	}()

	select {
	case <-ctx.Done():
		logrus.Warnf("Volume attachment cancelled by user")
		err = fmt.Errorf("volume attachment cancelled by user")
		return err
	default:
	}

	logrus.Infof("Volume '%s' successfully attached to host '%s' as device '%s'", volume.Name, host.Name, volumeUUID)
	return nil
}

func (handler *VolumeHandler) listAttachedDevices(ctx context.Context, host *resources.Host) (set mapset.Set, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	// FIXME: validate parameters

	defer scerr.OnExitLogError(concurrency.NewTracer(nil, "", true).TraceMessage(""), &err)()

	var (
		retcode        int
		stdout, stderr string
	)
	cmd := "sudo lsblk -l -o NAME,TYPE | grep disk | cut -d' ' -f1"
	sshHandler := NewSSHHandler(handler.service)
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			retcode, stdout, stderr, err = sshHandler.Run(ctx, host.ID, cmd)
			if err != nil {
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
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return nil, scerr.Wrap(retryErr, fmt.Sprintf("failed to get list of connected disks after %s", temporal.GetContextTimeout()))
	}
	disks := strings.Split(stdout, "\n")
	set = mapset.NewThreadUnsafeSet()
	for _, k := range disks {
		set.Add(k)
	}
	return set, nil
}

// Detach detach the volume identified by ref, ref can be the name or the id
func (handler *VolumeHandler) Detach(ctx context.Context, volumeName, hostName string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	// FIXME: validate parameters

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s')", volumeName, hostName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Load volume data
	volume, _, err := handler.Inspect(ctx, volumeName)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return err
		}
		return resources.ResourceNotFoundError("volume", volumeName)
	}
	mountPath := ""

	// Load host data
	hostSvc := NewHostHandler(handler.service)
	host, err := hostSvc.ForceInspect(ctx, hostName)
	if err != nil {
		return err
	}

	// Obtain volume attachment ID
	err = host.Properties.LockForWrite(HostProperty.VolumesV1).ThenUse(func(v interface{}) error {
		hostVolumesV1 := v.(*propsv1.HostVolumes)

		// Check the volume is effectively attached
		attachment, found := hostVolumesV1.VolumesByID[volume.ID]
		if !found {
			return fmt.Errorf("can't detach volume '%s': not attached to host '%s'", volumeName, host.Name)
		}

		// Obtain mounts information
		return host.Properties.LockForWrite(HostProperty.MountsV1).ThenUse(func(v interface{}) error {
			hostMountsV1 := v.(*propsv1.HostMounts)
			device := attachment.Device
			mountPath = hostMountsV1.LocalMountsByDevice[device]
			mount := hostMountsV1.LocalMountsByPath[mountPath]
			if mount == nil {
				return fmt.Errorf("metadata inconsistency: no mount corresponding to volume attachment")
			}

			// Check if volume has other mount(s) inside it
			for p, i := range hostMountsV1.LocalMountsByPath {
				if i.Device == device {
					continue
				}
				if strings.Index(p, mount.Path) == 0 {
					return fmt.Errorf("can't detach volume '%s' from '%s:%s', there is a volume mounted in '%s:%s'",
						volume.Name, host.Name, mount.Path, host.Name, p)
				}
			}
			for p := range hostMountsV1.RemoteMountsByPath {
				if strings.Index(p, mount.Path) == 0 {
					return fmt.Errorf("can't detach volume '%s' from '%s:%s', there is a share mounted in '%s:%s'",
						volume.Name, host.Name, mount.Path, host.Name, p)
				}
			}

			// Check if volume (or a subdir in volume) is shared
			return host.Properties.LockForWrite(HostProperty.SharesV1).ThenUse(func(v interface{}) error {
				hostSharesV1 := v.(*propsv1.HostShares)

				for _, v := range hostSharesV1.ByID {
					if strings.Index(v.Path, mount.Path) == 0 {
						return fmt.Errorf("can't detach volume '%s' from '%s:%s', '%s:%s' is shared",
							volume.Name, host.Name, mount.Path, host.Name, v.Path)
					}
				}

				// Unmount the Block Device ...
				sshHandler := NewSSHHandler(handler.service)
				sshConfig, err := sshHandler.GetConfig(ctx, host.ID)
				if err != nil {
					return err
				}
				nfsServer, err := nfs.NewServer(sshConfig)
				if err != nil {
					return err
				}
				err = nfsServer.UnmountBlockDevice(attachment.Device)
				if err != nil {
					// FIXME Think about this
					logrus.Error(err)
					//return err
				}

				// ... then detach volume
				err = handler.service.DeleteVolumeAttachment(host.ID, attachment.AttachID)
				if err != nil {
					switch err.(type) {
					case scerr.ErrNotFound, scerr.ErrInvalidRequest, scerr.ErrTimeout:
						return err
					default:
						return err
					}
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
	_, err = metadata.SaveHost(handler.service, host)
	if err != nil {
		return err
	}
	_, err = metadata.SaveVolume(handler.service, volume)
	if err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		logrus.Warnf("Volume detachment cancelled by user")
		// Currently format is not registered anywhere so we use ext4 the most common format (but as we mount the volume the format parameter is ignored anyway)
		err = handler.Attach(context.Background(), volumeName, hostName, mountPath, "ext4", true)
		if err != nil {
			return fmt.Errorf("failed to stop volume detachment")
		}
		return fmt.Errorf("volume detachment cancelled by user")
	default:
	}

	return nil
}
