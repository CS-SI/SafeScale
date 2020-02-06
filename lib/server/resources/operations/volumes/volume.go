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

package volumes

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumeproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/system/nfs"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// volumesFolderName is the technical name of the container used to store volume info
	volumesFolderName = "volumes"
)

// Volume links Object Storage folder and Volumes
type Volume struct {
	*runtime.Core
	properties *serialize.JSONProperties
}

// NewVolume creates an instance of metadata.Volume
func NewVolume(svc iaas.Service) (_ *Volume, err error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "can't be nil")
	}

	core, err := runtime.NewCore(svc, "volume", volumesFolderName)
	if err != nil {
		return nil, err
	}
	props, err := serialize.NewJSONProperties("resources.volume")
	if err != nil {
		return nil, err
	}
	return &Volume{Core: core, properties: props}, nil
}

// LoadVolume loads the metadata of a network
func LoadVolume(task concurrency.Task, svc iaas.Service, ref string) (*Volume, error) {
	if task != nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	objv, err := NewVolume(svc)
	if err != nil {
		return nil, err
	}
	return objv, objv.Read(task, ref)
}

// Properties returns the properties of the volume
func (objv *Volume) Properties(task concurrency.Task) (_ *serialize.JSONProperties, err error) {
	if objv == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", false).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	objv.RLock(task)
	defer objv.RUnlock(task)

	if objv.properties == nil {
		return nil, scerr.InvalidInstanceContentError("objv.properties", "cannot be nil")
	}
	return objv.properties, nil
}

// Browse walks through volume folder and executes a callback for each entries
func (objv *Volume) Browse(task concurrency.Task, callback func(*abstracts.Volume) error) error {
	// This function can be called from nil pointer by design, so no validation on objv being nil
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if callback == nil {
		return scerr.InvalidParameterError("callback", "cannot be nil")
	}

	return objv.Core.BrowseFolder(task, func(buf []byte) error {
		volume := abstracts.NewVolume()
		err := volume.Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(volume)
	})
}

// Delete deletes volume and its metadata
func (objv *Volume) Delete(task concurrency.Task) (err error) {
	if objv == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "can't be nil")
	}

	err = objv.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		inErr = props.Inspect(volumeproperty.AttachedV1, func(clonable data.Clonable) error {
			volumeAttachmentsV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' received", reflect.TypeOf(clonable).String())
			}
			nbAttach := uint(len(volumeAttachmentsV1.Hosts))
			if nbAttach > 0 {
				list := make([]string, 0, len(volumeAttachmentsV1.Hosts))
				for _, v := range volumeAttachmentsV1.Hosts {
					list = append(list, v)
				}
				return scerr.NotAvailableError("still attached to %d host%s: %s", nbAttach, utils.Plural(nbAttach), strings.Join(list, ", "))
			}
			return nil
		})
		if err != nil {
			return err
		}

		svc := objv.Service()
		err = svc.DeleteVolume(objv.ID())
		if err != nil {
			if _, ok := err.(scerr.ErrNotFound); !ok {
				return scerr.Wrap(err, "cannot delete volume")
			}
			logrus.Warnf("Unable to find the volume on provider side, cleaning up metadata")
		}
		return objv.Core.Delete(task)
	})
	if err != nil {
		return err
	}

	// select {
	// case <-ctx.Done():
	// 	logrus.Warnf("Volume deletion cancelled by user")
	// 	volumeBis, err := handler.Create(context.Background(), volume.Name, volume.Size, volume.Speed)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to stop volume deletion")
	// 	}
	// 	buf, err := volumeBis.Serialize()
	// 	if err != nil {
	// 		return fmt.Errorf("failed to recreate deleted volume")
	// 	}
	// 	return fmt.Errorf("deleted volume recreated by safescale : %s", buf)
	// default:
	// }

	return nil
}

// Create a volume
func (objv *Volume) Create(task concurrency.Task, req abstracts.VolumeRequest) (err error) {
	if objv == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "can't be nil")
	}
	if req.Name == "" {
		return scerr.InvalidParameterError("req.Name", "cannot be empty string")
	}
	if req.Size <= 0 {
		return scerr.InvalidParameterError("req.Size", "must be an integer > 0")
	}

	svc := objv.Service()
	rv, err := svc.CreateVolume(req)
	if err != nil {
		return err
	}

	// Starting from here, remove volume if exiting with error
	defer func() {
		if err != nil {
			derr := svc.DeleteVolume(rv.ID)
			if derr != nil {
				logrus.Errorf("After failure, cleanup failed to delete volume '%s': %v", req.Name, derr)
			}
		}
	}()

	// Sets err to possibly trigger defer calls
	return objv.Carry(task, rv)

	// select {
	// case <-ctx.Done():
	// 	logrus.Warnf("Volume creation cancelled by user")
	// 	err = fmt.Errorf("volume creation cancelled by user")
	// 	return nil, err
	// default:
	// }
}

// Attach a volume to an host
func (objv *Volume) Attach(task concurrency.Task, host resources.Host, path, format string, doNotFormat bool) (err error) {
	if objv == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if host == nil {
		return scerr.InvalidParameterError("host", "cannot be nil")
	}
	if path == "" {
		return scerr.InvalidParameterError("path", "cannot be empty string")
	}
	if format == "" {
		return scerr.InvalidParameterError("format", "cannot be empty string")
	}

	ctx, err := task.Context()
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

	svc := objv.Service()

	volumeID := objv.ID()
	volumeName := objv.Name()
	targetID := host.ID()
	targetName := host.Name()

	// -- proceed some checks on volume --
	err = objv.Inspect(task, func(clonable data.Clonable) error {
		props, inErr := objv.Properties(task)
		if inErr != nil {
			return inErr
		}
		return props.Inspect(VolumeProperty.AttachedV1, func(clonable data.Clonable) error {
			volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}

			mountPoint = path
			if path == abstracts.DefaultVolumeMountPoint {
				mountPoint = abstracts.DefaultVolumeMountPoint + volumeName
			}

			// For now, allows only one attachment...
			if len(volumeAttachedV1.Hosts) > 0 {
				for id := range volumeAttachedV1.Hosts {
					if id != targetID {
						return scerr.NotAvailableError("volume '%s' is already attached", volumeName)
					}
					break
				}
			}
			return nil
		})
	})
	if err != nil {
		return err
	}

	// -- proceed some checks on target server --
	err = host.Inspect(task, func(clonable data.Clonable) error {
		props, err := host.Properties(task)
		if err != nil {
			return err
		}
		return props.Inspect(HostProperty.VolumesV1, func(clonable data.Clonable) error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			return props.Inspect(HostProperty.MountsV1, func(clonable data.Clonable) error {
				hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
				if !ok {
					return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String()))
				}

				// Check if the volume is already mounted elsewhere
				if device, found := hostVolumesV1.DevicesByID[volumeID]; found {
					mount, ok := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[device]]
					if !ok {
						return scerr.InconsistentError(fmt.Sprintf("metadata inconsistency for volume '%s' attached to host '%s'", volumeName, targetName))
					}
					path := mount.Path
					if path != mountPoint {
						return scerr.InvalidRequestError(fmt.Sprintf("volume '%s' is already attached in '%s:%s'", volumeName, targetName, path))
					}
					return nil
				}

				// Check if there is no other device mounted in the path (or in subpath)
				for _, i := range hostMountsV1.LocalMountsByPath {
					if strings.Index(i.Path, mountPoint) == 0 {
						return scerr.InvalidRequestError(fmt.Sprintf("can't attach volume '%s' to '%s:%s': there is already a volume mounted in '%s:%s'", volumeName, targetName, mountPoint, targetName, i.Path))
					}
				}
				for _, i := range hostMountsV1.RemoteMountsByPath {
					if strings.Index(i.Path, mountPoint) == 0 {
						return scerr.InvalidRequestError(fmt.Sprintf("can't attach volume '%s' to '%s:%s': there is a share mounted in path '%s:%s[/...]'", volumeName, targetName, mountPoint, targetName, i.Path))
					}
				}
				return nil
			})
		})
	})

	// -- Get list of disks before attachment --
	// Note: some providers are not able to tell the real device name the volume
	//       will have on the host, so we have to use a way that can work everywhere
	oldDiskSet, err := objv.listAttachedDevices(task, host)
	if err != nil {
		return err
	}

	// -- creates volume attachment --
	vaID, err = svc.CreateVolumeAttachment(abstracts.VolumeAttachmentRequest{
		Name:     fmt.Sprintf("%s-%s", volumeName, targetName),
		HostID:   targetID,
		VolumeID: volumeID,
	})
	if err != nil {
		return err
	}

	// Starting from here, remove volume attachment if exit with error
	defer func() {
		if err != nil {
			derr := svc.DeleteVolumeAttachment(targetID, vaID)
			if derr != nil {
				logrus.Errorf("failed to detach volume '%s' from host '%s': %v", volumeName, targetName, derr)
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	// -- acknowledge the volume is really attached to host --
	var newDisk mapset.Set
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			newDiskSet, err := objv.listAttachedDevices(task, host)
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
		2*time.Minute,
	)
	if retryErr != nil {
		if _, ok := retryErr.(retry.ErrTimeout); ok {
			return retryErr
		}
		return scerr.Wrap(retryErr, fmt.Sprintf("failed to confirm the disk attachment after %s", 2*time.Minute))
	}

	// -- updates target properties --
	err = host.Alter(task, func(clonable data.Clonable) error {
		props, inErr := host.Properties(task)
		if inErr != nil {
			return inErr
		}
		inErr = props.Alter(HostProperty.VolumesV1, func(clonable data.Clonable) error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			// Recovers real device name from the system
			deviceName = "/dev/" + newDisk.ToSlice()[0].(string)

			// Create mount point
			sshConfig, err := host.SSHConfig(task)
			if err != nil {
				return err
			}

			server, err = nfs.NewServer(sshConfig)
			if err != nil {
				return err
			}
			volumeUUID, err = server.MountBlockDevice(ctx, deviceName, mountPoint, format, doNotFormat)
			if err != nil {
				return err
			}

			defer func() {
				if err != nil {
					derr := server.UnmountBlockDevice(ctx, volumeUUID)
					if derr != nil {
						logrus.Errorf("failed to unmount volume '%s' from host '%s': %v", volumeName, targetName, derr)
					}
					err = scerr.AddConsequence(err, derr)
				}
			}()

			// Saves volume information in property
			hostVolumesV1.VolumesByID[volumeID] = &propertiesv1.HostVolume{
				AttachID: vaID,
				Device:   volumeUUID,
			}
			hostVolumesV1.VolumesByName[volumeName] = volumeID
			hostVolumesV1.VolumesByDevice[volumeUUID] = volumeID
			hostVolumesV1.DevicesByID[volumeID] = volumeUUID
			return nil
		})
		if err != nil {
			return err
		}

		return props.Alter(HostProperty.MountsV1, func(clonable data.Clonable) error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			// Updates host properties
			hostMountsV1.LocalMountsByPath[mountPoint] = &propertiesv1.HostLocalMount{
				Device:     volumeUUID,
				Path:       mountPoint,
				FileSystem: "nfs",
			}
			hostMountsV1.LocalMountsByDevice[volumeUUID] = mountPoint

			return nil
		})
	})
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			derr := server.UnmountBlockDevice(ctx, volumeUUID)
			if derr != nil {
				logrus.Errorf("failed to unmount volume '%s' from host '%s': %v", volumeName, targetName, derr)
			}
			derr = host.Alter(task, func(clonable data.Clonable) error {
				props, inErr := host.Properties(task)
				if inErr != nil {
					inErr = scerr.AddConsequence(inErr, scerr.InconsistentError(fmt.Sprintf("'*abstracts.Host' expected, '%s' provided", reflect.TypeOf(clonable).String())))
					return inErr
				}
				err := props.Alter(HostProperty.VolumesV1, func(clonable data.Clonable) error {
					hostVolumesV1 := clonable.(*propertiesv1.HostVolumes)
					delete(hostVolumesV1.VolumesByID, volumeID)
					delete(hostVolumesV1.VolumesByName, volumeName)
					delete(hostVolumesV1.VolumesByDevice, volumeUUID)
					delete(hostVolumesV1.DevicesByID, volumeID)
					return nil
				})
				if err != nil {
					logrus.Warnf("Failed to set host '%s' metadata about volumes", volumeName)
				}
				return props.Alter(HostProperty.MountsV1, func(clonable data.Clonable) error {
					hostMountsV1 := clonable.(*propertiesv1.HostMounts)
					delete(hostMountsV1.LocalMountsByDevice, volumeUUID)
					delete(hostMountsV1.LocalMountsByPath, mountPoint)
					return nil
				})
			})
			if derr != nil {
				logrus.Errorf("After failure of attach volume, cleanup failed to update metadata of host '%s'", targetName)
			}
		}
	}()

	err = objv.Alter(task, func(clonable data.Clonable) error {
		props, inErr := objv.Properties(task)
		if inErr != nil {
			return inErr
		}
		return props.Alter(VolumeProperty.AttachedV1, func(clonable data.Clonable) error {
			volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			// Updates volume properties
			volumeAttachedV1.Hosts[targetID] = targetName
			return nil
		})
	})
	if err != nil {
		return err
	}

	// select {
	// case <-ctx.Done():
	// 	logrus.Warnf("Volume attachment cancelled by user")
	// 	err = fmt.Errorf("volume attachment cancelled by user")
	// 	return err
	// default:
	// }

	// logrus.Infof("Volume '%s' successfully attached to host '%s' as device '%s'", volumeName, targetName, volumeUUID)
	return nil
}

func (objv *Volume) listAttachedDevices(task concurrency.Task, host resources.Host) (mapset.Set, error) {
	var (
		retcode        int
		stdout, stderr string
		err            error
	)

	hostName := host.Name()
	cmd := "sudo lsblk -l -o NAME,TYPE | grep disk | cut -d' ' -f1"
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			retcode, stdout, stderr, err = host.Run(task, cmd, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
			if err != nil {
				return err
			}
			if retcode != 0 {
				if retcode == 255 {
					return fmt.Errorf("failed to reach SSH service of host '%s', retrying", hostName)
				}
				return fmt.Errorf(stderr)
			}
			return nil
		},
		2*time.Minute,
	)
	if retryErr != nil {
		return nil, scerr.Wrap(retryErr, fmt.Sprintf("failed to get list of connected disks after %s", 2*time.Minute))
	}
	disks := strings.Split(stdout, "\n")
	set := mapset.NewThreadUnsafeSet()
	for _, k := range disks {
		set.Add(k)
	}
	return set, nil
}

// Detach detach the volume identified by ref, ref can be the name or the id
func (objv *Volume) Detach(task concurrency.Task, host resources.Host) (err error) {
	if objv == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if host == nil {
		return scerr.InvalidParameterError("host", "cannot be nil")
	}

	const CANNOT = "cannot detach volume"

	var (
		volumeID, volumeName string
		mountPath            string
	)

	// -- retrives volume data --
	err = objv.Inspect(task, func(clonable data.Clonable) error {
		volume, ok := clonable.(*abstracts.Volume)
		if !ok {
			return scerr.InconsistentError(fmt.Sprintf("'*abstracts.Volume' expected, '%s' provided", reflect.TypeOf(clonable).String()))
		}
		volumeID = volume.ID
		volumeName = volume.Name
		return nil
	})
	if err != nil {
		return err
	}

	// -- retrieve host data --
	svc := objv.Service()
	targetID := host.ID()
	targetName := host.Name()
	ctx, err := task.Context()
	if err != nil {
		return err
	}

	// -- Update target attachments --
	err = host.Alter(task, func(clonable data.Clonable) error {
		props, inErr := host.Properties(task)
		if inErr != nil {
			return inErr
		}
		return props.Alter(HostProperty.VolumesV1, func(clonable data.Clonable) error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}

			// Check the volume is effectively attached
			attachment, found := hostVolumesV1.VolumesByID[volumeID]
			if !found {
				return scerr.NotFoundError("cannot detach volume '%s': not attached to host '%s'", volumeName, targetName)
			}

			// Obtain mounts information
			return props.Alter(HostProperty.MountsV1, func(clonable data.Clonable) error {
				hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
				if !ok {
					return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String()))
				}
				device := attachment.Device
				mountPath = hostMountsV1.LocalMountsByDevice[device]
				mount := hostMountsV1.LocalMountsByPath[mountPath]
				if mount == nil {
					return scerr.InconsistentError("metadata inconsistency: no mount corresponding to volume attachment")
				}

				// Check if volume has other mount(s) inside it
				for p, i := range hostMountsV1.LocalMountsByPath {
					if i.Device == device {
						continue
					}
					if strings.Index(p, mount.Path) == 0 {
						return scerr.InvalidRequestError(fmt.Sprintf("cannot detach volume '%s' from '%s:%s', there is a volume mounted in '%s:%s'",
							volumeName, targetName, mount.Path, targetName, p))
					}
				}
				for p := range hostMountsV1.RemoteMountsByPath {
					if strings.Index(p, mount.Path) == 0 {
						return scerr.InvalidRequestError(fmt.Sprintf("cannot detach volume '%s' from '%s:%s', there is a share mounted in '%s:%s'",
							volumeName, targetName, mount.Path, targetName, p))
					}
				}

				// Check if volume (or a subdir in volume) is shared
				return props.Alter(HostProperty.SharesV1, func(clonable data.Clonable) error {
					hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
					if !ok {
						return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String()))
					}

					for _, v := range hostSharesV1.ByID {
						if strings.Index(v.Path, mount.Path) == 0 {
							return scerr.InvalidRequestError(fmt.Sprintf("cannot detach volume '%s' from '%s:%s', '%s:%s' is shared",
								volumeName, targetName, mount.Path, targetName, v.Path))
						}
					}

					// Unmount the Block Device ...
					sshConfig, err := host.SSHConfig(task)
					if err != nil {
						return err
					}
					nfsServer, err := nfs.NewServer(sshConfig)
					if err != nil {
						return err
					}
					err = nfsServer.UnmountBlockDevice(ctx, attachment.Device)
					if err != nil {
						return err
					}

					// ... then detach volume
					err = svc.DeleteVolumeAttachment(targetID, attachment.AttachID)
					if err != nil {
						return err
					}

					// Updates host property propertiesv1.VolumesV1
					delete(hostVolumesV1.VolumesByID, volumeID)
					delete(hostVolumesV1.VolumesByName, volumeName)
					delete(hostVolumesV1.VolumesByDevice, attachment.Device)
					delete(hostVolumesV1.DevicesByID, volumeID)

					// Updates host property propertiesv1.MountsV1
					delete(hostMountsV1.LocalMountsByDevice, mount.Device)
					delete(hostMountsV1.LocalMountsByPath, mount.Path)
					return nil
				})
			})
		})
	})
	if err != nil {
		return err
	}

	// -- updates volume property propertiesv1.VolumeAttachments --
	return objv.Alter(task, func(clonable data.Clonable) error {
		props, inErr := objv.Properties(task)
		if inErr != nil {
			return inErr
		}
		return props.Alter(VolumeProperty.AttachedV1, func(clonable data.Clonable) error {
			volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			delete(volumeAttachedV1.Hosts, targetID)
			return nil
		})
	})

	// select {
	// case <-ctx.Done():
	// 	logrus.Warnf("Volume detachment cancelled by user")
	// 	// Currently format is not registerd anywhere so we use ext4 the most common format (but as we mount the volume the format parameter is ignored anyway)
	// 	err = handler.Attach(context.Background(), volumeName, hostName, mountPath, "ext4", true)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to stop volume detachment")
	// 	}
	// 	return fmt.Errorf("volume detachment canceld by user")
	// default:
	// }
}
