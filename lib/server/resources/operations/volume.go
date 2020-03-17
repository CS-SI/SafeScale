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

package operations

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumeproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system/nfs"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// volumesFolderName is the technical name of the container used to store volume info
	volumesFolderName = "volumes"
)

// Volume links Object Storage folder and Volumes
type volume struct {
	*Core
}

// nullVolume returns an instance of share corresponding to its null value.
// The idea is to avoid nil pointer using nullVolume()
func nullVolume() *volume {
	return &volume{Core: nullCore()}
}

// NewVolume creates an instance of Volume
func NewVolume(svc iaas.Service) (_ resources.Volume, err error) {
	if svc == nil {
		return nullVolume(), scerr.InvalidParameterError("svc", "can't be nil")
	}

	core, err := NewCore(svc, "volume", volumesFolderName)
	if err != nil {
		return nullVolume(), err
	}
	return &volume{Core: core}, nil
}

// LoadVolume loads the metadata of a network
func LoadVolume(task concurrency.Task, svc iaas.Service, ref string) (resources.Volume, error) {
	if task != nil {
		return nullVolume(), scerr.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return nullVolume(), scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nullVolume(), scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	volume, err := NewVolume(svc)
	if err != nil {
		return volume, err
	}
	err = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			return volume.Read(task, ref)
		},
		10*time.Second,
	)
	if err != nil {
		// If retry timed out, log it and return error ErrNotFound
		if _, ok := err.(retry.ErrTimeout); ok {
			logrus.Debugf("timeout reading metadata of volume '%s'", ref)
			err = scerr.NotFoundError("failed to load metadata of volume '%s': timeout", ref)
		}
		return nullVolume(), err
	}
	return volume, nil
}

// IsNull tells if the instance is a null value
func (objv *volume) IsNull() bool {
	return objv == nil || objv.Core.IsNull()
}

// GetSpeed ...
func (objv *volume) GetSpeed(task concurrency.Task) (volumespeed.Enum, error) {
	if objv.IsNull() {
		return 0, scerr.InvalidInstanceError()
	}
	if task == nil {
		return 0, scerr.InvalidParameterError("task", "cannot be nil")
	}

	var speed volumespeed.Enum
	err := objv.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		av, ok := clonable.(*abstract.Volume)
		if !ok {
			return scerr.InconsistentError("'*abstract.Volume' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		speed = av.Speed
		return nil
	})
	if err != nil {
		return 0, err
	}
	return speed, nil
}

// SafeGetSpeed ...
// Intended to be used when objv is notoriously not nil
func (objv *volume) SafeGetSpeed(task concurrency.Task) volumespeed.Enum {
	speed, _ := objv.GetSpeed(task)
	return speed
}

// GetSize ...
func (objv *volume) GetSize(task concurrency.Task) (int, error) {
	if objv.IsNull() {
		return 0, scerr.InvalidInstanceError()
	}
	if task == nil {
		return 0, scerr.InvalidParameterError("task", "cannot be nil")
	}

	var size int
	err := objv.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		av, ok := clonable.(*abstract.Volume)
		if !ok {
			return scerr.InconsistentError("'*abstract.Volume' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		size = av.Size
		return nil
	})
	if err != nil {
		return 0, err
	}
	return size, nil
}

// SafeGetSize ...
// Intended to be used when objv is notoriously not nil
func (objv *volume) SafeGetSize(task concurrency.Task) int {
	size, _ := objv.GetSize(task)
	return size
}

// GetAttachments ...
func (objv *volume) GetAttachments(task concurrency.Task) (*propertiesv1.VolumeAttachments, error) {
	if objv.IsNull() {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	var vaV1 *propertiesv1.VolumeAttachments
	err := objv.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(volumeproperty.AttachedV1, func(clonable data.Clonable) error {
			var ok bool
			vaV1, ok = clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return vaV1, nil
}

// Browse walks through volume folder and executes a callback for each entry
func (objv *volume) Browse(task concurrency.Task, callback func(*abstract.Volume) error) error {
	if objv.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if callback == nil {
		return scerr.InvalidParameterError("callback", "cannot be nil")
	}

	return objv.Core.BrowseFolder(task, func(buf []byte) error {
		av := abstract.NewVolume()
		err := av.Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(av)
	})
}

// Delete deletes volume and its metadata
func (objv *volume) Delete(task concurrency.Task) (err error) {
	if objv.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "can't be nil")
	}

	err = objv.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		innerErr := props.Inspect(volumeproperty.AttachedV1, func(clonable data.Clonable) error {
			volumeAttachmentsV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' received", reflect.TypeOf(clonable).String())
			}
			nbAttach := uint(len(volumeAttachmentsV1.Hosts))
			if nbAttach > 0 {
				list := make([]string, len(volumeAttachmentsV1.Hosts))
				for _, v := range volumeAttachmentsV1.Hosts {
					list = append(list, v)
				}
				return scerr.NotAvailableError("still attached to %d host%s: %s", nbAttach, strprocess.Plural(nbAttach), strings.Join(list, ", "))
			}
			return nil
		})
		if innerErr != nil {
			return innerErr
		}

		svc := objv.SafeGetService()
		innerErr = svc.DeleteVolume(objv.SafeGetID())
		if innerErr != nil {
			if _, ok := innerErr.(scerr.ErrNotFound); !ok {
				return scerr.Wrap(innerErr, "cannot delete volume")
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
	// 		return scerr.NewError("failed to stop volume deletion")
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
func (objv *volume) Create(task concurrency.Task, req abstract.VolumeRequest) (err error) {
	if objv.IsNull() {
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

	svc := objv.SafeGetService()
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
func (objv *volume) Attach(task concurrency.Task, host resources.Host, path, format string, doNotFormat bool) (err error) {
	if objv.IsNull() {
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

	var (
		deviceName string
		volumeUUID string
		mountPoint string
		vaID       string
		server     *nfs.Server
	)

	svc := objv.SafeGetService()

	volumeID := objv.SafeGetID()
	volumeName := objv.SafeGetName()
	targetID := host.SafeGetID()
	targetName := host.SafeGetName()

	// -- proceed some checks on volume --
	err = objv.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(volumeproperty.AttachedV1, func(clonable data.Clonable) error {
			volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			mountPoint = path
			if path == abstract.DefaultVolumeMountPoint {
				mountPoint = abstract.DefaultVolumeMountPoint + volumeName
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
	err = host.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(hostproperty.VolumesV1, func(clonable data.Clonable) error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return props.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) error {
				hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
				if !ok {
					return scerr.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				// Check if the volume is already mounted elsewhere
				if device, found := hostVolumesV1.DevicesByID[volumeID]; found {
					mount, ok := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[device]]
					if !ok {
						return scerr.InconsistentError("metadata inconsistency for volume '%s' attached to host '%s'", volumeName, targetName)
					}
					path := mount.Path
					if path != mountPoint {
						return scerr.InvalidRequestError("volume '%s' is already attached in '%s:%s'", volumeName, targetName, path)
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
	vaID, err = svc.CreateVolumeAttachment(abstract.VolumeAttachmentRequest{
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
				return scerr.NotAvailableError("disk not yet attached, retrying")
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
	err = host.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		innerErr := props.Alter(hostproperty.VolumesV1, func(clonable data.Clonable) error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			// Recovers real device name from the system
			deviceName = "/dev/" + newDisk.ToSlice()[0].(string)

			// Create mount point
			sshConfig, err := host.GetSSHConfig(task)
			if err != nil {
				return err
			}

			server, err = nfs.NewServer(sshConfig)
			if err != nil {
				return err
			}
			volumeUUID, err = server.MountBlockDevice(task, deviceName, mountPoint, format, doNotFormat)
			if err != nil {
				return err
			}

			defer func() {
				if err != nil {
					derr := server.UnmountBlockDevice(task, volumeUUID)
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
		if innerErr != nil {
			return innerErr
		}

		return props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
			derr := server.UnmountBlockDevice(task, volumeUUID)
			if derr != nil {
				logrus.Errorf("failed to unmount volume '%s' from host '%s': %v", volumeName, targetName, derr)
			}
			derr = host.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
				innerErr := props.Alter(hostproperty.VolumesV1, func(clonable data.Clonable) error {
					hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
					if !ok {
						return scerr.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					delete(hostVolumesV1.VolumesByID, volumeID)
					delete(hostVolumesV1.VolumesByName, volumeName)
					delete(hostVolumesV1.VolumesByDevice, volumeUUID)
					delete(hostVolumesV1.DevicesByID, volumeID)
					return nil
				})
				if innerErr != nil {
					logrus.Warnf("Failed to set host '%s' metadata about volumes", volumeName)
				}
				return props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) error {
					hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
					if !ok {
						return scerr.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
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

	err = objv.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(volumeproperty.AttachedV1, func(clonable data.Clonable) error {
			volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
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

func (objv *volume) listAttachedDevices(task concurrency.Task, host resources.Host) (mapset.Set, error) {
	var (
		retcode        int
		stdout, stderr string
		err            error
	)

	hostName := host.SafeGetName()
	cmd := "sudo lsblk -l -o NAME,TYPE | grep disk | cut -d' ' -f1"
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			retcode, stdout, stderr, err = host.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
			if err != nil {
				return err
			}
			if retcode != 0 {
				if retcode == 255 {
					return scerr.NotAvailableError("failed to reach SSH service of host '%s', retrying", hostName)
				}
				return scerr.NewError(stderr)
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
func (objv *volume) Detach(task concurrency.Task, host resources.Host) (err error) {
	if objv.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if host == nil {
		return scerr.InvalidParameterError("host", "cannot be nil")
	}

	// const CANNOT = "cannot detach volume"

	var (
		volumeID, volumeName string
		mountPath            string
	)

	// -- retrives volume data --
	err = objv.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		volume, ok := clonable.(*abstract.Volume)
		if !ok {
			return scerr.InconsistentError("'*abstract.Volume' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		volumeID = volume.ID
		volumeName = volume.Name
		return nil
	})
	if err != nil {
		return err
	}

	// -- retrieve host data --
	svc := objv.SafeGetService()
	targetID := host.SafeGetID()
	targetName := host.SafeGetName()

	// -- Update target attachments --
	err = host.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(hostproperty.VolumesV1, func(clonable data.Clonable) error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// Check the volume is effectively attached
			attachment, found := hostVolumesV1.VolumesByID[volumeID]
			if !found {
				return scerr.NotFoundError("cannot detach volume '%s': not attached to host '%s'", volumeName, targetName)
			}

			// Obtain mounts information
			return props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) error {
				hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
				if !ok {
					return scerr.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
						return scerr.InvalidRequestError("cannot detach volume '%s' from '%s:%s', there is a volume mounted in '%s:%s'",
							volumeName, targetName, mount.Path, targetName, p)
					}
				}
				for p := range hostMountsV1.RemoteMountsByPath {
					if strings.Index(p, mount.Path) == 0 {
						return scerr.InvalidRequestError("cannot detach volume '%s' from '%s:%s', there is a share mounted in '%s:%s'",
							volumeName, targetName, mount.Path, targetName, p)
					}
				}

				// Check if volume (or a subdir in volume) is shared
				return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) error {
					hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
					if !ok {
						return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					for _, v := range hostSharesV1.ByID {
						if strings.Index(v.Path, mount.Path) == 0 {
							return scerr.InvalidRequestError("cannot detach volume '%s' from '%s:%s', '%s:%s' is shared",
								volumeName, targetName, mount.Path, targetName, v.Path)
						}
					}

					// Unmount the Block Device ...
					sshConfig, err := host.GetSSHConfig(task)
					if err != nil {
						return err
					}
					nfsServer, err := nfs.NewServer(sshConfig)
					if err != nil {
						return err
					}
					err = nfsServer.UnmountBlockDevice(task, attachment.Device)
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
	return objv.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(volumeproperty.AttachedV1, func(clonable data.Clonable) error {
			volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
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

// ToProtocol converts the volume to protocol message VolumeInspectResponse
func (objv *volume) ToProtocol(task concurrency.Task) (*protocol.VolumeInspectResponse, error) {
	if objv.IsNull() {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	out := &protocol.VolumeInspectResponse{
		Id:          objv.SafeGetID(),
		Name:        objv.SafeGetName(),
		Speed:       converters.VolumeSpeedFromAbstractToProtocol(objv.SafeGetSpeed(task)),
		Size:        int32(objv.SafeGetSize(task)),
		Attachments: []*protocol.VolumeAttachmentResponse{},
	}

	attachments, err := objv.GetAttachments(task)
	if err != nil {
		return nil, err
	}

	for k := range attachments.Hosts {
		rh, err := LoadHost(task, objv.SafeGetService(), k)
		if err != nil {
			return nil, err
		}
		vols := rh.SafeGetVolumes(task)
		device, ok := vols.DevicesByID[objv.SafeGetID()]
		if !ok {
			return nil, scerr.InconsistentError("failed to find a device corresponding to the attached volume '%s' on host '%s'", objv.SafeGetName(), k)
		}
		mnts := rh.SafeGetMounts(task)
		path, ok := mnts.LocalMountsByDevice[device]
		if !ok {
			return nil, scerr.InconsistentError("failed to find a mount of attached volume '%s' on host '%s'", objv.SafeGetName(), k)
		}
		m, ok := mnts.LocalMountsByPath[path]
		if !ok {
			return nil, scerr.InconsistentError("failed to find a mount of attached volume '%s' on host '%s'", objv.SafeGetName(), k)
		}
		a := &protocol.VolumeAttachmentResponse{
			Host: &protocol.Reference{
				Name: k,
				Id:   rh.SafeGetID(),
			},
			MountPath: path,
			Format:    m.FileSystem,
			Device:    device,
		}
		out.Attachments = append(out.Attachments, a)
	}
	return out, nil
}
