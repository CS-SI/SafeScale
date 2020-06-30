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
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumeproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system/nfs"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// volumesFolderName is the technical name of the container used to store volume info
	volumesFolderName = "volumes"
)

// Volume links Object Storage folder and getVolumes
type volume struct {
	*core
}

// nullVolume returns an instance of share corresponding to its null value.
// The idea is to avoid nil pointer using nullVolume()
func nullVolume() *volume {
	return &volume{core: nullCore()}
}

// NewVolume creates an instance of Volume
func NewVolume(svc iaas.Service) (_ resources.Volume, xerr fail.Error) {
	if svc == nil {
		return nullVolume(), fail.InvalidParameterError("svc", "can't be nil")
	}

	coreInstance, err := newCore(svc, "volume", volumesFolderName, &abstract.Volume{})
	if err != nil {
		return nullVolume(), err
	}
	return &volume{core: coreInstance}, nil
}

// LoadVolume loads the metadata of a network
func LoadVolume(task concurrency.Task, svc iaas.Service, ref string) (resources.Volume, fail.Error) {
	if task == nil {
		return nullVolume(), fail.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return nullVolume(), fail.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nullVolume(), fail.InvalidParameterError("ref", "cannot be empty string")
	}

	rv, xerr := NewVolume(svc)
	if xerr != nil {
		return rv, xerr
	}
	xerr = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			return rv.Read(task, ref)
		},
		10*time.Second,
	)
	if xerr != nil {
		// If retry timed out, log it and return error ErrNotFound
		if _, ok := xerr.(*retry.ErrTimeout); ok {
			logrus.Debugf("timeout reading metadata of rv '%s'", ref)
			xerr = fail.NotFoundError("failed to load metadata of rv '%s': timeout", ref)
		}
		return nullVolume(), xerr
	}
	return rv, nil
}

// IsNull tells if the instance is a null value
func (objv *volume) IsNull() bool {
	return objv == nil || objv.core.IsNull()
}

// GetSpeed ...
func (objv volume) GetSpeed(task concurrency.Task) (volumespeed.Enum, fail.Error) {
	if objv.IsNull() {
		return 0, fail.InvalidInstanceError()
	}
	if task == nil {
		return 0, fail.InvalidParameterError("task", "cannot be nil")
	}

	var speed volumespeed.Enum
	xerr := objv.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		av, ok := clonable.(*abstract.Volume)
		if !ok {
			return fail.InconsistentError("'*abstract.Volume' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		speed = av.Speed
		return nil
	})
	if xerr != nil {
		return 0, xerr
	}
	return speed, nil
}

// getSpeed ...
// Intended to be used when objv is notoriously not nil
func (objv volume) getSpeed(task concurrency.Task) volumespeed.Enum {
	speed, _ := objv.GetSpeed(task)
	return speed
}

// GetSize ...
func (objv volume) GetSize(task concurrency.Task) (int, fail.Error) {
	if objv.IsNull() {
		return 0, fail.InvalidInstanceError()
	}
	if task == nil {
		return 0, fail.InvalidParameterError("task", "cannot be nil")
	}

	var size int
	xerr := objv.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		av, ok := clonable.(*abstract.Volume)
		if !ok {
			return fail.InconsistentError("'*abstract.Volume' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		size = av.Size
		return nil
	})
	if xerr != nil {
		return 0, xerr
	}
	return size, nil
}

// getSize ...
// Intended to be used when objv is notoriously not nil
func (objv volume) getSize(task concurrency.Task) int {
	size, _ := objv.GetSize(task)
	return size
}

// GetAttachments ...
func (objv volume) GetAttachments(task concurrency.Task) (*propertiesv1.VolumeAttachments, fail.Error) {
	if objv.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	var vaV1 *propertiesv1.VolumeAttachments
	xerr := objv.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
			var ok bool
			vaV1, ok = clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}
	return vaV1, nil
}

// Browse walks through volume folder and executes a callback for each entry
func (objv volume) Browse(task concurrency.Task, callback func(*abstract.Volume) fail.Error) fail.Error {
	if objv.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	return objv.core.BrowseFolder(task, func(buf []byte) fail.Error {
		av := abstract.NewVolume()
		xerr := av.Deserialize(buf)
		if xerr != nil {
			return xerr
		}
		return callback(av)
	})
}

// Delete deletes volume and its metadata
func (objv *volume) Delete(task concurrency.Task) (xerr fail.Error) {
	if objv.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "can't be nil")
	}

	xerr = objv.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		innerXErr := props.Inspect(task, volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
			volumeAttachmentsV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' received", reflect.TypeOf(clonable).String())
			}
			nbAttach := uint(len(volumeAttachmentsV1.Hosts))
			if nbAttach > 0 {
				list := make([]string, len(volumeAttachmentsV1.Hosts))
				for _, v := range volumeAttachmentsV1.Hosts {
					// Abort if asked for
					if task.Aborted() {
						return fail.AbortedError(fmt.Errorf("aborted"))
					}
					list = append(list, v)
				}
				return fail.NotAvailableError("still attached to %d host%s: %s", nbAttach, strprocess.Plural(nbAttach), strings.Join(list, ", "))
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		svc := objv.GetService()
		innerXErr = svc.DeleteVolume(objv.GetID())
		if innerXErr != nil {
			if _, ok := innerXErr.(*fail.ErrNotFound); !ok {
				return fail.Wrap(innerXErr, "cannot delete volume")
			}
			logrus.Warnf("Unable to find the volume on provider side, cleaning up metadata")
		}
		return objv.core.Delete(task)
	})
	if xerr != nil {
		return xerr
	}

	// select {
	// case <-ctx.Done():
	// 	logrus.Warnf("Volume deletion cancelled by user")
	// 	volumeBis, err := handler.Create(context.Background(), volume.GetName, volume.getSize, volume.getSpeed)
	// 	if err != nil {
	// 		return fail.NewError("failed to stop volume deletion")
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
func (objv *volume) Create(task concurrency.Task, req abstract.VolumeRequest) (xerr fail.Error) {
	if objv.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "can't be nil")
	}
	if req.Name == "" {
		return fail.InvalidParameterError("req.GetName", "cannot be empty string")
	}
	if req.Size <= 0 {
		return fail.InvalidParameterError("req.getSize", "must be an integer > 0")
	}

	svc := objv.GetService()
	rv, xerr := svc.CreateVolume(req)
	if xerr != nil {
		return xerr
	}

	// Starting from here, remove volume if exiting with error
	defer func() {
		if xerr != nil {
			derr := svc.DeleteVolume(rv.ID)
			if derr != nil {
				logrus.Errorf("After failure, cleanup failed to delete volume '%s': %v", req.Name, derr)
				_ = xerr.AddConsequence(derr)
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
func (objv *volume) Attach(task concurrency.Task, host resources.Host, path, format string, doNotFormat bool) (xerr fail.Error) {
	if objv.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if host == nil {
		return fail.InvalidParameterError("host", "cannot be nil")
	}
	if path == "" {
		return fail.InvalidParameterError("path", "cannot be empty string")
	}
	if format == "" {
		return fail.InvalidParameterError("format", "cannot be empty string")
	}

	var (
		deviceName string
		volumeUUID string
		mountPoint string
		vaID       string
		server     *nfs.Server
	)

	svc := objv.GetService()

	volumeID := objv.GetID()
	volumeName := objv.GetName()
	targetID := host.GetID()
	targetName := host.GetName()

	// -- proceed some checks on volume --
	xerr = objv.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
			volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			mountPoint = path
			if path == abstract.DefaultVolumeMountPoint {
				mountPoint = abstract.DefaultVolumeMountPoint + volumeName
			}

			// For now, allows only one attachment...
			if len(volumeAttachedV1.Hosts) > 0 {
				for id := range volumeAttachedV1.Hosts {
					if id != targetID {
						return fail.NotAvailableError("volume '%s' is already attached", volumeName)
					}
					break
				}
			}
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(fmt.Errorf("aborted"))
	}

	// -- proceed some checks on target server --
	xerr = host.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return props.Inspect(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
				hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				// Check if the volume is already mounted elsewhere
				if device, found := hostVolumesV1.DevicesByID[volumeID]; found {
					mount, ok := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[device]]
					if !ok {
						return fail.InconsistentError("metadata inconsistency for volume '%s' attached to host '%s'", volumeName, targetName)
					}
					path := mount.Path
					if path != mountPoint {
						return fail.InvalidRequestError("volume '%s' is already attached in '%s:%s'", volumeName, targetName, path)
					}
					return nil
				}

				// Check if there is no other device mounted in the path (or in subpath)
				for _, i := range hostMountsV1.LocalMountsByPath {
					if task.Aborted() {
						return fail.AbortedError(fmt.Errorf("aborted"))
					}

					if strings.Index(i.Path, mountPoint) == 0 {
						return fail.InvalidRequestError(fmt.Sprintf("can't attach volume '%s' to '%s:%s': there is already a volume mounted in '%s:%s'", volumeName, targetName, mountPoint, targetName, i.Path))
					}
				}
				for _, i := range hostMountsV1.RemoteMountsByPath {
					if task.Aborted() {
						return fail.AbortedError(fmt.Errorf("aborted"))
					}

					if strings.Index(i.Path, mountPoint) == 0 {
						return fail.InvalidRequestError(fmt.Sprintf("can't attach volume '%s' to '%s:%s': there is a share mounted in path '%s:%s[/...]'", volumeName, targetName, mountPoint, targetName, i.Path))
					}
				}
				return nil
			})
		})
	})
	if xerr != nil {
		return xerr
	}

	// -- Get list of disks before attachment --
	// Note: some providers are not able to tell the real device name the volume
	//       will have on the host, so we have to use a way that can work everywhere
	oldDiskSet, xerr := listAttachedDevices(task, host)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(fmt.Errorf("aborted"))
	}

	// -- creates volume attachment --
	vaID, xerr = svc.CreateVolumeAttachment(abstract.VolumeAttachmentRequest{
		Name:     fmt.Sprintf("%s-%s", volumeName, targetName),
		HostID:   targetID,
		VolumeID: volumeID,
	})
	if xerr != nil {
		return xerr
	}

	// Starting from here, remove volume attachment if exit with error
	defer func() {
		if xerr != nil {
			derr := svc.DeleteVolumeAttachment(targetID, vaID)
			if derr != nil {
				logrus.Errorf("failed to detach volume '%s' from host '%s': %v", volumeName, targetName, derr)
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	if task.Aborted() {
		return fail.AbortedError(fmt.Errorf("aborted"))
	}

	// -- acknowledge the volume is really attached to host --
	var newDisk mapset.Set
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			newDiskSet, xerr := listAttachedDevices(task, host)
			if xerr != nil {
				return xerr
			}
			// Isolate the new device
			newDisk = newDiskSet.Difference(oldDiskSet)
			if newDisk.Cardinality() == 0 {
				return fail.NotAvailableError("disk not yet attached, retrying")
			}
			return nil
		},
		2*time.Minute,
	)
	if retryErr != nil {
		if _, ok := retryErr.(*retry.ErrTimeout); ok {
			return retryErr
		}
		return fail.Wrap(retryErr, fmt.Sprintf("failed to confirm the disk attachment after %s", 2*time.Minute))
	}

	if task.Aborted() {
		return fail.AbortedError(fmt.Errorf("aborted"))
	}

	// -- updates target properties --
	xerr = host.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		innerXErr := props.Alter(task, hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			// Recovers real device name from the system
			deviceName = "/dev/" + newDisk.ToSlice()[0].(string)

			// Create mount point
			sshConfig, xerr := host.GetSSHConfig(task)
			if xerr != nil {
				return xerr
			}

			server, xerr = nfs.NewServer(sshConfig)
			if xerr != nil {
				return xerr
			}
			volumeUUID, xerr = server.MountBlockDevice(task, deviceName, mountPoint, format, doNotFormat)
			if xerr != nil {
				return xerr
			}

			defer func() {
				if xerr != nil {
					derr := server.UnmountBlockDevice(task, volumeUUID)
					if derr != nil {
						logrus.Errorf("failed to unmount volume '%s' from host '%s': %v", volumeName, targetName, derr)
					}
					_ = xerr.AddConsequence(derr)
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
		if innerXErr != nil {
			return innerXErr
		}

		return props.Alter(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
	if xerr != nil {
		return xerr
	}

	defer func() {
		if xerr != nil {
			derr := server.UnmountBlockDevice(task, volumeUUID)
			if derr != nil {
				logrus.Errorf("failed to unmount volume '%s' from host '%s': %v", volumeName, targetName, derr)
			}
			derr = host.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
				innerXErr := props.Alter(task, hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
					hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					delete(hostVolumesV1.VolumesByID, volumeID)
					delete(hostVolumesV1.VolumesByName, volumeName)
					delete(hostVolumesV1.VolumesByDevice, volumeUUID)
					delete(hostVolumesV1.DevicesByID, volumeID)
					return nil
				})
				if innerXErr != nil {
					logrus.Warnf("Failed to set host '%s' metadata about volumes", volumeName)
				}
				return props.Alter(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
					hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
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

	// last chance to abort ...
	if task.Aborted() {
		return fail.AbortedError(fmt.Errorf("aborted"))
	}

	xerr = objv.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
			volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			// Updates volume properties
			volumeAttachedV1.Hosts[targetID] = targetName
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	// select {
	// case <-ctx.Done():
	// 	logrus.Warnf("Volume attachment cancelled by user")
	// 	err = fmt.Errorf("volume attachment cancelled by user")
	// 	return err
	// default:
	// }

	logrus.Infof("Volume '%s' successfully attached to host '%s' as device '%s'", volumeName, targetName, volumeUUID)
	return nil
}

func listAttachedDevices(task concurrency.Task, host resources.Host) (_ mapset.Set, xerr fail.Error) {
	var (
		retcode        int
		stdout, stderr string
	)

	hostName := host.GetName()
	cmd := "sudo lsblk -l -o NAME,TYPE | grep disk | cut -d' ' -f1"
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			if task.Aborted() {
				return retry.StopRetryError(fmt.Errorf("aborted"))
			}
			retcode, stdout, stderr, xerr = host.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
			if xerr != nil {
				return xerr
			}
			if retcode != 0 {
				if retcode == 255 {
					return fail.NotAvailableError("failed to reach SSH service of host '%s', retrying", hostName)
				}
				return fail.NewError(stderr)
			}
			return nil
		},
		2*time.Minute,
	)
	if retryErr != nil {
		return nil, fail.Wrap(retryErr, fmt.Sprintf("failed to get list of connected disks after %s", 2*time.Minute))
	}
	disks := strings.Split(stdout, "\n")
	set := mapset.NewThreadUnsafeSet()
	for _, k := range disks {
		set.Add(k)
	}
	return set, nil
}

// Detach detach the volume identified by ref, ref can be the name or the id
func (objv *volume) Detach(task concurrency.Task, host resources.Host) (xerr fail.Error) {
	if objv.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if host == nil {
		return fail.InvalidParameterError("host", "cannot be nil")
	}

	// const CANNOT = "cannot detach volume"

	var (
		volumeID, volumeName string
		mountPath            string
	)

	// -- retrives volume data --
	xerr = objv.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		volume, ok := clonable.(*abstract.Volume)
		if !ok {
			return fail.InconsistentError("'*abstract.Volume' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		volumeID = volume.ID
		volumeName = volume.Name
		return nil
	})
	if xerr != nil {
		return xerr
	}

	// -- retrieve host data --
	svc := objv.GetService()
	targetID := host.GetID()
	targetName := host.GetName()

	// -- Update target attachments --
	xerr = host.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// Check the volume is effectively attached
			attachment, found := hostVolumesV1.VolumesByID[volumeID]
			if !found {
				return fail.NotFoundError("cannot detach volume '%s': not attached to host '%s'", volumeName, targetName)
			}

			// Obtain mounts information
			return props.Alter(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
				hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				device := attachment.Device
				mountPath = hostMountsV1.LocalMountsByDevice[device]
				mount := hostMountsV1.LocalMountsByPath[mountPath]
				if mount == nil {
					return fail.InconsistentError("metadata inconsistency: no mount corresponding to volume attachment")
				}

				// Check if volume has other mount(s) inside it
				for p, i := range hostMountsV1.LocalMountsByPath {
					if i.Device == device {
						continue
					}
					if strings.Index(p, mount.Path) == 0 {
						return fail.InvalidRequestError("cannot detach volume '%s' from '%s:%s', there is a volume mounted in '%s:%s'",
							volumeName, targetName, mount.Path, targetName, p)
					}
				}
				for p := range hostMountsV1.RemoteMountsByPath {
					if strings.Index(p, mount.Path) == 0 {
						return fail.InvalidRequestError("cannot detach volume '%s' from '%s:%s', there is a share mounted in '%s:%s'",
							volumeName, targetName, mount.Path, targetName, p)
					}
				}

				// Check if volume (or a subdir in volume) is shared
				return props.Alter(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
					hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					for _, v := range hostSharesV1.ByID {
						if strings.Index(v.Path, mount.Path) == 0 {
							return fail.InvalidRequestError("cannot detach volume '%s' from '%s:%s', '%s:%s' is shared",
								volumeName, targetName, mount.Path, targetName, v.Path)
						}
					}

					// Unmount the Block Device ...
					sshConfig, innerXErr := host.GetSSHConfig(task)
					if innerXErr != nil {
						return innerXErr
					}
					nfsServer, innerXErr := nfs.NewServer(sshConfig)
					if innerXErr != nil {
						return innerXErr
					}
					if innerXErr = nfsServer.UnmountBlockDevice(task, attachment.Device); innerXErr != nil {
						return innerXErr
					}

					// ... then detach volume
					if innerXErr = svc.DeleteVolumeAttachment(targetID, attachment.AttachID); innerXErr != nil {
						return innerXErr
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
	if xerr != nil {
		return xerr
	}

	// -- updates volume property propertiesv1.VolumeAttachments --
	return objv.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
			volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
func (objv volume) ToProtocol(task concurrency.Task) (*protocol.VolumeInspectResponse, fail.Error) {
	if objv.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	volumeID := objv.GetID()
	volumeName := objv.GetName()
	out := &protocol.VolumeInspectResponse{
		Id:          volumeID,
		Name:        volumeName,
		Speed:       converters.VolumeSpeedFromAbstractToProtocol(objv.getSpeed(task)),
		Size:        int32(objv.getSize(task)),
		Attachments: []*protocol.VolumeAttachmentResponse{},
	}

	attachments, xerr := objv.GetAttachments(task)
	if xerr != nil {
		return nil, xerr
	}

	svc := objv.GetService()
	for k := range attachments.Hosts {
		rh, xerr := LoadHost(task, svc, k)
		if xerr != nil {
			return nil, xerr
		}
		vols := rh.(*host).getVolumes(task)
		device, ok := vols.DevicesByID[volumeID]
		if !ok {
			return nil, fail.InconsistentError("failed to find a device corresponding to the attached volume '%s' on host '%s'", volumeName, k)
		}
		mnts := rh.(*host).getMounts(task)
		path, ok := mnts.LocalMountsByDevice[device]
		if !ok {
			return nil, fail.InconsistentError("failed to find a mount of attached volume '%s' on host '%s'", volumeName, k)
		}
		m, ok := mnts.LocalMountsByPath[path]
		if !ok {
			return nil, fail.InconsistentError("failed to find a mount of attached volume '%s' on host '%s'", volumeName, k)
		}
		a := &protocol.VolumeAttachmentResponse{
			Host: &protocol.Reference{
				Name: k,
				Id:   rh.GetID(),
			},
			MountPath: path,
			Format:    m.FileSystem,
			Device:    device,
		}
		out.Attachments = append(out.Attachments, a)
	}
	return out, nil
}
