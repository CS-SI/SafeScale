/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
		return nullVolume(), fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, err := newCore(svc, "volume", volumesFolderName, &abstract.Volume{})
	if err != nil {
		return nullVolume(), err
	}
	return &volume{core: coreInstance}, nil
}

// LoadVolume loads the metadata of a subnet
func LoadVolume(task concurrency.Task, svc iaas.Service, ref string) (resources.Volume, fail.Error) {
	if task == nil {
		return nullVolume(), fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nullVolume(), fail.AbortedError(nil, "canceled")
	}
	if svc == nil {
		return nullVolume(), fail.InvalidParameterCannotBeNilError("svc")
	}
	if ref == "" {
		return nullVolume(), fail.InvalidParameterError("ref", "cannot be empty string")
	}

	rv, xerr := NewVolume(svc)
	if xerr != nil {
		return rv, xerr
	}

	// TODO: core.Read() does not check communication failure, side effect of limitations of Stow (waiting for stow replacement by rclone)
	if xerr = rv.Read(task, ref); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// rewrite NotFoundError, user does not bother about metadata stuff
			return nullVolume(), fail.NotFoundError("failed to find Volume '%s'", ref)
		default:
			return nullVolume(), xerr
		}
	}
	return rv, nil
}

// IsNull tells if the instance is a null value
func (rv *volume) IsNull() bool {
	return rv == nil || rv.core.IsNull()
}

// GetSpeed ...
func (rv volume) GetSpeed(task concurrency.Task) (volumespeed.Enum, fail.Error) {
	if rv.IsNull() {
		return 0, fail.InvalidInstanceError()
	}
	if task == nil {
		return 0, fail.InvalidParameterError("task", "cannot be nil")
	}
	if task.Aborted() {
		return 0, fail.AbortedError(nil, "canceled")
	}

	var speed volumespeed.Enum
	xerr := rv.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
// Intended to be used when rv is notoriously not nil
func (rv volume) getSpeed(task concurrency.Task) volumespeed.Enum {
	speed, _ := rv.GetSpeed(task)
	return speed
}

// GetSize ...
func (rv volume) GetSize(task concurrency.Task) (int, fail.Error) {
	if rv.IsNull() {
		return 0, fail.InvalidInstanceError()
	}
	if task == nil {
		return 0, fail.InvalidParameterError("task", "cannot be nil")
	}
	if task.Aborted() {
		return 0, fail.AbortedError(nil, "canceled")
	}

	var size int
	xerr := rv.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
// Intended to be used when rv is notoriously not nil
func (rv volume) getSize(task concurrency.Task) int {
	size, _ := rv.GetSize(task)
	return size
}

// GetAttachments returns where the Volume is attached
func (rv volume) GetAttachments(task concurrency.Task) (*propertiesv1.VolumeAttachments, fail.Error) {
	if rv.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "canceled")
	}

	var vaV1 *propertiesv1.VolumeAttachments
	xerr := rv.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
func (rv volume) Browse(task concurrency.Task, callback func(*abstract.Volume) fail.Error) fail.Error {
	if rv.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if task.Aborted() {
		return fail.AbortedError(nil, "canceled")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	return rv.core.BrowseFolder(task, func(buf []byte) fail.Error {
		av := abstract.NewVolume()
		xerr := av.Deserialize(buf)
		if xerr != nil {
			return xerr
		}
		return callback(av)
	})
}

// Delete deletes Volume and its metadata
func (rv *volume) Delete(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rv.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if task.Aborted() {
		return fail.AbortedError(nil, "canceled")
	}

	rv.SafeLock(task)
	defer rv.SafeUnlock(task)

	xerr = rv.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		// check if volume can be deleted (must not be attached)
		return props.Inspect(task, volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
			volumeAttachmentsV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' received", reflect.TypeOf(clonable).String())
			}
			nbAttach := uint(len(volumeAttachmentsV1.Hosts))
			if nbAttach > 0 {
				list := make([]string, 0, len(volumeAttachmentsV1.Hosts))
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
	})
	if xerr != nil {
		return xerr
	}

	// delete volume
	if xerr = rv.GetService().DeleteVolume(rv.GetID()); xerr != nil {
		switch xerr.(type) { //nolint
		case *retry.ErrTimeout:
			if xerr.Cause() != nil {
				xerr = fail.ToError(xerr.Cause())
			}
		}
	}
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			logrus.Debugf("Unable to find the volume on provider side, cleaning up metadata")
		default:
			return xerr
		}
	}

	// remove metadata
	return rv.core.Delete(task)
}

// Create a volume
func (rv *volume) Create(task concurrency.Task, req abstract.VolumeRequest) (xerr fail.Error) {
	if rv.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if task.Aborted() {
		return fail.AbortedError(nil, "canceled")
	}
	if req.Name == "" {
		return fail.InvalidParameterError("req.GetName", "cannot be empty string")
	}
	if req.Size <= 0 {
		return fail.InvalidParameterError("req.Size", "must be an integer > 0")
	}

	// Check if Volume exists and is managed by SafeScale
	svc := rv.GetService()
	if _, xerr = LoadVolume(task, svc, req.Name); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
		// continue
		default:
			return fail.Wrap(xerr, "failed to check if Volume '%s' already exists", req.Name)
		}
	} else {
		return fail.DuplicateError("'%s' already exists", req.Name)
	}

	// Check if host exists but is not managed by SafeScale
	if _, xerr = svc.InspectVolume(req.Name); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
		default:
			return fail.Wrap(xerr, "failed to check if Volume name '%s' is already used", req.Name)
		}
	} else {
		return fail.DuplicateError("found an existing Volume named '%s' (but not managed by SafeScale)", req.Name)
	}

	av, xerr := svc.CreateVolume(req)
	if xerr != nil {
		return xerr
	}

	// Starting from here, remove volume if exiting with error
	defer func() {
		if xerr != nil {
			if derr := svc.DeleteVolume(av.ID); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete volume '%s'", actionFromError(xerr), req.Name))
			}
		}
	}()

	// Sets err to possibly trigger defer calls
	return rv.Carry(task, av)
}

// Attach a volume to an host
func (rv *volume) Attach(task concurrency.Task, host resources.Host, path, format string, doNotFormat bool) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rv.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if task.Aborted() {
		return fail.AbortedError(nil, "canceled")
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
		volumeID, volumeName, deviceName, volumeUUID, mountPoint, vaID string
		nfsServer                                                      *nfs.Server
	)

	svc := rv.GetService()
	targetID := host.GetID()
	targetName := host.GetName()

	// -- proceed some checks on volume --
	xerr = rv.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		av, ok := clonable.(*abstract.Volume)
		if !ok {
			return fail.InconsistentError("'*abstract.Volume' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		volumeID = av.ID
		volumeName = av.Name

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
						return fail.InvalidRequestError(fmt.Sprintf("cannot attach volume '%s' to '%s:%s': there is already a volume mounted in '%s:%s'", volumeName, targetName, mountPoint, targetName, i.Path))
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

	if task.Aborted() {
		return fail.AbortedError(fmt.Errorf("aborted"))
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
			if derr := svc.DeleteVolumeAttachment(targetID, vaID); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to detach Volume '%s' from Host '%s'", actionFromError(xerr), volumeName, targetName))
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

			nfsServer, xerr = nfs.NewServer(sshConfig)
			if xerr != nil {
				return xerr
			}

			volumeUUID, xerr = nfsServer.MountBlockDevice(task, deviceName, mountPoint, format, doNotFormat)
			if xerr != nil {
				return xerr
			}

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

		defer func() {
			if innerXErr != nil {
				// Disable abort signal during the clean up
				defer task.DisarmAbortSignal()()

				if derr := nfsServer.UnmountBlockDevice(task, volumeUUID); derr != nil {
					_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unmount volume '%s' from host '%s'", actionFromError(innerXErr), volumeName, targetName))
				}
			}
		}()

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
			// Disable abort signal during the clean up
			defer task.DisarmAbortSignal()()

			if derr := nfsServer.UnmountBlockDevice(task, volumeUUID); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unmount Volume '%s' from Host '%s'", actionFromError(xerr), volumeName, targetName))
			}
			derr := host.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to update metadata of host '%s'", actionFromError(xerr), targetName))
			}
		}
	}()

	// last chance to abort ...
	if task.Aborted() {
		return fail.AbortedError(fmt.Errorf("aborted"))
	}

	xerr = rv.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
func (rv *volume) Detach(task concurrency.Task, host resources.Host) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rv.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return fail.AbortedError(nil, "canceled")
	}
	if host == nil {
		return fail.InvalidParameterCannotBeNilError("host")
	}

	// const CANNOT = "cannot detach volume"

	var (
		volumeID, volumeName string
		mountPath            string
	)

	// -- retrives volume data --
	xerr = rv.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
	svc := rv.GetService()
	targetID := host.GetID()
	targetName := host.GetName()

	// -- Update target attachments --

	return host.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		var (
			attachment *propertiesv1.HostVolume
			mount      *propertiesv1.HostLocalMount
		)

		innerXErr := props.Inspect(task, hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// Check the volume is effectively attached
			var found bool
			attachment, found = hostVolumesV1.VolumesByID[volumeID]
			if !found {
				return fail.NotFoundError("cannot detach volume '%s': not attached to host '%s'", volumeName, targetName)
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		// Obtain mounts information
		innerXErr = props.Inspect(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			device := attachment.Device
			mountPath = hostMountsV1.LocalMountsByDevice[device]
			mount = hostMountsV1.LocalMountsByPath[mountPath]
			if mount == nil {
				return fail.InconsistentError("metadata inconsistency: no mount corresponding to volume attachment")
			}

			// Check if volume has other mount(s) inside it
			for p, i := range hostMountsV1.LocalMountsByPath {
				if i.Device == device {
					continue
				}
				if strings.Index(p, mount.Path) == 0 {
					return fail.InvalidRequestError("cannot detach volume '%s' from '%s:%s', there is a volume mounted in '%s:%s'", volumeName, targetName, mount.Path, targetName, p)
				}
			}
			for p := range hostMountsV1.RemoteMountsByPath {
				if strings.Index(p, mount.Path) == 0 {
					return fail.InvalidRequestError("cannot detach volume '%s' from '%s:%s', there is a share mounted in '%s:%s'", volumeName, targetName, mount.Path, targetName, p)
				}
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		// Check if volume (or a subdir in volume) is shared
		innerXErr = props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			for _, v := range hostSharesV1.ByID {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if strings.Index(v.Path, mount.Path) == 0 {
					return fail.InvalidRequestError("cannot detach volume '%s' from '%s': mounted in '%s' and shared", volumeName, targetName, mount.Path)
				}
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Unmount the Block Device ...
		sshConfig, innerXErr := host.GetSSHConfig(task)
		if innerXErr != nil {
			return innerXErr
		}

		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		// Create NFS Server instance
		nfsServer, innerXErr := nfs.NewServer(sshConfig)
		if innerXErr != nil {
			return innerXErr
		}

		// Last chance to abort...
		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		defer task.DisarmAbortSignal()()

		// Unmount block device ...
		if innerXErr = nfsServer.UnmountBlockDevice(task, attachment.Device); innerXErr != nil {
			return innerXErr
		}

		// ... then detach volume ...
		if innerXErr = svc.DeleteVolumeAttachment(targetID, attachment.AttachID); innerXErr != nil {
			return innerXErr
		}

		// ... then update host property propertiesv1.VolumesV1...
		innerXErr = props.Alter(task, hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			delete(hostVolumesV1.VolumesByID, volumeID)
			delete(hostVolumesV1.VolumesByName, volumeName)
			delete(hostVolumesV1.VolumesByDevice, attachment.Device)
			delete(hostVolumesV1.DevicesByID, volumeID)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// ... update host property propertiesv1.MountsV1 ...
		innerXErr = props.Alter(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			delete(hostMountsV1.LocalMountsByDevice, mount.Device)
			delete(hostMountsV1.LocalMountsByPath, mount.Path)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// ... and finish with update of volume property propertiesv1.VolumeAttachments
		return rv.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(task, volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
				volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				delete(volumeAttachedV1.Hosts, targetID)
				return nil
			})
		})
	})
}

// ToProtocol converts the volume to protocol message VolumeInspectResponse
func (rv volume) ToProtocol(task concurrency.Task) (*protocol.VolumeInspectResponse, fail.Error) {
	if rv.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "canceled")
	}

	volumeID := rv.GetID()
	volumeName := rv.GetName()
	out := &protocol.VolumeInspectResponse{
		Id:          volumeID,
		Name:        volumeName,
		Speed:       converters.VolumeSpeedFromAbstractToProtocol(rv.getSpeed(task)),
		Size:        int32(rv.getSize(task)),
		Attachments: []*protocol.VolumeAttachmentResponse{},
	}

	attachments, xerr := rv.GetAttachments(task)
	if xerr != nil {
		return nil, xerr
	}

	svc := rv.GetService()
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
		if mnts != nil {
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
	}
	return out, nil
}
