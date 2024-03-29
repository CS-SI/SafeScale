/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	sshfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/ssh"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	mapset "github.com/deckarep/golang-set"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumeproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/system/nfs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

const (
	volumeKind        = "volume"
	volumesFolderName = "volumes" // is the name of the Object Storage MetadataFolder used to store volume info
)

// Volume links Object Storage MetadataFolder and unsafeGetVolumes
type volume struct {
	*MetadataCore
}

// NewVolume creates an instance of Volume
func NewVolume(svc iaas.Service) (_ resources.Volume, ferr fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, xerr := NewCore(svc, volumeKind, volumesFolderName, &abstract.Volume{})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &volume{
		MetadataCore: coreInstance,
	}
	return instance, nil
}

// onVolumeCacheMiss is called when there is no instance in cache of Volume 'ref'
func onVolumeCacheMiss(ctx context.Context, svc iaas.Service, ref string) (data.Identifiable, fail.Error) {
	volumeInstance, innerXErr := NewVolume(svc)
	if innerXErr != nil {
		return nil, innerXErr
	}

	blank, innerXErr := NewVolume(svc)
	if innerXErr != nil {
		return nil, innerXErr
	}

	if innerXErr = volumeInstance.Read(ctx, ref); innerXErr != nil {
		return nil, innerXErr
	}

	if strings.Compare(fail.IgnoreError(volumeInstance.Sdump(ctx)).(string), fail.IgnoreError(blank.Sdump(ctx)).(string)) == 0 {
		return nil, fail.NotFoundError("volume with ref '%s' does NOT exist", ref)
	}

	return volumeInstance, nil
}

// IsNull tells if the instance is a null value
func (instance *volume) IsNull() bool {
	return instance == nil || instance.MetadataCore == nil || valid.IsNil(instance.MetadataCore)
}

// Exists checks if the resource actually exists in provider side (not in stow metadata)
func (instance *volume) Exists(ctx context.Context) (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}

	theID, err := instance.GetID()
	if err != nil {
		return false, fail.ConvertError(err)
	}

	if beta := os.Getenv("SAFESCALE_DETECT_CORRUPTION"); beta != "yes" {
		return true, nil
	}

	_, xerr := instance.Service().InspectVolume(ctx, theID)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return false, nil
		default:
			return false, xerr
		}
	}

	return true, nil
}

// carry overloads rv.core.Carry() to add Volume to service cache
func (instance *volume) carry(ctx context.Context, clonable data.Clonable) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) {
		if instance.MetadataCore.IsTaken() {
			return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
		}
	}
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}

	// Note: do not validate parameters, this call will do it
	xerr := instance.MetadataCore.Carry(ctx, clonable)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// GetSpeed ...
func (instance *volume) GetSpeed(ctx context.Context) (_ volumespeed.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	return instance.unsafeGetSpeed(ctx)
}

// GetSize ...
func (instance *volume) GetSize(ctx context.Context) (_ int, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	return instance.unsafeGetSize(ctx)
}

// GetAttachments returns where the Volume is attached
func (instance *volume) GetAttachments(ctx context.Context) (_ *propertiesv1.VolumeAttachments, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	var xerr fail.Error

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	var vaV1 *propertiesv1.VolumeAttachments
	xerr = instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
			var ok bool
			vaV1, ok = clonable.(*propertiesv1.VolumeAttachments)

			if !ok {
				return fail.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	return vaV1, nil
}

// Browse walks through volume MetadataFolder and executes a callback for each entry
func (instance *volume) Browse(ctx context.Context, callback func(*abstract.Volume) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	return instance.MetadataCore.BrowseFolder(ctx, func(buf []byte) fail.Error {
		av := abstract.NewVolume()
		xerr := av.Deserialize(buf)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		return callback(av)
	})
}

// Delete deletes Volume and its metadata
func (instance *volume) Delete(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}

	defer func() {
		// drop the cache when we are done creating the cluster
		if ka, err := instance.Service().GetCache(context.Background()); err == nil {
			if ka != nil {
				_ = ka.Clear(context.Background())
			}
		}
	}()

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		// check if volume can be deleted (must not be attached)
		return props.Inspect(volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
			volumeAttachmentsV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' received", reflect.TypeOf(clonable).String())
			}

			nbAttach := uint(len(volumeAttachmentsV1.Hosts))
			if nbAttach > 0 {
				list := make([]string, 0, len(volumeAttachmentsV1.Hosts))
				for _, v := range volumeAttachmentsV1.Hosts {
					list = append(list, v)
				}
				return fail.NotAvailableError("still attached to %d host%s: %s", nbAttach, strprocess.Plural(nbAttach), strings.Join(list, ", "))
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	volid, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	// delete volume
	xerr = instance.Service().DeleteVolume(ctx, volid)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			xerr = fail.ConvertError(fail.Cause(xerr))
			switch xerr.(type) {
			case *fail.ErrNotFound:
				logrus.WithContext(ctx).Debugf("Unable to find the volume on provider side, cleaning up metadata")
			default:
				return xerr
			}
		case *fail.ErrNotFound:
			logrus.WithContext(ctx).Debugf("Unable to find the volume on provider side, cleaning up metadata")
		default:
			return xerr
		}
	}

	theID, _ := instance.GetID()

	// remove metadata
	xerr = instance.MetadataCore.Delete(ctx)
	if xerr != nil {
		return xerr
	}

	if ka, err := instance.Service().GetCache(ctx); err == nil {
		if ka != nil {
			if theID != "" {
				_ = ka.Delete(ctx, fmt.Sprintf("%T/%s", instance, theID))
			}
		}
	}

	return nil
}

// Create a volume
func (instance *volume) Create(ctx context.Context, req abstract.VolumeRequest) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// NOTE: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance.MetadataCore) {
		if instance.MetadataCore.IsTaken() {
			return fail.InconsistentError("already carrying information")
		}
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if req.Name == "" {
		return fail.InvalidParameterError("req.GetName", "cannot be empty string")
	}
	if req.Size <= 0 {
		return fail.InvalidParameterError("req.Size", "must be an integer > 0")
	}

	// Check if Volume exists and is managed by SafeScale
	svc := instance.Service()
	mdv, xerr := LoadVolume(ctx, svc, req.Name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreError2(ctx, xerr)
		default:
			return fail.Wrap(xerr, "failed to check if Volume '%s' already exists", req.Name)
		}
	} else {
		exists, xerr := mdv.Exists(ctx)
		if xerr != nil {
			return xerr
		}
		if !exists {
			return fail.DuplicateError("there is already a Volume named '%s', but no longer exists, is a metadata mistake", req.Name)
		}
		return fail.DuplicateError("there is already a Volume named '%s'", req.Name)
	}

	// Check if host exists but is not managed by SafeScale
	_, xerr = svc.InspectVolume(ctx, req.Name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreError2(ctx, xerr)
		default:
			return fail.Wrap(xerr, "failed to check if Volume name '%s' is already used", req.Name)
		}
	} else {
		return fail.DuplicateError("found an existing Volume named '%s' (but not managed by SafeScale)", req.Name)
	}

	av, xerr := svc.CreateVolume(ctx, req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Starting from here, remove volume if exiting with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := svc.DeleteVolume(cleanupContextFrom(ctx), av.ID); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete volume '%s'", ActionFromError(ferr), req.Name))
			}
		}
	}()

	xerr = instance.carry(ctx, av)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Attach a volume to a host
func (instance *volume) Attach(ctx context.Context, host resources.Host, path, format string, doNotFormat, doNotMount bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
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

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	var (
		volumeID, volumeName, deviceName, volumeUUID, mountPoint, vaID string
		nfsServer                                                      *nfs.Server
	)

	svc := instance.Service()
	targetID, err := host.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}
	targetName := host.GetName()

	// -- proceed some checks on volume --
	xerr = instance.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		av, ok := clonable.(*abstract.Volume)
		if !ok {
			return fail.InconsistentError("'*abstract.Volume' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		volumeID = av.ID
		volumeName = av.Name

		return props.Inspect(volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
			volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if doNotMount {
				mountPoint = ""
			} else {
				mountPoint = path
				if path == abstract.DefaultVolumeMountPoint {
					mountPoint = abstract.DefaultVolumeMountPoint + volumeName
				}
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	var state hoststate.Enum
	state, xerr = host.ForceGetState(ctx)
	if xerr != nil {
		return xerr
	}

	if state != hoststate.Started {
		return fail.InvalidRequestError(fmt.Sprintf("cannot attach volume '%s' to '%s:%s': host '%s' is NOT started", volumeName, targetName, mountPoint, targetName))
	}

	// -- proceed some checks on target server --
	xerr = host.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return props.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
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
					if mountPoint != "" {
						if path != mountPoint {
							return fail.InvalidRequestError("volume '%s' is already attached in '%s:%s'", volumeName, targetName, path)
						}
					}
					return nil
				}

				if !doNotMount {
					// Check if there is no other device mounted in the path (or in subpath)
					for _, i := range hostMountsV1.LocalMountsByPath {
						if mountPoint != "" {
							if strings.Index(i.Path, mountPoint) == 0 {
								return fail.InvalidRequestError(fmt.Sprintf("cannot attach volume '%s' to '%s:%s': there is already a volume mounted in '%s:%s'", volumeName, targetName, mountPoint, targetName, i.Path))
							}
						}
					}
					for _, i := range hostMountsV1.RemoteMountsByPath {
						if mountPoint != "" {
							if strings.Index(i.Path, mountPoint) == 0 {
								return fail.InvalidRequestError(fmt.Sprintf("can't attach volume '%s' to '%s:%s': there is a share mounted in path '%s:%s[/...]'", volumeName, targetName, mountPoint, targetName, i.Path))
							}
						}
					}
				}
				return nil
			})
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// -- Get list of disks before attachment --
	// Note: some providers are not able to tell the real device name the volume
	//       will have on the host, so we have to use a way that can work everywhere
	oldDiskSet, xerr := listAttachedDevices(ctx, host)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// -- creates volume attachment --
	vaID, xerr = svc.CreateVolumeAttachment(ctx, abstract.VolumeAttachmentRequest{
		Name:     fmt.Sprintf("%s-%s", volumeName, targetName),
		HostID:   targetID,
		VolumeID: volumeID,
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Starting from here, remove volume attachment if exiting with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := svc.DeleteVolumeAttachment(cleanupContextFrom(ctx), targetID, vaID); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to detach Volume '%s' from Host '%s'", ActionFromError(ferr), volumeName, targetName))
			}
		}
	}()

	// -- acknowledge the volume is really attached to host --
	var newDisk mapset.Set
	retryErr := retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			newDiskSet, xerr := listAttachedDevices(ctx, host)
			xerr = debug.InjectPlannedFail(xerr)
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
		timings.SmallDelay(),
		timings.CommunicationTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return fail.Wrap(fail.Cause(retryErr), "timeout")
		default:
			return retryErr
		}
	}

	// -- updates target properties --
	xerr = host.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		innerXErr := props.Alter(hostproperty.VolumesV1, func(clonable data.Clonable) (ferr fail.Error) {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// Recovers real device name from the system
			deviceName = "/dev/" + newDisk.ToSlice()[0].(string)

			// Create mount point
			sshConfig, deeperXErr := host.GetSSHConfig(ctx)
			if deeperXErr != nil {
				return deeperXErr
			}

			sshProfile, deeperXErr := sshfactory.NewConnector(sshConfig)
			if deeperXErr != nil {
				return deeperXErr
			}

			nfsServer, deeperXErr = nfs.NewServer(svc, sshProfile)
			if deeperXErr != nil {
				return deeperXErr
			}

			if !doNotMount {
				volumeUUID, deeperXErr = nfsServer.MountBlockDevice(ctx, deviceName, mountPoint, format, doNotFormat)
				if deeperXErr != nil {
					return deeperXErr
				}

				defer func() {
					ferr = debug.InjectPlannedFail(ferr)
					if ferr != nil {
						if derr := nfsServer.UnmountBlockDevice(cleanupContextFrom(ctx), volumeUUID); derr != nil {
							_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unmount volume '%s' from host '%s'", ActionFromError(ferr), volumeName, targetName))
						}
					}
				}()
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
				if !doNotMount {
					if derr := nfsServer.UnmountBlockDevice(cleanupContextFrom(ctx), volumeUUID); derr != nil {
						_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unmount volume '%s' from host '%s'", ActionFromError(innerXErr), volumeName, targetName))
					}
				}
			}
		}()

		innerXErr = props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
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
		if innerXErr != nil {
			return innerXErr
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if !doNotMount {
				if derr := nfsServer.UnmountBlockDevice(cleanupContextFrom(ctx), volumeUUID); derr != nil {
					_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unmount Volume '%s' from Host '%s'", ActionFromError(ferr), volumeName, targetName))
				}
			}
			derr := host.Alter(cleanupContextFrom(ctx), func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
				innerXErr := props.Alter(hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
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
					logrus.WithContext(cleanupContextFrom(ctx)).Warnf("Failed to set host '%s' metadata about volumes", volumeName)
				}
				return props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
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
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to update metadata of host '%s'", ActionFromError(ferr), targetName))
			}
		}
	}()

	// Updates volume properties
	xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
			volumeAttachedV1, ok := clonable.(*propertiesv1.VolumeAttachments)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.VolumeAttachments' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			volumeAttachedV1.Hosts[targetID] = targetName
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	logrus.WithContext(ctx).Infof("Volume '%s' successfully attached to host '%s' as device '%s'", volumeName, targetName, volumeUUID)
	return nil
}

func listAttachedDevices(ctx context.Context, host resources.Host) (_ mapset.Set, ferr fail.Error) {
	var (
		retcode        int
		stdout, stderr string
	)

	svc := host.Service()

	timings, xerr := svc.Timings()
	if xerr != nil {
		return nil, xerr
	}

	hostName := host.GetName()
	cmd := "sudo lsblk -l -o NAME,TYPE | grep disk | cut -d' ' -f1"
	retryErr := retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			retcode, stdout, stderr, xerr = host.Run(ctx, cmd, outputs.COLLECT, timings.ConnectionTimeout(), timings.ExecutionTimeout())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
			if retcode != 0 {
				problem := fail.NewError("failure trying to run '%s' on host '%s'", cmd, hostName)
				problem.Annotate("stdout", stdout)
				problem.Annotate("stderr", stderr)
				problem.Annotate("retcode", retcode)

				return problem
			}
			return nil
		},
		timings.SmallDelay(),
		timings.ExecutionTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return nil, fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return nil, fail.Wrap(fail.Cause(retryErr), "timeout")
		default:
			return nil, retryErr
		}
	}

	disks := strings.Split(stdout, "\n")
	set := mapset.NewThreadUnsafeSet()
	for _, k := range disks {
		if k != "" {
			set.Add(k)
		}
	}
	return set, nil
}

// Detach detaches the volume identified by ref, ref can be the name or the id
func (instance *volume) Detach(ctx context.Context, host resources.Host) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if host == nil {
		return fail.InvalidParameterCannotBeNilError("host")
	}

	targetID, err := host.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	var (
		volumeID, volumeName string
		mountPath            string
	)

	targetName := host.GetName()

	state, xerr := host.ForceGetState(ctx)
	if xerr != nil {
		return xerr
	}

	if state != hoststate.Started {
		return fail.InvalidRequestError(fmt.Sprintf("cannot detach volume '%s' from '%s', '%s' is NOT started", volumeName, targetName, targetName))
	}

	// -- retrieves volume data --
	xerr = instance.Inspect(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		volume, ok := clonable.(*abstract.Volume)
		if !ok {
			return fail.InconsistentError("'*abstract.Volume' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		volumeID = volume.ID
		volumeName = volume.Name
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// -- retrieve host data --
	svc := instance.Service()

	// -- Update target attachments --
	return host.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		var (
			attachment *propertiesv1.HostVolume
			mount      *propertiesv1.HostLocalMount
		)

		innerXErr := props.Inspect(hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
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

		// Obtain mounts information
		notMounted := false
		innerXErr = props.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			device := attachment.Device
			mountPath = hostMountsV1.LocalMountsByDevice[device]
			if mountPath == "" {
				notMounted = true
			}
			if !notMounted {
				mount = hostMountsV1.LocalMountsByPath[mountPath]
				if mount == nil {
					return fail.InconsistentError("metadata inconsistency: no mount corresponding to volume attachment")
				}

				// Check if volume has other mount(s) inside it
				for p, i := range hostMountsV1.LocalMountsByPath {
					if i.Device == device {
						continue
					}
					if strings.Index(p+"/", mount.Path+"/") == 0 {
						return fail.InvalidRequestError("cannot detach volume '%s' from '%s:%s', there is a volume mounted in '%s:%s'", volumeName, targetName, mount.Path, targetName, p)
					}
				}
				for p := range hostMountsV1.RemoteMountsByPath {
					if strings.Index(p+"/", mount.Path+"/") == 0 {
						return fail.InvalidRequestError("cannot detach volume '%s' from '%s:%s', there is a share mounted in '%s:%s'", volumeName, targetName, mount.Path, targetName, p)
					}
				}
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Check if volume (or a subdir in volume) is shared
		if !notMounted {
			innerXErr = props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
				hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				for _, v := range hostSharesV1.ByID {
					if strings.Index(v.Path, mount.Path) == 0 {
						return fail.InvalidRequestError("cannot detach volume '%s' from '%s': mounted in '%s' and shared", volumeName, targetName, mount.Path)
					}
				}
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			// -- Unmount the Block Device ...
			sshConfig, innerXErr := host.GetSSHConfig(ctx)
			if innerXErr != nil {
				return innerXErr
			}

			sshProfile, innerXErr := sshfactory.NewConnector(sshConfig)
			if innerXErr != nil {
				return innerXErr
			}

			// Create NFS Server instance
			nfsServer, innerXErr := nfs.NewServer(svc, sshProfile)
			if innerXErr != nil {
				return innerXErr
			}

			// Unmount block device ...
			if innerXErr = nfsServer.UnmountBlockDevice(cleanupContextFrom(ctx), attachment.Device); innerXErr != nil {
				return innerXErr
			}
		}

		// ... then detach volume ...
		if innerXErr = svc.DeleteVolumeAttachment(ctx, targetID, attachment.AttachID); innerXErr != nil {
			return innerXErr
		}

		// ... then update host property propertiesv1.VolumesV1...
		innerXErr = props.Alter(hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
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
		if !notMounted {
			innerXErr = props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
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
		}

		// ... and finish with update of volume property propertiesv1.VolumeAttachments
		return instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(volumeproperty.AttachedV1, func(clonable data.Clonable) fail.Error {
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
func (instance *volume) ToProtocol(ctx context.Context) (*protocol.VolumeInspectResponse, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	// HUGE design mistakes in all ToProtocol functions
	// a ToProtocol function should just transform data, ALL the data should be ready BEFORE calling ToProtocol...
	// but as we see here, there is a min of 3 remote queries here...

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	volumeID, err := instance.GetID()
	if err != nil {
		return nil, fail.ConvertError(err)
	}
	volumeName := instance.GetName()
	out := &protocol.VolumeInspectResponse{
		Id:          volumeID,
		Name:        volumeName,
		Speed:       converters.VolumeSpeedFromAbstractToProtocol(func() volumespeed.Enum { out, _ := instance.unsafeGetSpeed(ctx); return out }()),
		Size:        func() int32 { out, _ := instance.unsafeGetSize(ctx); return int32(out) }(),
		Attachments: []*protocol.VolumeAttachmentResponse{},
	}

	attachments, xerr := instance.GetAttachments(ctx) // remote query
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	svc := instance.Service()
	for k := range attachments.Hosts {
		hostInstance, xerr := LoadHost(ctx, svc, k) // a few more remote queries for each attachment
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
			default:
				return nil, xerr
			}
			continue
		}

		vols, _ := hostInstance.(*Host).unsafeGetVolumes(ctx) // remote query
		device, ok := vols.DevicesByID[volumeID]
		if !ok {
			return nil, fail.InconsistentError("failed to find a device corresponding to the attached volume '%s' on host '%s'", volumeName, k)
		}

		mnts, _ := hostInstance.(*Host).unsafeGetMounts(ctx) // remote query
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
					Name: hostInstance.GetName(),
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
