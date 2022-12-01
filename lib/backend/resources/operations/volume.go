/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/eko/gocache/v2/store"
	"github.com/sirupsen/logrus"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumeproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	sshfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/ssh"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/system/nfs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	volumeKind        = "volume"
	volumesFolderName = "volumes" // is the name of the Object Storage MetadataFolder used to store volume info
)

// Volume links Object Storage MetadataFolder and unsafeGetVolumes
type volume struct {
	*metadata.Core
}

// NewVolume creates an instance of Volume
func NewVolume(ctx context.Context) (_ resources.Volume, ferr fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	coreInstance, xerr := metadata.NewCore(ctx, metadata.MethodObjectStorage, volumeKind, volumesFolderName, abstract.NewEmptyVolume())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &volume{
		Core: coreInstance,
	}
	return instance, nil
}

// LoadVolume loads the metadata of a subnet
func LoadVolume(inctx context.Context, ref string) (resources.Volume, fail.Error) {
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	myjob, xerr := jobapi.FromContext(inctx)
	if xerr != nil {
		return nil, xerr
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.Volume
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ resources.Volume, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// trick to avoid collisions
			var kt *volume
			cacheref := fmt.Sprintf("%T/%s", kt, ref)

			cache, xerr := myjob.Service().Cache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(resources.Volume)
					if ok {
						return casted, nil
					}
				}
			}

			cacheMissLoader := func() (data.Identifiable, fail.Error) { return onVolumeCacheMiss(ctx, ref) }
			anon, xerr := cacheMissLoader()
			if xerr != nil {
				return nil, xerr
			}

			var ok bool
			volumeInstance, ok := anon.(resources.Volume)
			if !ok {
				return nil, fail.InconsistentError("value in cache for Volume with key '%s' is not a resources.Volume", ref)
			}
			if volumeInstance == nil {
				return nil, fail.InconsistentError("nil value in cache for Volume with key '%s'", ref)
			}

			// if cache failed we are here, so we better retrieve updated information...
			xerr = volumeInstance.Reload(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, volumeInstance.GetName()), volumeInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(10 * time.Millisecond) // consolidate cache.Set
				hid, err := volumeInstance.GetID()
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), volumeInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(10 * time.Millisecond) // consolidate cache.Set

				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(resources.Volume)
					if ok {
						return casted, nil
					} else {
						logrus.WithContext(ctx).Warnf("wrong type of resources.Volume")
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}

			return volumeInstance, nil
		}()
		chRes <- result{ga, gerr}
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// onVolumeCacheMiss is called when there is no instance in cache of Volume 'ref'
func onVolumeCacheMiss(ctx context.Context, ref string) (data.Identifiable, fail.Error) {
	volumeInstance, innerXErr := NewVolume(ctx)
	if innerXErr != nil {
		return nil, innerXErr
	}

	blank, innerXErr := NewVolume(ctx)
	if innerXErr != nil {
		return nil, innerXErr
	}

	innerXErr = volumeInstance.Read(ctx, ref)
	if innerXErr != nil {
		return nil, innerXErr
	}

	if strings.Compare(fail.IgnoreError(volumeInstance.String(ctx)).(string), fail.IgnoreError(blank.String(ctx)).(string)) == 0 {
		return nil, fail.NotFoundError("volume with ref '%s' does NOT exist", ref)
	}

	return volumeInstance, nil
}

// IsNull tells if the instance is a null value
func (instance *volume) IsNull() bool {
	return instance == nil || valid.IsNil(instance.Core)
}

// Exists checks if the resource actually exists in provider side (not in stow metadata)
func (instance *volume) Exists(ctx context.Context) (bool, fail.Error) {
	theID, err := instance.GetID()
	if err != nil {
		return false, fail.ConvertError(err)
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
func (instance *volume) carry(ctx context.Context, clonable clonable.Clonable) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) && instance.Core.IsTaken() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}

	// Note: do not validate parameters, this call will do it
	xerr := instance.Core.Carry(ctx, clonable)
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

	return instance.unsafeGetSpeed(ctx)
}

// GetSize ...
func (instance *volume) GetSize(ctx context.Context) (_ int, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	return instance.unsafeGetSize(ctx)
}

// GetAttachments returns where the Volume is attached
func (instance *volume) GetAttachments(ctx context.Context) (_ *propertiesv1.VolumeAttachments, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	var vaV1 *propertiesv1.VolumeAttachments
	xerr := instance.InspectProperty(ctx, volumeproperty.AttachedV1, func(p clonable.Clonable) fail.Error {
		var innerErr error
		vaV1, innerErr = clonable.Cast[*propertiesv1.VolumeAttachments](p)
		return fail.Wrap(innerErr)
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

	// Note: Browse is intended to be callable from null value, so do not validate instance with .IsNull()
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.volume")).Entering()
	defer tracer.Exiting()

	return instance.BrowseFolder(ctx, func(buf []byte) fail.Error {
		av, _ := abstract.NewVolume()
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

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.volume")).Entering()
	defer tracer.Exiting()

	// check if volume can be deleted (must not be attached)
	xerr := metadata.InspectProperty(ctx, instance, volumeproperty.AttachedV1, func(volumeAttachmentsV1 *propertiesv1.VolumeAttachments) fail.Error {
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

	// remove metadata
	return instance.Core.Delete(ctx)
}

// Create a volume
func (instance *volume) Create(ctx context.Context, req abstract.VolumeRequest) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance.Core) && instance.IsTaken() {
		return fail.InconsistentError("already carrying information")
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

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.volume"), "('%s', %f, %s)", req.Name, req.Size, req.Speed.String()).Entering()
	defer tracer.Exiting()

	// Check if Volume exists and is managed by SafeScale
	mdv, xerr := LoadVolume(ctx, req.Name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreErrorWithContext(ctx, xerr)
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
	svc := instance.Service()
	_, xerr = svc.InspectVolume(ctx, req.Name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreErrorWithContext(ctx, xerr)
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

	return instance.carry(ctx, av)
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

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.volume"), "('%s', %s, %s, %v)", host.GetName(), path, format, doNotFormat).Entering()
	defer tracer.Exiting()

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
	xerr = instance.Inspect(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		av, innerErr := clonable.Cast[*abstract.Volume](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		volumeID = av.ID
		volumeName = av.Name

		return props.Inspect(volumeproperty.AttachedV1, func(p clonable.Clonable) fail.Error {
			volumeAttachedV1, innerErr := clonable.Cast[*propertiesv1.VolumeAttachments](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
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
	state, xerr = host.GetState(ctx)
	if xerr != nil {
		return xerr
	}

	if state != hoststate.Started {
		return fail.InvalidRequestError(fmt.Sprintf("cannot attach volume '%s' to '%s:%s': host '%s' is NOT started", volumeName, targetName, mountPoint, targetName))
	}

	// -- proceed some checks on target server --
	xerr = host.Inspect(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.VolumesV1, func(p clonable.Clonable) fail.Error {
			hostVolumesV1, innerErr := clonable.Cast[*propertiesv1.HostVolumes](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			return props.Inspect(hostproperty.MountsV1, func(p clonable.Clonable) fail.Error {
				hostMountsV1, innerErr := clonable.Cast[*propertiesv1.HostMounts](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
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
			derr := svc.DeleteVolumeAttachment(cleanupContextFrom(ctx), targetID, vaID)
			if derr != nil {
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
	xerr = host.Alter(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		innerXErr := props.Alter(hostproperty.VolumesV1, func(p clonable.Clonable) (ferr fail.Error) {
			hostVolumesV1, innerErr := clonable.Cast[*propertiesv1.HostVolumes](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
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
			if innerXErr != nil && !doNotMount {
				if derr := nfsServer.UnmountBlockDevice(cleanupContextFrom(ctx), volumeUUID); derr != nil {
					_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unmount volume '%s' from host '%s'", ActionFromError(innerXErr), volumeName, targetName))
				}
			}
		}()

		return props.Alter(hostproperty.MountsV1, func(p clonable.Clonable) fail.Error {
			hostMountsV1, innerErr := clonable.Cast[*propertiesv1.HostMounts](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
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
			derr := host.Alter(cleanupContextFrom(ctx), func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
				innerXErr := props.Alter(hostproperty.VolumesV1, func(p clonable.Clonable) fail.Error {
					hostVolumesV1, innerErr := clonable.Cast[*propertiesv1.HostVolumes](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
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
				return props.Alter(hostproperty.MountsV1, func(p clonable.Clonable) fail.Error {
					hostMountsV1, innerErr := clonable.Cast[*propertiesv1.HostMounts](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
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
	xerr = instance.AlterProperty(ctx, volumeproperty.AttachedV1, func(p clonable.Clonable) fail.Error {
		volumeAttachedV1, innerErr := clonable.Cast[*propertiesv1.VolumeAttachments](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		volumeAttachedV1.Hosts[targetID] = targetName
		return nil
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
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.volume"), "('%s')", targetID).Entering()
	defer tracer.Exiting()

	var (
		volumeID, volumeName string
		mountPath            string
	)

	targetName := host.GetName()

	state, xerr := host.GetState(ctx)
	if xerr != nil {
		return xerr
	}

	if state != hoststate.Started {
		return fail.InvalidRequestError(fmt.Sprintf("cannot detach volume '%s' from '%s', '%s' is NOT started", volumeName, targetName, targetName))
	}

	// -- retrieves volume data --
	xerr = instance.Review(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
		volume, innerErr := clonable.Cast[*abstract.Volume](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
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
	return host.Alter(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		var (
			attachment *propertiesv1.HostVolume
			mount      *propertiesv1.HostLocalMount
		)

		innerXErr := props.Inspect(hostproperty.VolumesV1, func(p clonable.Clonable) fail.Error {
			hostVolumesV1, innerErr := clonable.Cast[*propertiesv1.HostVolumes](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
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
		innerXErr = props.Inspect(hostproperty.MountsV1, func(p clonable.Clonable) fail.Error {
			hostMountsV1, innerErr := clonable.Cast[*propertiesv1.HostMounts](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
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
			innerXErr = props.Inspect(hostproperty.SharesV1, func(p clonable.Clonable) fail.Error {
				hostSharesV1, innerErr := clonable.Cast[*propertiesv1.HostShares](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
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
			if innerXErr = nfsServer.UnmountBlockDevice(jobapi.NewContextPropagatingJob(ctx), attachment.Device); innerXErr != nil {
				return innerXErr
			}
		}

		// ... then detach volume ...
		if innerXErr = svc.DeleteVolumeAttachment(ctx, targetID, attachment.AttachID); innerXErr != nil {
			return innerXErr
		}

		// ... then update host property propertiesv1.VolumesV1...
		innerXErr = props.Alter(hostproperty.VolumesV1, func(p clonable.Clonable) fail.Error {
			hostVolumesV1, innerErr := clonable.Cast[*propertiesv1.HostVolumes](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
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
			innerXErr = props.Alter(hostproperty.MountsV1, func(p clonable.Clonable) fail.Error {
				hostMountsV1, innerErr := clonable.Cast[*propertiesv1.HostMounts](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
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
		return instance.AlterProperty(ctx, volumeproperty.AttachedV1, func(p clonable.Clonable) fail.Error {
			volumeAttachedV1, innerErr := clonable.Cast[*propertiesv1.VolumeAttachments](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			delete(volumeAttachedV1.Hosts, targetID)
			return nil
		})
	})
}

// ToProtocol converts the volume to protocol message VolumeInspectResponse
func (instance *volume) ToProtocol(ctx context.Context) (*protocol.VolumeInspectResponse, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

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

	attachments, xerr := instance.GetAttachments(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	for k := range attachments.Hosts {
		hostInstance, xerr := LoadHost(ctx, k)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		vols, _ := hostInstance.(*Host).unsafeGetVolumes(ctx)
		device, ok := vols.DevicesByID[volumeID]
		if !ok {
			return nil, fail.InconsistentError("failed to find a device corresponding to the attached volume '%s' on host '%s'", volumeName, k)
		}

		mnts, _ := hostInstance.(*Host).unsafeGetMounts(ctx)
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
