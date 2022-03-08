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
	"reflect"
	"strings"
	"sync"

	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
	mapset "github.com/deckarep/golang-set"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/volumeproperty"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/v21/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v21/lib/system/nfs"
	"github.com/CS-SI/SafeScale/v21/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v21/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v21/lib/utils/strprocess"
)

const (
	volumeKind        = "volume"
	volumesFolderName = "volumes" // is the name of the Object Storage MetadataFolder used to store volume info
)

// Volume links Object Storage MetadataFolder and unsafeGetVolumes
type volume struct {
	*MetadataCore

	lock sync.RWMutex
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

// LoadVolume loads the metadata of a subnet
func LoadVolume(svc iaas.Service, ref string) (rv resources.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	timings, xerr := svc.Timings()
	if xerr != nil {
		return nil, xerr
	}

	volumeCache, xerr := svc.GetCache(volumeKind)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	options := iaas.CacheMissOption(
		func() (cache.Cacheable, fail.Error) { return onVolumeCacheMiss(svc, ref) },
		timings.MetadataTimeout(),
	)
	cacheEntry, xerr := volumeCache.Get(ref, options...)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreError(xerr)
			// rewrite NotFoundError, user does not bother about metadata stuff
			return nil, fail.NotFoundError("failed to find Volume '%s'", ref)
		default:
			return nil, xerr
		}
	}

	var ok bool
	rv, ok = cacheEntry.Content().(resources.Volume)
	if !ok {
		return nil, fail.InconsistentError("value in cache for Volume with key '%s' is not a resources.Volume", ref)
	}
	if rv == nil {
		return nil, fail.InconsistentError("nil value in cache for Volume with key '%s'", ref)
	}

	_ = cacheEntry.LockContent()
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			_ = cacheEntry.UnlockContent()
		}
	}()

	// FIXME: The reload problem
	// VPL: what state of Volume would you like to be updated by Reload?
	/*
		xerr = rv.Reload()
		if xerr != nil {
			return nil, xerr
		}
	*/

	return rv, nil
}

// onVolumeCacheMiss is called when there is no instance in cache of Volume 'ref'
func onVolumeCacheMiss(svc iaas.Service, ref string) (cache.Cacheable, fail.Error) {
	volumeInstance, innerXErr := NewVolume(svc)
	if innerXErr != nil {
		return nil, innerXErr
	}

	// TODO: core.ReadByID() does not check communication failure, side effect of limitations of Stow (waiting for stow replacement by rclone)
	if innerXErr = volumeInstance.Read(ref); innerXErr != nil {
		return nil, innerXErr
	}

	return volumeInstance, nil
}

// IsNull tells if the instance is a null value
func (instance *volume) IsNull() bool {
	return instance == nil || instance.MetadataCore == nil || valid.IsNil(instance.MetadataCore)
}

// carry overloads rv.core.Carry() to add Volume to service cache
func (instance *volume) carry(clonable data.Clonable) (ferr fail.Error) {
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
	identifiable, ok := clonable.(data.Identifiable)
	if !ok {
		return fail.InvalidParameterError("clonable", "must also satisfy interface 'data.Identifiable'")
	}

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	kindCache, xerr := instance.Service().GetCache(instance.MetadataCore.GetKind())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = kindCache.ReserveEntry(identifiable.GetID(), timings.MetadataTimeout())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := kindCache.FreeEntry(identifiable.GetID()); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free %s cache entry for key '%s'", instance.MetadataCore.GetKind(), identifiable.GetID()))
			}
		}
	}()

	// Note: do not validate parameters, this call will do it
	xerr = instance.MetadataCore.Carry(clonable)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	cacheEntry, xerr := kindCache.CommitEntry(identifiable.GetID(), instance)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	cacheEntry.LockContent()
	return nil
}

// GetSpeed ...
func (instance *volume) GetSpeed() (_ volumespeed.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.unsafeGetSpeed()
}

// GetSize ...
func (instance *volume) GetSize() (_ int, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.unsafeGetSize()
}

// GetAttachments returns where the Volume is attached
func (instance *volume) GetAttachments() (_ *propertiesv1.VolumeAttachments, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	var xerr fail.Error

	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var vaV1 *propertiesv1.VolumeAttachments
	xerr = instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return xerr
			}
		default:
			return xerr
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.volume")).Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.MetadataCore.BrowseFolder(func(buf []byte) fail.Error {
		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		av := abstract.NewVolume()
		xerr = av.Deserialize(buf)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		return callback(av)
	})
}

// Delete deletes Volume and its metadata
func (instance *volume) Delete(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return xerr
			}
		default:
			return xerr
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.volume")).Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
					if task.Aborted() {
						return fail.AbortedError(nil, "aborted")
					}

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

	// delete volume
	xerr = instance.Service().DeleteVolume(instance.GetID())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			xerr = fail.ConvertError(fail.Cause(xerr))
		default:
		}
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			logrus.Debugf("Unable to find the volume on provider side, cleaning up metadata")
		default:
			return xerr
		}
	}

	// remove metadata
	return instance.MetadataCore.Delete()
}

// Create a volume
func (instance *volume) Create(ctx context.Context, req abstract.VolumeRequest) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance.MetadataCore) {
		if instance.MetadataCore.IsTaken() {
			return fail.NotAvailableError("already carrying information")
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

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return xerr
			}
		default:
			return xerr
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.volume"), "('%s', %f, %s)", req.Name, req.Size, req.Speed.String()).Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	// Check if Volume exists and is managed by SafeScale
	svc := instance.Service()
	existing, xerr := LoadVolume(svc, req.Name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError(xerr)
			break // nolint
		default:
			return fail.Wrap(xerr, "failed to check if Volume '%s' already exists", req.Name)
		}
	} else {
		existing.Released()
		return fail.DuplicateError("there is already a Volume named '%s'", req.Name)
	}

	// Check if host exists but is not managed by SafeScale
	_, xerr = svc.InspectVolume(req.Name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError(xerr)
			break // nolint
		default:
			return fail.Wrap(xerr, "failed to check if Volume name '%s' is already used", req.Name)
		}
	} else {
		return fail.DuplicateError("found an existing Volume named '%s' (but not managed by SafeScale)", req.Name)
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	av, xerr := svc.CreateVolume(req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Starting from here, remove volume if exiting with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := svc.DeleteVolume(av.ID); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete volume '%s'", ActionFromError(ferr), req.Name))
			}
		}
	}()

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Sets err to possibly trigger defer calls
	return instance.carry(av)
}

// Attach a volume to a host
func (instance *volume) Attach(
	ctx context.Context, host resources.Host, path, format string, doNotFormat, doNotMount bool,
) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
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

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return xerr
			}
		default:
			return xerr
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.volume"), "('%s', %s, %s, %v)", host.GetName(), path, format, doNotFormat).Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	var (
		volumeID, volumeName, deviceName, volumeUUID, mountPoint, vaID string
		nfsServer                                                      *nfs.Server
	)

	svc := instance.Service()
	targetID := host.GetID()
	targetName := host.GetName()

	// -- proceed some checks on volume --
	xerr = instance.Inspect(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
					if task.Aborted() {
						return fail.AbortedError(nil, "aborted")
					}

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

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// -- proceed some checks on target server --
	xerr = host.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
						if task.Aborted() {
							return fail.AbortedError(nil, "aborted")
						}

						if mountPoint != "" {
							if strings.Index(i.Path, mountPoint) == 0 {
								return fail.InvalidRequestError(fmt.Sprintf("cannot attach volume '%s' to '%s:%s': there is already a volume mounted in '%s:%s'", volumeName, targetName, mountPoint, targetName, i.Path))
							}
						}
					}
					for _, i := range hostMountsV1.RemoteMountsByPath {
						if task.Aborted() {
							return fail.AbortedError(nil, "aborted")
						}

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

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// -- Get list of disks before attachment --
	// Note: some providers are not able to tell the real device name the volume
	//       will have on the host, so we have to use a way that can work everywhere
	oldDiskSet, xerr := listAttachedDevices(ctx, host)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// -- creates volume attachment --
	vaID, xerr = svc.CreateVolumeAttachment(abstract.VolumeAttachmentRequest{
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
			if derr := svc.DeleteVolumeAttachment(targetID, vaID); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to detach Volume '%s' from Host '%s'", ActionFromError(ferr), volumeName, targetName))
			}
		}
	}()

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// -- acknowledge the volume is really attached to host --
	var newDisk mapset.Set
	retryErr := retry.WhileUnsuccessful(
		func() error {
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

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// -- updates target properties --
	xerr = host.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		innerXErr := props.Alter(hostproperty.VolumesV1, func(clonable data.Clonable) (ferr fail.Error) {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// Recovers real device name from the system
			deviceName = "/dev/" + newDisk.ToSlice()[0].(string)

			// Create mount point
			sshConfig, deeperXErr := host.GetSSHConfig()
			if deeperXErr != nil {
				return deeperXErr
			}

			if task.Aborted() {
				return fail.AbortedError(nil, "aborted")
			}

			nfsServer, deeperXErr = nfs.NewServer(svc, sshConfig)
			if deeperXErr != nil {
				return deeperXErr
			}

			if task.Aborted() {
				return fail.AbortedError(nil, "aborted")
			}

			if !doNotMount {
				volumeUUID, deeperXErr = nfsServer.MountBlockDevice(ctx, deviceName, mountPoint, format, doNotFormat)
				if deeperXErr != nil {
					return deeperXErr
				}

				defer func() {
					if ferr != nil {
						// Disable abort signal during the cleanup
						defer task.DisarmAbortSignal()()

						if derr := nfsServer.UnmountBlockDevice(ctx, volumeUUID); derr != nil {
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
				// Disable abort signal during the cleanup
				defer task.DisarmAbortSignal()()

				if !doNotMount {
					if derr := nfsServer.UnmountBlockDevice(ctx, volumeUUID); derr != nil {
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
				if derr := nfsServer.UnmountBlockDevice(context.Background(), volumeUUID); derr != nil {
					_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unmount Volume '%s' from Host '%s'", ActionFromError(ferr), volumeName, targetName))
				}
			}
			derr := host.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
					logrus.Warnf("Failed to set host '%s' metadata about volumes", volumeName)
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

	// last chance to abort ...
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	defer task.DisarmAbortSignal()()

	// Updates volume properties
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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

	logrus.Infof("Volume '%s' successfully attached to host '%s' as device '%s'", volumeName, targetName, volumeUUID)
	return nil
}

func listAttachedDevices(ctx context.Context, host resources.Host) (_ mapset.Set, ferr fail.Error) {
	var (
		retcode        int
		stdout, stderr string
	)

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return nil, xerr
			}
		default:
			return nil, xerr
		}
	}

	svc := host.Service()

	timings, xerr := svc.Timings()
	if xerr != nil {
		return nil, xerr
	}

	hostName := host.GetName()
	cmd := "sudo lsblk -l -o NAME,TYPE | grep disk | cut -d' ' -f1"
	retryErr := retry.WhileUnsuccessful(
		func() error {
			if task.Aborted() {
				return retry.StopRetryError(fmt.Errorf("aborted"))
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

// Detach detach the volume identified by ref, ref can be the name or the id
func (instance *volume) Detach(ctx context.Context, host resources.Host) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if host == nil {
		return fail.InvalidParameterCannotBeNilError("host")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return xerr
			}
		default:
			return xerr
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	targetID := host.GetID()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.volume"), "('%s')", targetID).Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	var (
		volumeID, volumeName string
		mountPath            string
	)

	// -- retrieves volume data --
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
	targetName := host.GetName()

	// -- Update target attachments --
	return host.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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

		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
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
					if task.Aborted() {
						return fail.AbortedError(nil, "aborted")
					}

					if i.Device == device {
						continue
					}
					if strings.Index(p+"/", mount.Path+"/") == 0 {
						return fail.InvalidRequestError("cannot detach volume '%s' from '%s:%s', there is a volume mounted in '%s:%s'", volumeName, targetName, mount.Path, targetName, p)
					}
				}
				for p := range hostMountsV1.RemoteMountsByPath {
					if task.Aborted() {
						return fail.AbortedError(nil, "aborted")
					}

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

		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		// Check if volume (or a subdir in volume) is shared
		if !notMounted {
			innerXErr = props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
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

			// -- Unmount the Block Device ...
			sshConfig, innerXErr := host.GetSSHConfig()
			if innerXErr != nil {
				return innerXErr
			}

			if task.Aborted() {
				return fail.AbortedError(nil, "aborted")
			}

			// Create NFS Server instance
			nfsServer, innerXErr := nfs.NewServer(svc, sshConfig)
			if innerXErr != nil {
				return innerXErr
			}

			// Last chance to abort...
			if task.Aborted() {
				return fail.AbortedError(nil, "aborted")
			}

			defer task.DisarmAbortSignal()()

			// Unmount block device ...
			if innerXErr = nfsServer.UnmountBlockDevice(ctx, attachment.Device); innerXErr != nil {
				return innerXErr
			}
		}

		// ... then detach volume ...
		if innerXErr = svc.DeleteVolumeAttachment(targetID, attachment.AttachID); innerXErr != nil {
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
		return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
func (instance *volume) ToProtocol() (*protocol.VolumeInspectResponse, fail.Error) {
	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	volumeID := instance.GetID()
	volumeName := instance.GetName()
	out := &protocol.VolumeInspectResponse{
		Id:          volumeID,
		Name:        volumeName,
		Speed:       converters.VolumeSpeedFromAbstractToProtocol(func() volumespeed.Enum { out, _ := instance.unsafeGetSpeed(); return out }()),
		Size:        func() int32 { out, _ := instance.unsafeGetSize(); return int32(out) }(),
		Attachments: []*protocol.VolumeAttachmentResponse{},
	}

	attachments, xerr := instance.GetAttachments()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	svc := instance.Service()
	for k := range attachments.Hosts {
		hostInstance, xerr := LoadHost(svc, k)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		//goland:noinspection ALL
		defer func(item resources.Host) {
			item.Released()
		}(hostInstance)

		vols, _ := hostInstance.(*Host).unsafeGetVolumes()
		device, ok := vols.DevicesByID[volumeID]
		if !ok {
			return nil, fail.InconsistentError("failed to find a device corresponding to the attached volume '%s' on host '%s'", volumeName, k)
		}

		mnts, _ := hostInstance.(*Host).unsafeGetMounts()
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
