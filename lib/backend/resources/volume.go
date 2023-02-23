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

package resources

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	mapset "github.com/deckarep/golang-set"
	"github.com/eko/gocache/v2/store"
	"github.com/sirupsen/logrus"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/converters"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumeproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	sshfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/ssh"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
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
	volumesFolderName = "volumes" // is the name of the Object Storage MetadataFolder used to store Volume info
)

// Volume links Object Storage MetadataFolder and trxGetVolumes
type Volume struct {
	*metadata.Core[*abstract.Volume]
}

// NewVolume creates an instance of Volume
func NewVolume(ctx context.Context) (_ *Volume, ferr fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	coreInstance, xerr := metadata.NewCore(ctx, metadata.MethodObjectStorage, volumeKind, volumesFolderName, abstract.NewEmptyVolume())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &Volume{
		Core: coreInstance,
	}
	return instance, nil
}

// LoadVolume loads the metadata of a subnet
func LoadVolume(inctx context.Context, ref string) (*Volume, fail.Error) {
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

	svc, xerr := myjob.Service()
	if xerr != nil {
		return nil, xerr
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *Volume
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ *Volume, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// trick to avoid collisions
			var kt *Volume
			refcache := fmt.Sprintf("%T/%s", kt, ref)

			cache, xerr := svc.Cache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			var (
				volumeInstance *Volume
				inCache        bool
				err            error
			)
			if cache != nil {
				entry, err := cache.Get(ctx, refcache)
				if err == nil {
					volumeInstance, err = lang.Cast[*Volume](entry)
					if err != nil {
						return nil, fail.Wrap(err)
					}

					inCache = true

					// -- reload from metadata storage
					xerr := volumeInstance.Core.Reload(ctx)
					if xerr != nil {
						return nil, xerr
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}
			if volumeInstance == nil {
				anon, xerr := onVolumeCacheMiss(ctx, ref)
				if xerr != nil {
					return nil, xerr
				}

				volumeInstance, err = lang.Cast[*Volume](anon)
				if err != nil {
					return nil, fail.Wrap(err)
				}
			}

			if cache != nil && !inCache {
				// -- add host instance in cache by name
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, volumeInstance.GetName()), volumeInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.Wrap(err)
				}

				time.Sleep(10 * time.Millisecond) // consolidate cache.Set
				hid, err := volumeInstance.GetID()
				if err != nil {
					return nil, fail.Wrap(err)
				}

				// -- add host instance in cache by id
				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), volumeInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.Wrap(err)
				}

				time.Sleep(10 * time.Millisecond) // consolidate cache.Set

				val, xerr := cache.Get(ctx, refcache)
				if xerr == nil {
					if _, ok := val.(*Network); !ok {
						logrus.WithContext(ctx).Warnf("wrong type of *Network")
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}

			if svc.Capabilities().UseTerraformer {
				volumeTrx, xerr := newVolumeTransaction(ctx, volumeInstance)
				if xerr != nil {
					return nil, xerr
				}
				defer volumeTrx.TerminateFromError(ctx, &ferr)

				xerr = inspectVolumeMetadataAbstract(ctx, volumeTrx, func(av *abstract.Volume) fail.Error {
					prov, xerr := svc.ProviderDriver()
					if xerr != nil {
						return xerr
					}
					castedProv, innerErr := lang.Cast[providers.ReservedForTerraformerUse](prov)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					innerXErr := castedProv.ConsolidateVolumeSnippet(av)
					if innerXErr != nil {
						return innerXErr
					}

					// _, innerXErr = myjob.Scope().RegisterAbstractIfNeeded(av)
					// return innerXErr
					return nil
				})
				if xerr != nil {
					return nil, xerr
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
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
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

	if strings.Compare(fail.IgnoreError(volumeInstance.String()).(string), fail.IgnoreError(blank.String()).(string)) == 0 {
		return nil, fail.NotFoundError("failed to find Volume with ref '%s'", ref)
	}

	return volumeInstance, nil
}

// IsNull tells if the instance is a null value
func (instance *Volume) IsNull() bool {
	return instance == nil || valid.IsNil(instance.Core)
}

func (instance *Volume) Clone() (clonable.Clonable, error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}

	newInstance, err := newBulkVolume()
	if err != nil {
		return nil, err
	}

	return newInstance, newInstance.Replace(instance)
}

// newBulkVolume ...
func newBulkVolume() (*Volume, fail.Error) {
	protected, err := abstract.NewVolume()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	core, err := metadata.NewEmptyCore(abstract.VolumeKind, protected)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	instance := &Volume{Core: core}
	return instance, nil
}

func (instance *Volume) Replace(in clonable.Clonable) error {
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*Volume](in)
	if err != nil {
		return err
	}

	return instance.Core.Replace(src.Core)
}

// Exists checks if the resource actually exists in provider side (not in stow metadata)
func (instance *Volume) Exists(ctx context.Context) (bool, fail.Error) {
	theID, err := instance.GetID()
	if err != nil {
		return false, fail.Wrap(err)
	}

	svc, xerr := instance.Service()
	if xerr != nil {
		return false, xerr
	}

	_, xerr = svc.InspectVolume(ctx, theID)
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

// // Carry overloads rv.core.Carry() to add Volume to service cache
// func (instance *Volume) Carry(ctx context.Context, av *abstract.Volume) (ferr fail.Error) {
// 	if instance == nil {
// 		return fail.InvalidInstanceError()
// 	}
// 	if !valid.IsNil(instance) && instance.Core.IsTaken() {
// 		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
// 	}
// 	if av == nil {
// 		return fail.InvalidParameterCannotBeNilError("av")
// 	}
//
// 	// Note: do not validate parameters, this call will do it
// 	xerr := instance.Core.Carry(ctx, av)
// 	xerr = debug.InjectPlannedFail(xerr)
// 	if xerr != nil {
// 		return xerr
// 	}
//
// 	return nil
// }

// GetSpeed ...
func (instance *Volume) GetSpeed(ctx context.Context) (_ volumespeed.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	volumeTrx, xerr := newVolumeTransaction(ctx, instance)
	if xerr != nil {
		return 0, xerr
	}
	defer volumeTrx.TerminateFromError(ctx, &ferr)

	return volumeTrx.GetSpeed(ctx)
}

// GetSize ...
func (instance *Volume) GetSize(ctx context.Context) (_ int, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	volumeTrx, xerr := newVolumeTransaction(ctx, instance)
	if xerr != nil {
		return 0, xerr
	}
	defer volumeTrx.TerminateFromError(ctx, &ferr)

	return volumeTrx.GetSize(ctx)
}

// GetAttachments returns where the Volume is attached
func (instance *Volume) GetAttachments(ctx context.Context) (_ *propertiesv1.VolumeAttachments, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	volumeTrx, xerr := newVolumeTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer volumeTrx.TerminateFromError(ctx, &ferr)

	var volatts *propertiesv1.VolumeAttachments
	xerr = inspectVolumeMetadataProperty(ctx, volumeTrx, volumeproperty.AttachedV1, func(vaV1 *propertiesv1.VolumeAttachments) fail.Error {
		volatts = vaV1
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return volatts, nil
}

// Browse walks through Volume MetadataFolder and executes a callback for each entry
func (instance *Volume) Browse(ctx context.Context, callback func(*abstract.Volume) fail.Error) (ferr fail.Error) {
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

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.Volume")).Entering()
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
func (instance *Volume) Delete(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.Volume")).Entering()
	defer tracer.Exiting()

	volumeTrx, xerr := newVolumeTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer volumeTrx.TerminateFromError(ctx, &ferr)

	// check if Volume can be deleted (must not be attached)
	xerr = inspectVolumeMetadataProperty(ctx, volumeTrx, volumeproperty.AttachedV1, func(vaV1 *propertiesv1.VolumeAttachments) fail.Error {
		nbAttach := uint(len(vaV1.Hosts))
		if nbAttach > 0 {
			list := make([]string, 0, len(vaV1.Hosts))
			for _, v := range vaV1.Hosts {
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

	svc, xerr := instance.Service()
	if xerr != nil {
		return xerr
	}

	// Delete Volume
	xerr = inspectVolumeMetadataAbstract(ctx, volumeTrx, func(av *abstract.Volume) fail.Error {
		return svc.DeleteVolume(ctx, av)
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			xerr = fail.Wrap(fail.Cause(xerr))
			switch xerr.(type) {
			case *fail.ErrNotFound:
				logrus.WithContext(ctx).Debugf("Unable to find the Volume on provider side, cleaning up metadata")
			default:
				return xerr
			}
		case *fail.ErrNotFound:
			logrus.WithContext(ctx).Debugf("Unable to find the Volume on provider side, cleaning up metadata")
		default:
			return xerr
		}
	}

	// remove metadata
	volumeTrx.SilentTerminate(ctx)
	return instance.Core.Delete(ctx)
}

// Create a Volume
func (instance *Volume) Create(ctx context.Context, req abstract.VolumeRequest) (ferr fail.Error) {
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

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.Volume"), "('%s', %f, %s)", req.Name, req.Size, req.Speed.String()).Entering()
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
	svc, xerr := instance.Service()
	if xerr != nil {
		return xerr
	}

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

	// Starting from here, remove Volume if exiting with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := svc.DeleteVolume(cleanupContextFrom(ctx), av.ID); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete Volume '%s'", ActionFromError(ferr), req.Name))
			}
		}
	}()

	return instance.Carry(ctx, av)
}

// Carry registers 'as' as Core value of Subnet and register abstract in scope
func (instance *Volume) Carry(ctx context.Context, av *abstract.Volume) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if instance.Core.IsTaken() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}
	if av == nil {
		return fail.InvalidParameterCannotBeNilError("ac")
	}

	// Note: do not validate parameters, this call will do it
	xerr := instance.Core.Carry(ctx, av)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = instance.Job().Scope().RegisterAbstract(av)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Attach a Volume to a host
func (instance *Volume) Attach(ctx context.Context, host *Host, path, format string, doNotFormat, doNotMount bool) (ferr fail.Error) {
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

	svc, xerr := instance.Service()
	if xerr != nil {
		return xerr
	}

	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.Volume"), "('%s', %s, %s, %v)", host.GetName(), path, format, doNotFormat).Entering()
	defer tracer.Exiting()

	var (
		volumeID, volumeName, deviceName, volumeUUID, mountPoint, vaID string
		nfsServer                                                      *nfs.Server
	)

	targetID, err := host.GetID()
	if err != nil {
		return fail.Wrap(err)
	}
	targetName := host.GetName()

	volumeTrx, xerr := newVolumeTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer volumeTrx.TerminateFromError(ctx, &ferr)

	hostTrx, xerr := newHostTransaction(ctx, host)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	// -- proceed some checks on Volume --
	xerr = inspectVolumeMetadata(ctx, volumeTrx, func(av *abstract.Volume, props *serialize.JSONProperties) fail.Error {
		volumeID = av.ID
		volumeName = av.Name

		return props.Inspect(volumeproperty.AttachedV1, func(p clonable.Clonable) fail.Error {
			volumeAttachedV1, innerErr := lang.Cast[*propertiesv1.VolumeAttachments](p)
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
						return fail.NotAvailableError("Volume '%s' is already attached", volumeName)
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
		return fail.InvalidRequestError(fmt.Sprintf("cannot attach Volume '%s' to '%s:%s': host '%s' is NOT started", volumeName, targetName, mountPoint, targetName))
	}

	// -- proceed some checks on target server --
	xerr = inspectHostMetadataProperties(ctx, hostTrx, func(props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.VolumesV1, func(p clonable.Clonable) fail.Error {
			hostVolumesV1, innerErr := lang.Cast[*propertiesv1.HostVolumes](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			return props.Inspect(hostproperty.MountsV1, func(p clonable.Clonable) fail.Error {
				hostMountsV1, innerErr := lang.Cast[*propertiesv1.HostMounts](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				// Check if the Volume is already mounted elsewhere
				if device, found := hostVolumesV1.DevicesByID[volumeID]; found {
					mount, ok := hostMountsV1.LocalMountsByPath[hostMountsV1.LocalMountsByDevice[device]]
					if !ok {
						return fail.InconsistentError("metadata inconsistency for Volume '%s' attached to host '%s'", volumeName, targetName)
					}

					path := mount.Path
					if mountPoint != "" {
						if path != mountPoint {
							return fail.InvalidRequestError("Volume '%s' is already attached in '%s:%s'", volumeName, targetName, path)
						}
					}
					return nil
				}

				if !doNotMount {
					// Check if there is no other device mounted in the path (or in subpath)
					for _, i := range hostMountsV1.LocalMountsByPath {
						if mountPoint != "" {
							if strings.Index(i.Path, mountPoint) == 0 {
								return fail.InvalidRequestError(fmt.Sprintf("cannot attach Volume '%s' to '%s:%s': there is already a Volume mounted in '%s:%s'", volumeName, targetName, mountPoint, targetName, i.Path))
							}
						}
					}
					for _, i := range hostMountsV1.RemoteMountsByPath {
						if mountPoint != "" {
							if strings.Index(i.Path, mountPoint) == 0 {
								return fail.InvalidRequestError(fmt.Sprintf("can't attach Volume '%s' to '%s:%s': there is a share mounted in path '%s:%s[/...]'", volumeName, targetName, mountPoint, targetName, i.Path))
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
	// Note: some providers are not able to tell the real device name the Volume
	//       will have on the host, so we have to use a way that can work everywhere
	oldDiskSet, xerr := listAttachedDevices(ctx, host)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// -- creates Volume attachment --
	vaID, xerr = svc.CreateVolumeAttachment(ctx, abstract.VolumeAttachmentRequest{
		Name:     fmt.Sprintf("%s-%s", volumeName, targetName),
		HostID:   targetID,
		VolumeID: volumeID,
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Starting from here, remove Volume attachment if exiting with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := svc.DeleteVolumeAttachment(cleanupContextFrom(ctx), targetID, vaID)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to detach Volume '%s' from Host '%s'", ActionFromError(ferr), volumeName, targetName))
			}
		}
	}()

	// -- acknowledge the Volume is really attached to host --
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
	xerr = alterHostMetadataProperties(ctx, hostTrx, func(props *serialize.JSONProperties) fail.Error {
		innerXErr := props.Alter(hostproperty.VolumesV1, func(p clonable.Clonable) (ferr fail.Error) {
			hostVolumesV1, innerErr := lang.Cast[*propertiesv1.HostVolumes](p)
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
							_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unmount Volume '%s' from host '%s'", ActionFromError(ferr), volumeName, targetName))
						}
					}
				}()
			}

			// Saves Volume information in property
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
				derr := nfsServer.UnmountBlockDevice(cleanupContextFrom(ctx), volumeUUID)
				if derr != nil {
					_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unmount Volume '%s' from host '%s'", ActionFromError(innerXErr), volumeName, targetName))
				}
			}
		}()

		return props.Alter(hostproperty.MountsV1, func(p clonable.Clonable) fail.Error {
			hostMountsV1, innerErr := lang.Cast[*propertiesv1.HostMounts](p)
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
			// VPL: rollback() on transaction will do the same job
			// derr := host.Alter(cleanupContextFrom(ctx), func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
			// 	innerXErr := props.Alter(hostproperty.VolumesV1, func(p clonable.Clonable) fail.Error {
			// 		hostVolumesV1, innerErr := lang.Cast[*propertiesv1.HostVolumes](p)
			// 		if innerErr != nil {
			// 			return fail.Wrap(innerErr)
			// 		}
			//
			// 		Delete(hostVolumesV1.VolumesByID, volumeID)
			// 		Delete(hostVolumesV1.VolumesByName, volumeName)
			// 		Delete(hostVolumesV1.VolumesByDevice, volumeUUID)
			// 		Delete(hostVolumesV1.DevicesByID, volumeID)
			// 		return nil
			// 	})
			// 	if innerXErr != nil {
			// 		logrus.WithContext(cleanupContextFrom(ctx)).Warnf("Failed to set host '%s' metadata about volumes", volumeName)
			// 	}
			// 	return props.Alter(hostproperty.MountsV1, func(p clonable.Clonable) fail.Error {
			// 		hostMountsV1, innerErr := lang.Cast[*propertiesv1.HostMounts](p)
			// 		if innerErr != nil {
			// 			return fail.Wrap(innerErr)
			// 		}
			//
			// 		Delete(hostMountsV1.LocalMountsByDevice, volumeUUID)
			// 		Delete(hostMountsV1.LocalMountsByPath, mountPoint)
			// 		return nil
			// 	})
			// })
			// if derr != nil {
			// 	_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to update metadata of host '%s'", ActionFromError(ferr), targetName))
			// }
		}
	}()

	// Updates Volume properties
	xerr = alterVolumeMetadataProperty(ctx, volumeTrx, volumeproperty.AttachedV1, func(volumeAttachedV1 *propertiesv1.VolumeAttachments) fail.Error {
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

func listAttachedDevices(ctx context.Context, host *Host) (_ mapset.Set, ferr fail.Error) {
	var (
		retcode        int
		stdout, stderr string
	)

	svc, xerr := host.Service()
	if xerr != nil {
		return nil, xerr
	}

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

// Detach detaches the Volume identified by ref, ref can be the name or the id
func (instance *Volume) Detach(ctx context.Context, host *Host) (ferr fail.Error) {
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
	castedHost, err := lang.Cast[*Host](host)
	if err != nil {
		return fail.Wrap(err)
	}

	targetID, err := host.GetID()
	if err != nil {
		return fail.Wrap(err)
	}
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.Volume"), "('%s')", targetID).Entering()
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
		return fail.InvalidRequestError(fmt.Sprintf("cannot detach Volume '%s' from '%s', '%s' is NOT started", volumeName, targetName, targetName))
	}

	volumeTrx, xerr := newVolumeTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer volumeTrx.TerminateFromError(ctx, &ferr)

	hostTrx, xerr := newHostTransaction(ctx, castedHost)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	// -- retrieves Volume data --
	xerr = inspectVolumeMetadataAbstract(ctx, volumeTrx, func(av *abstract.Volume) fail.Error {
		volumeID = av.ID
		volumeName = av.Name
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// -- retrieve host data --
	svc, xerr := instance.Service()
	if xerr != nil {
		return xerr
	}

	// -- Update target attachments --
	return alterHostMetadataProperties(ctx, hostTrx, func(props *serialize.JSONProperties) fail.Error {
		var (
			attachment *propertiesv1.HostVolume
			mount      *propertiesv1.HostLocalMount
		)

		innerXErr := props.Inspect(hostproperty.VolumesV1, func(p clonable.Clonable) fail.Error {
			hostVolumesV1, innerErr := lang.Cast[*propertiesv1.HostVolumes](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			// Check the Volume is effectively attached
			var found bool
			attachment, found = hostVolumesV1.VolumesByID[volumeID]
			if !found {
				return fail.NotFoundError("cannot detach Volume '%s': not attached to host '%s'", volumeName, targetName)
			}

			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Obtain mounts information
		notMounted := false
		innerXErr = props.Inspect(hostproperty.MountsV1, func(p clonable.Clonable) fail.Error {
			hostMountsV1, innerErr := lang.Cast[*propertiesv1.HostMounts](p)
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
					return fail.InconsistentError("metadata inconsistency: no mount corresponding to Volume attachment")
				}

				// Check if Volume has other mount(s) inside it
				for p, i := range hostMountsV1.LocalMountsByPath {
					if i.Device == device {
						continue
					}
					if strings.Index(p+"/", mount.Path+"/") == 0 {
						return fail.InvalidRequestError("cannot detach Volume '%s' from '%s:%s', there is a Volume mounted in '%s:%s'", volumeName, targetName, mount.Path, targetName, p)
					}
				}
				for p := range hostMountsV1.RemoteMountsByPath {
					if strings.Index(p+"/", mount.Path+"/") == 0 {
						return fail.InvalidRequestError("cannot detach Volume '%s' from '%s:%s', there is a share mounted in '%s:%s'", volumeName, targetName, mount.Path, targetName, p)
					}
				}
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Check if Volume (or a subdir in Volume) is shared
		if !notMounted {
			innerXErr = props.Inspect(hostproperty.SharesV1, func(p clonable.Clonable) fail.Error {
				hostSharesV1, innerErr := lang.Cast[*propertiesv1.HostShares](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				for _, v := range hostSharesV1.ByID {
					if strings.Index(v.Path, mount.Path) == 0 {
						return fail.InvalidRequestError("cannot detach Volume '%s' from '%s': mounted in '%s' and shared", volumeName, targetName, mount.Path)
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

		// ... then detach Volume ...
		if innerXErr = svc.DeleteVolumeAttachment(ctx, targetID, attachment.AttachID); innerXErr != nil {
			return innerXErr
		}

		// ... then update host property propertiesv1.VolumesV1...
		innerXErr = props.Alter(hostproperty.VolumesV1, func(p clonable.Clonable) fail.Error {
			hostVolumesV1, innerErr := lang.Cast[*propertiesv1.HostVolumes](p)
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
				hostMountsV1, innerErr := lang.Cast[*propertiesv1.HostMounts](p)
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

		// ... and finish with update of Volume property propertiesv1.VolumeAttachments
		return alterVolumeMetadataProperty(ctx, volumeTrx, volumeproperty.AttachedV1, func(vaV1 *propertiesv1.VolumeAttachments) fail.Error {
			delete(vaV1.Hosts, targetID)
			return nil
		})
	})
}

// ToProtocol converts the Volume to protocol message VolumeInspectResponse
func (instance *Volume) ToProtocol(ctx context.Context) (_ *protocol.VolumeInspectResponse, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	volumeID, err := instance.GetID()
	if err != nil {
		return nil, fail.Wrap(err)
	}
	volumeName := instance.GetName()

	volumeTrx, xerr := newVolumeTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer volumeTrx.TerminateFromError(ctx, &ferr)

	out := &protocol.VolumeInspectResponse{
		Id:          volumeID,
		Name:        volumeName,
		Speed:       converters.VolumeSpeedFromAbstractToProtocol(func() volumespeed.Enum { out, _ := volumeTrx.GetSpeed(ctx); return out }()),
		Size:        func() int32 { out, _ := volumeTrx.GetSize(ctx); return int32(out) }(),
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

		vols, _ := hostInstance.GetVolumes(ctx)
		device, ok := vols.DevicesByID[volumeID]
		if !ok {
			return nil, fail.InconsistentError("failed to find a device corresponding to the attached Volume '%s' on host '%s'", volumeName, k)
		}

		mnts, _ := hostInstance.GetMounts(ctx)
		if mnts != nil {
			path, ok := mnts.LocalMountsByDevice[device]
			if !ok {
				return nil, fail.InconsistentError("failed to find a mount of attached Volume '%s' on host '%s'", volumeName, k)
			}

			m, ok := mnts.LocalMountsByPath[path]
			if !ok {
				return nil, fail.InconsistentError("failed to find a mount of attached Volume '%s' on host '%s'", volumeName, k)
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
