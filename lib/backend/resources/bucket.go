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
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/eko/gocache/v2/store"
	"github.com/sirupsen/logrus"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/bucketproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/system/bucketfs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	bucketKind = "bucket"
	// bucketsFolderName is the name of the object storage folder used to store buckets info
	bucketsFolderName = "buckets"
)

// Bucket describes a Bucket and satisfies interface resources.Bucket
type Bucket struct {
	*metadata.Core[*abstract.Bucket]

	lock sync.RWMutex
}

// NewBucket instantiates Bucket struct
func NewBucket(ctx context.Context) (*Bucket, fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	emptyBucketInstance, _ := abstract.NewBucket()
	coreInstance, xerr := metadata.NewCore(ctx, metadata.MethodObjectStorage, bucketKind, bucketsFolderName, emptyBucketInstance)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &Bucket{
		Core: coreInstance,
	}
	return instance, nil
}

// LoadBucket instantiates a Bucket struct and fill it with Provider metadata of Object Storage Bucket
func LoadBucket(inctx context.Context, name string) (*Bucket, fail.Error) {
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	myjob, xerr := jobapi.FromContext(inctx)
	if xerr != nil {
		return nil, xerr
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *Bucket
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gb, gerr := func() (_ *Bucket, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// trick to avoid collisions
			var kt *Bucket
			refcache := fmt.Sprintf("%T/%s", kt, name)

			cache, xerr := myjob.Service().Cache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			var (
				bucketInstance *Bucket
				err            error
				inCache        bool
			)
			if cache != nil {
				entry, err := cache.Get(ctx, refcache)
				if err == nil {
					bucketInstance, err = lang.Cast[*Bucket](entry)
					if err != nil {
						return nil, fail.Wrap(err)
					}

					inCache = true

					// -- reload from metadata storage
					xerr := bucketInstance.Core.Reload(ctx)
					if xerr != nil {
						return nil, xerr
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}
			if bucketInstance == nil {
				anon, xerr := onBucketCacheMiss(ctx, name)
				if xerr != nil {
					return nil, xerr
				}

				bucketInstance, err = lang.Cast[*Bucket](anon)
				if err != nil {
					return nil, fail.Wrap(err)
				}
			}

			if cache != nil && !inCache {
				// -- add host instance in cache by name
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, bucketInstance.GetName()), bucketInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.Wrap(err)
				}

				time.Sleep(10 * time.Millisecond) // consolidate cache.Set
				hid, err := bucketInstance.GetID()
				if err != nil {
					return nil, fail.Wrap(err)
				}

				// -- add host instance in cache by id
				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), bucketInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.Wrap(err)
				}

				time.Sleep(10 * time.Millisecond) // consolidate cache.Set

				entry, xerr := cache.Get(ctx, refcache)
				if xerr == nil {
					_, err := lang.Cast[*Network](entry)
					if err != nil {
						logrus.WithContext(ctx).Warnf("wrong type of *Bucket")
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}

			if myjob.Service().Capabilities().UseTerraformer {
				bucketTrx, xerr := newBucketTransaction(ctx, bucketInstance)
				if xerr != nil {
					return nil, xerr
				}
				defer bucketTrx.TerminateFromError(ctx, &ferr)

				xerr = reviewBucketMetadataAbstract(ctx, bucketTrx, func(ab *abstract.Bucket) fail.Error {
					_, innerXErr := myjob.Scope().RegisterAbstractIfNeeded(ab)
					return innerXErr
				})
				if xerr != nil {
					return nil, xerr
				}
			}

			return bucketInstance, nil
		}()
		chRes <- result{gb, gerr}
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

func onBucketCacheMiss(ctx context.Context, ref string) (data.Identifiable, fail.Error) {
	bucketInstance, xerr := NewBucket(ctx)
	if xerr != nil {
		return nil, xerr
	}

	blank, xerr := NewBucket(ctx)
	if xerr != nil {
		return nil, xerr
	}

	xerr = bucketInstance.Read(ctx, ref)
	if xerr != nil {
		return nil, xerr
	}

	if strings.Compare(fail.IgnoreError(bucketInstance.String()).(string), fail.IgnoreError(blank.String()).(string)) == 0 {
		return nil, fail.NotFoundError("Bucket with ref '%s' does NOT exist", ref)
	}

	return bucketInstance, nil
}

// IsNull tells if the instance corresponds to null value
func (instance *Bucket) IsNull() bool {
	return instance == nil || valid.IsNil(instance.Core)
}

func (instance *Bucket) Clone() (clonable.Clonable, error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}

	newInstance := &Bucket{}
	return newInstance, newInstance.Replace(instance)
}

func (instance *Bucket) Replace(in clonable.Clonable) error {
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*Bucket](in)
	if err != nil {
		return err
	}

	instance.Core, err = clonable.CastedClone[*metadata.Core[*abstract.Bucket]](src.Core)
	return err
}

// Exists checks if the resource actually exists in provider side (not in stow metadata)
func (instance *Bucket) Exists(ctx context.Context) (bool, fail.Error) {
	theID, err := instance.GetID()
	if err != nil {
		return false, fail.Wrap(err)
	}

	_, xerr := instance.Service().InspectBucket(ctx, theID)
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

// Carry ...
func (instance *Bucket) Carry(ctx context.Context, ab *abstract.Bucket) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) && instance.IsTaken() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}
	if ab == nil {
		return fail.InvalidParameterCannotBeNilError("ab")
	}

	// Note: do not validate parameters, this call will do it
	xerr := instance.Core.Carry(ctx, ab)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Browse walks through Bucket metadata folder and executes a callback for each entry
func (instance *Bucket) Browse(ctx context.Context, callback func(storageBucket *abstract.Bucket) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// Note: Do not test with Isnull here, as Browse may be used from null value
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.Bucket")).WithStopwatch().Entering()
	defer tracer.Exiting()

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	xerr := instance.BrowseFolder(ctx, func(buf []byte) (innerXErr fail.Error) {
		ab, _ := abstract.NewBucket()
		inErr := ab.Deserialize(buf)
		if inErr != nil {
			return inErr
		}

		return callback(ab)
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// GetHost ...
func (instance *Bucket) GetHost(ctx context.Context) (_ string, ferr fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return "", fail.InvalidParameterCannotBeNilError("ctx")
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	bucketTrx, xerr := newBucketTransaction(ctx, instance)
	if xerr != nil {
		return "", xerr
	}
	defer bucketTrx.TerminateFromError(ctx, &ferr)

	var res string
	xerr = inspectBucketMetadataAbstract(ctx, bucketTrx, func(ab *abstract.Bucket) fail.Error {
		res = ab.Host
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return res, xerr
	}

	return res, nil
}

// GetMountPoint ...
func (instance *Bucket) GetMountPoint(ctx context.Context) (_ string, ferr fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return "", fail.InvalidParameterCannotBeNilError("ctx")
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	bucketTrx, xerr := newBucketTransaction(ctx, instance)
	if xerr != nil {
		return "", xerr
	}
	defer bucketTrx.TerminateFromError(ctx, &ferr)

	var res string
	xerr = inspectBucketMetadataAbstract(ctx, bucketTrx, func(ab *abstract.Bucket) fail.Error {
		res = ab.MountPoint
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}

	return res, nil
}

// Create a Bucket
func (instance *Bucket) Create(ctx context.Context, name string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance.Core) && instance.IsTaken() {
		return fail.InconsistentError("already carrying information")
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if name == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	tracer := debug.NewTracer(ctx, true, "('"+name+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage(""))

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	// -- check if Bucket already exist in SafeScale
	bucketInstance, xerr := LoadBucket(ctx, name)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// no Bucket with this name managed by SafeScale, continue
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}
	if bucketInstance != nil {
		return abstract.ResourceDuplicateError("Bucket", name)
	}

	// -- check if Bucket already exist on provider side
	ab, xerr := instance.Service().InspectBucket(ctx, name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreError(xerr)
		default:
			if strings.Contains(xerr.Error(), objectstorage.NotFound) {
				debug.IgnoreError(xerr)
				break
			}
			return xerr
		}
	}
	if !valid.IsNil(&ab) {
		return abstract.ResourceDuplicateError("Bucket", name)
	}

	// -- create Bucket
	ab, xerr = instance.Service().CreateBucket(ctx, name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// -- write metadata
	xerr = instance.Carry(ctx, ab)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Delete a Bucket
func (instance *Bucket) Delete(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, true, "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage(""))

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	bun := instance.GetName()

	bucketTrx, xerr := metadata.NewTransaction[*abstract.Bucket, *Bucket](ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer bucketTrx.TerminateFromError(ctx, &ferr)

	// -- check Bucket is not still mounted
	xerr = inspectBucketMetadataProperty(ctx, bucketTrx, bucketproperty.MountsV1, func(mountsV1 *propertiesv1.BucketMounts) fail.Error {
		if len(mountsV1.ByHostID) > 0 {
			return fail.NotAvailableError("still mounted on some Hosts")
		}

		return nil
	})
	if xerr != nil {
		return xerr
	}

	// -- delete Bucket
	xerr = instance.Service().DeleteBucket(ctx, bun)
	if xerr != nil {
		if strings.Contains(xerr.Error(), objectstorage.NotFound) {
			return fail.NotFoundError("failed to find Bucket '%s'", bun)
		}
		return xerr
	}

	// Need to explicitly terminate bucket transaction to be able to delete metadata (dead-lock otherwise)
	bucketTrx.SilentTerminate(ctx)
	return instance.Core.Delete(ctx)
}

// Mount a Bucket on a host on the given mount point
// Returns:
// - nil: mount successful
// - *fail.ErrNotFound: Host not found
// - *fail.ErrDuplicate: already mounted on Host
// - *fail.ErrNotAvailable: already mounted
func (instance *Bucket) Mount(ctx context.Context, hostName, path string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostName")
	}
	if path == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("path")
	}

	tracer := debug.NewTracer(ctx, true, "('%s', '%s')", hostName, path).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage(""))

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	bun := instance.GetName()

	svc := instance.Service()
	hostInstance, xerr := LoadHost(ctx, hostName)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to mount Bucket '%s' on Host '%s'", bun, hostName)
	}

	hostID, err := hostInstance.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	bucketTrx, xerr := newBucketTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer bucketTrx.TerminateFromError(ctx, &ferr)

	// -- check if Bucket is already mounted on any Host (only one Mount by Bucket allowed by design, to mitigate sync issues induced by Object Storage)
	xerr = reviewBucketMetadataProperty(ctx, bucketTrx, bucketproperty.MountsV1, func(mountsV1 *propertiesv1.BucketMounts) fail.Error {
		// First check if mounted on Host...
		if mountPath, ok := mountsV1.ByHostName[hostName]; ok {
			return fail.DuplicateError("there is already a mount of Bucket '%s' on Host '%s' in folder '%s'", bun, hostName, mountPath)
		}

		// Second check if already mounted on another Host...
		if len(mountsV1.ByHostName) > 0 {
			for hostName := range mountsV1.ByHostName {
				return fail.NotAvailableError("already mounted on Host '%s'", hostName)
			}
		}

		return nil
	})
	if xerr != nil {
		return xerr
	}

	authOpts, xerr := svc.AuthenticationOptions()
	if xerr != nil {
		return xerr
	}

	bucketFSClient, xerr := bucketfs.NewClient(hostInstance)
	if xerr != nil {
		return xerr
	}

	// -- assemble parameters for mount description
	osConfig, xerr := svc.ObjectStorageConfiguration(ctx)
	if xerr != nil {
		return xerr
	}

	mountPoint := path
	if path == abstract.DefaultBucketMountPoint {
		mountPoint = abstract.DefaultBucketMountPoint + bun
	}

	fsProtocol, err := svc.Protocol()
	if err != nil {
		return fail.Wrap(err)
	}

	desc := bucketfs.Description{
		AuthURL:    osConfig.AuthURL,
		Endpoint:   osConfig.Endpoint,
		BucketName: bun,
		Protocol:   fsProtocol,
		MountPoint: mountPoint,
		Username:   osConfig.User,
		Password:   osConfig.SecretKey,
		Region:     osConfig.Region,
	}

	// needed value for Description.ProjectName may come from various config entries depending on the Cloud Provider
	desc.ProjectName = authOpts.ProjectName
	if desc.ProjectName == "" {
		desc.ProjectName = authOpts.ProjectID
		if desc.ProjectName == "" {
			desc.ProjectName = authOpts.TenantName
		}
	}

	// -- execute the mount
	xerr = bucketFSClient.Mount(ctx, desc)
	if xerr != nil {
		return xerr
	}

	defer func() {
		if ferr != nil {
			derr := bucketFSClient.Unmount(ctx, desc)
			if derr != nil {
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

	// -- update metadata of Bucket
	xerr = alterBucketMetadataProperty(ctx, bucketTrx, bucketproperty.MountsV1, func(p clonable.Clonable) fail.Error {
		mountsV1, innerErr := clonable.Cast[*propertiesv1.BucketMounts](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		mountsV1.ByHostID[hostID] = mountPoint
		mountsV1.ByHostName[hostName] = mountPoint
		return nil
	})
	if xerr != nil {
		return xerr
	}

	// -- update metadata of Host
	hostTrx, xerr := newHostTransaction(ctx, hostInstance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return alterHostMetadataProperty(ctx, hostTrx, hostproperty.MountsV1, func(mountsV1 *propertiesv1.HostMounts) fail.Error {
		mountsV1.BucketMounts[hostName] = mountPoint
		return nil
	})
}

// Unmount a Bucket
func (instance *Bucket) Unmount(ctx context.Context, hostName string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostName")
	}

	tracer := debug.NewTracer(ctx, true, "('%s')", hostName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage(""))

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	bucketTrx, xerr := newBucketTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer bucketTrx.TerminateFromError(ctx, &ferr)

	hostInstance, xerr := LoadHost(ctx, hostName)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	hostID, err := hostInstance.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	hostTrx, xerr := newHostTransaction(ctx, hostInstance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	var mountPoint string
	bucketName := instance.GetName()

	mounts, xerr := hostInstance.GetMounts(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	for k, v := range mounts.BucketMounts {
		if k == bucketName {
			mountPoint = v
			break
		}
	}
	if mountPoint == "" {
		return fail.NotFoundError("failed to find corresponding mount on Host")
	}

	bucketFSClient, xerr := bucketfs.NewClient(hostInstance)
	if xerr != nil {
		return xerr
	}

	description := bucketfs.Description{
		BucketName: bucketName,
		MountPoint: mountPoint,
	}
	xerr = bucketFSClient.Unmount(ctx, description)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// If mount is not found on remote server, consider unmount as successful
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}

	xerr = alterHostMetadataProperty(ctx, hostTrx, hostproperty.MountsV1, func(mountsV1 *propertiesv1.HostMounts) fail.Error {
		delete(mountsV1.BucketMounts, bucketName)
		return nil
	})
	if xerr != nil {
		return xerr
	}

	xerr = alterBucketMetadataProperty(ctx, bucketTrx, bucketproperty.MountsV1, func(mountsV1 *propertiesv1.BucketMounts) fail.Error {
		delete(mountsV1.ByHostID, hostID)
		delete(mountsV1.ByHostName, hostName)
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// ToProtocol returns the protocol message corresponding to Bucket fields
func (instance *Bucket) ToProtocol(ctx context.Context) (_ *protocol.BucketResponse, ferr fail.Error) {
	bun := instance.GetName()

	out := &protocol.BucketResponse{
		Name: bun,
	}

	bucketTrx, xerr := newBucketTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer bucketTrx.TerminateFromError(ctx, &ferr)

	xerr = reviewBucketMetadataProperty(ctx, bucketTrx, bucketproperty.MountsV1, func(mountsV1 *propertiesv1.BucketMounts) fail.Error {
		out.Mounts = make([]*protocol.BucketMount, 0, len(mountsV1.ByHostID))
		for k, v := range mountsV1.ByHostID {
			hostInstance, innerXErr := LoadHost(ctx, k)
			if innerXErr != nil {
				return innerXErr
			}

			hostName := hostInstance.GetName()
			out.Mounts = append(out.Mounts, &protocol.BucketMount{
				Host: &protocol.Reference{
					Id:   k,
					Name: hostName,
				},
				Path: v,
			})
		}
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	return out, nil
}
