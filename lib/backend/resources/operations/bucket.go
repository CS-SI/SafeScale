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
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/bucketproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/system/bucketfs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"reflect"
	"strings"
	"sync"
)

const (
	bucketKind = "bucket"
	// bucketsFolderName is the name of the object storage MetadataFolder used to store buckets info
	bucketsFolderName = "buckets"
)

// bucket describes a bucket and satisfies interface resources.ObjectStorageBucket
type bucket struct {
	*MetadataCore

	lock sync.RWMutex
}

// NewBucket instantiates bucket struct
func NewBucket(svc iaas.Service) (resources.Bucket, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, xerr := NewCore(svc, bucketKind, bucketsFolderName, &abstract.ObjectStorageBucket{})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &bucket{
		MetadataCore: coreInstance,
	}
	return instance, nil
}

func onBucketCacheMiss(ctx context.Context, svc iaas.Service, ref string) (data.Identifiable, fail.Error) {
	bucketInstance, innerXErr := NewBucket(svc)
	if innerXErr != nil {
		return nil, innerXErr
	}

	blank, innerXErr := NewBucket(svc)
	if innerXErr != nil {
		return nil, innerXErr
	}

	if innerXErr = bucketInstance.Read(ctx, ref); innerXErr != nil {
		return nil, innerXErr
	}

	if strings.Compare(fail.IgnoreError(bucketInstance.Sdump(ctx)).(string), fail.IgnoreError(blank.Sdump(ctx)).(string)) == 0 {
		return nil, fail.NotFoundError("bucket with ref '%s' does NOT exist", ref)
	}

	return bucketInstance, nil
}

// IsNull tells if the instance corresponds to null value
func (instance *bucket) IsNull() bool {
	return instance == nil || instance.MetadataCore == nil || valid.IsNil(instance.MetadataCore)
}

// Exists checks if the resource actually exists in provider side (not in stow metadata)
func (instance *bucket) Exists(ctx context.Context) (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}

	theID, err := instance.GetID()
	if err != nil {
		return false, fail.ConvertError(err)
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

// carry ...
func (instance *bucket) carry(ctx context.Context, clonable data.Clonable) (ferr fail.Error) {
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

// Browse walks through Bucket metadata folder and executes a callback for each entry
func (instance *bucket) Browse(ctx context.Context, callback func(storageBucket *abstract.ObjectStorageBucket) fail.Error) (ferr fail.Error) {
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

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.bucket")).WithStopwatch().Entering()
	defer tracer.Exiting()

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	xerr := instance.MetadataCore.BrowseFolder(ctx, func(buf []byte) (innerXErr fail.Error) {
		ab := abstract.NewObjectStorageBucket()
		var inErr fail.Error
		if inErr = ab.Deserialize(buf); inErr != nil {
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
func (instance *bucket) GetHost(ctx context.Context) (_ string, ferr fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return "", fail.InvalidParameterCannotBeNilError("ctx")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var res string
	xerr := instance.Inspect(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		ab, ok := clonable.(*abstract.ObjectStorageBucket)
		if !ok {
			return fail.InconsistentError("'*abstract.ObjectStorageBucket' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

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
func (instance *bucket) GetMountPoint(ctx context.Context) (string, fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return "", fail.InvalidParameterCannotBeNilError("ctx")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var res string
	xerr := instance.Inspect(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		ab, ok := clonable.(*abstract.ObjectStorageBucket)
		if !ok {
			return fail.InconsistentError("'*abstract.ObjectStorageBucket' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		res = ab.MountPoint
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}
	return res, nil
}

// Create a bucket
func (instance *bucket) Create(ctx context.Context, name string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance.MetadataCore) {
		if instance.MetadataCore.IsTaken() {
			return fail.InconsistentError("already carrying information")
		}
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, true, "('"+name+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage(""))

	instance.lock.Lock()
	defer instance.lock.Unlock()

	svc := instance.Service()

	// -- check if bucket already exist in SafeScale
	bucketInstance, xerr := LoadBucket(ctx, svc, name)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// no bucket with this name managed by SafeScale, continue
			debug.IgnoreError2(ctx, xerr)
		default:
			return xerr
		}
	}
	if bucketInstance != nil {
		return abstract.ResourceDuplicateError("bucket", name)
	}

	// -- check if bucket already exist on provider side
	ab, xerr := svc.InspectBucket(ctx, name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreError2(ctx, xerr)
		default:
			if strings.Contains(xerr.Error(), objectstorage.NotFound) {
				debug.IgnoreError2(ctx, xerr)
				break
			}
			return xerr
		}
	}
	if !valid.IsNil(&ab) {
		return abstract.ResourceDuplicateError("bucket", name)
	}

	// -- create bucket
	ab, xerr = svc.CreateBucket(ctx, name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// -- write metadata
	xerr = instance.carry(ctx, &ab)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Delete a bucket
func (instance *bucket) Delete(ctx context.Context) (ferr fail.Error) {
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

	instance.lock.Lock()
	defer instance.lock.Unlock()

	bun := instance.GetName()

	// -- check Bucket is not still mounted
	xerr := instance.Review(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(bucketproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			mountsV1, ok := clonable.(*propertiesv1.BucketMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.BucketMount' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if len(mountsV1.ByHostID) > 0 {
				return fail.NotAvailableError("still mounted on some Hosts")
			}

			return nil
		})
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

	theID, _ := instance.GetID()

	// -- delete metadata
	xerr = instance.MetadataCore.Delete(ctx)
	xerr = debug.InjectPlannedFail(xerr)
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

// Mount a bucket on a host on the given mount point
// Returns:
// - nil: mount successful
// - *fail.ErrNotFound: Host not found
// - *fail.ErrDuplicate: already mounted on Host
// - *fail.ErrNotAvailable: already mounted
func (instance *bucket) Mount(ctx context.Context, hostName, path string) (ferr fail.Error) {
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

	instance.lock.Lock()
	defer instance.lock.Unlock()

	bun := instance.GetName()

	svc := instance.Service()
	hostInstance, xerr := LoadHost(ctx, svc, hostName)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to mount bucket '%s' on Host '%s'", bun, hostName)
	}

	hostID, err := hostInstance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	// -- check if Bucket is already mounted on any Host (only one Mount by Bucket allowed by design, to mitigate sync issues induced by Object Storage)
	xerr = instance.Review(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(bucketproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			mountsV1, ok := clonable.(*propertiesv1.BucketMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.BucketMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

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
	})
	if xerr != nil {
		return xerr
	}

	authOpts, xerr := svc.GetAuthenticationOptions(ctx)
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
		return fail.ConvertError(err)
	}

	desc := bucketfs.Description{
		BucketName: bun,
		Protocol:   fsProtocol,
		MountPoint: mountPoint,
	}
	if anon, ok := authOpts.Config("AuthURL"); ok {
		if aurl, ok := anon.(string); ok {
			desc.AuthURL = aurl
		}
	}
	desc.Endpoint = osConfig.Endpoint

	// needed value for Description.ProjectName may come from various config entries depending on the Cloud Provider
	if anon, ok := authOpts.Config("ProjectName"); ok {
		desc.ProjectName, ok = anon.(string)
		if !ok {
			return fail.InconsistentError("anon should be a string")
		}
	} else if anon, ok := authOpts.Config("ProjectID"); ok {
		desc.ProjectName, ok = anon.(string)
		if !ok {
			return fail.InconsistentError("anon should be a string")
		}
	} else if anon, ok := authOpts.Config("TenantName"); ok {
		desc.ProjectName, ok = anon.(string)
		if !ok {
			return fail.InconsistentError("anon should be a string")
		}
	}

	desc.Username = osConfig.User
	desc.Password = osConfig.SecretKey
	desc.Region = osConfig.Region

	// -- execute the mount
	xerr = bucketFSClient.Mount(ctx, desc)
	if xerr != nil {
		return xerr
	}

	// -- update metadata of Bucket
	xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(bucketproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			mountsV1, ok := clonable.(*propertiesv1.BucketMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.BucketMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			mountsV1.ByHostID[hostID] = mountPoint
			mountsV1.ByHostName[hostName] = mountPoint
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	// -- update metadata of Host
	return hostInstance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			mountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			mountsV1.BucketMounts[hostName] = mountPoint
			return nil
		})
	})
}

// Unmount a bucket
func (instance *bucket) Unmount(ctx context.Context, hostName string) (ferr fail.Error) {
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

	instance.lock.Lock()
	defer instance.lock.Unlock()

	svc := instance.Service()
	hostInstance, xerr := LoadHost(ctx, svc, hostName)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	hostID, err := hostInstance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

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
			debug.IgnoreError2(ctx, xerr)
		default:
			return xerr
		}
	}

	xerr = hostInstance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			mountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			delete(mountsV1.BucketMounts, bucketName)
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(bucketproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			mountsV1, ok := clonable.(*propertiesv1.BucketMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.BucketMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			delete(mountsV1.ByHostID, hostID)
			delete(mountsV1.ByHostName, hostName)
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// ToProtocol returns the protocol message corresponding to Bucket fields
func (instance *bucket) ToProtocol(ctx context.Context) (*protocol.BucketResponse, fail.Error) {
	bun := instance.GetName()

	out := &protocol.BucketResponse{
		Name: bun,
	}

	xerr := instance.Review(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(bucketproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			mountsV1, ok := clonable.(*propertiesv1.BucketMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.BucketMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			svc := instance.Service()
			out.Mounts = make([]*protocol.BucketMount, 0, len(mountsV1.ByHostID))
			for k, v := range mountsV1.ByHostID {
				hostInstance, xerr := LoadHost(ctx, svc, k)
				if xerr != nil {
					return xerr
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
	})
	if xerr != nil {
		return nil, xerr
	}

	return out, nil
}
