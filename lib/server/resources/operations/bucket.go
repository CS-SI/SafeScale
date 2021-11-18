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

//go:generate rice embed-go

import (
	"bytes"
	"context"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/template"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
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

// NewBucket intanciates bucket struct
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

// LoadBucket instantiates a bucket struct and fill it with Provider metadata of Object Storage ObjectStorageBucket
func LoadBucket(svc iaas.Service, name string) (b resources.Bucket, xerr fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	bucketCache, xerr := svc.GetCache(bucketKind)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	cacheOptions := iaas.CacheMissOption(
		func() (cache.Cacheable, fail.Error) { return onBucketCacheMiss(svc, name) },
		temporal.GetMetadataTimeout(),
	)
	cacheEntry, xerr := bucketCache.Get(name, cacheOptions...)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// rewrite NotFoundError, user does not bother about metadata stuff
			return nil, fail.NotFoundError("failed to find Bucket '%s'", name)
		default:
			return nil, xerr
		}
	}

	if b = cacheEntry.Content().(resources.Bucket); b == nil {
		return nil, fail.InconsistentError("nil value found in Bucket cache for key '%s'", name)
	}
	_ = cacheEntry.LockContent()

	return b, nil
}

func onBucketCacheMiss(svc iaas.Service, ref string) (cache.Cacheable, fail.Error) {
	bucketInstance, innerXErr := NewBucket(svc)
	if innerXErr != nil {
		return nil, innerXErr
	}

	// TODO: core.ReadByID() does not check communication failure, side effect of limitations of Stow (waiting for stow replacement by rclone)
	if innerXErr = bucketInstance.Read(ref); innerXErr != nil {
		return nil, innerXErr
	}

	return bucketInstance, nil
}

// IsNull tells if the instance corresponds to null value
func (instance *bucket) IsNull() bool {
	return instance == nil || instance.MetadataCore == nil || instance.MetadataCore.IsNull()
}

// carry ...
func (instance *bucket) carry(clonable data.Clonable) (xerr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !instance.IsNull() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}
	identifiable, ok := clonable.(data.Identifiable)
	if !ok {
		return fail.InvalidParameterError("clonable", "must also satisfy interface 'data.Identifiable'")
	}

	kindCache, xerr := instance.GetService().GetCache(instance.MetadataCore.GetKind())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = kindCache.ReserveEntry(identifiable.GetID(), temporal.GetMetadataTimeout())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if derr := kindCache.FreeEntry(identifiable.GetID()); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free %s cache entry for key '%s'", instance.MetadataCore.GetKind(), identifiable.GetID()))
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

// Browse walks through Bucket metadata folder and executes a callback for each entries
func (instance *bucket) Browse(ctx context.Context, callback func(storageBucket *abstract.ObjectStorageBucket) fail.Error) (outerr fail.Error) {
	defer fail.OnPanic(&outerr)

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

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.bucket")).WithStopwatch().Entering()
	defer tracer.Exiting()

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.MetadataCore.BrowseFolder(
		func(buf []byte) (innerXErr fail.Error) {
			if task.Aborted() {
				return fail.AbortedError(nil, "aborted")
			}

			ab := abstract.NewObjectStorageBucket()
			if innerXErr = ab.Deserialize(buf); innerXErr != nil {
				return innerXErr
			}

			return callback(ab)
		},
	)
}

// GetHost ...
func (instance *bucket) GetHost(ctx context.Context) (_ string, xerr fail.Error) {
	if instance == nil || instance.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return "", fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return "", xerr
			}
		default:
			return "", xerr
		}
	}

	if task.Aborted() {
		return "", fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var res string
	xerr = instance.Inspect(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
	if instance == nil || instance.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return "", fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return "", xerr
			}
		default:
			return "", xerr
		}
	}

	if task.Aborted() {
		return "", fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var res string
	xerr = instance.Inspect(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		ab, ok := clonable.(*abstract.ObjectStorageBucket)
		if !ok {
			return fail.InconsistentError("'*abstract.ObjectStorageBucket' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		res = ab.MountPoint
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		logrus.Errorf(xerr.Error())
	}
	return res, nil
}

// Create a bucket
func (instance *bucket) Create(ctx context.Context, name string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !instance.IsNull() {
		bucketName := instance.GetName()
		if bucketName != "" {
			return fail.NotAvailableError("already carrying Share '%s'", bucketName)
		}
		return fail.InvalidInstanceContentError("s", "is not null value")
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
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

	tracer := debug.NewTracer(task, true, "('"+name+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	instance.lock.Lock()
	defer instance.lock.Unlock()

	svc := instance.GetService()

	// -- check if bucket already exist in SafeScale
	bucketInstance, xerr := LoadBucket(svc, name)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// no bucket with this name managed by SafeScale, continue
			debug.IgnoreError(xerr)
			break
		default:
			return xerr
		}
	}
	if bucketInstance != nil {
		bucketInstance.Released()
		return abstract.ResourceDuplicateError("bucket", name)
	}

	// -- check if bucket already exist on provider side
	ab, xerr := svc.InspectBucket(name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreError(xerr)
			break
		default:
			if strings.Contains(xerr.Error(), "not found") {
				debug.IgnoreError(xerr)
				break
			}
			return xerr
		}
	}
	if !ab.IsNull() {
		return abstract.ResourceDuplicateError("bucket", name)
	}

	// -- create bucket
	ab, xerr = svc.CreateBucket(name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// -- write metadata
	return instance.carry(&ab)
}

// Delete a bucket
func (instance *bucket) Delete(ctx context.Context) (xerr fail.Error) {
	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
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

	tracer := debug.NewTracer(task, true, "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	instance.lock.Lock()
	defer instance.lock.Unlock()

	// -- delete Bucket
	xerr = instance.GetService().DeleteBucket(instance.GetName())
	if xerr != nil {
		if strings.Contains(xerr.Error(), "not found") {
			return fail.NotFoundError("failed to find Bucket '%s'", instance.GetName())
		}
		return xerr
	}

	// -- delete metadata
	return instance.MetadataCore.Delete()
}

// Mount a bucket on an host on the given mount point
func (instance *bucket) Mount(ctx context.Context, hostName, path string) (xerr fail.Error) {
	if instance == nil || instance.IsNull() {
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

	tracer := debug.NewTracer(task, true, "('%s', '%s')", hostName, path).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	instance.lock.Lock()
	defer instance.lock.Unlock()

	// Get Host data
	hostInstance, xerr := LoadHost(instance.GetService(), hostName)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to mount bucket '%s' on Host '%s'", instance.GetName(), hostName)
	}

	// Create mount point
	mountPoint := path
	if path == abstract.DefaultBucketMountPoint {
		mountPoint = abstract.DefaultBucketMountPoint + instance.GetName()
	}

	svc := instance.GetService()
	authOpts, _ := svc.GetAuthenticationOptions()
	authurlCfg, _ := authOpts.Config("AuthUrl")
	authurl := authurlCfg.(string)
	authurl = regexp.MustCompile("https?:/+(.*)/.*").FindStringSubmatch(authurl)[1]
	tenantCfg, _ := authOpts.Config("TenantName")
	tenant := tenantCfg.(string)
	loginCfg, _ := authOpts.Config("Login")
	login := loginCfg.(string)
	passwordCfg, _ := authOpts.Config("Password")
	password := passwordCfg.(string)
	regionCfg, _ := authOpts.Config("Region")
	region := regionCfg.(string)

	objStorageProtocol := svc.ObjectStorageProtocol()
	if objStorageProtocol == "swift" {
		objStorageProtocol = "swiftks"
	}
	if objStorageProtocol == "google" {
		objStorageProtocol = "gs"
	}

	d := struct {
		Bucket     string
		Tenant     string
		Login      string
		Password   string
		AuthURL    string
		Region     string
		MountPoint string
		Protocol   string
	}{
		Bucket:     instance.GetName(),
		Tenant:     tenant,
		Login:      login,
		Password:   password,
		AuthURL:    authurl,
		Region:     region,
		MountPoint: mountPoint,
		Protocol:   objStorageProtocol,
	}

	err := instance.exec(ctx, hostInstance, "mount_object_storage.sh", d)
	return fail.ConvertError(err)
}

// Unmount a bucket
func (instance *bucket) Unmount(ctx context.Context, hostName string) (xerr fail.Error) {
	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostName")
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

	tracer := debug.NewTracer(task, true, "('%s')", hostName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	instance.lock.Lock()
	defer instance.lock.Unlock()

	svc := instance.GetService()

	// -- Check bucket existence
	_, xerr = svc.InspectBucket(instance.GetName())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		if strings.Contains(xerr.Error(), "not found") {
			return fail.NotFoundError("failed to find Bucket '%s'", instance.GetName())
		}
		return xerr
	}

	// Get Host
	hostInstance, xerr := LoadHost(svc, hostName)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	dataBu := struct {
		Bucket string
	}{
		Bucket: instance.GetName(),
	}

	err := instance.exec(ctx, hostInstance, "umount_object_storage.sh", dataBu)
	return fail.ConvertError(err)
}

// Execute the given script (embedded in a rice-box) with the given data on the host identified by hostid
func (instance *bucket) exec(ctx context.Context, host resources.Host, script string, data interface{}) fail.Error {
	scriptCmd, xerr := getBoxContent(script, data)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	rc, stdout, stderr, rerr := host.Run(ctx, `sudo bash `+scriptCmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if rerr != nil {
		return xerr
	}

	if rc != 0 {
		finnerXerr := fail.NewError("embedded script %s failed to run", script)
		_ = finnerXerr.Annotate("retcode", rc)
		_ = finnerXerr.Annotate("stdout", stdout)
		_ = finnerXerr.Annotate("stderr", stderr)
		return finnerXerr
	}

	return nil
}

// Return the script (embedded in a rice-box) with placeholders replaced by the values given in data
func getBoxContent(script string, data interface{}) (tplcmd string, xerr fail.Error) {
	defer fail.OnExitLogError(&xerr, debug.NewTracer(nil, true, "").TraceMessage(""))

	box, err := rice.FindBox("../operations/scripts")
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", fail.ConvertError(err)
	}
	scriptContent, err := box.String(script)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", fail.ConvertError(err)
	}
	tpl, err := template.Parse("TemplateName", scriptContent)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", fail.ConvertError(err)
	}

	var buffer bytes.Buffer
	err = tpl.Option("missingkey=error").Execute(&buffer, data)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", fail.ConvertError(err)
	}

	tplcmd = buffer.String()
	// fmt.Println(tplcmd)
	return tplcmd, nil
}
