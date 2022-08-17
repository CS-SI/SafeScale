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

package handlers

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	bucketfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/bucket"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/handlers.BucketHandler -o mocks/mock_bucket.go

// BucketHandler defines interface to manipulate buckets
type BucketHandler interface {
	List(bool) ([]string, fail.Error)
	Create(string) fail.Error
	Delete(string) fail.Error
	Inspect(string) (resources.Bucket, fail.Error)
	Download(string) ([]byte, fail.Error)
	Clear(string) fail.Error
	Upload(string, string) fail.Error
	Mount(string, string, string) fail.Error
	Unmount(string, string) fail.Error
}

// bucketHandler bucket service
type bucketHandler struct {
	job server.Job
}

// NewBucketHandler creates a BucketHandler
func NewBucketHandler(job server.Job) BucketHandler {
	return &bucketHandler{job: job}
}

// List retrieves all available buckets
func (handler *bucketHandler) List(all bool) (_ []string, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(handler.job.Context(), true, "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	if all {
		return handler.job.Service().ListBuckets(handler.job.Context(), objectstorage.RootPath)
	}

	bucketBrowser, xerr := bucketfactory.New(handler.job.Service())
	if xerr != nil {
		return nil, xerr
	}

	var bucketList []string
	xerr = bucketBrowser.Browse(handler.job.Context(), func(bucket *abstract.ObjectStorageBucket) fail.Error {
		bucketList = append(bucketList, bucket.Name)
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	return bucketList, nil
}

// Create a bucket
func (handler *bucketHandler) Create(name string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task.Context(), tracing.ShouldTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	svc := handler.job.Service()
	rb, xerr := bucketfactory.Load(handler.job.Context(), svc, name)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok || valid.IsNil(xerr) {
			return xerr
		}
	}
	if rb != nil {
		return fail.DuplicateError("bucket '%s' already exist", name)
	}

	rb, xerr = bucketfactory.New(svc)
	if xerr != nil {
		return xerr
	}
	return rb.Create(task.Context(), name)
}

// Delete a bucket
func (handler *bucketHandler) Delete(name string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task.Context(), tracing.ShouldTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	rb, xerr := bucketfactory.Load(handler.job.Context(), handler.job.Service(), name)
	if xerr != nil {
		return xerr
	}
	return rb.Delete(task.Context())
}

// Uploads a bucket
func (handler *bucketHandler) Upload(bucketName, directoryName string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}
	if directoryName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("directoryName")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task.Context(), tracing.ShouldTrace("handlers.bucket"), "('"+directoryName+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	// -- upload bucket
	xerr := handler.job.Service().UploadBucket(task.Context(), bucketName, directoryName)
	if xerr != nil {
		return xerr
	}
	return nil
}

// Download a bucket
func (handler *bucketHandler) Download(name string) (bytes []byte, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task.Context(), tracing.ShouldTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	// -- download bucket
	ct, xerr := handler.job.Service().DownloadBucket(task.Context(), name, "")
	if xerr != nil {
		return nil, xerr
	}
	return ct, nil
}

// Clear a bucket
func (handler *bucketHandler) Clear(name string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task.Context(), tracing.ShouldTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	// clear bucket
	xerr := handler.job.Service().ClearBucket(task.Context(), name, "", "")
	if xerr != nil {
		return xerr
	}
	return nil
}

// Inspect a bucket
func (handler *bucketHandler) Inspect(name string) (rb resources.Bucket, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task.Context(), tracing.ShouldTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	var xerr fail.Error
	rb, xerr = bucketfactory.Load(handler.job.Context(), handler.job.Service(), name)
	if xerr != nil {
		return nil, xerr
	}

	exists, xerr := rb.Exists(handler.job.Context())
	if xerr != nil {
		return nil, xerr
	}

	if !exists {
		return nil, abstract.ResourceNotFoundError("bucket", name)
	}

	return rb, nil
}

// Mount a bucket on a host on the given mount point
func (handler *bucketHandler) Mount(bucketName, hostName, path string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if hostName == "" {
		return fail.InvalidParameterError("hostName", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task.Context(), tracing.ShouldTrace("handlers.bucket"), "('%s', '%s', '%s')", bucketName, hostName, path).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			ferr = fail.Wrap(ferr, "failed to mount bucket '%s' on '%s:%s'", bucketName, hostName, path)
		}
	}()

	// Check bucket existence
	rb, xerr := bucketfactory.Load(handler.job.Context(), handler.job.Service(), bucketName)
	if xerr != nil {
		return xerr
	}

	return rb.Mount(task.Context(), hostName, path)
}

// Unmount a bucket
func (handler *bucketHandler) Unmount(bucketName, hostName string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if hostName == "" {
		return fail.InvalidParameterError("hostName", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task.Context(), tracing.ShouldTrace("handlers.bucket"), "('%s', '%s')", bucketName, hostName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			ferr = fail.Wrap(ferr, "failed to unmount bucket '%s' from host '%s'", bucketName, hostName)
		}
	}()

	// Check bucket existence
	rb, xerr := bucketfactory.Load(handler.job.Context(), handler.job.Service(), bucketName)
	if xerr != nil {
		return xerr
	}

	return rb.Unmount(task.Context(), hostName)
}
