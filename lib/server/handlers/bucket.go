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
	"github.com/CS-SI/SafeScale/v22/lib/server"
	"github.com/CS-SI/SafeScale/v22/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	bucketfactory "github.com/CS-SI/SafeScale/v22/lib/server/resources/factories/bucket"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/server/handlers.BucketHandler -o mocks/mock_bucket.go

// BucketHandler defines interface to manipulate buckets
type BucketHandler interface {
	List(bool) ([]string, fail.Error)
	Create(string) fail.Error
	Delete(string) fail.Error
	Inspect(string) (resources.Bucket, fail.Error)
	Download(string) ([]byte, fail.Error)
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
	defer fail.OnPanic(&ferr)
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(handler.job.Task(), true, "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage(""))

	if all {
		return handler.job.Service().ListBuckets(objectstorage.RootPath)
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
	defer fail.OnPanic(&ferr)
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage(""))

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
	defer fail.OnPanic(&ferr)
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage(""))

	rb, xerr := bucketfactory.Load(handler.job.Context(), handler.job.Service(), name)
	if xerr != nil {
		return xerr
	}
	return rb.Delete(task.Context())
}

// Download a bucket
func (handler *bucketHandler) Download(name string) (bytes []byte, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage(""))

	// -- download bucket
	ct, xerr := handler.job.Service().DownloadBucket(name, "")
	if xerr != nil {
		return nil, xerr
	}
	return ct, nil
}

// Inspect a bucket
func (handler *bucketHandler) Inspect(name string) (rb resources.Bucket, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage(""))

	var xerr fail.Error
	rb, xerr = bucketfactory.Load(handler.job.Context(), handler.job.Service(), name)
	if xerr != nil {
		return nil, xerr
	}
	return rb, nil
}

// Mount a bucket on a host on the given mount point
func (handler *bucketHandler) Mount(bucketName, hostName, path string) (ferr fail.Error) {
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
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.bucket"), "('%s', '%s', '%s')", bucketName, hostName, path).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage(""))

	defer func() {
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
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.bucket"), "('%s', '%s')", bucketName, hostName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage(""))

	defer func() {
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
