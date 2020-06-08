/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	bucketfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/bucket"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate mockgen -destination=../mocks/mock_bucketapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers BucketHandler

// BucketHandler defines interface to manipulate buckets
type BucketHandler interface {
	List() ([]string, fail.Error)
	Create(string) fail.Error
	Delete(string) fail.Error
	Inspect(string) (resources.Bucket, fail.Error)
	Mount(string, string, string) fail.Error
	Unmount(string, string) fail.Error
}

// bucketHandler bucket service
type bucketHandler struct {
	job server.Job
}

// NewBucketHandler creates a Bucket service
func NewBucketHandler(job server.Job) BucketHandler {
	return &bucketHandler{job: job}
}

// ErrorList retrieves all available buckets
func (handler *bucketHandler) List() (rv []string, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(handler.job.SafeGetTask(), true, "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)

	r, xerr := handler.job.SafeGetService().ListBuckets(objectstorage.RootPath)
	if xerr != nil {
		return nil, xerr
	}
	return r, nil
}

// Create a bucket
func (handler *bucketHandler) Create(name string) (xerr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)

	svc := handler.job.SafeGetService()
	rb, xerr := bucketfactory.Load(svc, name)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return xerr
		}
	}
	if rb != nil {
		return fail.DuplicateError("bucket '%s' does already exist", name)
	}

	rb, xerr = bucketfactory.New(svc)
	if xerr != nil {
		return xerr
	}
	return rb.Create(task, name)
}

// Delete a bucket
func (handler *bucketHandler) Delete(name string) (xerr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)

	rb, xerr := bucketfactory.Load(handler.job.SafeGetService(), name)
	if xerr != nil {
		return xerr
	}
	return rb.Delete(task)
}

// Inspect a bucket
func (handler *bucketHandler) Inspect(name string) (rb resources.Bucket, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)

	rb, xerr = bucketfactory.Load(handler.job.SafeGetService(), name)
	if xerr != nil {
		return nil, xerr
	}
	return rb, nil
}

// Mount a bucket on an host on the given mount point
func (handler *bucketHandler) Mount(bucketName, hostName, path string) (xerr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if hostName == "" {
		return fail.InvalidParameterError("hostName", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.bucket"), "('%s', '%s', '%s')", bucketName, hostName, path).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)

	defer func() {
		if xerr != nil {
			xerr = fail.Wrap(xerr, "failed to mount bucket '%s' on '%s:%s'", bucketName, hostName, path)
		}
	}()

	// Check bucket existence
	svc := handler.job.SafeGetService()
	rb, xerr := bucketfactory.Load(svc, bucketName)
	if xerr != nil {
		return xerr
	}

	return rb.Mount(task, hostName, path)
}

// Unmount a bucket
func (handler *bucketHandler) Unmount(bucketName, hostName string) (xerr fail.Error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if hostName == "" {
		return fail.InvalidParameterError("hostName", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.bucket"), "('%s', '%s')", bucketName, hostName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)

	defer func() {
		if xerr != nil {
			xerr = fail.Wrap(xerr, "failed to unmount bucket '%s' from host '%s'", bucketName, hostName)
		}
	}()

	// Check bucket existence
	svc := handler.job.SafeGetService()
	rb, xerr := bucketfactory.Load(svc, bucketName)
	if xerr != nil {
		return xerr
	}

	return rb.Unmount(task, hostName)
}
