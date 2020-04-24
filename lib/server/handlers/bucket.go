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
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

//go:generate mockgen -destination=../mocks/mock_bucketapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers BucketHandler

// BucketHandler defines interface to manipulate buckets
type BucketHandler interface {
	List() ([]string, error)
	Create(string) error
	Delete(string) error
	Inspect(string) (resources.Bucket, error)
	Mount(string, string, string) error
	Unmount(string, string) error
}

// bucketHandler bucket service
type bucketHandler struct {
	job server.Job
}

// NewBucketHandler creates a Bucket service
func NewBucketHandler(job server.Job) BucketHandler {
	return &bucketHandler{job: job}
}

// List retrieves all available buckets
func (handler *bucketHandler) List() (rv []string, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(handler.job.SafeGetTask(), true, "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)

	rv, err = handler.job.SafeGetService().ListBuckets(objectstorage.RootPath)
	return rv, err
}

// Create a bucket
func (handler *bucketHandler) Create(name string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if name == "" {
		return scerr.InvalidParameterError("name", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)

	svc := handler.job.SafeGetService()
	rb, err := bucketfactory.Load(svc, name)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return err
		}
	}
	if rb != nil {
		return scerr.DuplicateError("bucket '%s' does already exist", name)
	}

	rb, err = bucketfactory.New(svc)
	if err != nil {
		return err
	}
	return rb.Create(task, name)
}

// Delete a bucket
func (handler *bucketHandler) Delete(name string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if name == "" {
		return scerr.InvalidParameterError("name", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)

	rb, err := bucketfactory.Load(handler.job.SafeGetService(), name)
	if err != nil {
		return err
	}
	return rb.Delete(task)
}

// Inspect a bucket
func (handler *bucketHandler) Inspect(name string) (rb resources.Bucket, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)

	rb, err = bucketfactory.Load(handler.job.SafeGetService(), name)
	if err != nil {
		return nil, err
	}
	return rb, err
}

// Mount a bucket on an host on the given mount point
func (handler *bucketHandler) Mount(bucketName, hostName, path string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if hostName == "" {
		return scerr.InvalidParameterError("hostName", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.bucket"), "('%s', '%s', '%s')", bucketName, hostName, path).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)

	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "failed to mount bucket '%s' on '%s:%s'", bucketName, hostName, path)
		}
	}()

	// Check bucket existence
	svc := handler.job.SafeGetService()
	rb, err := bucketfactory.Load(svc, bucketName)
	if err != nil {
		return err
	}

	return rb.Mount(task, hostName, path)
}

// Unmount a bucket
func (handler *bucketHandler) Unmount(bucketName, hostName string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if hostName == "" {
		return scerr.InvalidParameterError("hostName", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.bucket"), "('%s', '%s')", bucketName, hostName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)

	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "failed to unmount bucket '%s' from host '%s'", bucketName, hostName)
		}
	}()

	// Check bucket existence
	svc := handler.job.SafeGetService()
	rb, err := bucketfactory.Load(svc, bucketName)
	if err != nil {
		return err
	}

	return rb.Unmount(task, hostName)
}
