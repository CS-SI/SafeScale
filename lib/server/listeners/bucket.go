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

package listeners

import (
	"context"

	"github.com/asaskevich/govalidator"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// safescale bucket create c1
// safescale bucket mount c1 host1 --path="/shared/data" (utilisation de s3ql, par default /buckets/c1)
// safescale bucket umount c1 host1
// safescale bucket delete c1
// safescale bucket list
// safescale bucket inspect C1

// BucketListener is the bucket service grpc server
type BucketListener struct{}

// ErrorList available buckets
func (s *BucketListener) List(ctx context.Context, in *googleprotobuf.Empty) (bl *protocol.BucketList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list buckets")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, xerr := PrepareJob(ctx, "", "bucket list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.bucket"), "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewBucketHandler(job)
	buckets, xerr := handler.List()
	if err != nil {
		return nil, xerr
	}

	return converters.BucketListFromAbstractToProtocol(buckets), nil
}

// Create a new bucket
func (s *BucketListener) Create(ctx context.Context, in *protocol.Bucket) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot create bucket")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, xerr := PrepareJob(ctx, "", "bucket create")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	bucketName := in.GetName()
	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.bucket"), "('%s')", bucketName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewBucketHandler(job)
	if xerr = handler.Create(bucketName); xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// Delete a bucket
func (s *BucketListener) Delete(ctx context.Context, in *protocol.Bucket) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete bucket")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, xerr := PrepareJob(ctx, "", "bucket list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	bucketName := in.GetName()
	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.bucket"), "('%s')", bucketName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewBucketHandler(job)
	if err = handler.Delete(bucketName); err != nil {
		return empty, err
	}

	return empty, nil
}

// Inspect a bucket
func (s *BucketListener) Inspect(ctx context.Context, in *protocol.Bucket) (_ *protocol.BucketMountingPoint, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect bucket")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "can't be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, xerr := PrepareJob(ctx, "", "bucket inspect")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	bucketName := in.GetName()
	task := job.GetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("listeners.bucket"), "('%s')", bucketName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewBucketHandler(job)
	resp, xerr := handler.Inspect(bucketName)
	if xerr != nil {
		return nil, xerr
	}
	// DEFENSIVE CODING: this _must not_ happen, but InspectHost has different implementations for each stack, and sometimes mistakes happens, so the test is necessary
	if resp == nil {
		return nil, fail.NotFoundError("bucket '%s' not found", bucketName)
	}
	return converters.BucketMountPointFromResourceToProtocol(task, resp)
}

// Mount a bucket on the filesystem of the host
func (s *BucketListener) Mount(ctx context.Context, in *protocol.BucketMountingPoint) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot mount bucket")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, xerr := PrepareJob(ctx, "", "bucket mount")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	bucketName := in.GetBucket()
	hostName := in.GetHost().Name
	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.bucket"), "('%s', '%s')", bucketName, hostName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewBucketHandler(job)
	if xerr = handler.Mount(bucketName, hostName, in.GetPath()); xerr != nil {
		return empty, xerr
	}
	return empty, nil
}

// Unmount a bucket from the filesystem of the host
func (s *BucketListener) Unmount(ctx context.Context, in *protocol.BucketMountingPoint) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot unmount bucket")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "can't be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, xerr := PrepareJob(ctx, "", "bucket unmount")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	bucketName := in.GetBucket()
	hostName := in.GetHost().Name
	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.bucket"), "('%s', '%s')", bucketName, hostName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewBucketHandler(job)
	if xerr = handler.Unmount(bucketName, hostName); xerr != nil {
		return empty, xerr
	}
	return empty, nil
}
