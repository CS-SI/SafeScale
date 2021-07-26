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

package listeners

import (
	"context"
	"fmt"

	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/asaskevich/govalidator"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
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

// List available buckets
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
			logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
		}
	}

	job, xerr := PrepareJob(ctx, "", "/buckets/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.bucket"), "").WithStopwatch().Entering()
	defer tracer.Exiting()
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
			logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
		}
	}

	bucketName := in.GetName()
	job, xerr := PrepareJob(ctx, "", fmt.Sprintf("/bucket/%s/create", bucketName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.bucket"), "('%s')", bucketName).WithStopwatch().Entering()
	defer tracer.Exiting()
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
			logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
		}
	}

	bucketName := in.GetName()
	job, xerr := PrepareJob(ctx, "", fmt.Sprintf("/bucket/%s/delete", bucketName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.bucket"), "('%s')", bucketName).WithStopwatch().Entering()
	defer tracer.Exiting()
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
			logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
		}
	}

	bucketName := in.GetName()
	job, xerr := PrepareJob(ctx, "", fmt.Sprintf("/bucket/%s/inspect", bucketName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	task := job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.bucket"), "('%s')", bucketName).WithStopwatch().Entering()
	defer tracer.Exiting()
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
	return converters.BucketMountPointFromResourceToProtocol(task.Context(), resp)
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
			logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
		}
	}

	bucketName := in.GetBucket()
	hostRef, _ := srvutils.GetReference(in.GetHost())
	job, xerr := PrepareJob(ctx, "", fmt.Sprintf("/bucket/%s/host/%s/mount", bucketName, hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.bucket"), "('%s', '%s')", bucketName, hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewBucketHandler(job)
	if xerr = handler.Mount(bucketName, hostRef, in.GetPath()); xerr != nil {
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
			logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
		}
	}

	bucketName := in.GetBucket()
	hostRef, _ := srvutils.GetReference(in.GetHost())
	job, xerr := PrepareJob(ctx, "", fmt.Sprintf("/bucket/%s/host/%s/unmount", bucketName, hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.bucket"), "('%s', '%s')", bucketName, hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewBucketHandler(job)
	if xerr = handler.Unmount(bucketName, hostRef); xerr != nil {
		return empty, xerr
	}
	return empty, nil
}
