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

package listeners

import (
	"context"
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/handlers"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/v22/lib/server/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
)

// safescale bucket create c1
// safescale bucket mount c1 host1 --path="/shared/data" (uses s3ql, by default /buckets/c1)
// safescale bucket umount c1 host1
// safescale bucket delete c1
// safescale bucket list
// safescale bucket inspect C1

// BucketListener is the bucket service gRPC server
type BucketListener struct {
	protocol.UnimplementedBucketServiceServer
}

// List available buckets
func (s *BucketListener) List(ctx context.Context, in *protocol.BucketListRequest) (bl *protocol.BucketListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list Buckets")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
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
	bucketList, xerr := handler.List(in.GetAll())
	if xerr != nil {
		return nil, xerr
	}

	return converters.BucketListFromAbstractToProtocol(bucketList), nil
}

// Create a new bucket
func (s *BucketListener) Create(ctx context.Context, in *protocol.BucketRequest) (empty *googleprotobuf.Empty, err error) {
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

	bucketName := in.GetName()
	job, xerr := PrepareJob(ctx, "", fmt.Sprintf("/bucket/%s/create", bucketName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.bucket"), "('%s')", bucketName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	xerr = handlers.NewBucketHandler(job).Create(bucketName)
	if xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// Delete a bucket
func (s *BucketListener) Delete(ctx context.Context, in *protocol.BucketRequest) (empty *googleprotobuf.Empty, err error) {
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

	bucketName := in.GetName()
	job, xerr := PrepareJob(ctx, "", fmt.Sprintf("/bucket/%s/delete", bucketName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.bucket"), "('%s')", bucketName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return empty, handlers.NewBucketHandler(job).Delete(bucketName)
}

// Download a bucket
func (s *BucketListener) Download(ctx context.Context, in *protocol.BucketRequest) (_ *protocol.BucketDownloadResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot download bucket")

	empty := &protocol.BucketDownloadResponse{}

	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "can't be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	bucketName := in.GetName()
	if bucketName == "" {
		return empty, fail.InvalidParameterError("bucket name", "cannot be empty")
	}

	job, xerr := PrepareJob(ctx, "", fmt.Sprintf("/bucket/%s/download", bucketName))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.bucket"), "('%s')", bucketName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewBucketHandler(job)
	empty.Content, xerr = handler.Download(bucketName)
	if xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// Inspect a bucket
func (s *BucketListener) Inspect(ctx context.Context, in *protocol.BucketRequest) (_ *protocol.BucketResponse, err error) {
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

	bucketName := in.GetName()
	job, xerr := PrepareJob(ctx, "", fmt.Sprintf("/bucket/%s/inspect", bucketName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.bucket"), "('%s')", bucketName).WithStopwatch().Entering()
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

	return resp.ToProtocol(job.Context())
}

// Mount a bucket on the filesystem of the host
func (s *BucketListener) Mount(ctx context.Context, in *protocol.BucketMountRequest) (empty *googleprotobuf.Empty, err error) {
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

	return empty, handlers.NewBucketHandler(job).Mount(bucketName, hostRef, in.GetPath())
}

// Unmount a bucket from the filesystem of the host
func (s *BucketListener) Unmount(ctx context.Context, in *protocol.BucketMountRequest) (empty *googleprotobuf.Empty, err error) {
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

	return empty, handlers.NewBucketHandler(job).Unmount(bucketName, hostRef)
}
