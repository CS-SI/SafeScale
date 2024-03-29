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

package listeners

import (
	"context"
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/backend/handlers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/v22/lib/backend/utils"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
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
func (s *BucketListener) List(inctx context.Context, in *protocol.BucketListRequest) (
	bl *protocol.BucketListResponse, err error,
) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list Buckets")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	job, xerr := PrepareJob(inctx, "", "/buckets/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	handler := handlers.NewBucketHandler(job)
	bucketList, xerr := handler.List(in.GetAll())
	if xerr != nil {
		return nil, xerr
	}

	return converters.BucketListFromAbstractToProtocol(bucketList), nil
}

// Create a new bucket
func (s *BucketListener) Create(inctx context.Context, in *protocol.BucketRequest) (
	empty *googleprotobuf.Empty, err error,
) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot create bucket")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil").ToGRPCStatus()
	}

	bucketName := in.GetName()
	job, xerr := PrepareJob(inctx, "", fmt.Sprintf("/bucket/%s/create", bucketName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	xerr = handlers.NewBucketHandler(job).Create(bucketName)
	if xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// Delete a bucket
func (s *BucketListener) Delete(inctx context.Context, in *protocol.BucketDeleteRequest) (
	empty *googleprotobuf.Empty, err error,
) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot delete bucket")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil").ToGRPCStatus()
	}

	bucketName := in.GetName()
	job, xerr := PrepareJob(inctx, "", fmt.Sprintf("/bucket/%s/delete", bucketName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	return empty, handlers.NewBucketHandler(job).Delete(bucketName)
}

// Download a bucket
func (s *BucketListener) Download(
	inctx context.Context, in *protocol.BucketRequest,
) (_ *protocol.BucketDownloadResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot download bucket")

	empty := &protocol.BucketDownloadResponse{}

	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "can't be nil")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	bucketName := in.GetName()
	if bucketName == "" {
		return empty, fail.InvalidParameterError("bucket name", "cannot be empty")
	}

	job, xerr := PrepareJob(inctx, "", fmt.Sprintf("/bucket/%s/download", bucketName))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	handler := handlers.NewBucketHandler(job)
	empty.Content, xerr = handler.Download(bucketName)
	if xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// Clear a bucket
func (s *BucketListener) Clear(inctx context.Context, in *protocol.BucketRequest) (
	empty *googleprotobuf.Empty, err error,
) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot download bucket")

	empty = &googleprotobuf.Empty{}

	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "can't be nil")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	bucketName := in.GetName()
	if bucketName == "" {
		return empty, fail.InvalidParameterError("bucket name", "cannot be empty")
	}

	job, xerr := PrepareJob(inctx, "", fmt.Sprintf("/bucket/%s/upload", bucketName))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	handler := handlers.NewBucketHandler(job)
	xerr = handler.Clear(bucketName)
	if xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// Inspect a bucket
func (s *BucketListener) Inspect(inctx context.Context, in *protocol.BucketRequest) (
	_ *protocol.BucketResponse, err error,
) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot inspect bucket")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "can't be nil")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	bucketName := in.GetName()
	job, xerr := PrepareJob(inctx, "", fmt.Sprintf("/bucket/%s/inspect", bucketName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	handler := handlers.NewBucketHandler(job)
	resp, xerr := handler.Inspect(bucketName)
	if xerr != nil {
		return nil, xerr
	}

	// returning nil, nil IS a mistake
	if resp == nil {
		return nil, fail.NotFoundError("bucket '%s' not found", bucketName)
	}

	return resp.ToProtocol(job.Context())
}

// Mount a bucket on the filesystem of the host
func (s *BucketListener) Mount(inctx context.Context, in *protocol.BucketMountRequest) (
	empty *googleprotobuf.Empty, err error,
) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot mount bucket")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil").ToGRPCStatus()
	}

	bucketName := in.GetBucket()
	hostRef, _ := srvutils.GetReference(in.GetHost())
	job, xerr := PrepareJob(inctx, "", fmt.Sprintf("/bucket/%s/host/%s/mount", bucketName, hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	return empty, handlers.NewBucketHandler(job).Mount(bucketName, hostRef, in.GetPath())
}

// Unmount a bucket from the filesystem of the host
func (s *BucketListener) Unmount(inctx context.Context, in *protocol.BucketMountRequest) (
	empty *googleprotobuf.Empty, err error,
) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot unmount bucket")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "can't be nil")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	bucketName := in.GetBucket()
	hostRef, _ := srvutils.GetReference(in.GetHost())
	job, xerr := PrepareJob(inctx, "", fmt.Sprintf("/bucket/%s/host/%s/unmount", bucketName, hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	return empty, handlers.NewBucketHandler(job).Unmount(bucketName, hostRef)
}
