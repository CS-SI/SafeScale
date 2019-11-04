/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	conv "github.com/CS-SI/SafeScale/lib/server/utils"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// FIXME Technical debt Input verification, ctx cannot be nil

// BucketHandler ...
var BucketHandler = handlers.NewBucketHandler

// safescale bucket create c1
// safescale bucket mount c1 host1 --path="/shared/data" (utilisation de s3ql, par default /buckets/c1)
// safescale bucket umount c1 host1
// safescale bucket delete c1
// safescale bucket list
// safescale bucket inspect C1

// BucketListener is the bucket service grpc server
type BucketListener struct{}

// List available buckets
func (s *BucketListener) List(ctx context.Context, in *google_protobuf.Empty) (bl *pb.BucketList, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}

	tracer := concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Bucket List"); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		logrus.Info("Can't list buckets: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "cannot list buckets: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	buckets, err := handler.List(ctx)
	if err != nil {
		tbr := scerr.Wrap(err, "can't list buckets")
		return nil, tbr.ToGRPCStatus()
	}

	return conv.ToPBBucketList(buckets), nil
}

// Create a new bucket
func (s *BucketListener) Create(ctx context.Context, in *pb.Bucket) (empty *google_protobuf.Empty, err error) {
	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}

	bucketName := in.GetName()
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", bucketName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Bucket Create : "+bucketName); err != nil {
		return empty, status.Errorf(codes.FailedPrecondition, fmt.Errorf("failed to register the process : %s", err.Error()).Error())
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		logrus.Info("Can't create bucket: no tenant set")
		return empty, status.Errorf(codes.FailedPrecondition, "cannot create bucket: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	err = handler.Create(ctx, bucketName)
	if err != nil {
		return empty, scerr.Wrap(err, "cannot create bucket").ToGRPCStatus()
	}

	return empty, nil
}

// Delete a bucket
func (s *BucketListener) Delete(ctx context.Context, in *pb.Bucket) (empty *google_protobuf.Empty, err error) {
	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}

	bucketName := in.GetName()
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", bucketName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Bucket Delete : "+bucketName); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, fmt.Errorf("failed to register the process : %s", err.Error()).Error())
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		// logrus.Info("Can't delete buckets: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "cannot delete bucket: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	err = handler.Delete(ctx, bucketName)
	if err != nil {
		return empty, scerr.Wrap(err, "cannot delete bucket").ToGRPCStatus()
	}

	return empty, nil
}

// Inspect a bucket
func (s *BucketListener) Inspect(ctx context.Context, in *pb.Bucket) (_ *pb.BucketMountingPoint, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}

	bucketName := in.GetName()
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", bucketName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Bucket Inspect : "+in.GetName()); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, fmt.Errorf("failed to register the process : %s", err.Error()).Error())
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		// logrus.Info("Can't inspect bucket: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "cannot inspect bucket: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	resp, err := handler.Inspect(ctx, bucketName)
	if err != nil {
		return nil, scerr.Wrap(err, "cannot inspect bucket").ToGRPCStatus()
	}
	// this _must not_ happen, but InspectHost has different implementations for each stack, and sometimes mistakes happens, so the test is necessary
	if resp == nil {
		return nil, status.Errorf(codes.NotFound, "cannot inspect bucket '%s': not found", in.GetName())
	}
	return conv.ToPBBucketMountPoint(resp), nil
}

// Mount a bucket on the filesystem of the host
func (s *BucketListener) Mount(ctx context.Context, in *pb.BucketMountingPoint) (empty *google_protobuf.Empty, err error) {
	empty = &google_protobuf.Empty{}
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}

	bucketName := in.GetBucket()
	hostName := in.GetHost().GetName()
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s')", bucketName, hostName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Bucket Mount : "+bucketName+" on "+hostName); err != nil {
		return empty, status.Errorf(codes.FailedPrecondition, fmt.Errorf("failed to register the process : %s", err.Error()).Error())
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		// logrus.Info("Can't mount buckets: no tenant set")
		return empty, status.Errorf(codes.FailedPrecondition, "cannot mount bucket: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	err = handler.Mount(ctx, bucketName, hostName, in.GetPath())
	if err != nil {
		return empty, scerr.Wrap(err, "cannot mount bucket").ToGRPCStatus()
	}
	return empty, nil
}

// Unmount a bucket from the filesystem of the host
func (s *BucketListener) Unmount(ctx context.Context, in *pb.BucketMountingPoint) (empty *google_protobuf.Empty, err error) {
	empty = &google_protobuf.Empty{}
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}

	bucketName := in.GetBucket()
	hostName := in.GetHost().GetName()
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s')", bucketName, hostName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Bucket Unmount : "+bucketName+" off "+hostName); err != nil {
		return empty, status.Errorf(codes.FailedPrecondition, fmt.Errorf("failed to register the process : %s", err.Error()).Error())
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		logrus.Info("Can't unmount bucket: no tenant set")
		return empty, status.Errorf(codes.FailedPrecondition, "cannot unmount bucket: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	err = handler.Unmount(ctx, bucketName, hostName)
	if err != nil {
		return empty, scerr.Wrap(err, "cannot unmount bucket").ToGRPCStatus()
	}
	return empty, nil
}
