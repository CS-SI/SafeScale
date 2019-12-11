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

	"github.com/asaskevich/govalidator"

	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	conv "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
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
func (s *BucketListener) List(ctx context.Context, in *google_protobuf.Empty) (bl *pb.BucketList, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot list buckets").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "bucket list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.Task(), "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := BucketHandler(job)
	buckets, err := handler.List()
	if err != nil {
		return nil, err
	}

	return conv.ToPBBucketList(buckets), nil
}

// Create a new bucket
func (s *BucketListener) Create(ctx context.Context, in *pb.Bucket) (empty *google_protobuf.Empty, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot create bucket").ToGRPCStatus()
		}
	}()

	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "bucket create")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	bucketName := in.GetName()
	tracer := concurrency.NewTracer(job.Task(), fmt.Sprintf("('%s')", bucketName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := BucketHandler(job)
	err = handler.Create(bucketName)
	if err != nil {
		return empty, err
	}

	return empty, nil
}

// Delete a bucket
func (s *BucketListener) Delete(ctx context.Context, in *pb.Bucket) (empty *google_protobuf.Empty, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot delete bucket").ToGRPCStatus()
		}
	}()

	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "bucket list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	bucketName := in.GetName()
	tracer := concurrency.NewTracer(job.Task(), fmt.Sprintf("('%s')", bucketName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := BucketHandler(job)
	err = handler.Delete(bucketName)
	if err != nil {
		return empty, err
	}

	return empty, nil
}

// Inspect a bucket
func (s *BucketListener) Inspect(ctx context.Context, in *pb.Bucket) (_ *pb.BucketMountingPoint, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot inspect bucket").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "can't be nil")
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "bucket inspect")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	bucketName := in.GetName()
	tracer := concurrency.NewTracer(job.Task(), fmt.Sprintf("('%s')", bucketName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := BucketHandler(job)
	resp, err := handler.Inspect(bucketName)
	if err != nil {
		return nil, err
	}
	// DEFENSIVE CODING: this _must not_ happen, but InspectHost has different implementations for each stack, and sometimes mistakes happens, so the test is necessary
	if resp == nil {
		return nil, scerr.NotFoundError(fmt.Sprintf("bucket '%s' not found", bucketName))
	}
	return conv.ToPBBucketMountPoint(resp), nil
}

// Mount a bucket on the filesystem of the host
func (s *BucketListener) Mount(ctx context.Context, in *pb.BucketMountingPoint) (empty *google_protobuf.Empty, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot mount bucket").ToGRPCStatus()
		}
	}()

	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "bucket mount")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	bucketName := in.GetBucket()
	hostName := in.GetHost().GetName()
	tracer := concurrency.NewTracer(job.Task(), fmt.Sprintf("('%s', '%s')", bucketName, hostName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := BucketHandler(job)
	err = handler.Mount(bucketName, hostName, in.GetPath())
	if err != nil {
		return empty, err
	}
	return empty, nil
}

// Unmount a bucket from the filesystem of the host
func (s *BucketListener) Unmount(ctx context.Context, in *pb.BucketMountingPoint) (empty *google_protobuf.Empty, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot unmount bucket").ToGRPCStatus()
		}
	}()

	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError()
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "can't be nil")
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "bucket unmount")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	bucketName := in.GetBucket()
	hostName := in.GetHost().GetName()
	tracer := concurrency.NewTracer(job.Task(), fmt.Sprintf("('%s', '%s')", bucketName, hostName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := BucketHandler(job)
	err = handler.Unmount(bucketName, hostName)
	if err != nil {
		return empty, err
	}
	return empty, nil
}
