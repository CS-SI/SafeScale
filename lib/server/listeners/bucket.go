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

	"github.com/pkg/errors"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/utils"
	conv "github.com/CS-SI/SafeScale/lib/server/utils"
)

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
func (s *BucketListener) List(ctx context.Context, in *google_protobuf.Empty) (*pb.BucketList, error) {
	log.Infof("safescaled receiving 'bucket list'")
	log.Debugf(">>> listeners.BucketListener::List()")
	defer log.Debugf("<<< listeners.BucketListener::List()")

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "Bucket List"); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't list buckets: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't list buckets: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	buckets, err := handler.List(ctx)
	if err != nil {
		tbr := errors.Wrap(err, "Can't list buckets")
		return nil, grpc.Errorf(codes.Internal, tbr.Error())
	}

	return conv.ToPBBucketList(buckets), nil
}

// Create a new bucket
func (s *BucketListener) Create(ctx context.Context, in *pb.Bucket) (*google_protobuf.Empty, error) {
	bucketName := in.GetName()
	log.Infof("safescaled receiving 'bucket create %s'", bucketName)
	log.Debugf(">>> listeners.BucketListener::Create(%s)", bucketName)
	defer log.Debugf("<<< listeners.BucketListener::Create(%s)", bucketName)

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := utils.ProcessRegister(ctx, cancelFunc, "Bucket Create : "+bucketName); err != nil {
		return nil, fmt.Errorf("Failed to register the process : %s", err.Error())
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't create bucket: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't create bucket: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	err := handler.Create(ctx, bucketName)
	if err != nil {
		tbr := errors.Wrap(err, "can't create bucket")
		return nil, grpc.Errorf(codes.Internal, tbr.Error())
	}

	return &google_protobuf.Empty{}, nil
}

// Delete a bucket
func (s *BucketListener) Delete(ctx context.Context, in *pb.Bucket) (*google_protobuf.Empty, error) {
	bucketName := in.GetName()
	log.Infof("safescaled receiving 'bucket delete %s'", bucketName)
	log.Debugf(">>> listeners.BucketListener::Delete(%s)", bucketName)
	defer log.Debugf("<<< listeners.BucketListener::Delete(%s)", bucketName)

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "Bucket Delete : "+bucketName); err != nil {
		return nil, fmt.Errorf("Failed to register the process : %s", err.Error())
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't delete buckets: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't delete bucket: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	err := handler.Delete(ctx, bucketName)
	if err != nil {
		tbr := errors.Wrap(err, "can't delete bucket")
		return nil, grpc.Errorf(codes.Internal, tbr.Error())
	}

	return &google_protobuf.Empty{}, nil
}

// Inspect a bucket
func (s *BucketListener) Inspect(ctx context.Context, in *pb.Bucket) (*pb.BucketMountingPoint, error) {
	bucketName := in.GetName()
	log.Infof("safescaled receiving 'bucket inspect %s'", bucketName)
	log.Debugf(">>> listeners.BucketListener::Inspect(%s)", bucketName)
	defer log.Debugf("<<< listeners.BucketListener::Inspect(%s)", bucketName)

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := utils.ProcessRegister(ctx, cancelFunc, "Bucket Inspect : "+in.GetName()); err != nil {
		return nil, fmt.Errorf("Failed to register the process : %s", err.Error())
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't inspect bucket: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't inspect bucket: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	resp, err := handler.Inspect(ctx, bucketName)
	if err != nil {
		tbr := errors.Wrap(err, "can't inspect bucket")
		return nil, grpc.Errorf(codes.Internal, tbr.Error())
	}
	if resp == nil {
		return nil, grpc.Errorf(codes.NotFound, "can't inspect bucket '%s': not found", in.GetName())
	}
	return conv.ToPBBucketMountPoint(resp), nil
}

// Mount a bucket on the filesystem of the host
func (s *BucketListener) Mount(ctx context.Context, in *pb.BucketMountingPoint) (*google_protobuf.Empty, error) {
	bucketName := in.GetBucket()
	hostName := in.GetHost().GetName()
	log.Infof("safescaled receiving 'bucket mount %s %s'", bucketName, hostName)
	log.Debugf(">>> listeners.BucketListener::Mount(%s, %s)", bucketName, hostName)
	defer log.Debugf("<<< listeners.BucketListener::Mount(%s, %s)", bucketName, hostName)

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := utils.ProcessRegister(ctx, cancelFunc, "Bucket Mount : "+bucketName+" on "+hostName); err != nil {
		return nil, fmt.Errorf("Failed to register the process : %s", err.Error())
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't mount buckets: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't mount bucket: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	err := handler.Mount(ctx, bucketName, hostName, in.GetPath())
	if err != nil {
		return &google_protobuf.Empty{}, grpc.Errorf(codes.Internal, err.Error())
	}
	return &google_protobuf.Empty{}, nil
}

// Unmount a bucket from the filesystem of the host
func (s *BucketListener) Unmount(ctx context.Context, in *pb.BucketMountingPoint) (*google_protobuf.Empty, error) {
	bucketName := in.GetBucket()
	hostName := in.GetHost().GetName()
	log.Infof("safescaled receiving 'bucket unmount %s %s'", bucketName, hostName)
	log.Debugf(">>> listeners.BucketListener::Unmount(%s, %s)", bucketName, hostName)
	defer log.Debugf("<<< listeners.BucketListener::Unmount(%s, %s)", bucketName, hostName)

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "Bucket Unount : "+bucketName+" off "+hostName); err != nil {
		return nil, fmt.Errorf("Failed to register the process : %s", err.Error())
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't unmount bucket: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't unmount bucket: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	err := handler.Unmount(ctx, bucketName, hostName)
	if err != nil {
		return &google_protobuf.Empty{}, grpc.Errorf(codes.Internal, err.Error())
	}
	return &google_protobuf.Empty{}, nil
}
