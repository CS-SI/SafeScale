/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/pkg/errors"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/server/handlers"
	conv "github.com/CS-SI/SafeScale/broker/utils"
)

const logListenerBase = "Listeners: bucket"

// BucketHandler ...
var BucketHandler = handlers.NewBucketHandler

// broker bucket create c1
// broker bucket mount c1 host1 --path="/shared/data" (utilisation de s3ql, par default /buckets/c1)
// broker bucket umount c1 host1
// broker bucket delete c1
// broker bucket list
// broker bucket inspect C1

// BucketListener is the bucket service grpc server
type BucketListener struct{}

// List available buckets
func (s *BucketListener) List(ctx context.Context, in *google_protobuf.Empty) (*pb.BucketList, error) {
	log.Infof("%s list called", logListenerBase)
	defer log.Debugf("%s list done", logListenerBase)

	tenant := GetCurrentTenant()
	if tenant == nil {
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't list buckets: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	buckets, err := handler.List()
	if err != nil {
		tbr := errors.Wrap(err, "Can't list buckets")
		return nil, grpc.Errorf(codes.Internal, tbr.Error())
	}

	return conv.ToPBBucketList(buckets), nil
}

// Create a new bucket
func (s *BucketListener) Create(ctx context.Context, in *pb.Bucket) (*google_protobuf.Empty, error) {
	log.Infof("%s create '%s' called", logListenerBase, in.Name)
	defer log.Debugf("%s create '%s' done", logListenerBase, in.Name)

	tenant := GetCurrentTenant()
	if tenant == nil {
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't create bucket: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	err := handler.Create(in.GetName())
	if err != nil {
		tbr := errors.Wrap(err, "can't create bucket")
		return nil, grpc.Errorf(codes.Internal, tbr.Error())
	}

	return &google_protobuf.Empty{}, nil
}

// Delete a bucket
func (s *BucketListener) Delete(ctx context.Context, in *pb.Bucket) (*google_protobuf.Empty, error) {
	log.Infof("%s delete '%s' called", logListenerBase, in.Name)
	defer log.Debugf("%s delete '%s' done", logListenerBase, in.Name)

	tenant := GetCurrentTenant()
	if tenant == nil {
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't delete bucket: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	err := handler.Delete(in.GetName())
	if err != nil {
		tbr := errors.Wrap(err, "can't delete bucket")
		return nil, grpc.Errorf(codes.Internal, tbr.Error())
	}

	return &google_protobuf.Empty{}, nil
}

// Inspect a bucket
func (s *BucketListener) Inspect(ctx context.Context, in *pb.Bucket) (*pb.BucketMountingPoint, error) {
	log.Infof("%s inspect '%s' called", logListenerBase, in.Name)
	defer log.Debugf("%s inspect '%s' called", logListenerBase, in.Name)

	tenant := GetCurrentTenant()
	if tenant == nil {
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't inspect bucket: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	resp, err := handler.Inspect(in.GetName())
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
	log.Infof("%s mount '%v' called", logListenerBase, in)
	defer log.Debugf("%s mount '%v' called", logListenerBase, in)

	tenant := GetCurrentTenant()
	if tenant == nil {
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't mount bucket: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	err := handler.Mount(in.GetBucket(), in.GetHost().GetName(), in.GetPath())
	if err != nil {
		return &google_protobuf.Empty{}, grpc.Errorf(codes.Internal, err.Error())
	}
	return &google_protobuf.Empty{}, nil
}

// Unmount a bucket from the filesystem of the host
func (s *BucketListener) Unmount(ctx context.Context, in *pb.BucketMountingPoint) (*google_protobuf.Empty, error) {
	log.Infof("%s umount '%v' called", logListenerBase, in)
	defer log.Debugf("%s umount '%v' done", logListenerBase, in)

	tenant := GetCurrentTenant()
	if tenant == nil {
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't unmount bucket: no tenant set")
	}

	handler := BucketHandler(tenant.Service)
	err := handler.Unmount(in.GetBucket(), in.GetHost().GetName())
	if err != nil {
		return &google_protobuf.Empty{}, grpc.Errorf(codes.Internal, err.Error())
	}
	return &google_protobuf.Empty{}, nil
}
