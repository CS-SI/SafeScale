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
	"fmt"

	"github.com/CS-SI/SafeScale/broker/server/services"
	conv "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/broker"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

const logListenerBase = "Listeners: bucket"

// broker bucket create c1
// broker bucket mount c1 host1 --path="/shared/data" (utilisation de s3ql, par default /buckets/c1)
// broker bucket umount c1 host1
// broker bucket delete c1
// broker bucket list
// broker bucket inspect C1

// BucketServiceListener is the bucket service grpc server
type BucketServiceListener struct{}

// List available buckets
func (s *BucketServiceListener) List(ctx context.Context, in *google_protobuf.Empty) (*pb.BucketList, error) {
	log.Infof("%s list called", logListenerBase)
	defer log.Debugf("%s list done", logListenerBase)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot list buckets: No tenant set")
	}
	service := services.NewBucketService(currentTenant.Service)
	buckets, err := service.List()
	if err != nil {
		tbr := errors.Wrap(err, "Cannot list buckets")
		return nil, tbr
	}

	return conv.ToPBBucketList(buckets), nil
}

// Create a new bucket
func (s *BucketServiceListener) Create(ctx context.Context, in *pb.Bucket) (*google_protobuf.Empty, error) {
	log.Infof("%s create '%s' called", logListenerBase, in.Name)
	defer log.Debugf("%s create '%s' done", logListenerBase, in.Name)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("can't create bucket: no tenant set")
	}

	service := services.NewBucketService(currentTenant.Service)
	err := service.Create(in.GetName())
	if err != nil {
		tbr := errors.Wrap(err, "can't create bucket")
		return nil, tbr
	}

	return &google_protobuf.Empty{}, nil
}

// Delete a bucket
func (s *BucketServiceListener) Delete(ctx context.Context, in *pb.Bucket) (*google_protobuf.Empty, error) {
	log.Infof("%s delete '%s' called", logListenerBase, in.Name)
	defer log.Debugf("%s delete '%s' done", logListenerBase, in.Name)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("can't delete bucket: no tenant set")
	}

	service := services.NewBucketService(currentTenant.Service)
	err := service.Delete(in.GetName())
	if err != nil {
		tbr := errors.Wrap(err, "can't delete bucket")
		return nil, tbr
	}

	return &google_protobuf.Empty{}, nil
}

// Inspect a bucket
func (s *BucketServiceListener) Inspect(ctx context.Context, in *pb.Bucket) (*pb.BucketMountingPoint, error) {
	log.Infof("%s inspect '%s' called", logListenerBase, in.Name)
	defer log.Debugf("%s inspect '%s' called", logListenerBase, in.Name)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("can't inspect bucket: no tenant set")
	}

	service := services.NewBucketService(currentTenant.Service)
	resp, err := service.Inspect(in.GetName())
	if err != nil {
		tbr := errors.Wrap(err, "can't inspect bucket")
		return nil, tbr
	}

	return conv.ToPBBucketMountPoint(resp), nil
}

// Mount a bucket on the filesystem of the host
func (s *BucketServiceListener) Mount(ctx context.Context, in *pb.BucketMountingPoint) (*google_protobuf.Empty, error) {
	log.Infof("%s mount '%v' called", logListenerBase, in)
	defer log.Debugf("%s mount '%v' called", logListenerBase, in)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("can't mount bucket: no tenant set")
	}

	service := services.NewBucketService(currentTenant.Service)
	err := service.Mount(in.GetBucket(), in.GetHost().GetName(), in.GetPath())
	return &google_protobuf.Empty{}, err
}

// Unmount a bucket from the filesystem of the host
func (s *BucketServiceListener) Unmount(ctx context.Context, in *pb.BucketMountingPoint) (*google_protobuf.Empty, error) {
	log.Infof("%s umount '%v' called", logListenerBase, in)
	defer log.Debugf("%s umount '%v' done", logListenerBase, in)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't unmount bucket: no tenant set")
	}

	service := services.NewBucketService(currentTenant.Service)
	err := service.Unmount(in.GetBucket(), in.GetHost().GetName())

	return &google_protobuf.Empty{}, err
}
