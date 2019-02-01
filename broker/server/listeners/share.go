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

	"github.com/CS-SI/SafeScale/providers/model"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/server/handlers"
	convert "github.com/CS-SI/SafeScale/broker/utils"
)

// ShareHandler ...
var ShareHandler = handlers.NewShareHandler

// broker nas|share create share1 host1 --path="/shared/data"
// broker nas|share delete share1
// broker nas|share mount share1 host2 --path="/data"
// broker nas|share umount share1 host2
// broker nas|share list
// broker nas|share inspect share1

// ShareListener Share service server grpc
type ShareListener struct{}

// Create calls share service creation
func (s *ShareListener) Create(ctx context.Context, in *pb.ShareDefinition) (*pb.ShareDefinition, error) {
	log.Infof(">>> Listeners: share create '%v'", in)
	defer log.Debugf("<<< Listeners: share create '%v'", in)

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't create share: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't create share: no tenant set")
	}

	handler := ShareHandler(tenant.Service)
	shareName := in.GetName()
	share, err := handler.Create(shareName, in.GetHost().GetName(), in.GetPath())
	if err != nil {
		tbr := errors.Wrap(err, fmt.Sprintf("can't create share '%s'", shareName))
		return nil, grpc.Errorf(codes.Internal, tbr.Error())
	}
	return convert.ToPBShare(in.GetName(), share), err
}

// Delete call share service deletion
func (s *ShareListener) Delete(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	shareName := in.GetName()
	log.Infof(">>> Listeners: share delete '%s'", shareName)
	defer log.Debugf("<<< Listeners: share delete '%s'", shareName)

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't delete share: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't delete share: no tenant set")
	}

	handler := ShareHandler(tenant.Service)
	_, _, _, err := handler.Inspect(shareName)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
			return &google_protobuf.Empty{}, grpc.Errorf(codes.NotFound, err.Error())
		default:
			return &google_protobuf.Empty{}, grpc.Errorf(codes.Internal, errors.Wrap(err, fmt.Sprintf("can't delete share '%s'", shareName)).Error())
		}
	}

	err = handler.Delete(shareName)
	if err != nil {
		return &google_protobuf.Empty{}, grpc.Errorf(codes.Internal, errors.Wrap(err, fmt.Sprintf("can't delete share '%s'", shareName)).Error())
	}
	return &google_protobuf.Empty{}, nil
}

// List return the list of all available shares
func (s *ShareListener) List(ctx context.Context, in *google_protobuf.Empty) (*pb.ShareList, error) {
	log.Infof(">>> Listeners: share list '%v'", in)
	defer log.Debugf("<<< Listeners: share list '%v'", in)

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't list share: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't list shares: no tenant set")
	}

	handler := ShareHandler(tenant.Service)
	shares, err := handler.List()
	if err != nil {
		tbr := errors.Wrap(err, "Can't list Shares")
		return nil, grpc.Errorf(codes.Internal, tbr.Error())
	}

	var pbshares []*pb.ShareDefinition
	for k, item := range shares {
		for _, share := range item {
			pbshares = append(pbshares, convert.ToPBShare(k, share))
		}
	}
	list := &pb.ShareList{ShareList: pbshares}
	return list, nil
}

// Mount mounts share on a local directory of the given host
func (s *ShareListener) Mount(ctx context.Context, in *pb.ShareMountDefinition) (*pb.ShareMountDefinition, error) {
	log.Infof(">>> Listeners: share mount '%v'", in)
	defer log.Debugf("<<< Listeners: share mount '%v'", in)

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't mount share: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't mount share: no tenant set")
	}

	shareName := in.GetShare().GetName()

	handler := ShareHandler(tenant.Service)
	mount, err := handler.Mount(shareName, in.GetHost().GetName(), in.GetPath())
	if err != nil {
		tbr := errors.Wrap(err, fmt.Sprintf("Can't mount share '%s'", shareName))
		return nil, grpc.Errorf(codes.Internal, tbr.Error())
	}
	return convert.ToPBShareMount(in.GetShare().GetName(), in.GetHost().GetName(), mount), nil
}

// Unmount unmounts share from the given host
func (s *ShareListener) Unmount(ctx context.Context, in *pb.ShareMountDefinition) (*google_protobuf.Empty, error) {
	log.Infof(">>> Listeners: share unmount '%v'", in)
	defer log.Debugf("<<< Listeners: share unmount '%v'", in)

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't mount share: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't unmount share: no tenant set")
	}

	shareName := in.GetShare().GetName()
	hostName := in.GetHost().GetName()

	handler := ShareHandler(tenant.Service)
	err := handler.Unmount(shareName, hostName)
	if err != nil {
		return &google_protobuf.Empty{}, grpc.Errorf(codes.Internal, errors.Wrap(err, fmt.Sprintf("Can't unmount share '%s'", shareName)).Error())
	}
	return &google_protobuf.Empty{}, nil
}

// Inspect shows the detail of a share and all connected clients
func (s *ShareListener) Inspect(ctx context.Context, in *pb.Reference) (*pb.ShareMountList, error) {
	shareName := in.GetName()
	log.Infof(">>> Listeners: share inspect '%s'", shareName)
	defer log.Debugf("<<< Listeners: share inspect '%s'", shareName)

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't inspect share: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't inspect share: no tenant set")
	}

	handler := ShareHandler(tenant.Service)
	host, share, mounts, err := handler.Inspect(shareName)
	if err != nil {
		err := errors.Wrap(err, fmt.Sprintf("can't inspect share '%s'", shareName))
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}
	if host == nil {
		return nil, model.ResourceNotFoundError("host", "host:"+shareName)
	}

	return convert.ToPBShareMountList(host.Name, share, mounts), nil
}
