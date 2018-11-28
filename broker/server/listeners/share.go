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
	"github.com/CS-SI/SafeScale/providers/model"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/broker"
	convert "github.com/CS-SI/SafeScale/broker/utils"
)

// broker nas|share create share1 host1 --path="/shared/data"
// broker nas|share delete share1
// broker nas|share mount share1 host2 --path="/data"
// broker nas|share umount share1 host2
// broker nas|share list
// broker nas|share inspect share1

// ShareServiceListener Share service server grpc
type ShareServiceListener struct{}

// Create calls share service creation
func (s *ShareServiceListener) Create(ctx context.Context, in *pb.ShareDefinition) (*pb.ShareDefinition, error) {
	log.Infof("Listeners: share create '%v'", in)
	defer log.Debugf("Listeners: share create '%v' done", in)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("can't create share: no tenant set")
	}
	shareService := services.NewShareService(currentTenant.Service)
	shareName := in.GetName()
	share, err := shareService.Create(shareName, in.GetHost().GetName(), in.GetPath())
	if err != nil {
		tbr := errors.Wrap(err, fmt.Sprintf("can't create share '%s'", shareName))
		return nil, tbr
	}
	return convert.ToPBShare(in.GetName(), share), err
}

// Delete call share service deletion
func (s *ShareServiceListener) Delete(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	shareName := in.GetName()
	log.Infof("Listeners: share delete '%s' called", shareName)
	defer log.Debugf("Listeners: share delete '%s' done", shareName)

	if GetCurrentTenant() == nil {
		return &google_protobuf.Empty{}, fmt.Errorf("can't delete share '%s': no tenant set", shareName)
	}

	shareService := services.NewShareService(currentTenant.Service)
	_, _, _, err := shareService.Inspect(shareName)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
			return &google_protobuf.Empty{}, err
		default:
			return &google_protobuf.Empty{}, errors.Wrap(err, fmt.Sprintf("can't delete share '%s'", shareName))
		}
	}

	err = shareService.Delete(shareName)
	if err != nil {
		return &google_protobuf.Empty{}, errors.Wrap(err, fmt.Sprintf("can't delete share '%s'", shareName))
	}
	return &google_protobuf.Empty{}, nil
}

// List return the list of all available shares
func (s *ShareServiceListener) List(ctx context.Context, in *google_protobuf.Empty) (*pb.ShareList, error) {
	log.Infof("Listeners: share list '%v' called", in)
	defer log.Debugf("Listeners: share list '%v' done", in)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't list Shares: no tenant set")
	}

	shareService := services.NewShareService(currentTenant.Service)
	shares, err := shareService.List()
	if err != nil {
		tbr := errors.Wrap(err, "Can't list Shares")
		return nil, tbr
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
func (s *ShareServiceListener) Mount(ctx context.Context, in *pb.ShareMountDefinition) (*pb.ShareMountDefinition, error) {
	log.Infof("Listeners: share mount '%v' called", in)
	defer log.Debugf("Listeners: share mount '%v' called", in)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't mount share: no tenant set")
	}

	shareService := services.NewShareService(currentTenant.Service)
	shareName := in.GetShare().GetName()
	mount, err := shareService.Mount(shareName, in.GetHost().GetName(), in.GetPath())
	if err != nil {
		tbr := errors.Wrap(err, fmt.Sprintf("Can't mount share '%s'", shareName))
		return nil, tbr
	}
	return convert.ToPBShareMount(in.GetShare().GetName(), in.GetHost().GetName(), mount), err
}

// Unmount unmounts share from the given host
func (s *ShareServiceListener) Unmount(ctx context.Context, in *pb.ShareMountDefinition) (*google_protobuf.Empty, error) {
	log.Infof("Listeners: share unmount '%v' called", in)
	defer log.Debugf("Listeners: share unmount '%v' called", in)

	shareName := in.GetShare().GetName()
	if GetCurrentTenant() == nil {
		err := fmt.Errorf("Can't unmount share '%s': no tenant set", shareName)
		return &google_protobuf.Empty{}, err
	}

	shareService := services.NewShareService(currentTenant.Service)
	hostName := in.GetHost().GetName()
	err := shareService.Unmount(shareName, hostName)
	if err != nil {
		return &google_protobuf.Empty{}, errors.Wrap(err, fmt.Sprintf("Can't unmount share '%s'", shareName))
	}
	return &google_protobuf.Empty{}, nil
}

// Inspect shows the detail of a share and all connected clients
func (s *ShareServiceListener) Inspect(ctx context.Context, in *pb.Reference) (*pb.ShareMountList, error) {
	shareName := in.GetName()
	log.Infof("Listeners: share inspect '%s' called", shareName)
	defer log.Debugf("Listeners: share inspect '%s' done", shareName)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("can't inspect share '%s': no tenant set", shareName)
	}

	shareService := services.NewShareService(currentTenant.Service)
	host, share, mounts, err := shareService.Inspect(shareName)
	if err != nil {
		err := errors.Wrap(err, fmt.Sprintf("can't inspect share '%s'", shareName))
		return nil, err
	}

	return convert.ToPBShareMountList(host.Name, share, mounts), nil
}
