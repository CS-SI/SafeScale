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

package commands

import (
	"context"
	"fmt"

	"github.com/CS-SI/SafeScale/broker/server/services"
	"github.com/CS-SI/SafeScale/providers"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/broker"
	convert "github.com/CS-SI/SafeScale/broker/utils"
)

// broker nas|share create nas1 host1 --path="/shared/data"
// broker nas|share delete nas1
// broker nas|share mount nas1 host2 --path="/data"
// broker nas|share umount nas1 host2
// broker nas|share list
// broker nas|share inspect nas1

// ShareServiceServer Share service server grpc
type ShareServiceServer struct{}

// Create calls share service creation
func (s *ShareServiceServer) Create(ctx context.Context, in *pb.ShareDefinition) (*pb.ShareDefinition, error) {
	log.Debugf("Create share '%s' called", in.GetName())

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't create Share: no tenant set")
	}
	shareService := services.NewShareService(providers.FromClient(currentTenant.Client))
	share, err := shareService.Create(in.GetName(), in.GetHost().GetName(), in.GetPath())
	if err != nil {
		tbr := errors.Wrap(err, "Can't create Share")
		return nil, tbr
	}
	return convert.ToPBShare(in.GetName(), share), err
}

// Delete call share service deletion
func (s *ShareServiceServer) Delete(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Debugf("Delete Share '%s' called", in.GetName())

	if GetCurrentTenant() == nil {
		return &google_protobuf.Empty{}, fmt.Errorf("Can't delete Share: no tenant set")
	}

	shareService := services.NewShareService(providers.FromClient(currentTenant.Client))
	_, _, err := shareService.Inspect(in.GetName())
	if err != nil {
		return &google_protobuf.Empty{}, errors.Wrap(err, fmt.Sprintf("Can't delete Share '%s'", in.GetName()))
	}

	err = shareService.Delete(in.GetName())
	if err != nil {
		return &google_protobuf.Empty{}, errors.Wrap(err, fmt.Sprintf("Can't delete Share '%s'", in.GetName()))
	}
	return &google_protobuf.Empty{}, nil
}

// List return the list of all available nas
func (s *ShareServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.ShareList, error) {
	log.Debugf("ShareServiceServer.List called")

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't list Shares: no tenant set")
	}

	shareService := services.NewShareService(providers.FromClient(currentTenant.Client))
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
func (s *ShareServiceServer) Mount(ctx context.Context, in *pb.ShareMountDefinition) (*pb.ShareMountDefinition, error) {
	log.Debugf("ShareServiceServer.Mount() called for share '%s' on host '%s' ", in.GetShare().GetName(), in.GetHost().GetName())

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't mount share: no tenant set")
	}

	shareService := services.NewShareService(providers.FromClient(currentTenant.Client))
	mount, err := shareService.Mount(in.GetShare().GetName(), in.GetHost().GetName(), in.GetPath())

	if err != nil {
		tbr := errors.Wrap(err, "Can't mount Share")
		return nil, tbr
	}
	return convert.ToPBShareMount(in.GetShare().GetName(), in.GetHost().GetName(), mount), err
}

// Unmount unmounts share from the given host
func (s *ShareServiceServer) Unmount(ctx context.Context, in *pb.ShareMountDefinition) (*google_protobuf.Empty, error) {
	shareName := in.GetShare().GetName()
	hostName := in.GetHost().GetName()
	log.Debugf("ShareServiceServer.Unmount() called for share '%s' on host '%s'", shareName, hostName)

	if GetCurrentTenant() == nil {
		err := fmt.Errorf("Can't unmount Share '%s': no tenant set", shareName)
		return &google_protobuf.Empty{}, err
	}

	shareService := services.NewShareService(providers.FromClient(currentTenant.Client))
	err := shareService.Unmount(shareName, hostName)
	if err != nil {
		return &google_protobuf.Empty{}, errors.Wrap(err, "Can't unmount Share")
	}
	return &google_protobuf.Empty{}, nil
}

// Inspect shows the detail of a share and all connected clients
func (s *ShareServiceServer) Inspect(ctx context.Context, in *pb.Reference) (*pb.ShareList, error) {
	log.Debugf("ShareServiceServer.Inspect() called for '%s'", in.GetName())

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't inspect Share '%s': no tenant set", in.GetName())
	}

	shareService := services.NewShareService(providers.FromClient(currentTenant.Client))
	host, share, err := shareService.Inspect(in.GetName())
	if err != nil {
		err := errors.Wrap(err, fmt.Sprintf("Can't inspect Share '%s'", in.GetName()))
		return nil, err
	}

	// Map propsv1.HostShare to pb.NasShare
	list := &pb.ShareList{ShareList: []*pb.ShareDefinition{convert.ToPBShare(host.ID, share)}}
	return list, nil
}
