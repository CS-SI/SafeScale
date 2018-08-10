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
	conv "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/providers"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/broker"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// broker container create c1
// broker container mount c1 host1 --path="/shared/data" (utilisation de s3ql, par default /containers/c1)
// broker container umount c1 host1
// broker container delete c1
// broker container list
// broker container inspect C1

//ContainerServiceServer is the container service grpc server
type ContainerServiceServer struct{}

//List available containers
func (s *ContainerServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.ContainerList, error) {
	log.Printf("Container list called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot list containers : No tenant set")
	}

<<<<<<< develop:broker/server/commands/container.go
	service := services.NewContainerService(providers.FromClient(currentTenant.Client))
||||||| ancestor
	service := services.NewContainerService(currentTenant.Client)
=======
	service := services.NewContainerServiceObject(currentTenant.Location)
>>>>>>> Update object storage management:broker/daemon/commands/container.go
	containers, err := service.List()
	if err != nil {
		tbr := errors.Wrap(err, "Cannot list containers")
		return nil, tbr
	}

	return conv.ToPBContainerList(containers), nil
}

//Create a new container
func (s *ContainerServiceServer) Create(ctx context.Context, in *pb.Container) (*google_protobuf.Empty, error) {
	log.Printf("Create container called '%s'", in.Name)
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't create container: no tenant set")
	}

<<<<<<< develop:broker/server/commands/container.go
	service := services.NewContainerService(providers.FromClient(currentTenant.Client))
||||||| ancestor
	service := services.NewContainerService(currentTenant.Client)
=======
	service := services.NewContainerServiceObject(currentTenant.Location)
>>>>>>> Update object storage management:broker/daemon/commands/container.go
	err := service.Create(in.GetName())
	if err != nil {
		tbr := errors.Wrap(err, "Can't create container")
		return nil, tbr
	}

	return &google_protobuf.Empty{}, nil
}

//Delete a container
func (s *ContainerServiceServer) Delete(ctx context.Context, in *pb.Container) (*google_protobuf.Empty, error) {
	log.Printf("Delete container called '%s'", in.Name)
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't delete container: no tenant set")
	}

<<<<<<< develop:broker/server/commands/container.go
	service := services.NewContainerService(providers.FromClient(currentTenant.Client))
||||||| ancestor
	service := services.NewContainerService(currentTenant.Client)
=======
	service := services.NewContainerServiceObject(currentTenant.Location)
>>>>>>> Update object storage management:broker/daemon/commands/container.go
	err := service.Delete(in.GetName())
	if err != nil {
		tbr := errors.Wrap(err, "Can't delete container")
		return nil, tbr
	}

	return &google_protobuf.Empty{}, nil
}

//Inspect a container
func (s *ContainerServiceServer) Inspect(ctx context.Context, in *pb.Container) (*pb.ContainerMountingPoint, error) {
	log.Printf("Inspect container called '%s'", in.Name)
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't inspect container: no tenant set")
	}

	service := services.NewContainerService(providers.FromClient(currentTenant.Client))
	resp, err := service.Inspect(in.GetName())
	if err != nil {
		tbr := errors.Wrap(err, "Can't inspect container")
		return nil, tbr
	}

	return conv.ToPBContainerMountPoint(resp), nil
}

//Mount a container on the filesystem of the host
func (s *ContainerServiceServer) Mount(ctx context.Context, in *pb.ContainerMountingPoint) (*google_protobuf.Empty, error) {
	log.Printf("Mount container called, host '%s', mountpoint '%s'", in.Host, in.Container)
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't mount container: no tenant set")
	}

	service := services.NewContainerService(providers.FromClient(currentTenant.Client))
	err := service.Mount(in.GetContainer(), in.GetHost().GetName(), in.GetPath())

	return &google_protobuf.Empty{}, err
}

//UMount a container from the filesystem of the host
func (s *ContainerServiceServer) UMount(ctx context.Context, in *pb.ContainerMountingPoint) (*google_protobuf.Empty, error) {
	log.Printf("UMount container called, host '%s', mountpoint '%s'", in.Host, in.Container)
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't unmount container: no tenant set")
	}

	service := services.NewContainerService(providers.FromClient(currentTenant.Client))
	err := service.UMount(in.GetContainer(), in.GetHost().GetName())

	return &google_protobuf.Empty{}, err
}
