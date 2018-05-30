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
	"log"

	services "github.com/CS-SI/SafeScale/broker/daemon/services"
	conv "github.com/CS-SI/SafeScale/broker/utils"

	pb "github.com/CS-SI/SafeScale/broker"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// broker container create c1
// broker container mount c1 vm1 --path="/shared/data" (utilisation de s3ql, par default /containers/c1)
// broker container umount c1 vm1
// broker container delete c1
// broker container list
// broker container inspect C1

//ContainerServiceServer is the container service grpc server
type ContainerServiceServer struct{}

//List available containers
func (s *ContainerServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.ContainerList, error) {
	log.Printf("Container list called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := services.NewContainerService(currentTenant.client)
	containers, err := service.List()
	if err != nil {
		return nil, err
	}

	log.Println("End container list")
	return conv.ToPBContainerList(containers), nil
}

//Create a new container
func (s *ContainerServiceServer) Create(ctx context.Context, in *pb.Container) (*google_protobuf.Empty, error) {
	log.Printf("Create container called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := services.NewContainerService(currentTenant.client)
	err := service.Create(in.GetName())
	if err != nil {
		return nil, err
	}

	log.Println("End container container")
	return &google_protobuf.Empty{}, nil
}

//Delete a container
func (s *ContainerServiceServer) Delete(ctx context.Context, in *pb.Container) (*google_protobuf.Empty, error) {
	log.Printf("Delete container called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := services.NewContainerService(currentTenant.client)
	err := service.Delete(in.GetName())
	if err != nil {
		return nil, err
	}

	log.Println("End delete container")
	return &google_protobuf.Empty{}, nil
}

//Inspect a container
func (s *ContainerServiceServer) Inspect(ctx context.Context, in *pb.Container) (*pb.ContainerMountingPoint, error) {
	log.Printf("Inspect container called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := services.NewContainerService(currentTenant.client)
	resp, err := service.Inspect(in.GetName())
	if err != nil {
		return nil, err
	}

	log.Println("End inspect container")
	return conv.ToPBContainerMountPoint(resp), nil
}

//Mount a container on the filesystem of the VM
func (s *ContainerServiceServer) Mount(ctx context.Context, in *pb.ContainerMountingPoint) (*google_protobuf.Empty, error) {
	log.Printf("Mount container called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := services.NewContainerService(currentTenant.client)
	err := service.Mount(in.GetContainer(), in.GetVM().GetName(), in.GetPath())

	log.Println("End Mount container")
	return &google_protobuf.Empty{}, err
}

//UMount a container from the filesystem of the VM
func (s *ContainerServiceServer) UMount(ctx context.Context, in *pb.ContainerMountingPoint) (*google_protobuf.Empty, error) {
	log.Printf("UMount container called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := services.NewContainerService(currentTenant.client)
	err := service.UMount(in.GetContainer(), in.GetVM().GetName())

	log.Println("End UMount container")
	return &google_protobuf.Empty{}, err
}
