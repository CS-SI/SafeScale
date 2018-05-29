package commands
/*
* Copyright 2015-2018, CS Systemes d'Information, http://www.c-s.fr
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

import (
	"context"
	"fmt"
	"log"

	services "github.com/SafeScale/broker/daemon/services"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"

	pb "github.com/SafeScale/broker"
	convert "github.com/SafeScale/broker/utils"
)

// broker nas create nas1 vm1 --path="/shared/data"
// broker nas delete nas1
// broker nas mount nas1 vm2 --path="/data"
// broker nas umount nas1 vm2
// broker nas list
// broker nas inspect nas1

//NasServiceServer NAS service server grpc
type NasServiceServer struct{}

//Create call nas service creation
func (s *NasServiceServer) Create(ctx context.Context, in *pb.NasDefinition) (*pb.NasDefinition, error) {
	log.Printf("Create NAS called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	nasService := services.NewNasService(currentTenant.client)
	nas, err := nasService.Create(in.GetNas().GetName(), in.GetVM().GetName(), in.GetPath())

	if err != nil {
		log.Println(err)
		return nil, err
	}
	log.Printf("End Create Nas")
	return convert.ToPBNas(nas), err
}

//Delete call nas service deletion
func (s *NasServiceServer) Delete(ctx context.Context, in *pb.NasName) (*pb.NasDefinition, error) {
	log.Printf("Delete NAS called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	nasService := services.NewNasService(currentTenant.client)
	nas, err := nasService.Delete(in.GetName())

	if err != nil {
		log.Println(err)
		return nil, err
	}
	log.Printf("End Delete Nas")
	return convert.ToPBNas(nas), err
}

//List return the list of all available nas
func (s *NasServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.NasList, error) {
	log.Printf("List NAS called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	nasService := services.NewNasService(currentTenant.client)
	nass, err := nasService.List()

	if err != nil {
		log.Println(err)
		return nil, err
	}

	var pbnass []*pb.NasDefinition

	// Map api.Network to pb.Network
	for _, nas := range nass {
		pbnass = append(pbnass, convert.ToPBNas(&nas))
	}
	rv := &pb.NasList{NasList: pbnass}
	log.Printf("End List Nas")
	return rv, nil
}

//Mount mount exported directory from nas on a local directory of the given vm
func (s *NasServiceServer) Mount(ctx context.Context, in *pb.NasDefinition) (*pb.NasDefinition, error) {
	log.Printf("Mount NAS called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	nasService := services.NewNasService(currentTenant.client)
	nas, err := nasService.Mount(in.GetNas().GetName(), in.GetVM().GetName(), in.GetPath())

	if err != nil {
		log.Println(err)
		return nil, err
	}
	log.Printf("End mount Nas")
	return convert.ToPBNas(nas), err
}

//UMount umount exported directory from nas on a local directory of the given vm
func (s *NasServiceServer) UMount(ctx context.Context, in *pb.NasDefinition) (*pb.NasDefinition, error) {
	log.Printf("UMount NAS called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	nasService := services.NewNasService(currentTenant.client)
	nas, err := nasService.UMount(in.GetNas().GetName(), in.GetVM().GetName())

	if err != nil {
		log.Println(err)
		return nil, err
	}
	log.Printf("End umount Nas")
	return convert.ToPBNas(nas), err
}

//Inspect shows the detail of a nfs server and all connected clients
func (s *NasServiceServer) Inspect(ctx context.Context, in *pb.NasName) (*pb.NasList, error) {
	log.Printf("Inspect NAS called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	nasService := services.NewNasService(currentTenant.client)
	nass, err := nasService.Inspect(in.GetName())

	if err != nil {
		log.Println(err)
		return nil, err
	}
	var pbnass []*pb.NasDefinition

	// Map api.Network to pb.Network
	for _, nas := range nass {
		pbnass = append(pbnass, convert.ToPBNas(&nas))
	}
	rv := &pb.NasList{NasList: pbnass}
	log.Printf("End Inspect Nas")
	return rv, nil
}
