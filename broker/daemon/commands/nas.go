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
	"github.com/CS-SI/SafeScale/broker/daemon/services"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/broker"
	convert "github.com/CS-SI/SafeScale/broker/utils"
)

// broker nas create nas1 host1 --path="/shared/data"
// broker nas delete nas1
// broker nas mount nas1 host2 --path="/data"
// broker nas umount nas1 host2
// broker nas list
// broker nas inspect nas1

//NasServiceServer NAS service server grpc
type NasServiceServer struct{}

//Create call nas service creation
func (s *NasServiceServer) Create(ctx context.Context, in *pb.NasDefinition) (*pb.NasDefinition, error) {
	log.Printf("Create NAS called, name: %s", in.GetNas().GetName())
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot create NAS : No tenant set")
	}

	nasService := services.NewNasService(currentTenant.Client)
	nas, err := nasService.Create(in.GetNas().GetName(), in.GetHost().GetName(), in.GetPath())

	if err != nil {
		tbr := errors.Wrap(err, "Cannot create NAS")
		return nil, tbr
	}

	return convert.ToPBNas(nas), err
}

//Delete call nas service deletion
func (s *NasServiceServer) Delete(ctx context.Context, in *pb.NasName) (*pb.NasDefinition, error) {
	log.Printf("Delete NAS called, name %s", in.GetName())
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot delete NAS : No tenant set")
	}

	nasService := services.NewNasService(currentTenant.Client)
	nas, err := nasService.Delete(in.GetName())

	if err != nil {
		tbr := errors.Wrap(err, "Cannot delete NAS")
		return nil, tbr
	}
	return convert.ToPBNas(nas), err
}

//List return the list of all available nas
func (s *NasServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.NasList, error) {
	log.Printf("List NAS called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot list NAS : No tenant set")
	}

	nasService := services.NewNasService(currentTenant.Client)
	nass, err := nasService.List()

	if err != nil {
		tbr := errors.Wrap(err, "Cannot list NAS")
		return nil, tbr
	}

	var pbnass []*pb.NasDefinition

	// Map api.Network to pb.Network
	for _, nas := range nass {
		pbnass = append(pbnass, convert.ToPBNas(&nas))
	}
	rv := &pb.NasList{NasList: pbnass}
	return rv, nil
}

//Mount mount exported directory from nas on a local directory of the given host
func (s *NasServiceServer) Mount(ctx context.Context, in *pb.NasDefinition) (*pb.NasDefinition, error) {
	log.Printf("Mount NAS called, name %s", in.GetNas().GetName())
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot mount NAS : No tenant set")
	}

	nasService := services.NewNasService(currentTenant.Client)
	nas, err := nasService.Mount(in.GetNas().GetName(), in.GetHost().GetName(), in.GetPath())

	if err != nil {
		tbr := errors.Wrap(err, "Cannot mount NAS")
		return nil, tbr
	}
	return convert.ToPBNas(nas), err
}

//UMount umount exported directory from nas on a local directory of the given host
func (s *NasServiceServer) UMount(ctx context.Context, in *pb.NasDefinition) (*pb.NasDefinition, error) {
	log.Printf("UMount NAS called, name %s", in.GetNas().GetName())
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot unmount NAS : No tenant set")
	}

	nasService := services.NewNasService(currentTenant.Client)
	nas, err := nasService.UMount(in.GetNas().GetName(), in.GetHost().GetName())

	if err != nil {
		tbr := errors.Wrap(err, "Cannot unmount NAS")
		return nil, tbr
	}
	return convert.ToPBNas(nas), err
}

//Inspect shows the detail of a nfs server and all connected clients
func (s *NasServiceServer) Inspect(ctx context.Context, in *pb.NasName) (*pb.NasList, error) {
	log.Printf("Inspect NAS called, name %s", in.GetName())
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot inspect NAS : No tenant set")
	}

	nasService := services.NewNasService(currentTenant.Client)
	nass, err := nasService.Inspect(in.GetName())

	if err != nil {
		tbr := errors.Wrap(err, "Cannot inspect NAS")
		return nil, tbr
	}
	var pbnass []*pb.NasDefinition

	// Map api.Network to pb.Network
	for _, nas := range nass {
		pbnass = append(pbnass, convert.ToPBNas(nas))
	}
	rv := &pb.NasList{NasList: pbnass}
	return rv, nil
}
