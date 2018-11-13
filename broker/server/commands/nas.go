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

// broker nas create nas1 host1 --path="/shared/data"
// broker nas delete nas1
// broker nas mount nas1 host2 --path="/data"
// broker nas umount nas1 host2
// broker nas list
// broker nas inspect nas1

// NasServiceServer NAS service server grpc
type NasServiceServer struct{}

// Create call nas service creation
func (s *NasServiceServer) Create(ctx context.Context, in *pb.NasExportDefinition) (*pb.NasExportDefinition, error) {
	log.Printf("Create NAS called, name: '%s'", in.GetName().GetName())
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot create NAS : No tenant set")
	}

	nasService := services.NewNasService(providers.FromClient(currentTenant.Client))
	export, err := nasService.Create(in.GetName().GetName(), in.GetHost().GetName(), in.GetPath())

	if err != nil {
		tbr := errors.Wrap(err, "Cannot create NAS")
		return nil, tbr
	}
	if export == nil {
		tbr := errors.Errorf("Cannot create NAS: unknown error")
		return nil, tbr
	}

	return convert.ToPBNasExport(in.GetName().GetName(), *export), err
}

// Delete call nas service deletion
func (s *NasServiceServer) Delete(ctx context.Context, in *pb.NasExportName) (*google_protobuf.Empty, error) {
	log.Printf("Delete NAS called, name '%s'", in.GetName())
	if GetCurrentTenant() == nil {
		return &google_protobuf.Empty{}, fmt.Errorf("Cannot delete NAS : No tenant set")
	}

	nasService := services.NewNasService(providers.FromClient(currentTenant.Client))
	_, _, err := nasService.Inspect(in.GetName())
	if err != nil {
		return &google_protobuf.Empty{}, errors.Wrap(err, fmt.Sprintf("Cannot delete NAS export '%s'", in.GetName()))
	}

	err = nasService.Delete(in.GetName())
	if err != nil {
		return &google_protobuf.Empty{}, errors.Wrap(err, fmt.Sprintf("Cannot delete NAS export '%s'", in.GetName()))
	}
	return &google_protobuf.Empty{}, nil
}

// List return the list of all available nas
func (s *NasServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.NasExportList, error) {
	log.Infof("List NAS called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot list NAS : No tenant set")
	}

	nasService := services.NewNasService(providers.FromClient(currentTenant.Client))
	exports, err := nasService.List()

	if err != nil {
		tbr := errors.Wrap(err, "Cannot list NAS")
		return nil, tbr
	}

	var pbexports []*pb.NasExportDefinition

	// Map api.Network to pb.Network
	for k, item := range exports {
		for _, export := range item {
			pbexports = append(pbexports, convert.ToPBNasExport(k, export))
		}
	}
	list := &pb.NasExportList{ExportList: pbexports}
	return list, nil
}

// Mount mount exported directory from nas on a local directory of the given host
func (s *NasServiceServer) Mount(ctx context.Context, in *pb.NasMountDefinition) (*pb.NasMountDefinition, error) {
	log.Infof("Mount NAS called, name '%s'", in.GetName().GetName())
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot mount NAS : No tenant set")
	}

	nasService := services.NewNasService(providers.FromClient(currentTenant.Client))
	mount, err := nasService.Mount(in.GetName().GetName(), in.GetHost().GetName(), in.GetPath())

	if err != nil {
		tbr := errors.Wrap(err, "Cannot mount NAS")
		return nil, tbr
	}
	return convert.ToPBNasMount(in.GetName().GetName(), in.GetHost().GetName(), mount), err
}

// Unmount unmounts remotely exported directory from the given host
func (s *NasServiceServer) Unmount(ctx context.Context, in *pb.NasMountDefinition) (*google_protobuf.Empty, error) {
	log.Infof("Unmount NAS export name '%s' called.", in.GetName().GetName())
	if GetCurrentTenant() == nil {
		err := fmt.Errorf("Cannot unmount NAS export '%s': No tenant set", in.GetName().GetName())
		return &google_protobuf.Empty{}, err
	}

	nasService := services.NewNasService(providers.FromClient(currentTenant.Client))
	err := nasService.Unmount(in.GetName().GetName(), in.GetHost().GetName())
	if err != nil {
		return &google_protobuf.Empty{}, errors.Wrap(err, "Cannot unmount NAS export")
	}
	return &google_protobuf.Empty{}, nil
}

// Inspect shows the detail of a nfs server and all connected clients
func (s *NasServiceServer) Inspect(ctx context.Context, in *pb.NasExportName) (*pb.NasExportList, error) {
	log.Infof("Inspect NAS export '%s' called", in.GetName())
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot inspect NAS export: No tenant set")
	}

	nasService := services.NewNasService(providers.FromClient(currentTenant.Client))
	nas, export, err := nasService.Inspect(in.GetName())
	if err != nil {
		err := errors.Wrap(err, fmt.Sprintf("Cannot inspect NAS export '%s'", in.GetName()))
		return nil, err
	}

	// Map propsv1.HostExport to pb.NasExport
	list := &pb.NasExportList{ExportList: []*pb.NasExportDefinition{convert.ToPBNasExport(nas.Name, export)}}
	return list, nil
}
