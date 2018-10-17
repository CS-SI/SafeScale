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

	pb "github.com/CS-SI/SafeScale/broker"
	services "github.com/CS-SI/SafeScale/broker/daemon/services"
	conv "github.com/CS-SI/SafeScale/broker/utils"
	utils "github.com/CS-SI/SafeScale/broker/utils"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// broker host create host1 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=true
// broker host list --all=false
// broker host inspect host1
// broker host create host2 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=false

// HostServiceServer host service server grpc
type HostServiceServer struct{}

func (s *HostServiceServer) Start(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Start host called '%s'", in.Name)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot start host : No tenant set")
	}

	ref := utils.GetReference(in)
	hostAPI := services.NewHostService(currentTenant.Client)

	err := hostAPI.Start(ref)
	if err != nil {
		return nil, err
	}

	log.Printf("Host '%s' started", ref)
	return &google_protobuf.Empty{}, nil
}

func (s *HostServiceServer) Stop(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Stop host called '%s'", in.Name)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot stop host : No tenant set")
	}

	ref := utils.GetReference(in)
	hostAPI := services.NewHostService(currentTenant.Client)

	err := hostAPI.Stop(ref)
	if err != nil {
		return nil, err
	}

	log.Printf("Host '%s' rebooted", ref)
	return &google_protobuf.Empty{}, nil
}

func (s *HostServiceServer) Reboot(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Reboot host called, '%s'", in.Name)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot reboot host : No tenant set")
	}

	ref := utils.GetReference(in)
	hostAPI := services.NewHostService(currentTenant.Client)

	err := hostAPI.Reboot(ref)
	if err != nil {
		return nil, err
	}

	log.Printf("Host '%s' rebooted", ref)
	return &google_protobuf.Empty{}, nil
}

// List available hosts
func (s *HostServiceServer) List(ctx context.Context, in *pb.HostListRequest) (*pb.HostList, error) {
	log.Printf("List hosts called")

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot list hosts : No tenant set")
	}

	hostAPI := services.NewHostService(currentTenant.Client)

	hosts, err := hostAPI.List(in.GetAll())
	if err != nil {
		return nil, err
	}

	var pbhost []*pb.Host

	// Map api.Host to pb.Host
	for _, host := range hosts {
		pbhost = append(pbhost, conv.ToPBHost(&host))
	}
	rv := &pb.HostList{Hosts: pbhost}
	log.Printf("End List hosts")
	return rv, nil
}

// Create a new host
func (s *HostServiceServer) Create(ctx context.Context, in *pb.HostDefinition) (*pb.Host, error) {
	log.Printf("Create host called '%s'", in.Name)
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot create host : No tenant set")
	}

	hostService := services.NewHostService(currentTenant.Client)
	host, err := hostService.Create(in.GetName(), in.GetNetwork(),
		int(in.GetCPUNumber()), in.GetRAM(), int(in.GetDisk()), in.GetImageID(), in.GetPublic())

	if err != nil {
		log.Println(err)
		return nil, err
	}

	log.Printf("Host '%s' created", in.GetName())
	return conv.ToPBHost(host), nil
}

// Inspect an host
func (s *HostServiceServer) Inspect(ctx context.Context, in *pb.Reference) (*pb.Host, error) {
	log.Printf("Inspect Host called '%s'", in.Name)

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Cannot inspect host : Neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot inspect host : No tenant set")
	}

	hostService := services.NewHostService(currentTenant.Client)
	host, err := hostService.Get(ref)
	if err != nil {
		return nil, err
	}
	if host == nil {
		return nil, fmt.Errorf("Cannot inspect host : No host '%s' found", ref)
	}

	log.Printf("End Inspect Host: '%s'", ref)
	return conv.ToPBHost(host), nil
}

// Delete an host
func (s *HostServiceServer) Delete(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Delete Host called '%s'", in.Name)

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Cannot delete host : Neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot delete host : No tenant set")
	}
	hostService := services.NewHostService(currentTenant.Client)
	err := hostService.Delete(ref)
	if err != nil {
		return nil, err
	}
	log.Printf("Host '%s' deleted", ref)
	return &google_protobuf.Empty{}, nil
}

// SSH returns ssh parameters to access an host
func (s *HostServiceServer) SSH(ctx context.Context, in *pb.Reference) (*pb.SshConfig, error) {
	log.Printf("Ssh Host called '%s'", in.Name)

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Cannot ssh host : Neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot ssh host : No tenant set")
	}
	hostService := services.NewHostService(currentTenant.Client)
	sshConfig, err := hostService.SSH(ref)
	if err != nil {
		return nil, err
	}
	log.Printf("Got Ssh config for host '%s'", ref)
	return conv.ToPBSshConfig(sshConfig), nil
}
