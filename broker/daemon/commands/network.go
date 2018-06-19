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
	utils "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/providers/api/IPVersion"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// broker network create net1 --cidr="192.145.0.0/16" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" (par défault "192.168.0.0/24", on crée une gateway sur chaque réseau: gw_net1)
// broker network list
// broker network delete net1
// broker network inspect net1

//NetworkServiceServer network service server grpc
type NetworkServiceServer struct{}

//Create a new network
func (s *NetworkServiceServer) Create(ctx context.Context, in *pb.NetworkDefinition) (*pb.Network, error) {
	log.Println("Create Network called")

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	networkAPI := services.NewNetworkService(currentTenant.Client)
	network, err := networkAPI.Create(in.GetName(), in.GetCIDR(), IPVersion.IPv4,
		int(in.Gateway.GetCPU()), in.GetGateway().GetRAM(), int(in.GetGateway().GetDisk()), in.GetGateway().GetImageID(), in.GetGateway().GetName())

	if err != nil {
		log.Println(err)
		return nil, err
	}

	log.Println("Network created")
	return &pb.Network{
		ID:   network.ID,
		Name: network.Name,
		CIDR: network.CIDR,
	}, nil
}

//List existing networks
func (s *NetworkServiceServer) List(ctx context.Context, in *pb.NWListRequest) (*pb.NetworkList, error) {
	log.Printf("List Network called")

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	networkAPI := services.NewNetworkService(currentTenant.Client)

	networks, err := networkAPI.List(in.GetAll())
	if err != nil {
		return nil, err
	}

	var pbnetworks []*pb.Network

	// Map api.Network to pb.Network
	for _, network := range networks {
		pbnetworks = append(pbnetworks, &pb.Network{
			ID:   network.ID,
			Name: network.Name,
			CIDR: network.CIDR,
		})
	}
	rv := &pb.NetworkList{Networks: pbnetworks}
	log.Printf("End List Network")
	return rv, nil
}

//Inspect returns infos on a network
func (s *NetworkServiceServer) Inspect(ctx context.Context, in *pb.Reference) (*pb.Network, error) {
	log.Printf("Inspect Network called")

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	networkAPI := services.NewNetworkService(currentTenant.Client)
	network, err := networkAPI.Get(ref)
	if err != nil {
		return nil, err
	}

	log.Printf("End Inspect Network: '%s'", ref)
	return &pb.Network{
		ID:        network.ID,
		Name:      network.Name,
		CIDR:      network.CIDR,
		GatewayID: network.GatewayID,
	}, nil
}

//Delete a network
func (s *NetworkServiceServer) Delete(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Delete Network called for network '%s'", in.GetName())

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	networkAPI := services.NewNetworkService(currentTenant.Client)
	err := networkAPI.Delete(ref)
	if err != nil {
		return nil, err
	}

	log.Printf("Network '%s' deleted", ref)
	return &google_protobuf.Empty{}, nil
}
