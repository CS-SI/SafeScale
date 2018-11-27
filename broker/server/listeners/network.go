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

	log "github.com/sirupsen/logrus"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/server/services"
	"github.com/CS-SI/SafeScale/broker/utils"
	conv "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/providers/model/enums/IPVersion"
)

// broker network create net1 --cidr="192.145.0.0/16" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" (par défault "192.168.0.0/24", on crée une gateway sur chaque réseau: gw_net1)
// broker network list
// broker network delete net1
// broker network inspect net1

// NetworkServiceListener network service server grpc
type NetworkServiceListener struct{}

// Create a new network
func (s *NetworkServiceListener) Create(ctx context.Context, in *pb.NetworkDefinition) (*pb.Network, error) {
	log.Printf("Create Network called '%s'", in.Name)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot create network : No tenant set")
	}

	networkAPI := services.NewNetworkService(currentTenant.Service)
	network, err := networkAPI.Create(in.GetName(), in.GetCIDR(), IPVersion.IPv4,
		int(in.Gateway.GetCPU()), in.GetGateway().GetRAM(), int(in.GetGateway().GetDisk()), in.GetGateway().GetImageID(), in.GetGateway().GetName())

	if err != nil {
		return nil, err
	}

	log.Println("Network created")
	return conv.ToPBNetwork(network), nil
}

// List existing networks
func (s *NetworkServiceListener) List(ctx context.Context, in *pb.NWListRequest) (*pb.NetworkList, error) {
	log.Printf("List Network called")

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot list networks : No tenant set")
	}

	networkAPI := services.NewNetworkService(currentTenant.Service)

	networks, err := networkAPI.List(in.GetAll())
	if err != nil {
		return nil, err
	}

	var pbnetworks []*pb.Network

	// Map api.Network to pb.Network
	for _, network := range networks {
		pbnetworks = append(pbnetworks, conv.ToPBNetwork(network))
	}
	rv := &pb.NetworkList{Networks: pbnetworks}
	return rv, nil
}

// Inspect returns infos on a network
func (s *NetworkServiceListener) Inspect(ctx context.Context, in *pb.Reference) (*pb.Network, error) {
	log.Debugf("broker.server.listeners.NetworkServiceListener.Inspect(%s) called'", in.Name)
	defer log.Debugf("broker.server.listeners.NetworkServiceListener.Inspect(%s) done'", in.Name)

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Can't inspect network : Neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't inspect network : No tenant set")
	}

	networkAPI := services.NewNetworkService(currentTenant.Service)
	network, err := networkAPI.Get(ref)
	if err != nil {
		return nil, err
	}
	if network == nil {
		return nil, fmt.Errorf("Can't inspect network: no network '%s' found", ref)
	}

	return conv.ToPBNetwork(network), nil
}

// Delete a network
func (s *NetworkServiceListener) Delete(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Delete Network called for network '%s'", in.GetName())

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Can't delete network: neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't delete network: no tenant set")
	}

	networkAPI := services.NewNetworkService(currentTenant.Service)
	err := networkAPI.Delete(ref)
	if err != nil {
		return nil, err
	}

	log.Printf("Network '%s' deleted", ref)
	return &google_protobuf.Empty{}, nil
}
