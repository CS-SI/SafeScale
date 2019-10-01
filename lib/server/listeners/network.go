/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"google.golang.org/grpc/status"

	log "github.com/sirupsen/logrus"

	"google.golang.org/grpc/codes"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/IPVersion"
	"github.com/CS-SI/SafeScale/lib/server/utils"
	conv "github.com/CS-SI/SafeScale/lib/server/utils"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
)

// NetworkHandler ...
var NetworkHandler = handlers.NewNetworkHandler

// safescale network create net1 --cidr="192.145.0.0/16" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" (par défault "192.168.0.0/24", on crée une gateway sur chaque réseau: gw-net1)
// safescale network list
// safescale network delete net1
// safescale network inspect net1

// NetworkListener network service server grpc
type NetworkListener struct{}

// Create a new network
func (s *NetworkListener) Create(ctx context.Context, in *pb.NetworkDefinition) (net *pb.Network, err error) {
	// defer timing.TimerErrWithLevel(fmt.Sprintf("Listeners: network create '%s' called...", in.Name), &err, log.TraceLevel)()

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "Create network "+in.GetName()); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't create network: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "can't create network: no tenant set")
	}

	var sizing *resources.SizingRequirements
	if in.Gateway.Sizing == nil {
		sizing = &resources.SizingRequirements{
			MinCores:    int(in.Gateway.Sizing.MinCpuCount),
			MaxCores:    int(in.Gateway.Sizing.MaxCpuCount),
			MinRAMSize:  in.Gateway.Sizing.MinRamSize,
			MaxRAMSize:  in.Gateway.Sizing.MaxRamSize,
			MinDiskSize: int(in.Gateway.Sizing.MinDiskSize),
			MinGPU:      int(in.Gateway.Sizing.GpuCount),
			MinFreq:     in.Gateway.Sizing.MinCpuFreq,
		}
	} else {
		s := srvutils.FromPBHostSizing(*in.Gateway.Sizing)
		sizing = &s
	}

	handler := NetworkHandler(tenant.Service)
	network, err := handler.Create(ctx,
		in.GetName(),
		in.GetCidr(),
		IPVersion.IPv4,
		*sizing,
		in.GetGateway().GetImageId(),
		in.GetGateway().GetName(),
		in.FailOver,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	log.Infof("Network '%s' successfuly created.", network.Name)
	return conv.ToPBNetwork(network), nil
}

// List existing networks
func (s *NetworkListener) List(ctx context.Context, in *pb.NetworkListRequest) (rv *pb.NetworkList, err error) {
	// defer timing.TimerErrWithLevel("Listeners: network list called", &err, log.TraceLevel)()

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "List networks"); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't list network: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "can't list networks: no tenant set")
	}

	handler := NetworkHandler(tenant.Service)
	networks, err := handler.List(ctx, in.GetAll())
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	// Map resources.Network to pb.Network
	var pbnetworks []*pb.Network
	for _, network := range networks {
		pbnetworks = append(pbnetworks, conv.ToPBNetwork(network))
	}
	rv = &pb.NetworkList{Networks: pbnetworks}
	return rv, nil
}

// Inspect returns infos on a network
func (s *NetworkListener) Inspect(ctx context.Context, in *pb.Reference) (net *pb.Network, err error) {
	// defer timing.TimerErrWithLevel(fmt.Sprintf("Listeners: network inspect '%s' called'", in.Name), &err, log.TraceLevel)()

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "Inspect network "+in.GetName()); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("can't inspect network: neither name nor id given as reference")
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't inspect network: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "can't inspect network: no tenant set")
	}

	handler := NetworkHandler(currentTenant.Service)
	network, err := handler.Inspect(ctx, ref)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if network == nil {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("can't inspect network '%s': not found", ref))
	}

	return conv.ToPBNetwork(network), nil
}

// Delete a network
func (s *NetworkListener) Delete(ctx context.Context, in *pb.Reference) (buf *google_protobuf.Empty, err error) {
	// defer timing.TimerErrWithLevel(fmt.Sprintf("Delete Network called for network '%s'", in.GetName()), &err, log.TraceLevel)()

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "Delete network "+in.GetName()); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("can't delete network: neither name nor id given as reference")
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't delete network: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "can't delete network: no tenant set")
	}

	handler := NetworkHandler(currentTenant.Service)
	err = handler.Delete(ctx, ref)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	log.Infof("Network '%s' successfully deleted.", ref)
	return &google_protobuf.Empty{}, nil
}
