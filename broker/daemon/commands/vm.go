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

// broker vm create vm1 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=true
// broker vm list --all=false
// broker vm inspect vm1
// broker vm create vm2 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=false

//VMServiceServer VM service server grpc
type VMServiceServer struct{}

//List available VMs
func (s *VMServiceServer) List(ctx context.Context, in *pb.VMListRequest) (*pb.VMList, error) {
	log.Printf("List VM called")

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	vmAPI := services.NewVMService(currentTenant.Client)

	vms, err := vmAPI.List(in.GetAll())
	if err != nil {
		return nil, err
	}

	var pbvm []*pb.VM

	// Map api.VM to pb.VM
	for _, vm := range vms {
		pbvm = append(pbvm, conv.ToPBVM(&vm))
	}
	rv := &pb.VMList{VMs: pbvm}
	log.Printf("End List VM")
	return rv, nil
}

//Create a new VM
func (s *VMServiceServer) Create(ctx context.Context, in *pb.VMDefinition) (*pb.VM, error) {
	log.Printf("Create VM called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	vmService := services.NewVMService(currentTenant.Client)
	vm, err := vmService.Create(in.GetName(), in.GetNetwork(),
		int(in.GetCPUNumber()), in.GetRAM(), int(in.GetDisk()), in.GetImageID(), in.GetPublic())

	if err != nil {
		log.Println(err)
		return nil, err
	}

	log.Printf("VM '%s' created", in.GetName())
	return conv.ToPBVM(vm), nil
}

//Inspect a VM
func (s *VMServiceServer) Inspect(ctx context.Context, in *pb.Reference) (*pb.VM, error) {
	log.Printf("Inspect VM called")

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	vmService := services.NewVMService(currentTenant.Client)
	vm, err := vmService.Get(ref)
	if err != nil {
		return nil, err
	}

	log.Printf("End Inspect VM: '%s'", in.GetName())
	return conv.ToPBVM(vm), nil
}

//Delete a VM
func (s *VMServiceServer) Delete(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Delete VM called")

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}
	vmService := services.NewVMService(currentTenant.Client)
	err := vmService.Delete(ref)
	if err != nil {
		return nil, err
	}
	log.Printf("VM '%s' deleted", ref)
	return &google_protobuf.Empty{}, nil
}

//SSH returns ssh parameters to access a VM
func (s *VMServiceServer) SSH(ctx context.Context, in *pb.Reference) (*pb.SshConfig, error) {
	log.Printf("Ssh VM called")

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}
	vmService := services.NewVMService(currentTenant.Client)
	sshConfig, err := vmService.SSH(ref)
	if err != nil {
		return nil, err
	}
	log.Printf("Got Ssh config for VM '%s'", ref)
	return conv.ToPBSshconfig(sshConfig), nil
}
