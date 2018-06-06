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

package utils

import (
	"context"
	"fmt"
	"log"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc"
)

//GetConnection returns a connection to GRPC server
func GetConnection() *grpc.ClientConn {
	// Set up a connection to the server.
	conn, err := grpc.Dial(Address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	return conn
}

//GetContext return a context for grpc commands
func GetContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	// Contact the server and print out its response.
	return context.WithTimeout(context.Background(), timeout)
}

//GetCurrentTenant returns the string of the current tenant set by broker
func GetCurrentTenant() (string, error) {
	conn := GetConnection()
	defer conn.Close()
	tenantSvc := pb.NewTenantServiceClient(conn)
	ctx, cancel := GetContext(TimeoutCtxDefault)
	defer cancel()
	tenant, err := tenantSvc.Get(ctx, &google_protobuf.Empty{})
	if err != nil {
		return "", err
	}
	if tenant == nil || tenant.Name == "" {
		return "", fmt.Errorf("Tenant must be set; use 'broker tenant set'.")
	}
	return tenant.Name, nil
}

//CreateNetwork creates a network using brokerd
func CreateNetwork(name string, cidr string) (*pb.Network, error) {
	conn := GetConnection()
	defer conn.Close()
	ctx, cancel := GetContext(10 * time.Minute)
	defer cancel()
	networkService := pb.NewNetworkServiceClient(conn)
	netdef := &pb.NetworkDefinition{
		CIDR: cidr,
		Name: name,
		Gateway: &pb.GatewayDefinition{
			CPU:  1,
			Disk: 30,
			RAM:  1.0,
			// CPUFrequency: ??,
			ImageID: "Ubuntu 16.04",
		},
	}
	network, err := networkService.Create(ctx, netdef)
	if err != nil {
		return nil, fmt.Errorf("failed to create Network: %v", err)
	}
	//sleep 3s to wait Network in READY state for now, has to be smarter... Probably in service.CreateNetwork()
	fmt.Println("Sleeping 3s...")
	time.Sleep(3 * time.Second)
	fmt.Println("Waking up...")

	return network, nil
}

//DeleteNetwork deletes a network using brokerd
func DeleteNetwork(id string) error {
	conn := GetConnection()
	defer conn.Close()
	ctx, cancel := GetContext(10 * time.Minute)
	defer cancel()
	networkService := pb.NewNetworkServiceClient(conn)
	_, err := networkService.Delete(ctx, &pb.Reference{ID: id})
	if err != nil {
		return fmt.Errorf("failed to delete Network: %v", err)
	}
	return nil
}

//CreateVM creates a VM using brokerd
func CreateVM(req *pb.VMDefinition) (*pb.VM, error) {
	conn := GetConnection()
	defer conn.Close()
	ctx, cancel := GetContext(TimeoutCtxVM)
	defer cancel()
	service := pb.NewVMServiceClient(conn)
	vm, err := service.Create(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create server: %v", err)
	}
	return vm, nil
}

//DeleteVM deletes a VM using brokerd
func DeleteVM(id string) error {
	conn := GetConnection()
	defer conn.Close()
	ctx, cancel := GetContext(TimeoutCtxVM)
	defer cancel()
	service := pb.NewVMServiceClient(conn)
	_, err := service.Delete(ctx, &pb.Reference{ID: id})
	return err
}

//GetVM returns information about a VM
func GetVM(id string) (*pb.VM, error) {
	conn := GetConnection()
	defer conn.Close()
	ctx, cancel := GetContext(TimeoutCtxDefault)
	defer cancel()
	service := pb.NewVMServiceClient(conn)
	return service.Inspect(ctx, &pb.Reference{ID: id})
}
