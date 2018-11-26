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

package brokeruse

import (
	"context"
	"fmt"
	"log"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/utils"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc"
)

// GetConnection returns a connection to GRPC server
func GetConnection() *grpc.ClientConn {
	// Set up a connection to the server.
	conn, err := grpc.Dial(utils.Address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	return conn
}

// GetContext return a context for grpc commands
func GetContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	// Contact the server and print out its response.
	return context.WithTimeout(context.Background(), timeout)
}

// GetCurrentTenant returns the string of the current tenant set by broker
func GetCurrentTenant() (string, error) {
	conn := GetConnection()
	defer conn.Close()
	tenantSvc := pb.NewTenantServiceClient(conn)
	ctx, cancel := GetContext(utils.TimeoutCtxDefault)
	defer cancel()
	tenant, err := tenantSvc.Get(ctx, &google_protobuf.Empty{})
	if err != nil {
		return "", err
	}
	if tenant == nil || tenant.Name == "" {
		return "", fmt.Errorf("tenant must be set; use 'broker tenant set'.")
	}
	return tenant.Name, nil
}

// CreateNetwork creates a network using brokerd
func CreateNetwork(name string, cidr string, GWdef *pb.GatewayDefinition) (*pb.Network, error) {
	conn := GetConnection()
	defer conn.Close()
	ctx, cancel := GetContext(10 * time.Minute)
	defer cancel()
	networkService := pb.NewNetworkServiceClient(conn)
	if GWdef == nil {
		GWdef = &pb.GatewayDefinition{
			CPU:     1,
			Disk:    30,
			RAM:     1.0,
			ImageID: "Ubuntu 16.04",
		}
	}
	netdef := &pb.NetworkDefinition{
		CIDR:    cidr,
		Name:    name,
		Gateway: GWdef,
	}
	network, err := networkService.Create(ctx, netdef)
	if err != nil {
		return nil, fmt.Errorf("failed to create Network: %v", err)
	}

	return network, nil
}

// DeleteNetwork deletes a network using brokerd
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

// CreateHost creates an host using brokerd
func CreateHost(req *pb.HostDefinition) (*pb.Host, error) {
	conn := GetConnection()
	defer conn.Close()
	ctx, cancel := GetContext(utils.TimeoutCtxHost)
	defer cancel()
	service := pb.NewHostServiceClient(conn)
	host, err := service.Create(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create server: %v", err)
	}
	return host, nil
}

// DeleteHost deletes an host using brokerd
func DeleteHost(id string) error {
	conn := GetConnection()
	defer conn.Close()
	ctx, cancel := GetContext(utils.TimeoutCtxHost)
	defer cancel()
	service := pb.NewHostServiceClient(conn)
	_, err := service.Delete(ctx, &pb.Reference{ID: id})
	return err
}

// GetHost returns information about an host
func GetHost(id string) (*pb.Host, error) {
	conn := GetConnection()
	defer conn.Close()
	ctx, cancel := GetContext(utils.TimeoutCtxDefault)
	defer cancel()
	service := pb.NewHostServiceClient(conn)
	return service.Inspect(ctx, &pb.Reference{ID: id})
}

// SSHRun executes a command on an host
func SSHRun(id string, command string, timeout time.Duration) error {
	conn := GetConnection()
	defer conn.Close()
	if timeout == 0 {
		timeout = utils.TimeoutCtxDefault
	}
	ctx, cancel := GetContext(timeout)
	defer cancel()
	service := pb.NewSshServiceClient(conn)

	resp, err := service.Run(ctx, &pb.SshCommand{
		Host:    &pb.Reference{Name: id},
		Command: command,
	})

	// TODO output result to stdout
	if err != nil {
		return fmt.Errorf("Could not execute ssh command: %v", err)
	}
	fmt.Println(resp)
	//fmt.Print(fmt.Sprintf(resp.GetOutput()))
	//fmt.Fprint(os.Stderr, fmt.Sprintf(resp.GetErr()))
	// fmt.Println(fmt.Sprintf(string(resp.GetStatus())))

	return nil
}
