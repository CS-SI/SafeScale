package main

import (
	"fmt"
	"log"
	"os"
	"time"

	pb "github.com/SafeScale/brokerd"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	address     = "localhost:50051"
	defaultName = "world"
)

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	var name string
	// broker tenant list
	if len(os.Args) > 1 {
		name = os.Args[1]
		fmt.Printf("param : %s", name)
	}

	// Image
	imageService := pb.NewImageServiceClient(conn)
	r, err := imageService.List(ctx, &pb.Reference{})
	if err != nil {
		log.Fatalf("could not get image list: %v", err)
	}

	for i, image := range r.GetImages() {
		log.Printf("Image %d: %s", i, image)
	}

	// Tenant
	tenantService := pb.NewTenantServiceClient(conn)
	tenants, err := tenantService.List(ctx, &pb.Empty{})
	if err != nil {
		log.Fatalf("could not get tenant list: %v", err)
	}

	for i, tenant := range tenants.GetTenants() {
		log.Printf("Tenant %d: %s", i, tenant)
	}

	// Network
	networkService := pb.NewNetworkServiceClient(conn)
	networks, err := networkService.List(ctx, &pb.TenantName{Name: "TestOvh"})
	// networks, err := networkService.ListNetwork(ctx, &pb.TenantName{Name: "TestCloudwatt"})
	if err != nil {
		log.Fatalf("could not get network list: %v", err)
	}
	for i, network := range networks.GetNetworks() {
		log.Printf("Network %d: %s", i, network)
	}
}
