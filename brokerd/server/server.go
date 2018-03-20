package main

import (
	"fmt"
	"log"
	"net"

	"github.com/SafeScale/providers/api/IPVersion"

	"github.com/SafeScale/broker/commands"
	pb "github.com/SafeScale/brokerd"
	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/ovh"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	port = ":50051"
)

/*
broker provider list
broker provider sample p1

broker tenant add ovh1 --provider="OVH" --config="ovh1.json"
broker tenant list
broker tenant get ovh1
broker tenant set ovh1

broker network create net1 --cidr="192.145.0.0/16" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" (par défault "192.168.0.0/24", on crée une gateway sur chaque réseau: gw_net1)
broker network list
broker network delete net1
broker network inspect net1

broker vm create vm1 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=true
broker vm list
broker vm inspect vm1
broker vm create vm2 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=false

broker ssh connect vm2
broker ssh run vm2 -c "uname -a"
broker ssh copy /file/test.txt vm1://tmp
broker ssh copy vm1:/file/test.txt /tmp

broker volume create v1 --speed="SSD" --size=2000 (par default HDD, possible SSD, HDD, COLD)
broker volume attach v1 vm1 --path="/shared/data" --format="xfs" (par default /shared/v1 et ext4)
broker volume detach v1
broker volume delete v1
broker volume inspect v1
broker volume update v1 --speed="HDD" --size=1000

broker container create c1
broker container mount c1 vm1 --path="/shared/data" (utilisation de s3ql, par default /containers/c1)
broker container umount c1 vm1
broker container delete c1
broker container list
broker container inspect C1

broker nas create nas1 vm1 --path="/shared/data"
broker nas delete nas1
broker nas mount nas1 vm2 --path="/data"
broker nas umount nas1 vm2
broker nas list
broker nas inspect nas1

*/

// server is used to implement SafeScale.broker.
type tenantServiceServer struct{}

// Tenant
func (s *tenantServiceServer) List(ctx context.Context, in *pb.Empty) (*pb.TenantList, error) {
	// func (s *server) ListTenant(ctx context.Context, in *pb.Empty) (*pb.TenantList, error) {
	// TODO To be implemented
	log.Println("List tenant called")
	return &pb.TenantList{[]*pb.Tenant{
			{Name: "Tenant_name_1", Provider: "Tenant_provider_1"},
			{Name: "Tenant_name_2", Provider: "Tenant_provider_2"}}},
		nil
}

func (s *tenantServiceServer) Reload(ctx context.Context, in *pb.Empty) (*pb.Empty, error) {
	// TODO To be implemented
	log.Println("Realod called")
	return &pb.Empty{}, nil
}

type imageServiceServer struct{}

// Image
func (s *imageServiceServer) List(ctx context.Context, in *pb.Reference) (*pb.ImageList, error) {
	// TODO To be implemented
	log.Println("List image called")
	return &pb.ImageList{[]*pb.Image{
			{ID: "Image id 1", Name: "Image Name 1"},
			{Name: "Image name 2", ID: "Image id 2"}}},
		nil
}

// Network
type networkServiceServer struct{}

func (s *networkServiceServer) Create(ctx context.Context, in *pb.NetworkDefinition) (*pb.Network, error) {
	// TODO To be implemented
	log.Println("Create Network called")

	// TODO Move serviceFactory initialisation to higher level (server initialisation ?)
	serviceFactory := providers.NewFactory()
	serviceFactory.RegisterClient("ovh", &ovh.Client{})
	serviceFactory.Load()

	clientAPI, ok := serviceFactory.Services[in.GetName()]
	if !ok {
		return nil, fmt.Errorf("Unknown tenant: %s", in.GetName())
	}

	networkAPI := commands.NewNetworkService(clientAPI)
	network, err := networkAPI.Create(in.GetName(), in.GetCIDR(), IPVersion.IPv4,
		in.Gateway.GetCPU(), in.GetGateway().GetRAM(), in.GetGateway().GetDisk(), in.GetGateway().GetImageID())

	if err != nil {
		return nil, err
	}

	return &pb.Network{
		ID:   network.ID,
		Name: network.Name,
		CIDR: network.CIDR,
	}, nil
}

func (s *networkServiceServer) List(ctx context.Context, in *pb.TenantName) (*pb.NetworkList, error) {
	log.Printf("List Network called with tenant: %s", in.GetName())

	// TODO Move serviceFactory initialisation to higher level (server initialisation ?)
	serviceFactory := providers.NewFactory()
	serviceFactory.RegisterClient("ovh", &ovh.Client{})
	serviceFactory.Load()

	clientAPI, ok := serviceFactory.Services[in.GetName()]
	if !ok {
		return nil, fmt.Errorf("Unknown tenant: %s", in.GetName())
	}

	networkAPI := commands.NewNetworkService(clientAPI)
	networks, err := networkAPI.List()
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
	log.Printf("End List Network for tenant: %s", in.GetName())
	return rv, nil
}

func (s *networkServiceServer) Inspect(ctx context.Context, in *pb.Reference) (*pb.Network, error) {
	// TODO To be implemented
	log.Printf("Inspect Network called for network %s")
	return &pb.Network{
		ID:   "myNetworkid",
		Name: "myNetworkName",
		CIDR: "myNetworkCIDR",
	}, nil
}

func (s *networkServiceServer) Delete(ctx context.Context, in *pb.Reference) (*pb.Empty, error) {
	// TODO To be implemented
	log.Println("Delete Network called")
	return &pb.Empty{}, nil
}

// *** MAIN ***
func main() {
	log.Println("Starting server")
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	log.Println("Registering services")
	pb.RegisterTenantServiceServer(s, &tenantServiceServer{})
	pb.RegisterImageServiceServer(s, &imageServiceServer{})
	pb.RegisterNetworkServiceServer(s, &networkServiceServer{})
	// pb.RegisterContainerServiceServer(s, &server{})
	// pb.RegisterVMServiceServer(s, &server{})
	// pb.RegisterVolumeServiceServer(s, &server{})

	// Register reflection service on gRPC server.
	reflection.Register(s)
	log.Println("Ready to serve :-)")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
