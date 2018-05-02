package commands

import (
	"context"
	"fmt"
	"log"
	"strings"

	pb "github.com/SafeScale/broker"
	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/providers/api/IPVersion"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// broker network create net1 --cidr="192.145.0.0/16" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" (par défault "192.168.0.0/24", on crée une gateway sur chaque réseau: gw_net1)
// broker network list
// broker network delete net1
// broker network inspect net1

//NetworkAPI defines API to manage networks
type NetworkAPI interface {
	Create(net string, cidr string, ipVersion IPVersion.Enum, cpu int, ram float32, disk int, os string) (*api.Network, error)
	List() ([]api.Network, error)
	Get(ref string) (*api.Network, error)
	Delete(ref string) error
}

//NetworkService an instance of NetworkAPI
type NetworkService struct {
	provider  *providers.Service
	ipVersion IPVersion.Enum
}

//NewNetworkService Creates new Network service
func NewNetworkService(api api.ClientAPI) NetworkAPI {
	return &NetworkService{
		provider: providers.FromClient(api),
	}
}

//Create creates a network
func (srv *NetworkService) Create(net string, cidr string, ipVersion IPVersion.Enum, cpu int, ram float32, disk int, os string) (*api.Network, error) {
	// Check that no network with same name already exists
	_net, err := srv.Get(net)
	if _net != nil {
		return nil, fmt.Errorf("Network %s already exists", net)
	}
	if err != nil && !strings.Contains(err.Error(), "does not exists") {
		return nil, fmt.Errorf("Network %s already exists", net)
	}

	// Create the network
	network, err := srv.provider.CreateNetwork(api.NetworkRequest{
		Name:      net,
		IPVersion: ipVersion,
		CIDR:      cidr,
	})
	if err != nil {
		return nil, err
	}

	// Create a gateway
	tpls, err := srv.provider.SelectTemplatesBySize(api.SizingRequirements{
		MinCores:    cpu,
		MinRAMSize:  ram,
		MinDiskSize: disk,
	})
	img, err := srv.provider.SearchImage(os)
	if err != nil {
		srv.provider.DeleteNetwork(network.ID)
		return nil, err
	}

	keypair, err := srv.provider.CreateKeyPair("kp_" + network.Name)
	defer srv.provider.DeleteKeyPair(keypair.ID)

	if err != nil {
		srv.provider.DeleteNetwork(network.ID)
		return nil, err
	}

	gwRequest := api.GWRequest{
		ImageID:    img.ID,
		NetworkID:  network.ID,
		KeyPair:    keypair,
		TemplateID: tpls[0].ID,
	}

	err = srv.provider.CreateGateway(gwRequest)
	if err != nil {
		srv.provider.DeleteNetwork(network.ID)
		return nil, err
	}

	return network, nil
}

//List returns the network list
func (srv *NetworkService) List() ([]api.Network, error) {
	return srv.provider.ListNetworks()
}

//Get returns the network identified by ref, ref can be the name or the id
func (srv *NetworkService) Get(ref string) (*api.Network, error) {
	nets, err := srv.List()
	if err != nil {
		return nil, err
	}
	for _, n := range nets {
		if n.ID == ref || n.Name == ref {
			return &n, nil
		}
	}
	return nil, fmt.Errorf("Network '%s' does not exists", ref)
}

//Delete deletes network referenced by ref
func (srv *NetworkService) Delete(ref string) error {
	n, err := srv.Get(ref)
	if err != nil {
		return fmt.Errorf("Network %s does not exists", ref)
	}
	return srv.provider.DeleteNetwork(n.ID)
}

//NetworkServiceServer network service server grpc
type NetworkServiceServer struct{}

//Create a new network
func (s *NetworkServiceServer) Create(ctx context.Context, in *pb.NetworkDefinition) (*pb.Network, error) {
	log.Println("Create Network called")

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	networkAPI := NewNetworkService(currentTenant.client)
	network, err := networkAPI.Create(in.GetName(), in.GetCIDR(), IPVersion.IPv4,
		int(in.Gateway.GetCPU()), in.GetGateway().GetRAM(), int(in.GetGateway().GetDisk()), in.GetGateway().GetImageID())

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
func (s *NetworkServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.NetworkList, error) {
	log.Printf("List Network called")

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	networkAPI := NewNetworkService(currentTenant.client)
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
	log.Printf("End List Network")
	return rv, nil
}

//Inspect returns infos on a network
func (s *NetworkServiceServer) Inspect(ctx context.Context, in *pb.Reference) (*pb.Network, error) {
	log.Printf("Inspect Network called for network %s", in.GetName())

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	networkAPI := NewNetworkService(currentTenant.client)
	network, err := networkAPI.Get(in.GetName())
	if err != nil {
		return nil, err
	}

	log.Printf("End Inspect Network: '%s'", in.GetName())
	return &pb.Network{
		ID:   network.ID,
		Name: network.Name,
		CIDR: network.CIDR,
	}, nil
}

//Delete a network
func (s *NetworkServiceServer) Delete(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Delete Network called for nerwork '%s'", in.GetName())

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	networkAPI := NewNetworkService(currentTenant.client)
	err := networkAPI.Delete(in.GetName())
	if err != nil {
		return nil, err
	}

	log.Printf("Network '%s' deleted", in.GetName())
	return &google_protobuf.Empty{}, nil
}
