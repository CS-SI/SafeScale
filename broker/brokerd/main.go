package main

import (
	"fmt"
	"log"
	"net"

	"github.com/SafeScale/providers/api/VolumeSpeed"

	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/providers/api/IPVersion"

	pb "github.com/SafeScale/broker"
	"github.com/SafeScale/broker/brokerd/commands"
	conv "github.com/SafeScale/broker/utils"
	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/ovh"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
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

type tenant struct {
	name   string
	client api.ClientAPI
}

var (
	currentTenant  *tenant
	serviceFactory *providers.ServiceFactory
)

// server is used to implement SafeScale.broker.
type tenantServiceServer struct{}

// Tenant
func (s *tenantServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.TenantList, error) {
	log.Println("List tenant called")

	var tl []*pb.Tenant
	for name := range serviceFactory.Services {
		tl = append(tl, &pb.Tenant{
			Name:     name,
			Provider: "myprovider",
		})
	}

	return &pb.TenantList{Tenants: tl}, nil
}

func (s *tenantServiceServer) Reload(ctx context.Context, in *google_protobuf.Empty) (*google_protobuf.Empty, error) {
	// TODO To be implemented
	log.Println("Reload called")
	return &google_protobuf.Empty{}, nil
}

func (s *tenantServiceServer) Get(ctx context.Context, in *google_protobuf.Empty) (*pb.TenantName, error) {
	log.Println("Tenant Get called")
	tenant := getCurrentTenant()
	if tenant == nil {
		return nil, fmt.Errorf("No tenant set")
	}
	return &pb.TenantName{Name: tenant.name}, nil
}

func getCurrentTenant() *tenant {
	if currentTenant == nil {
		if len(serviceFactory.Services) != 1 {
			return nil
		}
		// Set unqiue tenant as selected
		log.Println("Unique tenant set")
		for name, service := range serviceFactory.Services {
			currentTenant = &tenant{name: name, client: service}
		}
	}
	return currentTenant
}

func (s *tenantServiceServer) Set(ctx context.Context, in *pb.TenantName) (*google_protobuf.Empty, error) {
	log.Println("Tenant Set called")

	if currentTenant != nil && currentTenant.name == in.GetName() {
		log.Printf("Tenant '%s' is already selected", in.GetName())
		return &google_protobuf.Empty{}, nil
	}

	clientAPI, ok := serviceFactory.Services[in.GetName()]
	if !ok {
		return nil, fmt.Errorf("Unknown tenant '%s'", in.GetName())
	}
	currentTenant = &tenant{name: in.GetName(), client: clientAPI}
	log.Printf("Current tenant is now '%s'", in.GetName())
	return &google_protobuf.Empty{}, nil
}

type imageServiceServer struct{}

// Image
func (s *imageServiceServer) List(ctx context.Context, in *pb.Reference) (*pb.ImageList, error) {
	// TODO To be implemented
	log.Println("List image called")
	return &pb.ImageList{Images: []*pb.Image{
			{ID: "Image id 1", Name: "Image Name 1"},
			{Name: "Image name 2", ID: "Image id 2"}}},
		nil
}

// Network
type networkServiceServer struct{}

func (s *networkServiceServer) Create(ctx context.Context, in *pb.NetworkDefinition) (*pb.Network, error) {
	log.Println("Create Network called")

	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	networkAPI := commands.NewNetworkService(currentTenant.client)
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

func (s *networkServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.NetworkList, error) {
	log.Printf("List Network called")

	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	networkAPI := commands.NewNetworkService(currentTenant.client)
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

func (s *networkServiceServer) Inspect(ctx context.Context, in *pb.Reference) (*pb.Network, error) {
	log.Printf("Inspect Network called for network %s", in.GetName())

	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	networkAPI := commands.NewNetworkService(currentTenant.client)
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

func (s *networkServiceServer) Delete(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Delete Network called for nerwork '%s'", in.GetName())

	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	networkAPI := commands.NewNetworkService(currentTenant.client)
	err := networkAPI.Delete(in.GetName())
	if err != nil {
		return nil, err
	}

	log.Printf("Network '%s' deleted", in.GetName())
	return &google_protobuf.Empty{}, nil
}

// VM
type vmServiceServer struct{}

func (s *vmServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.VMList, error) {
	log.Printf("List VM called")

	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	vmAPI := commands.NewVMService(currentTenant.client)
	vms, err := vmAPI.List()
	if err != nil {
		return nil, err
	}

	var pbvm []*pb.VM

	// Map api.VM to pb.VM
	for _, vm := range vms {
		pbvm = append(pbvm, &pb.VM{
			CPU:        int32(vm.Size.Cores),
			Disk:       int32(vm.Size.DiskSize),
			GatewayID:  vm.GatewayID,
			ID:         vm.ID,
			IP:         vm.GetAccessIP(),
			Name:       vm.Name,
			PrivateKey: vm.PrivateKey,
			RAM:        vm.Size.RAMSize,
			State:      pb.VMState(vm.State),
		})
	}
	rv := &pb.VMList{VMs: pbvm}
	log.Printf("End List VM")
	return rv, nil
}

func (s *vmServiceServer) Create(ctx context.Context, in *pb.VMDefinition) (*pb.VM, error) {
	log.Printf("Create VM called")
	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	vmService := commands.NewVMService(currentTenant.client)
	vm, err := vmService.Create(in.GetName(), in.GetNetwork(),
		int(in.GetCPUNumber()), in.GetRAM(), int(in.GetDisk()), in.GetImageID(), in.GetPublic())

	if err != nil {
		log.Println(err)
		return nil, err
	}

	log.Printf("VM '%s' created", in.GetName())
	return &pb.VM{
		CPU:        int32(vm.Size.Cores),
		Disk:       int32(vm.Size.DiskSize),
		GatewayID:  vm.GatewayID,
		ID:         vm.ID,
		IP:         vm.GetAccessIP(),
		Name:       vm.Name,
		PrivateKey: vm.PrivateKey,
		RAM:        vm.Size.RAMSize,
		State:      pb.VMState(vm.State),
	}, nil
}

func (s *vmServiceServer) Inspect(ctx context.Context, in *pb.Reference) (*pb.VM, error) {
	log.Printf("Inspect VM called")
	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	vmService := commands.NewVMService(currentTenant.client)
	vm, err := vmService.Get(in.GetName())
	if err != nil {
		return nil, err
	}

	log.Printf("End Inspect VM: '%s'", in.GetName())
	return &pb.VM{
		CPU:        int32(vm.Size.Cores),
		Disk:       int32(vm.Size.DiskSize),
		GatewayID:  vm.GatewayID,
		ID:         vm.ID,
		IP:         vm.GetAccessIP(),
		Name:       vm.Name,
		PrivateKey: vm.PrivateKey,
		RAM:        vm.Size.RAMSize,
		State:      pb.VMState(vm.State),
	}, nil
}

func (s *vmServiceServer) Delete(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Delete VM called")
	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}
	vmService := commands.NewVMService(currentTenant.client)
	err := vmService.Delete(in.GetName())
	if err != nil {
		return nil, err
	}
	log.Printf("VM '%s' deleted", in.GetName())
	return &google_protobuf.Empty{}, nil
}

func (s *vmServiceServer) Ssh(ctx context.Context, in *pb.Reference) (*pb.SshConfig, error) {
	log.Printf("Ssh VM called")
	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}
	vmService := commands.NewVMService(currentTenant.client)
	sshConfig, err := vmService.SSH(in.GetName())
	if err != nil {
		return nil, err
	}
	log.Printf("Got Ssh config for VM '%s'", in.GetName())
	return conv.ToPBSshconfig(sshConfig), nil
}

// Volume
type volumeServiceServer struct{}

func (s *volumeServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.VolumeList, error) {
	log.Printf("Volume List called")
	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}
	service := commands.NewVolumeService(currentTenant.client)
	volumes, err := service.List()
	if err != nil {
		return nil, err
	}
	var pbvolumes []*pb.Volume

	// Map api.Volume to pb.Volume
	for _, volume := range volumes {
		pbvolumes = append(pbvolumes, conv.ToPbVolume(volume))
	}
	rv := &pb.VolumeList{Volumes: pbvolumes}
	log.Printf("End Volume List")
	return rv, nil
}

func (s *volumeServiceServer) Create(ctx context.Context, in *pb.VolumeDefinition) (*pb.Volume, error) {
	log.Printf("Create Volume called")
	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := commands.NewVolumeService(currentTenant.client)
	vol, err := service.Create(in.GetName(), int(in.GetSize()), VolumeSpeed.Enum(in.GetSpeed()))
	if err != nil {
		return nil, err
	}

	log.Printf("Volume '%s' created: %s", in.GetName(), vol)
	return conv.ToPbVolume(*vol), nil
}

func (s *volumeServiceServer) Attach(ctx context.Context, in *pb.VolumeAttachment) (*google_protobuf.Empty, error) {
	log.Println("Attach volume called")

	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := commands.NewVolumeService(currentTenant.client)
	err := service.Attach(in.GetVolume().GetName(), in.GetVM().GetName(), in.GetMountPath(), in.GetFormat())

	if err != nil {
		log.Println(err)
		return nil, err
	}

	return &google_protobuf.Empty{}, nil
}

func (s *volumeServiceServer) Detach(ctx context.Context, in *pb.VolumeDetachment) (*google_protobuf.Empty, error) {
	log.Println("Detach volume called")

	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := commands.NewVolumeService(currentTenant.client)
	err := service.Detach(in.GetVolume().GetName(), in.GetVM().GetName())

	if err != nil {
		log.Println(err)
		return nil, err
	}

	log.Println(fmt.Sprintf("Volume '%s' detached from '%s'", in.GetVolume().GetName(), in.GetVM().GetName()))
	return &google_protobuf.Empty{}, nil
}

func (s *volumeServiceServer) Delete(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Volume delete called")
	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}
	service := commands.NewVolumeService(currentTenant.client)
	err := service.Delete(in.GetName())
	if err != nil {
		return nil, err
	}
	log.Printf("Volume '%s' deleted", in.GetName())
	return &google_protobuf.Empty{}, nil
}

func (s *volumeServiceServer) Inspect(ctx context.Context, in *pb.Reference) (*pb.Volume, error) {
	log.Printf("Inspect Volume called")
	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := commands.NewVolumeService(currentTenant.client)
	vol, err := service.Get(in.GetName())
	if err != nil {
		return nil, err
	}

	log.Printf("End Inspect volume: '%s'", in.GetName())
	return conv.ToPbVolume(*vol), nil
}

// SSH
type sshServiceServer struct{}

func (s *sshServiceServer) Run(ctx context.Context, in *pb.SshCommand) (*pb.SshResponse, error) {
	log.Printf("Ssh run called")
	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := commands.NewSSHService(currentTenant.client)
	out, err := service.Run(in.GetVM().GetName(), in.GetCommand())
	if err != nil {
		return nil, err
	}

	log.Println("End ssh run")
	return &pb.SshResponse{
		Status: 0,
		Output: out,
		Err:    "",
	}, nil
}

func (s *sshServiceServer) Copy(ctx context.Context, in *pb.SshCopyCommand) (*google_protobuf.Empty, error) {
	log.Printf("Ssh copy called")
	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := commands.NewSSHService(currentTenant.client)
	err := service.Copy(in.GetSource(), in.GetDestination())
	if err != nil {
		return nil, err
	}

	log.Println("End ssh copy")
	return &google_protobuf.Empty{}, nil
}

// container
type containerServiceServer struct{}

func (s *containerServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.ContainerList, error) {
	log.Printf("Container list called")
	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := commands.NewContainerService(currentTenant.client)
	containers, err := service.List()
	if err != nil {
		return nil, err
	}

	log.Println("End container list")
	return conv.ToPBContainerList(containers), nil
}

func (s *containerServiceServer) Create(ctx context.Context, in *pb.Container) (*google_protobuf.Empty, error) {
	log.Printf("Crete container called")
	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := commands.NewContainerService(currentTenant.client)
	err := service.Create(in.GetName())
	if err != nil {
		return nil, err
	}

	log.Println("End container container")
	return &google_protobuf.Empty{}, nil
}

func (s *containerServiceServer) Delete(ctx context.Context, in *pb.Container) (*google_protobuf.Empty, error) {
	log.Printf("Delete container called")
	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := commands.NewContainerService(currentTenant.client)
	err := service.Delete(in.GetName())
	if err != nil {
		return nil, err
	}

	log.Println("End delete container")
	return &google_protobuf.Empty{}, nil
}

func (s *containerServiceServer) Inspect(ctx context.Context, in *pb.Container) (*pb.ContainerMountingPoint, error) {
	log.Printf("Inspect container called")
	if getCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := commands.NewContainerService(currentTenant.client)
	resp, err := service.Inspect(in.GetName())
	if err != nil {
		return nil, err
	}

	log.Println("End inspect container")
	return conv.ToPBContainerMountPoint(resp), nil
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
	pb.RegisterVMServiceServer(s, &vmServiceServer{})
	pb.RegisterVolumeServiceServer(s, &volumeServiceServer{})
	pb.RegisterSshServiceServer(s, &sshServiceServer{})
	pb.RegisterContainerServiceServer(s, &containerServiceServer{})

	log.Println("Initializing service factory")
	serviceFactory = providers.NewFactory()
	serviceFactory.RegisterClient("ovh", &ovh.Client{})
	serviceFactory.Load()

	// Register reflection service on gRPC server.
	reflection.Register(s)
	log.Println("Ready to serve :-)")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
