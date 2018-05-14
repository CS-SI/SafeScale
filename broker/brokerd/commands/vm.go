package commands

import (
	"context"
	"fmt"
	"log"
	"strings"

	pb "github.com/SafeScale/broker"
	conv "github.com/SafeScale/broker/utils"
	utils "github.com/SafeScale/broker/utils"
	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/system"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

// broker vm create vm1 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=true
// broker vm list
// broker vm inspect vm1
// broker vm create vm2 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=false

//VMAPI defines API to manipulate VMs
type VMAPI interface {
	Create(name string, net string, cpu int, ram float32, disk int, os string, public bool) (*api.VM, error)
	List() ([]api.VM, error)
	Get(ref string) (*api.VM, error)
	Delete(ref string) error
	SSH(ref string) (*system.SSHConfig, error)
}

//NewVMService creates a VM service
func NewVMService(api api.ClientAPI) VMAPI {
	return &VMService{
		provider: providers.FromClient(api),
		network:  NewNetworkService(api),
	}
}

//VMService vm service
type VMService struct {
	provider *providers.Service
	network  NetworkAPI
}

//Create creates a network
func (srv *VMService) Create(name string, net string, cpu int, ram float32, disk int, os string, public bool) (*api.VM, error) {
	_vm, err := srv.Get(name)
	if _vm != nil || (err != nil && !strings.Contains(err.Error(), "does not exists")) {
		return nil, fmt.Errorf("VM '%s' already exists", name)
	}

	n, err := srv.network.Get(net)
	if err != nil {
		return nil, err
	}
	tpls, err := srv.provider.SelectTemplatesBySize(api.SizingRequirements{
		MinCores:    cpu,
		MinRAMSize:  ram,
		MinDiskSize: disk,
	})
	img, err := srv.provider.SearchImage(os)
	if err != nil {
		return nil, err
	}
	vmRequest := api.VMRequest{
		ImageID:    img.ID,
		Name:       name,
		TemplateID: tpls[0].ID,
		// IsGateway:  false,
		PublicIP:   public,
		NetworkIDs: []string{n.ID},
	}
	vm, err := srv.provider.CreateVM(vmRequest)
	if err != nil {
		return nil, err
	}
	return vm, nil

}

//List returns the network list
func (srv *VMService) List() ([]api.VM, error) {
	return srv.provider.ListVMs()
}

//Get returns the network identified by ref, ref can be the name or the id
func (srv *VMService) Get(ref string) (*api.VM, error) {
	vms, err := srv.provider.ListVMs()
	if err != nil {
		return nil, err
	}
	for _, vm := range vms {
		if vm.ID == ref || vm.Name == ref {
			return &vm, nil
		}
	}
	return nil, fmt.Errorf("VM %s does not exists", ref)
}

//Delete deletes network referenced by ref
func (srv *VMService) Delete(ref string) error {
	vm, err := srv.Get(ref)
	if err != nil {
		return fmt.Errorf("VM '%s' does not exists", ref)
	}
	return srv.provider.DeleteVM(vm.ID)
}

// SSH returns ssh parameters to access the vm referenced by ref
func (srv *VMService) SSH(ref string) (*system.SSHConfig, error) {
	vm, err := srv.Get(ref)
	if err != nil {
		return nil, fmt.Errorf("VM '%s' does not exists", ref)
	}

	return srv.provider.GetSSHConfig(vm.ID)
}

//VMServiceServer VM service server grpc
type VMServiceServer struct{}

//List available VMs
func (s *VMServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.VMList, error) {
	log.Printf("List VM called")

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	vmAPI := NewVMService(currentTenant.client)
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

//Create a new VM
func (s *VMServiceServer) Create(ctx context.Context, in *pb.VMDefinition) (*pb.VM, error) {
	log.Printf("Create VM called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	vmService := NewVMService(currentTenant.client)
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

	vmService := NewVMService(currentTenant.client)
	vm, err := vmService.Get(ref)
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
	vmService := NewVMService(currentTenant.client)
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
	vmService := NewVMService(currentTenant.client)
	sshConfig, err := vmService.SSH(ref)
	if err != nil {
		return nil, err
	}
	log.Printf("Got Ssh config for VM '%s'", ref)
	return conv.ToPBSshconfig(sshConfig), nil
}
