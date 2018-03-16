package commands

import (
	"fmt"

	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
)

// broker vm create vm1 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=true
// broker vm list
// broker vm inspect vm1
// broker vm create vm2 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=false

//VMAPI defines API to manipulate VMs
type VMAPI interface {
	Create(name string, net string, cpu int, ram float32, disk int, os string, public bool) (*api.VM, error)
	List() ([]api.VM, error)
	Inspect(ref string) (*api.VM, error)
	Delete(ref string) error
}

// //NewVMService creates a VM service
// func NewVMService(api api.ClientAPI) VMAPI {
// 	return &VMService{
// 		provider: providers.FromClient(api),
// 		network:  NewNetworkService(api),
// 	}
// }

//VMService vm service
type VMService struct {
	provider *providers.Service
	network  NetworkAPI
}

//Create creates a network
func (srv *VMService) Create(name string, net string, cpu int, ram float32, disk int, os string, public bool) (*api.VM, error) {
	_, err := srv.Get(net)
	if err != nil {
		return nil, fmt.Errorf("VM %s already exists", net)
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
	gwRequest := api.VMRequest{
		ImageID:    img.ID,
		Name:       net,
		TemplateID: tpls[0].ID,
		// IsGateway:  false,
		PublicIP:   public,
		NetworkIDs: []string{n.ID},
	}
	vm, err := srv.provider.CreateVM(gwRequest)
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
	return nil, fmt.Errorf("Network %s does not exists", ref)
}

//Delete deletes network referenced by ref
func (srv *VMService) Delete(ref string) error {
	vm, err := srv.Get(ref)
	if err != nil {
		return fmt.Errorf("Network %s does not exists", ref)
	}
	return srv.provider.DeleteVM(vm.ID)
}
