package services

import (
	"fmt"
	"strings"

	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/system"
)

//VMAPI defines API to manipulate VMs
type VMAPI interface {
	Create(name string, net string, cpu int, ram float32, disk int, os string, public bool) (*api.VM, error)
	List(all bool) ([]api.VM, error)
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
func (srv *VMService) List(all bool) ([]api.VM, error) {
	return srv.provider.ListVMs(all)
}

//Get returns the network identified by ref, ref can be the name or the id
func (srv *VMService) Get(ref string) (*api.VM, error) {
	vms, err := srv.provider.ListVMs(false)
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
