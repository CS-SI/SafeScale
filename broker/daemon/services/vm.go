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

package services

import (
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/system"
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

//Get returns the VM identified by ref, ref can be the name or the id
func (srv *VMService) Get(ref string) (*api.VM, error) {
	m, err := metadata.NewHost()
	if err != nil {
		return nil, err
	}
	found, err := m.ReadByName(ref)
	if !found {
		found, err = m.ReadByID(ref)
	}
	if found {
		return m.Get(), nil
	}
	return nil, fmt.Errorf("VM %s does not exists", ref)
}

//Delete deletes VM referenced by ref
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
