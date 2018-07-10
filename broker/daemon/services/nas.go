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
	"path"
	"strings"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/system/nfs"
)

//NasAPI defines API to manipulate NAS
type NasAPI interface {
	Create(name, vm, path string) (*api.Nas, error)
	Delete(name string) (*api.Nas, error)
	List() ([]api.Nas, error)
	Mount(name, vm, path string) (*api.Nas, error)
	UMount(name, vm string) (*api.Nas, error)
	Inspect(name string) ([]api.Nas, error)
}

//NewNasService creates a NAS service
func NewNasService(api api.ClientAPI) NasAPI {
	return &NasService{
		provider:  providers.FromClient(api),
		vmService: NewVMService(api),
	}
}

//NasService nas service
type NasService struct {
	provider  *providers.Service
	vmService VMAPI
}

func sanitize(in string) (string, error) {
	sanitized := path.Clean(in)
	if !path.IsAbs(sanitized) {
		return "", fmt.Errorf("Exposed path must be absolute")
	}
	return sanitized, nil
}

//Create a nas
func (srv *NasService) Create(name, vmName, path string) (*api.Nas, error) {

	// Check if a nas already exist with the same name
	nas, err := srv.findNas(name)
	if nas != nil {
		return nil, fmt.Errorf("NAS '%s' already exists", name)
	}
	if _, ok := err.(providers.ResourceNotFound); !ok {
		return nil, err
	}

	// Sanitize path
	exportedPath, err := sanitize(path)
	if err != nil {
		return nil, fmt.Errorf("Invalid path to be exposed: '%s' : '%s'", path, err)
	}

	vm, err := srv.vmService.Get(vmName)
	if err != nil {
		return nil, fmt.Errorf("No VM found with name or id '%s'", vmName)
	}

	sshConfig, err := srv.provider.GetSSHConfig(vm.ID)
	if err != nil {
		return nil, err
	}

	server, err := nfs.NewServer(sshConfig)
	if err != nil {
		return nil, err
	}
	err = server.Install()
	if err != nil {
		return nil, err
	}

	err = server.AddShare(exportedPath, "")
	if err != nil {
		return nil, err
	}

	nas = &api.Nas{
		Name:     name,
		ServerID: vm.ID,
		Path:     exportedPath,
		IsServer: true,
	}
	err = srv.saveNASDefinition(*nas)
	return nas, err
}

//Delete a container
func (srv *NasService) Delete(name string) (*api.Nas, error) {
	// Retrieve info about the nas
	nass, err := srv.Inspect(name)
	if err != nil {
		return nil, err
	}

	if len(nass) == 0 {
		return nil, providers.ResourceNotFoundError("Nas", name)
	}
	if len(nass) > 1 {
		var vms []string
		for _, nas := range nass {
			if !nas.IsServer {
				vms = append(vms, nas.ServerID)
			}
		}
		return nil, fmt.Errorf("Cannot delete nas '%s' because it is mounted on VMs : %s", name, strings.Join(vms, " "))
	}

	nas := nass[0]

	vm, err := srv.vmService.Get(nas.ServerID)
	if err != nil {
		return nil, fmt.Errorf("No VM found with name or id '%s'", nas.ServerID)
	}

	sshConfig, err := srv.provider.GetSSHConfig(vm.ID)
	if err != nil {
		return nil, err
	}

	server, err := nfs.NewServer(sshConfig)
	if err != nil {
		return nil, err
	}

	err = server.RemoveShare(nas.Path)
	if err != nil {
		return nil, err
	}

	err = srv.removeNASDefinition(nas)
	return &nas, err
}

//List return the list of all created nas
func (srv *NasService) List() ([]api.Nas, error) {
	var nass []api.Nas
	m, err := metadata.NewNas(srv.provider)
	if err != nil {
		return nass, err
	}
	err = m.Browse(func(nas *api.Nas) error {
		nass = append(nass, *nas)
		return nil
	})
	if err != nil {
		return nass, err
	}
	return nass, nil
}

//Mount a directory exported by a nas on a local directory of a vm
func (srv *NasService) Mount(name, vmName, path string) (*api.Nas, error) {
	// Sanitize path
	mountPath, err := sanitize(path)
	if err != nil {
		return nil, fmt.Errorf("Invalid path to be mounted: '%s' : '%s'", path, err)
	}

	nas, err := srv.findNas(name)
	if err != nil {
		return nil, err
	}

	vm, err := srv.vmService.Get(vmName)
	if err != nil {
		return nil, providers.ResourceNotFoundError("VM", vmName)
	}

	nfsServer, err := srv.vmService.Get(nas.ServerID)
	if err != nil {
		return nil, providers.ResourceNotFoundError("VM", nas.ServerID)
	}

	sshConfig, err := srv.provider.GetSSHConfig(vm.ID)
	if err != nil {
		return nil, err
	}

	nsfclient, err := nfs.NewNFSClient(sshConfig)
	if err != nil {
		return nil, err
	}

	err = nsfclient.Install()
	if err != nil {
		return nil, err
	}

	err = nsfclient.Mount(nfsServer.GetAccessIP(), nas.Path, mountPath)
	if err != nil {
		return nil, err
	}

	client := &api.Nas{
		Name:     name,
		ServerID: vm.ID,
		Path:     mountPath,
		IsServer: false,
	}
	err = srv.saveNASDefinition(*client)
	return client, err
}

//UMount a directory exported by a nas on a local directory of a vm
func (srv *NasService) UMount(name, vmName string) (*api.Nas, error) {
	nas, err := srv.findNas(name)
	if err != nil {
		return nil, err
	}

	vm, err := srv.vmService.Get(vmName)
	if err != nil {
		return nil, providers.ResourceNotFoundError("VM", vmName)
	}

	nfsServer, err := srv.vmService.Get(nas.ServerID)
	if err != nil {
		return nil, providers.ResourceNotFoundError("VM", nas.ServerID)
	}

	sshConfig, err := srv.provider.GetSSHConfig(vm.ID)
	if err != nil {
		return nil, err
	}

	nsfclient, err := nfs.NewNFSClient(sshConfig)
	if err != nil {
		return nil, err
	}

	err = nsfclient.Unmount(nfsServer.GetAccessIP(), nas.Path)
	if err != nil {
		return nil, err
	}

	client := &api.Nas{
		Name:     name,
		ServerID: vm.ID,
		Path:     nas.Path,
		IsServer: false,
	}
	err = srv.removeNASDefinition(*client)
	return client, err
}

//Inspect return the detail the nas whose nas is given and all clients connected to
func (srv *NasService) Inspect(name string) ([]api.Nas, error) {
	names, err := srv.provider.ListObjects(api.NasContainerName, api.ObjectFilter{
		Path:   "",
		Prefix: name,
	})
	if err != nil {
		return nil, err
	}

	var nass []api.Nas

	for _, name := range names {
		nas, err := srv.readNasDefinition(name)
		if err != nil {
			return nil, providers.ResourceNotFoundError("Nas", name)
		}
		if nas.IsServer {
			// NAS server is inserted at the 1st place in the list
			nass = append([]api.Nas{*nas}, nass...)
		} else {
			nass = append(nass, *nas)
		}
	}

	return nass, nil

}

func (srv *NasService) saveNASDefinition(nas api.Nas) error {
	return metadata.SaveNas(srv.provider, &nas)
}

func (srv *NasService) removeNASDefinition(nas api.Nas) error {
	return metadata.RemoveNas(srv.provider, &nas)
}

func (srv *NasService) readNasDefinition(nasName string) (*api.Nas, error) {
	return srv.findNas(nasName)
}

func (srv *NasService) findNas(name string) (*api.Nas, error) {
	mn, err := metadata.NewNas(srv.provider)
	if err != nil {
		return nil, err
	}

	found, err := mn.ReadByName(name)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, providers.ResourceNotFoundError("Nas", name)
	}
	return mn.Get(), nil
}
