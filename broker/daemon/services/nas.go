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
	uuid "github.com/satori/go.uuid"
)

//NasAPI defines API to manipulate NAS
type NasAPI interface {
	Create(name, host, path string) (*api.Nas, error)
	Delete(name string) (*api.Nas, error)
	List() ([]api.Nas, error)
	Mount(name, host, path string) (*api.Nas, error)
	UMount(name, host string) (*api.Nas, error)
	Inspect(name string) ([]*api.Nas, error)
}

// NewNasService creates a NAS service
func NewNasService(api api.ClientAPI) NasAPI {
	return &NasService{
		provider:    providers.FromClient(api),
		hostService: NewHostService(api),
	}
}

// NasService nas service
type NasService struct {
	provider    *providers.Service
	hostService HostAPI
}

func sanitize(in string) (string, error) {
	sanitized := path.Clean(in)
	if !path.IsAbs(sanitized) {
		return "", fmt.Errorf("Exposed path must be absolute")
	}
	return sanitized, nil
}

//Create a nas
func (srv *NasService) Create(name, hostName, path string) (*api.Nas, error) {

	// Check if a nas already exist with the same name
	nas, err := srv.findNas(name)
	if err != nil {
		return nil, err
	}
	if nas != nil {
		return nil, providers.ResourceAlreadyExistsError("NAS", name)
	}

	// Sanitize path
	exportedPath, err := sanitize(path)
	if err != nil {
		return nil, fmt.Errorf("Invalid path to be exposed: '%s' : '%s'", path, err)
	}

	host, err := srv.hostService.Get(hostName)
	if err != nil {
		return nil, fmt.Errorf("no host found with name or id '%s'", hostName)
	}

	sshConfig, err := srv.provider.GetSSHConfig(host.ID)
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

	nasid, _ := uuid.NewV4()
	nas = &api.Nas{
		ID:       nasid.String(),
		Name:     name,
		Host:     host.Name,
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
		return nil, providers.ResourceNotFoundError("NAS", name)
	}
	if len(nass) > 1 {
		var hosts []string
		for _, nas := range nass {
			if !nas.IsServer {
				hosts = append(hosts, nas.Host)
			}
		}
		return nil, fmt.Errorf("cannot delete nas '%s' because it is mounted on hosts : %s", name, strings.Join(hosts, " "))
	}

	nas := nass[0]

	host, err := srv.hostService.Get(nas.Host)
	if err != nil {
		return nil, fmt.Errorf("no host found with name or id '%s'", nas.Host)
	}

	sshConfig, err := srv.provider.GetSSHConfig(host.ID)
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

	err = srv.removeNASDefinition(*nas)
	return nas, err
}

//List return the list of all created nas
func (srv *NasService) List() ([]api.Nas, error) {
	var nass []api.Nas
	m := metadata.NewNas(srv.provider)
	err := m.Browse(func(nas *api.Nas) error {
		nass = append(nass, *nas)
		return nil
	})
	if err != nil {
		return nass, err
	}
	return nass, nil
}

//Mount a directory exported by a nas on a local directory of an host
func (srv *NasService) Mount(name, hostName, path string) (*api.Nas, error) {
	// Sanitize path
	mountPath, err := sanitize(path)
	if err != nil {
		return nil, fmt.Errorf("Invalid path to be mounted: '%s' : '%s'", path, err)
	}

	nas, err := srv.findNas(name)
	if err != nil {
		return nil, err
	}
	if nas == nil {
		return nil, providers.ResourceNotFoundError("NAS", name)

	}

	host, err := srv.hostService.Get(hostName)
	if err != nil {
		return nil, providers.ResourceNotFoundError("host", hostName)
	}

	nfsServer, err := srv.hostService.Get(nas.Host)
	if err != nil {
		return nil, providers.ResourceNotFoundError("host", nas.Host)
	}

	sshConfig, err := srv.provider.GetSSHConfig(host.ID)
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

	nasid, _ := uuid.NewV4()
	client := &api.Nas{
		ID:       nasid.String(),
		Name:     name,
		Host:     host.Name,
		Path:     mountPath,
		IsServer: false,
	}
	err = metadata.MountNas(srv.provider, client, nas)
	return client, err
}

//UMount a directory exported by a nas on a local directory of an host
func (srv *NasService) UMount(name, hostName string) (*api.Nas, error) {
	nas, err := srv.findNas(name)
	if err != nil {
		return nil, err
	}
	if nas == nil {
		return nil, providers.ResourceNotFoundError("NAS", name)
	}

	client, err := srv.findClient(name, hostName)
	if err != nil {
		return nil, err
	}

	host, err := srv.hostService.Get(hostName)
	if err != nil {
		return nil, providers.ResourceNotFoundError("host", hostName)
	}

	nfsServer, err := srv.hostService.Get(nas.Host)
	if err != nil {
		return nil, providers.ResourceNotFoundError("host", nas.Host)
	}

	sshConfig, err := srv.provider.GetSSHConfig(host.ID)
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

	err = metadata.UmountNas(srv.provider, client, nas)
	return client, err
}

//Inspect return the detail the nas whose nas is given and all clients connected to
func (srv *NasService) Inspect(name string) ([]*api.Nas, error) {
	mtdNas, err := metadata.LoadNas(srv.provider, name)
	if err != nil {
		return nil, err
	}
	if mtdNas == nil {
		return nil, providers.ResourceNotFoundError("NAS", name)
	}

	nass, err := mtdNas.Listclients()
	if err != nil {
		return nil, err
	}

	nass = append([]*api.Nas{mtdNas.Get()}, nass...)

	return nass, nil
}

func (srv *NasService) saveNASDefinition(nas api.Nas) error {
	return metadata.SaveNas(srv.provider, &nas)
}

func (srv *NasService) removeNASDefinition(nas api.Nas) error {
	return metadata.RemoveNas(srv.provider, &nas)
}

func (srv *NasService) findNas(name string) (*api.Nas, error) {
	mtdNas, err := metadata.LoadNas(srv.provider, name)
	if err != nil {
		return nil, err
	}
	if mtdNas == nil {
		return nil, nil
	}
	return mtdNas.Get(), nil
}

func (srv *NasService) findClient(nasName, hostName string) (*api.Nas, error) {
	mtdnas, err := metadata.LoadNas(srv.provider, nasName)
	if err != nil {
		return nil, err
	}
	if mtdnas == nil {
		return nil, providers.ResourceNotFoundError("NAS", nasName)
	}

	client, err := mtdnas.FindClient(hostName)
	return client, err
}
