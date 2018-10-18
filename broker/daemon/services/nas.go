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
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"path"
	"strings"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/metadata"

	"github.com/CS-SI/SafeScale/system/nfs"

	"github.com/satori/go.uuid"
)

//go:generate mockgen -destination=../mocks/mock_nasapi.go -package=mocks github.com/CS-SI/SafeScale/broker/daemon/services NasAPI

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
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	if nas != nil {
		return nil, providers.ResourceAlreadyExistsError("NAS", name)
	}

	// Sanitize path
	exportedPath, err := sanitize(path)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	host, err := srv.hostService.Get(hostName)
	if err != nil || host == nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	sshConfig, err := srv.provider.GetSSHConfig(host.ID)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	server, err := nfs.NewServer(sshConfig)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	err = server.Install()
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	err = server.AddShare(exportedPath, "")
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	nasid, _ := uuid.NewV4()
	nas = &api.Nas{
		ID:       nasid.String(),
		Name:     name,
		Host:     host.Name,
		Path:     exportedPath,
		IsServer: true,
	}

	// TODO OPP Check this
	err = srv.saveNASDefinition(*nas)
	if err != nil {
		tbr := errors.Wrap(err, "Error saving NAS definition")
		log.Errorf("%+v", tbr)
		return nas, tbr
	}

	return nas, err
}

//Delete a container
func (srv *NasService) Delete(name string) (*api.Nas, error) {
	// Retrieve info about the nas
	nass, err := srv.Inspect(name)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	if len(nass) == 0 {
		return nil, errors.Wrap(providers.ResourceNotFoundError("NAS", name), "Cannot delete NAS")
	}
	if len(nass) > 1 {
		var hosts []string
		for _, nas := range nass {
			if !nas.IsServer {
				hosts = append(hosts, nas.Host)
			}
		}
		return nil, fmt.Errorf("Cannot delete nas '%s' because it is mounted on hosts : %s", name, strings.Join(hosts, " "))
	}

	nas := nass[0]

	host, err := srv.hostService.Get(nas.Host)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	sshConfig, err := srv.provider.GetSSHConfig(host.ID)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	server, err := nfs.NewServer(sshConfig)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	err = server.RemoveShare(nas.Path)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	// TODO OPP Check this
	err = srv.removeNASDefinition(*nas)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nas, tbr
	}

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
		tbr := errors.Wrap(err, "Error browsing nas")
		log.Errorf("%+v", tbr)
		return nass, tbr
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
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	if nas == nil {
		return nil, errors.Wrap(providers.ResourceNotFoundError("NAS", name), "Cannot Mount NAS")

	}

	host, err := srv.hostService.Get(hostName)
	if err != nil {
		return nil, errors.Wrap(providers.ResourceNotFoundError("host", hostName), "Cannot Mount NAS")
	}

	nfsServer, err := srv.hostService.Get(nas.Host)
	if err != nil {
		return nil, errors.Wrap(providers.ResourceNotFoundError("host", nas.Host), "Cannot Mount NAS")
	}

	sshConfig, err := srv.provider.GetSSHConfig(host.ID)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	nsfclient, err := nfs.NewNFSClient(sshConfig)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	err = nsfclient.Install()
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	err = nsfclient.Mount(nfsServer.GetAccessIP(), nas.Path, mountPath)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
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
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return client, tbr
	}

	return client, err
}

//UMount a directory exported by a nas on a local directory of an host
func (srv *NasService) UMount(name, hostName string) (*api.Nas, error) {
	nas, err := srv.findNas(name)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	if nas == nil {
		return nil, errors.Wrap(providers.ResourceNotFoundError("NAS", name), "Cannot detach NAS")
	}

	client, err := srv.findClient(name, hostName)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	host, err := srv.hostService.Get(hostName)
	if err != nil {
		return nil, errors.Wrap(providers.ResourceNotFoundError("host", hostName), "Cannot detach NAS")
	}

	nfsServer, err := srv.hostService.Get(nas.Host)
	if err != nil {
		return nil, errors.Wrap(providers.ResourceNotFoundError("host", nas.Host), "Cannot detach NAS")
	}

	sshConfig, err := srv.provider.GetSSHConfig(host.ID)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	nsfclient, err := nfs.NewNFSClient(sshConfig)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	err = nsfclient.Unmount(nfsServer.GetAccessIP(), nas.Path)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	err = metadata.UmountNas(srv.provider, client, nas)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return client, tbr
	}

	return client, err
}

//Inspect return the detail the nas whose nas is given and all clients connected to
func (srv *NasService) Inspect(name string) ([]*api.Nas, error) {
	mtdNas, err := metadata.LoadNas(srv.provider, name)
	if err != nil {
		tbr := errors.Wrap(err, "Error loading NAS metadata")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	if mtdNas == nil {
		tbr := errors.Wrap(providers.ResourceNotFoundError("NAS", name), "Cannot inspect NAS")
		return nil, tbr
	}

	nass, err := mtdNas.Listclients()
	if err != nil {
		tbr := errors.Wrap(err, "Error listing NAS clients")
		log.Errorf("%+v", tbr)
		return nil, tbr
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
		tbr := errors.Wrap(err, "Cannot load NAS")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	if mtdNas == nil {
		return nil, nil
	}
	return mtdNas.Get(), nil
}

func (srv *NasService) findClient(nasName, hostName string) (*api.Nas, error) {
	mtdnas, err := metadata.LoadNas(srv.provider, nasName)
	if err != nil {
		tbr := errors.Wrap(err, "Cannot load NAS")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	if mtdnas == nil {
		return nil, errors.Wrap(providers.ResourceNotFoundError("NAS", nasName), "Cannot load NAS")
	}

	client, err := mtdnas.FindClient(hostName)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return client, tbr
	}

	return client, err
}
