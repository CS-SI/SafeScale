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

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"

	"github.com/satori/go.uuid"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/system/nfs"
)

//go:generate mockgen -destination=../mocks/mock_nasapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/services NasAPI

//NasAPI defines API to manipulate NAS
type NasAPI interface {
	Create(name, host, path string) (*model.Nas, error)
	Delete(name string) (*model.Nas, error)
	List() ([]model.Nas, error)
	Mount(name, host, path string) (*model.Nas, error)
	UMount(name, host string) (*model.Nas, error)
	Inspect(name string) ([]*model.Nas, error)
}

// NasService nas service
type NasService struct {
	provider *providers.Service
}

// NewNasService creates a NAS service
func NewNasService(api *providers.Service) NasAPI {
	return &NasService{
		provider: api,
	}
}

func sanitize(in string) (string, error) {
	sanitized := path.Clean(in)
	if !path.IsAbs(sanitized) {
		return "", fmt.Errorf("Exposed path must be absolute")
	}
	return sanitized, nil
}

//Create a nas
func (svc *NasService) Create(name, hostName, path string) (*model.Nas, error) {
	// Check if a nas already exists with the same name
	nas, err := svc.findNas(name)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	if nas != nil {
		return nil, model.ResourceAlreadyExistsError("NAS", name)
	}

	// Sanitize path
	exportedPath, err := sanitize(path)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	hostSvc := NewHostService(svc.provider)
	host, err := hostSvc.Get(hostName)
	if err != nil || host == nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	sshSvc := NewSSHService(svc.provider)
	sshConfig, err := sshSvc.GetConfig(host)
	if err != nil {
		tbr := errors.Wrap(err, "Error getting NAS ssh config")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	server, err := nfs.NewServer(sshConfig)
	if err != nil {
		tbr := errors.Wrap(err, "Error creating NAS structure")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	err = server.Install()
	if err != nil {
		tbr := errors.Wrap(err, "Error installing nas")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	err = server.AddShare(exportedPath, "")
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	nasid, err := uuid.NewV4()
	if err != nil {
		tbr := errors.Wrap(err, "Error creating UID for NAS")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	nas = &model.Nas{
		ID:       nasid.String(),
		Name:     name,
		Host:     host.Name,
		Path:     exportedPath,
		IsServer: true,
	}

	err = svc.saveNASDefinition(*nas)
	if err != nil {
		tbr := errors.Wrap(err, "Error saving NAS definition")
		log.Errorf("%+v", tbr)
		return nas, tbr
	}

	return nas, err
}

// Delete a container
func (svc *NasService) Delete(name string) (*model.Nas, error) {
	// Retrieve info about the nas
	nass, err := svc.Inspect(name)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	if len(nass) == 0 {
		return nil, errors.Wrap(model.ResourceNotFoundError("NAS", name), "Cannot delete NAS")
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

	hostSvc := NewHostService(svc.provider)
	host, err := hostSvc.Get(nas.Host)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	sshSvc := NewSSHService(svc.provider)
	sshConfig, err := sshSvc.GetConfig(host.ID)
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

	err = svc.removeNASDefinition(*nas)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nas, tbr
	}

	return nas, err
}

// List return the list of all created nas
func (svc *NasService) List() ([]model.Nas, error) {
	var nass []model.Nas
	m := metadata.NewNas(svc.provider)
	err := m.Browse(func(nas *model.Nas) error {
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

// Mount a directory exported by a nas on a local directory of an host
func (svc *NasService) Mount(name, hostName, path string) (*model.Nas, error) {
	// Sanitize path
	mountPath, err := sanitize(path)
	if err != nil {
		return nil, fmt.Errorf("Invalid path to be mounted: '%s' : '%s'", path, err)
	}

	nas, err := svc.findNas(name)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	if nas == nil {
		return nil, errors.Wrap(model.ResourceNotFoundError("NAS", name), "Cannot Mount NAS")

	}

	hostSvc := NewHostService(svc.provider)
	host, err := hostSvc.Get(hostName)
	if err != nil {
		return nil, errors.Wrap(model.ResourceNotFoundError("host", hostName), "Cannot Mount NAS")
	}

	nfsServer, err := hostSvc.Get(nas.Host)
	if err != nil {
		return nil, errors.Wrap(model.ResourceNotFoundError("host", nas.Host), "Cannot Mount NAS")
	}

	sshSvc := NewSSHService(svc.provider)
	sshConfig, err := sshSvc.GetConfig(host.ID)
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

	nasid, err := uuid.NewV4()
	if err != nil {
		tbr := errors.Wrap(err, "Error creating UID for NAS")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	client := &model.Nas{
		ID:       nasid.String(),
		Name:     name,
		Host:     host.Name,
		Path:     mountPath,
		IsServer: false,
	}
	err = metadata.MountNas(svc.provider, client, nas)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return client, tbr
	}

	return client, err
}

// UMount a directory exported by a nas on a local directory of an host
func (svc *NasService) UMount(name, hostName string) (*model.Nas, error) {
	nas, err := svc.findNas(name)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	if nas == nil {
		return nil, errors.Wrap(model.ResourceNotFoundError("NAS", name), "Cannot detach NAS")
	}

	client, err := svc.findClient(name, hostName)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	hostSvc := NewHostService(svc.provider)
	host, err := hostSvc.Get(hostName)
	if err != nil {
		return nil, errors.Wrap(model.ResourceNotFoundError("host", hostName), "Cannot detach NAS")
	}

	nfsServer, err := hostSvc.Get(nas.Host)
	if err != nil {
		return nil, errors.Wrap(model.ResourceNotFoundError("host", nas.Host), "Cannot detach NAS")
	}

	if host != nil {
		sshSvc := NewSSHService(svc.provider)
		sshConfig, err := sshSvc.GetConfig(host.ID)
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
	}

	err = metadata.UmountNas(svc.provider, client, nas)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return client, tbr
	}

	return client, err
}

// Inspect return the detail the nas whose nas is given and all clients connected to
func (svc *NasService) Inspect(name string) ([]*model.Nas, error) {
	mtdNas, err := metadata.LoadNas(svc.provider, name)
	if err != nil {
		tbr := errors.Wrap(err, "Error loading NAS metadata")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	if mtdNas == nil {
		tbr := errors.Wrap(model.ResourceNotFoundError("NAS", name), "Cannot inspect NAS")
		return nil, tbr
	}

	nass, err := mtdNas.Listclients()
	if err != nil {
		tbr := errors.Wrap(err, "Error listing NAS clients")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	nass = append([]*model.Nas{mtdNas.Get()}, nass...)

	return nass, nil
}

func (svc *NasService) saveNASDefinition(nas model.Nas) error {
	return metadata.SaveNas(svc.provider, &nas)
}

func (svc *NasService) removeNASDefinition(nas model.Nas) error {
	return metadata.RemoveNas(svc.provider, &nas)
}

func (svc *NasService) findNas(name string) (*model.Nas, error) {
	mtdNas, err := metadata.LoadNas(svc.provider, name)
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

func (svc *NasService) findClient(nasName, hostName string) (*model.Nas, error) {
	mtdnas, err := metadata.LoadNas(svc.provider, nasName)
	if err != nil {
		tbr := errors.Wrap(err, "Cannot load NAS")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	if mtdnas == nil {
		return nil, errors.Wrap(model.ResourceNotFoundError("NAS", nasName), "Cannot load NAS")
	}

	client, err := mtdnas.FindClient(hostName)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return client, tbr
	}

	return client, err
}
