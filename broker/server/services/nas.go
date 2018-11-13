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

	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"

	"github.com/satori/go.uuid"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/system/nfs"
)

//go:generate mockgen -destination=../mocks/mock_nasapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/services NasAPI

// NasAPI defines API to manipulate NAS
type NasAPI interface {
	Create(name, host, path string) (*propsv1.HostExport, error)
	Delete(name string) error
	List() (map[string]map[string]propsv1.HostExport, error)
	Mount(name, host, path string) (*propsv1.HostMount, error)
	Unmount(name, host string) error
	Inspect(name string) (*model.Host, propsv1.HostExport, error)
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

// Create a nas export on host
func (svc *NasService) Create(name, hostName, path string) (*propsv1.HostExport, error) {
	// Check if a nas already exists with the same name
	nasHostID, err := svc.findNas(name)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	if nasHostID == "" {
		return nil, model.ResourceAlreadyExistsError("NAS", name)
	}

	// Sanitize path
	exportedPath, err := sanitize(path)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	// Load host information
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

	hpNasV1 := propsv1.BlankHostNas
	err = host.Properties.Get(HostProperty.NasV1, &hpNasV1)
	if err != nil {
		return nil, err
	}

	if len(hpNasV1.ExportsByID) == 0 {
		// Host endorses the Nas role for the first time
		err = server.Install()
		if err != nil {
			tbr := errors.Wrap(err, "")
			log.Errorf("%+v", tbr)
			return nil, tbr
		}
	}

	err = server.AddShare(exportedPath, "")
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	// Create export struct
	export := propsv1.BlankHostExport
	export.Name = name
	exportID, err := uuid.NewV4()
	if err != nil {
		tbr := errors.Wrap(err, "Error creating UID for NAS")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	export.ID = exportID.String()
	export.Path = exportedPath
	export.Type = "nfs"

	hpNasV1.ExportsByID[export.ID] = export
	hpNasV1.ExportsByName[export.Name] = export.ID

	// Updates Host Property propsv1.HostNas
	err = host.Properties.Set(HostProperty.NasV1, &hpNasV1)
	if err != nil {
		return nil, err
	}

	err = metadata.SaveHost(svc.provider, host)
	if err != nil {
		tbr := errors.Wrap(err, "Error saving NAS metadata")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	return &export, nil
}

// Delete a Nas export from host
func (svc *NasService) Delete(name string) error {
	// Retrieve info about the nas
	nas, export, err := svc.Inspect(name)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}

	hpNasV1 := propsv1.BlankHostNas
	err = nas.Properties.Get(HostProperty.NasV1, &hpNasV1)
	if err != nil {
		return err
	}

	if len(export.ClientsByName) > 0 {
		list := []string{}
		for k := range export.ClientsByName {
			list = append(list, k)
		}
		return fmt.Errorf("cannot delete nas export '%s' because clients are still using it: %s", name, strings.Join(list, ","))
	}

	sshSvc := NewSSHService(svc.provider)
	sshConfig, err := sshSvc.GetConfig(nas.ID)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}

	server, err := nfs.NewServer(sshConfig)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}

	err = server.RemoveShare(export.Path)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}

	delete(hpNasV1.ExportsByID, export.ID)
	delete(hpNasV1.ExportsByName, export.Name)
	err = nas.Properties.Set(HostProperty.NasV1, &hpNasV1)
	if err != nil {
		return err
	}

	// Save host metadata
	err = metadata.SaveHost(svc.provider, nas)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}

	return err
}

// List return the list of all exports from all NASes
func (svc *NasService) List() (map[string]map[string]propsv1.HostExport, error) {
	exports := map[string]map[string]propsv1.HostExport{}

	hosts := map[string]struct{}{}
	mn := metadata.NewNas(svc.provider)
	err := mn.Browse(func(hostID string, exportID string) error {
		hosts[hostID] = struct{}{}
		return nil
	})
	if err != nil {
		tbr := errors.Wrap(err, "Error browsing NASes")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	// Now walks through the hosts acting as Nas
	for k := range hosts {
		mh, err := metadata.LoadHost(svc.provider.ClientAPI, k)
		if err != nil {
			return nil, err
		}
		host := mh.Get()

		hpNasV1 := propsv1.BlankHostNas
		err = host.Properties.Get(HostProperty.NasV1, &hpNasV1)
		if err != nil {
			return nil, err
		}

		exports[k] = hpNasV1.ExportsByID
	}
	return exports, nil
}

// Mount a directory exported by a nas on a local directory of an host
func (svc *NasService) Mount(name, hostName, path string) (*propsv1.HostMount, error) {
	// Sanitize path
	mountPath, err := sanitize(path)
	if err != nil {
		return nil, fmt.Errorf("Invalid path to be mounted: '%s' : '%s'", path, err)
	}

	nasHostID, err := svc.findNas(name)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	hostSvc := NewHostService(svc.provider)
	target, err := hostSvc.Get(hostName)
	if err != nil {
		return nil, errors.Wrap(model.ResourceNotFoundError("host", hostName), "Cannot Mount NAS")
	}
	hpMountsV1 := propsv1.BlankHostMounts
	err = target.Properties.Get(HostProperty.MountsV1, &hpMountsV1)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot Mount NAS")
	}
	if _, found := hpMountsV1.MountsByPath[mountPath]; found {
		return nil, fmt.Errorf("there is already an export mounted in '%s'", path)
	}

	source, err := hostSvc.Get(nasHostID)
	if err != nil {
		return nil, errors.Wrap(model.ResourceNotFoundError("host", nasHostID), "Cannot Mount NAS")
	}
	hpNasV1 := propsv1.BlankHostNas
	err = source.Properties.Get(HostProperty.NasV1, &hpNasV1)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot mount NAS")
	}
	_, found := hpNasV1.ExportsByID[hpNasV1.ExportsByName[name]]
	if !found {
		return nil, errors.Wrap(fmt.Errorf("failed to find an export called '%s'", name), "Cannot mount NAS")
	}
	export := hpNasV1.ExportsByID[hpNasV1.ExportsByName[name]]

	sshSvc := NewSSHService(svc.provider)
	sshConfig, err := sshSvc.GetConfig(target)
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

	err = nsfclient.Mount(source.GetAccessIP(), export.Path, mountPath)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	export.ClientsByName[target.Name] = target.ID
	export.ClientsByID[target.ID] = target.Name
	err = source.Properties.Set(HostProperty.NasV1, &hpNasV1)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot mount NAS")
	}

	mount := propsv1.BlankHostMount
	mount.Local = false
	mount.Device = source.Name + ":" + export.Path
	mount.Path = mountPath
	mount.FileSystem = "nfs"
	hpMountsV1.MountsByPath[mount.Path] = mount
	hpMountsV1.MountsByDevice[mount.Device] = mount.Path
	err = target.Properties.Set(HostProperty.MountsV1, &hpMountsV1)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot mount NAS")
	}

	// nasid, err := uuid.NewV4()
	// if err != nil {
	// 	tbr := errors.Wrap(err, "Error creating UID for NAS")
	// 	log.Errorf("%+v", tbr)
	// 	return nil, tbr
	// }

	// client := &model.Nas{
	// 	ID:       nasid.String(),
	// 	Name:     name,
	// 	Host:     host.Name,
	// 	Path:     mountPath,
	// 	IsServer: false,
	// }

	// err = metadata.MountNas(svc.provider, client, nas)
	// if err != nil {
	// 	tbr := errors.Wrap(err, "")
	// 	log.Errorf("%+v", tbr)
	// 	return client, tbr
	// }

	err = metadata.SaveHost(svc.provider.ClientAPI, target)
	if err != nil {
		return nil, err
	}
	err = metadata.SaveHost(svc.provider.ClientAPI, source)
	if err != nil {
		return nil, err
	}
	return &mount, nil
}

// Unmount a directory exported by a nas on a local directory of an host
func (svc *NasService) Unmount(name, hostName string) error {
	nasHostID, err := svc.findNas(name)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}
	if nasHostID == "" {
		return errors.Wrap(model.ResourceNotFoundError("NAS", name), "Cannot detach NAS")
	}

	hostSvc := NewHostService(svc.provider)
	source, err := hostSvc.Get(nasHostID)
	if err != nil {
		return errors.Wrap(model.ResourceNotFoundError("host", nasHostID), "Cannot detach NAS")
	}
	if source == nil {
		return errors.Wrap(err, "Cannot detach NAS")
	}
	hpNasV1 := propsv1.BlankHostNas
	err = source.Properties.Get(HostProperty.NasV1, &hpNasV1)
	if err != nil {
		return errors.Wrap(err, "Cannot detach NAS")
	}
	exportID, found := hpNasV1.ExportsByName[name]
	if !found {
		return errors.Wrap(fmt.Errorf("failed to find an export called '%s'", name), "Cannot detach NAS")
	}
	export := hpNasV1.ExportsByID[exportID]
	exportPath := source.Name + ":" + export.Path

	target, err := hostSvc.Get(hostName)
	if err != nil {
		return errors.Wrap(err, "Cannot detach NAS")
	}
	if target == nil {
		return errors.Wrap(model.ResourceNotFoundError("host", hostName), "Cannot detach NAS")
	}
	hpMountsV1 := propsv1.BlankHostMounts
	err = target.Properties.Get(HostProperty.MountsV1, &hpMountsV1)
	if err != nil {
		return errors.Wrap(err, "Cannot detach NAS")
	}
	mount, found := hpMountsV1.MountsByPath[hpMountsV1.MountsByDevice[exportPath]]
	if !found {
		return errors.Wrap(fmt.Errorf("failed to find on host '%s' a mount from '%s'", target.Name, exportPath), "Cannot detach NAS")

	}

	// client, err := svc.findClient(name, hostName)
	// if err != nil {
	// 	tbr := errors.Wrap(err, "")
	// 	log.Errorf("%+v", tbr)
	// 	return nil, tbr
	// }

	// nfsServer, err := hostSvc.Get(nas.Host)
	// if err != nil {
	// 	return nil, errors.Wrap(model.ResourceNotFoundError("host", nas.Host), "Cannot detach NAS")
	// }

	sshSvc := NewSSHService(svc.provider)
	sshConfig, err := sshSvc.GetConfig(target.ID)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}

	nsfclient, err := nfs.NewNFSClient(sshConfig)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}

	err = nsfclient.Unmount(source.GetAccessIP(), mount.Path)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}

	// Remove mount from mount list
	delete(hpMountsV1.MountsByDevice, mount.Device)
	delete(hpMountsV1.MountsByPath, mount.Path)
	err = target.Properties.Set(HostProperty.MountsV1, &hpMountsV1)
	if err != nil {
		return errors.Wrap(err, "Cannot detach NAS")
	}

	// Remove host from client lists of the export
	delete(export.ClientsByName, target.Name)
	delete(export.ClientsByID, target.ID)
	err = source.Properties.Set(HostProperty.NasV1, &hpNasV1)
	if err != nil {
		return errors.Wrap(err, "Cannot detach NAS")
	}

	// Saves metadata
	err = metadata.SaveHost(svc.provider.ClientAPI, source)
	if err != nil {
		return errors.Wrap(err, "Cannot detach NAS")
	}
	err = metadata.SaveHost(svc.provider.ClientAPI, target)
	if err != nil {
		return errors.Wrap(err, "Cannot detach NAS")
	}

	// err = metadata.UmountNas(svc.provider, client, nas)
	// if err != nil {
	// 	tbr := errors.Wrap(err, "")
	// 	log.Errorf("%+v", tbr)
	// 	return client, tbr
	// }

	return nil
}

// Inspect returns the host defines as NAS 'name'
func (svc *NasService) Inspect(name string) (*model.Host, propsv1.HostExport, error) {
	hostID, err := metadata.LoadNas(svc.provider, name)
	if err != nil {
		tbr := errors.Wrap(err, "Error loading NAS metadata")
		log.Errorf("%+v", tbr)
		return nil, propsv1.BlankHostExport, tbr
	}
	if hostID == "" {
		tbr := errors.Wrap(model.ResourceNotFoundError("NAS", name), "Cannot inspect NAS")
		return nil, propsv1.BlankHostExport, tbr
	}

	mh, err := metadata.LoadHost(svc.provider, hostID)
	if err != nil {
		return nil, propsv1.BlankHostExport, errors.Wrap(err, "Cannot inspect NAS")
	}
	host := mh.Get()
	if host == nil {
		return nil, propsv1.BlankHostExport, errors.Wrap(fmt.Errorf("failed to find data of host"), "Cannot inspect NAS")
	}
	hpNasV1 := propsv1.BlankHostNas
	err = host.Properties.Get(HostProperty.NasV1, &hpNasV1)
	if err != nil {
		return nil, propsv1.BlankHostExport, errors.Wrap(err, "Cannot inspect NAS")
	}
	exportID, found := hpNasV1.ExportsByName[name]
	if !found {
		exportID = name
		_, found = hpNasV1.ExportsByID[exportID]
	}
	if !found {
		return nil, propsv1.BlankHostExport, errors.Wrap(err, "Cannot inspect NAS")
	}
	return host, hpNasV1.ExportsByID[exportID], nil
}

func (svc *NasService) findNas(name string) (string, error) {
	hostID, err := metadata.LoadNas(svc.provider, name)
	if err != nil {
		tbr := errors.Wrap(err, "Cannot load NAS")
		log.Errorf("%+v", tbr)
		return "", tbr
	}
	if hostID == "" {
		return "", nil
	}
	return hostID, nil
}

// func (svc *NasService) findClient(nasName, hostName string) (*model.Nas, error) {
// 	mtdnas, err := metadata.LoadNas(svc.provider, nasName)
// 	if err != nil {
// 		tbr := errors.Wrap(err, "Cannot load NAS")
// 		log.Errorf("%+v", tbr)
// 		return nil, tbr
// 	}
// 	if mtdnas == nil {
// 		return nil, errors.Wrap(model.ResourceNotFoundError("NAS", nasName), "Cannot load NAS")
// 	}

// 	client, err := mtdnas.FindClient(hostName)
// 	if err != nil {
// 		tbr := errors.Wrap(err, "")
// 		log.Errorf("%+v", tbr)
// 		return client, tbr
// 	}

// 	return client, err
// }
