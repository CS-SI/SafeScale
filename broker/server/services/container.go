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
	"regexp"

	"github.com/CS-SI/SafeScale/providers"
<<<<<<< develop:broker/server/services/container.go
	"github.com/CS-SI/SafeScale/providers/model"
||||||| ancestor
	"github.com/CS-SI/SafeScale/providers/api"
=======
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/object"
>>>>>>> Update object storage management:broker/daemon/services/container.go
)

//go:generate mockgen -destination=../mocks/mock_containerapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/services ContainerAPI

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

//ContainerAPI defines API to manipulate containers
type ContainerAPI interface {
	List() ([]string, error)
	Create(string) error
	Delete(string) error
	Inspect(string) (*model.ContainerInfo, error)
	Mount(string, string, string) error
	UMount(string, string) error
}

//NewContainerService creates a Container service
func NewContainerService(api *providers.Service) ContainerAPI {
	return &ContainerService{
		provider: api,
	}
}

//NewContainerServiceObject creates a Container service
func NewContainerServiceObject(location *object.Location) ContainerAPI {
	return &ContainerService{
		provider: providers.FromClientObject(location),
	}
}

// ContainerService container service
type ContainerService struct {
	provider *providers.Service
}

// List retrieves all available containers
<<<<<<< develop:broker/server/services/container.go
func (svc *ContainerService) List() ([]string, error) {
	return svc.provider.ListContainers()
||||||| ancestor
func (srv *ContainerService) List() ([]string, error) {
	return srv.provider.ListContainers()
=======
func (srv *ContainerService) List() ([]string, error) {
	fmt.Println("ooooooo List")
	fmt.Println("ooooooo List", srv.provider.Location)
	return srv.provider.Location.ListContainers()
>>>>>>> Update object storage management:broker/daemon/services/container.go
}

// Create a container
<<<<<<< develop:broker/server/services/container.go
func (svc *ContainerService) Create(name string) error {
	container, _ := svc.provider.GetContainer(name)
	if container != nil {
		return model.ResourceAlreadyExistsError("Container", name)
	}
	return svc.provider.CreateContainer(name)
||||||| ancestor
func (srv *ContainerService) Create(name string) error {
	container, _ := srv.provider.GetContainer(name)
	if container != nil {
		return providers.ResourceAlreadyExistsError("Container", name)
	}
	return srv.provider.CreateContainer(name)
=======
func (srv *ContainerService) Create(name string) error {
	fmt.Println("ooooooo Create ")
	fmt.Println("ooooooo Create", srv.provider.Location)
	/*	container, _ := srv.provider.GetContainer(name)
		if container != nil {
			return providers.ResourceAlreadyExistsError("Container", name)
		}*/
	return srv.provider.Location.Create(name)
>>>>>>> Update object storage management:broker/daemon/services/container.go
}

// Delete a container
<<<<<<< develop:broker/server/services/container.go
func (svc *ContainerService) Delete(name string) error {
	return svc.provider.DeleteContainer(name)
||||||| ancestor
func (srv *ContainerService) Delete(name string) error {
	return srv.provider.DeleteContainer(name)
=======
func (srv *ContainerService) Delete(name string) error {
	return srv.provider.Location.Remove(name)
>>>>>>> Update object storage management:broker/daemon/services/container.go
}

// Inspect a container
func (svc *ContainerService) Inspect(name string) (*model.ContainerInfo, error) {
	return svc.provider.GetContainer(name)
}

// Mount a container on an host on the given mount point
func (svc *ContainerService) Mount(containerName, hostName, path string) error {
	// Check container existence
	_, err := svc.Inspect(containerName)
	if err != nil {
		return srvLog(err)
	}

	// Get Host ID
<<<<<<< develop:broker/server/services/container.go
	hostService := NewHostService(svc.provider)
||||||| ancestor
	hostService := NewHostService(srv.provider)
=======
	hostService := NewHostService(srv.provider.ClientAPI)
>>>>>>> Update object storage management:broker/daemon/services/container.go
	host, err := hostService.Get(hostName)
	if err != nil {
		return srvLogMessage(err, fmt.Sprintf("no host found with name or id '%s'", hostName))
	}

	// Create mount point
	mountPoint := path
	if path == model.DefaultContainerMountPoint {
		mountPoint = model.DefaultContainerMountPoint + containerName
	}

	authOpts, _ := svc.provider.GetAuthOpts()
	authurlCfg, _ := authOpts.Config("AuthUrl")
	authurl := authurlCfg.(string)
	authurl = regexp.MustCompile("https?:/+(.*)/.*").FindStringSubmatch(authurl)[1]
	tenantCfg, _ := authOpts.Config("TenantName")
	tenant := tenantCfg.(string)
	loginCfg, _ := authOpts.Config("Login")
	login := loginCfg.(string)
	passwordCfg, _ := authOpts.Config("Password")
	password := passwordCfg.(string)
	regionCfg, _ := authOpts.Config("Region")
	region := regionCfg.(string)

	cfgOpts, _ := svc.provider.GetCfgOpts()
	objStorageProtocolCfg, _ := cfgOpts.Config("S3Protocol")
	objStorageProtocol := objStorageProtocolCfg.(string)

	data := struct {
		Container  string
		Tenant     string
		Login      string
		Password   string
		AuthURL    string
		Region     string
		MountPoint string
		S3Protocol string
	}{
		Container:  containerName,
		Tenant:     tenant,
		Login:      login,
		Password:   password,
		AuthURL:    authurl,
		Region:     region,
		MountPoint: mountPoint,
		S3Protocol: objStorageProtocol,
	}

	return exec("mount_object_storage.sh", data, host.ID, svc.provider)
}

// UMount a container
func (svc *ContainerService) UMount(containerName, hostName string) error {
	// Check container existence
	_, err := svc.Inspect(containerName)
	if err != nil {
		return srvLog(err)
	}

	// Get Host ID
<<<<<<< develop:broker/server/services/container.go
	hostService := NewHostService(svc.provider)
||||||| ancestor
	hostService := NewHostService(srv.provider)
=======
	hostService := NewHostService(srv.provider.ClientAPI)
>>>>>>> Update object storage management:broker/daemon/services/container.go
	host, err := hostService.Get(hostName)
	if err != nil {
		return fmt.Errorf("no host found with name or id '%s'", hostName)
	}

	data := struct {
		Container string
	}{
		Container: containerName,
	}

	return exec("umount_object_storage.sh", data, host.ID, svc.provider)
}
