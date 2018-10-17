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
	"log"
	"regexp"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
)

//go:generate mockgen -destination=../mocks/mock_containerapi.go -package=mocks github.com/CS-SI/SafeScale/broker/daemon/services ContainerAPI

//ContainerAPI defines API to manipulate containers
type ContainerAPI interface {
	List() ([]string, error)
	Create(string) error
	Delete(string) error
	Inspect(string) (*api.ContainerInfo, error)
	Mount(string, string, string) error
	UMount(string, string) error
}

//NewContainerService creates a Container service
func NewContainerService(api api.ClientAPI) ContainerAPI {
	return &ContainerService{
		provider: providers.FromClient(api),
	}
}

// ContainerService container service
type ContainerService struct {
	provider *providers.Service
}

// List retrieves all available containers
func (srv *ContainerService) List() ([]string, error) {
	return srv.provider.ListContainers()
}

// Create a container
func (srv *ContainerService) Create(name string) error {
	container, _ := srv.provider.GetContainer(name)
	if container != nil {
		return providers.ResourceAlreadyExistsError("Container", name)
	}
	return srv.provider.CreateContainer(name)
}

// Delete a container
func (srv *ContainerService) Delete(name string) error {
	return srv.provider.DeleteContainer(name)
}

// Inspect a container
func (srv *ContainerService) Inspect(name string) (*api.ContainerInfo, error) {
	return srv.provider.GetContainer(name)
}

// Mount a container on an host on the given mount point
func (srv *ContainerService) Mount(containerName, hostName, path string) error {
	// Check container existence
	_, err := srv.Inspect(containerName)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Printf("%+v", tbr)
		return tbr
	}

	// Get Host ID
	hostService := NewHostService(srv.provider)
	host, err := hostService.Get(hostName)
	if err != nil {
		return fmt.Errorf("no host found with name or id '%s'", hostName)
	}

	// Create mount point
	mountPoint := path
	if path == api.DefaultContainerMountPoint {
		mountPoint = api.DefaultContainerMountPoint + containerName
	}

	authOpts, _ := srv.provider.GetAuthOpts()
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

	cfgOpts, _ := srv.provider.GetCfgOpts()
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

	return exec("mount_object_storage.sh", data, host.ID, srv.provider)
}

//UMount a container
func (srv *ContainerService) UMount(containerName, hostName string) error {
	// Check container existence
	_, err := srv.Inspect(containerName)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Printf("%+v", tbr)
		return tbr
	}

	// Get Host ID
	hostService := NewHostService(srv.provider)
	host, err := hostService.Get(hostName)
	if err != nil {
		return fmt.Errorf("no host found with name or id '%s'", hostName)
	}

	data := struct {
		Container string
	}{
		Container: containerName,
	}

	return exec("umount_object_storage.sh", data, host.ID, srv.provider)
}
