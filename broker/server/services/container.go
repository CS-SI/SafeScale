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
	"github.com/CS-SI/SafeScale/providers/model"
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

// ContainerService container service
type ContainerService struct {
	provider *providers.Service
}

// List retrieves all available containers
func (svc *ContainerService) List() ([]string, error) {
	return svc.provider.ListContainers()
}

// Create a container
func (svc *ContainerService) Create(name string) error {
	container, _ := svc.provider.GetContainer(name)
	if container != nil {
		return model.ResourceAlreadyExistsError("Container", name)
	}
	return svc.provider.CreateContainer(name)
}

// Delete a container
func (svc *ContainerService) Delete(name string) error {
	return svc.provider.DeleteContainer(name)
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
	hostService := NewHostService(svc.provider)
	host, err := hostService.Get(hostName)
	if err != nil {
		return srvLog(fmt.Errorf("no host found with name or id '%s'", hostName))
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
	hostService := NewHostService(svc.provider)
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
