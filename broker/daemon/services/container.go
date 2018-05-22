package services

import (
	"fmt"
	"regexp"

	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
)

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

//ContainerService container service
type ContainerService struct {
	provider *providers.Service
}

//List retrieves all available containers
func (srv *ContainerService) List() ([]string, error) {
	return srv.provider.ListContainers()
}

//Create a container
func (srv *ContainerService) Create(name string) error {
	container, _ := srv.provider.GetContainer(name)
	if container != nil {
		return providers.ResourceAlreadyExistsError("Container", name)
	}
	return srv.provider.CreateContainer(name)
}

//Delete a container
func (srv *ContainerService) Delete(name string) error {
	return srv.provider.DeleteContainer(name)
}

//Inspect a container
func (srv *ContainerService) Inspect(name string) (*api.ContainerInfo, error) {
	return srv.provider.GetContainer(name)
}

//Mount a container on a VM on the given mount point
func (srv *ContainerService) Mount(containerName, vmName, path string) error {
	// Check container existence
	_, err := srv.Inspect(containerName)
	if err != nil {
		return err
	}

	// Get VM ID
	vmService := NewVMService(srv.provider)
	vm, err := vmService.Get(vmName)
	if err != nil {
		return fmt.Errorf("No VM found with name or id '%s'", vmName)
	}

	// Create mount point
	mountPoint := path
	if path == api.DefaultContainerMountPoint {
		mountPoint = api.DefaultContainerMountPoint + containerName
	}

	authOpts, _ := srv.provider.GetAuthOpts()
	authurl, _ := authOpts.Config("AuthUrl")
	authurl = regexp.MustCompile("https?:/+(.*)/.*").FindStringSubmatch(authurl)[1]
	tenant, _ := authOpts.Config("TenantName")
	login, _ := authOpts.Config("Login")
	password, _ := authOpts.Config("Password")
	region, _ := authOpts.Config("Region")

	cfgOpts, _ := srv.provider.GetCfgOpts()
	s3protocol, _ := cfgOpts.Config("S3Protocol")

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
		S3Protocol: s3protocol,
	}

	return exec("mount_object_storage.sh", data, vm.ID, srv.provider)
}

//UMount a container
func (srv *ContainerService) UMount(containerName, vmName string) error {
	// Check container existence
	_, err := srv.Inspect(containerName)
	if err != nil {
		return err
	}

	// Get VM ID
	vmService := NewVMService(srv.provider)
	vm, err := vmService.Get(vmName)
	if err != nil {
		return fmt.Errorf("No VM found with name or id '%s'", vmName)
	}

	data := struct {
		Container string
	}{
		Container: containerName,
	}

	return exec("umount_object_storage.sh", data, vm.ID, srv.provider)
}
