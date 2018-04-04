package commands

import (
	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
)

// broker container create c1
// broker container mount c1 vm1 --path="/shared/data" (utilisation de s3ql, par default /containers/c1)
// broker container umount c1 vm1
// broker container delete c1
// broker container list
// broker container inspect C1

//ContainerAPI defines API to manipulate containers
type ContainerAPI interface {
	List() ([]string, error)
	Create(string) error
	Delete(string) error
	Inspect(string) (*api.ContainerInfo, error)
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

//Create creates a container
func (srv *ContainerService) Create(name string) error {
	return srv.provider.CreateContainer(name)
}

//Delete deletes a container
func (srv *ContainerService) Delete(name string) error {
	return srv.provider.DeleteContainer(name)
}

//Inspect inspect a container
func (srv *ContainerService) Inspect(name string) (*api.ContainerInfo, error) {
	return srv.provider.GetContainer(name)
}
