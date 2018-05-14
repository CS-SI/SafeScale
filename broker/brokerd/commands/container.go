package commands

import (
	"context"
	"fmt"
	"log"
	"regexp"

	conv "github.com/SafeScale/broker/utils"

	pb "github.com/SafeScale/broker"

	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
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

	cfg, _ := srv.provider.GetAuthOpts()
	authurl, _ := cfg.Config("AuthUrl")
	authurl = regexp.MustCompile("https?:/+(.*)/.*").FindStringSubmatch(authurl)[1]
	tenant, _ := cfg.Config("TenantName")
	login, _ := cfg.Config("Login")
	password, _ := cfg.Config("Password")
	region, _ := cfg.Config("Region")

	data := struct {
		Container  string
		Tenant     string
		Login      string
		Password   string
		AuthURL    string
		Region     string
		MountPoint string
	}{
		Container:  containerName,
		Tenant:     tenant,
		Login:      login,
		Password:   password,
		AuthURL:    authurl,
		Region:     region,
		MountPoint: mountPoint,
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

//ContainerServiceServer is the container service grpc server
type ContainerServiceServer struct{}

//List available containers
func (s *ContainerServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.ContainerList, error) {
	log.Printf("Container list called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := NewContainerService(currentTenant.client)
	containers, err := service.List()
	if err != nil {
		return nil, err
	}

	log.Println("End container list")
	return conv.ToPBContainerList(containers), nil
}

//Create a new container
func (s *ContainerServiceServer) Create(ctx context.Context, in *pb.Container) (*google_protobuf.Empty, error) {
	log.Printf("Crete container called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := NewContainerService(currentTenant.client)
	err := service.Create(in.GetName())
	if err != nil {
		return nil, err
	}

	log.Println("End container container")
	return &google_protobuf.Empty{}, nil
}

//Delete a container
func (s *ContainerServiceServer) Delete(ctx context.Context, in *pb.Container) (*google_protobuf.Empty, error) {
	log.Printf("Delete container called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := NewContainerService(currentTenant.client)
	err := service.Delete(in.GetName())
	if err != nil {
		return nil, err
	}

	log.Println("End delete container")
	return &google_protobuf.Empty{}, nil
}

//Inspect a container
func (s *ContainerServiceServer) Inspect(ctx context.Context, in *pb.Container) (*pb.ContainerMountingPoint, error) {
	log.Printf("Inspect container called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := NewContainerService(currentTenant.client)
	resp, err := service.Inspect(in.GetName())
	if err != nil {
		return nil, err
	}

	log.Println("End inspect container")
	return conv.ToPBContainerMountPoint(resp), nil
}

//Mount a container on the filesystem of the VM
func (s *ContainerServiceServer) Mount(ctx context.Context, in *pb.ContainerMountingPoint) (*google_protobuf.Empty, error) {
	log.Printf("Mount container called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := NewContainerService(currentTenant.client)
	err := service.Mount(in.GetContainer(), in.GetVM().GetName(), in.GetPath())

	log.Println("End Mount container")
	return &google_protobuf.Empty{}, err
}

//UMount a container from the filesystem of the VM
func (s *ContainerServiceServer) UMount(ctx context.Context, in *pb.ContainerMountingPoint) (*google_protobuf.Empty, error) {
	log.Printf("UMount container called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := NewContainerService(currentTenant.client)
	err := service.UMount(in.GetContainer(), in.GetVM().GetName())

	log.Println("End UMount container")
	return &google_protobuf.Empty{}, err
}
