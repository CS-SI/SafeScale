package commands

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"log"
	"path"

	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"

	pb "github.com/SafeScale/broker"
	convert "github.com/SafeScale/broker/utils"
)

// broker nas create nas1 vm1 --path="/shared/data"
// broker nas delete nas1
// broker nas mount nas1 vm2 --path="/data"
// broker nas umount nas1 vm2
// broker nas list
// broker nas inspect nas1

//NasAPI defines API to manipulate NAS
type NasAPI interface {
	Create(name, vm, path string) (*api.Nas, error)
	Delete(name string) (*api.Nas, error)
	List() ([]api.Nas, error)
	Mount(name, vm, path string) (*api.Nas, error)
	UMount(name, vm string) (*api.Nas, error)
	Inspect(name string) ([]api.Nas, error)
}

//NewNasService creates a NAS service
func NewNasService(api api.ClientAPI) NasAPI {
	return &NasService{
		provider:  providers.FromClient(api),
		vmService: NewVMService(api),
	}
}

//NasService nas service
type NasService struct {
	provider  *providers.Service
	vmService VMAPI
}

func sanitize(in string) (string, error) {
	sanitized := path.Clean(in)
	if !path.IsAbs(sanitized) {
		return "", fmt.Errorf("Exposed path must be absolute")
	}
	return sanitized, nil
}

//Create a nas
func (srv *NasService) Create(name, vmName, path string) (*api.Nas, error) {

	vm, err := srv.vmService.Get(vmName)
	if err != nil {
		return nil, fmt.Errorf("No VM found with name or id '%s'", vmName)
	}

	// Sanitize path
	exportedPath, err := sanitize(path)
	if err != nil {
		return nil, fmt.Errorf("Invalid path to be exposed: '%s' : '%s'", path, err)
	}

	data := struct {
		ExportedPath string
	}{
		ExportedPath: exportedPath,
	}
	scriptCmd, err := getBoxContent("create_nas.sh", data)
	if err != nil {
		// TODO Use more explicit error
		return nil, err
	}
	// retrieve ssh config to perform some commands
	ssh, err := srv.provider.GetSSHConfig(vm.ID)
	if err != nil {
		// TODO Use more explicit error
		return nil, err
	}

	cmd, err := ssh.SudoCommand(scriptCmd)
	if err != nil {
		// TODO Use more explicit error
		return nil, err
	}
	_, err = cmd.Output()
	if err != nil {
		return nil, err
	}

	nas := &api.Nas{
		Name:     name,
		ServerID: vm.ID,
		Path:     exportedPath,
		IsServer: true,
	}
	err = srv.saveNASDefinition(*nas)
	return nas, err
}

//Delete a container
func (srv *NasService) Delete(name string) (*api.Nas, error) {
	// TODO umount all clients
	nas, err := srv.findNas(name)
	if err != nil {
		return nil, providers.ResourceNotFoundError("Nas", name)
	}

	vm, err := srv.vmService.Get(nas.ServerID)
	if err != nil {
		return nil, fmt.Errorf("No VM found with name or id '%s'", nas.ServerID)
	}

	data := struct {
		ExportedPath string
	}{
		ExportedPath: nas.Path,
	}
	scriptCmd, err := getBoxContent("nfs_unexport_repository.sh", data)
	if err != nil {
		// TODO Use more explicit error
		return nil, err
	}
	// retrieve ssh config to perform some commands
	ssh, err := srv.provider.GetSSHConfig(vm.ID)
	if err != nil {
		// TODO Use more explicit error
		return nil, err
	}

	cmd, err := ssh.SudoCommand(scriptCmd)
	if err != nil {
		// TODO Use more explicit error
		return nil, err
	}
	_, err = cmd.Output()
	if err != nil {
		return nil, err
	}

	err = srv.removeNASDefinition(*nas)
	return nas, err

}

//List return the list of all created nas
func (srv *NasService) List() ([]api.Nas, error) {
	names, err := srv.provider.ListObjects(api.NasContainerName, api.ObjectFilter{
		Path:   "",
		Prefix: "",
	})
	if err != nil {
		return nil, err
	}

	var nass []api.Nas

	for _, name := range names {
		nas, err := srv.readNasDefinition(name)
		if err != nil {
			return nil, providers.ResourceNotFoundError("Nas", name)
		}
		if nas.IsServer {
			nass = append(nass, *nas)
		}
	}

	return nass, nil

}

//Mount a directory exported by a nas on a local directory of a vm
func (srv *NasService) Mount(name, vmName, path string) (*api.Nas, error) {
	nas, err := srv.findNas(name)
	if err != nil {
		return nil, err
	}

	vm, err := srv.vmService.Get(vmName)
	if err != nil {
		return nil, providers.ResourceNotFoundError("VM", vmName)
	}

	nfsServer, err := srv.vmService.Get(nas.ServerID)
	if err != nil {
		return nil, providers.ResourceNotFoundError("VM", nas.ServerID)
	}

	// Sanitize path
	mountPath, err := sanitize(path)
	if err != nil {
		return nil, fmt.Errorf("Invalid path to be mounted: '%s' : '%s'", path, err)
	}

	data := struct {
		NFSServer    string
		ExportedPath string
		MountPath    string
	}{
		NFSServer:    nfsServer.GetAccessIP(),
		ExportedPath: nas.Path,
		MountPath:    mountPath,
	}
	scriptCmd, err := getBoxContent("mount_nfs_directory.sh", data)
	if err != nil {
		// TODO Use more explicit error
		return nil, err
	}
	// retrieve ssh config to perform some commands
	ssh, err := srv.provider.GetSSHConfig(vm.ID)
	if err != nil {
		// TODO Use more explicit error
		return nil, err
	}

	cmd, err := ssh.SudoCommand(scriptCmd)
	if err != nil {
		// TODO Use more explicit error
		return nil, err
	}
	_, err = cmd.Output()
	if err != nil {
		return nil, err
	}

	client := &api.Nas{
		Name:     name,
		ServerID: vm.ID,
		Path:     mountPath,
		IsServer: false,
	}
	err = srv.saveNASDefinition(*client)
	return client, err
}

//UMount a directory exported by a nas on a local directory of a vm
func (srv *NasService) UMount(name, vmName string) (*api.Nas, error) {
	nas, err := srv.findNas(name)
	if err != nil {
		return nil, err
	}

	vm, err := srv.vmService.Get(vmName)
	if err != nil {
		return nil, providers.ResourceNotFoundError("VM", vmName)
	}

	nfsServer, err := srv.vmService.Get(nas.ServerID)
	if err != nil {
		return nil, providers.ResourceNotFoundError("VM", nas.ServerID)
	}

	data := struct {
		NFSServer    string
		ExportedPath string
	}{
		NFSServer:    nfsServer.GetAccessIP(),
		ExportedPath: nas.Path,
	}
	scriptCmd, err := getBoxContent("umount_nfs_directory.sh", data)
	if err != nil {
		// TODO Use more explicit error
		return nil, err
	}
	// retrieve ssh config to perform some commands
	ssh, err := srv.provider.GetSSHConfig(vm.ID)
	if err != nil {
		// TODO Use more explicit error
		return nil, err
	}

	cmd, err := ssh.SudoCommand(scriptCmd)
	if err != nil {
		// TODO Use more explicit error
		return nil, err
	}
	_, err = cmd.Output()
	if err != nil {
		return nil, err
	}

	client := &api.Nas{
		Name:     name,
		ServerID: vm.ID,
		Path:     nas.Path,
		IsServer: false,
	}
	err = srv.removeNASDefinition(*client)
	return client, err
}

//Inspect return the detail the nas whose nas is given and all clients connected to
func (srv *NasService) Inspect(name string) ([]api.Nas, error) {
	names, err := srv.provider.ListObjects(api.NasContainerName, api.ObjectFilter{
		Path:   "",
		Prefix: name,
	})
	if err != nil {
		return nil, err
	}

	var nass []api.Nas

	for _, name := range names {
		nas, err := srv.readNasDefinition(name)
		if err != nil {
			return nil, providers.ResourceNotFoundError("Nas", name)
		}
		if nas.IsServer {
			nass = append([]api.Nas{*nas}, nass...)
		} else {
			nass = append(nass, *nas)
		}
	}

	return nass, nil

}

func (srv *NasService) saveNASDefinition(nas api.Nas) error {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(nas)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%s/%s", nas.Name, nas.ServerID)
	log.Printf("Saving nas definition: %s", name)
	return srv.provider.PutObject(api.NasContainerName, api.Object{
		Name:    name,
		Content: bytes.NewReader(buffer.Bytes()),
	})
}

func (srv *NasService) removeNASDefinition(nas api.Nas) error {

	fullName := fmt.Sprintf("%s/%s", nas.Name, nas.ServerID)
	log.Printf("Removing name definition: %s", fullName)

	return srv.provider.DeleteObject(api.NasContainerName, fullName)
}

func (srv *NasService) readNasDefinition(nasName string) (*api.Nas, error) {
	o, err := srv.provider.GetObject(api.NasContainerName, nasName, nil)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.ReadFrom(o.Content)
	enc := gob.NewDecoder(&buffer)
	var nas api.Nas
	err = enc.Decode(&nas)
	if err != nil {
		return nil, err
	}
	return &nas, nil
}

func (srv *NasService) findNas(name string) (*api.Nas, error) {
	names, err := srv.provider.ListObjects(api.NasContainerName, api.ObjectFilter{
		Path:   "",
		Prefix: name,
	})
	if err != nil {
		return nil, err
	}

	found := false
	var nas *api.Nas
	for _, nasName := range names {
		nas, err = srv.readNasDefinition(nasName)
		if err != nil {
			return nil, providers.ResourceNotFoundError("Nas", nasName)
		}
		if nas.IsServer {
			found = true
			break
		}
	}
	if !found {
		return nil, providers.ResourceNotFoundError("Nas", name)
	}

	return nas, nil
}

//NasServiceServer NAS service server grpc
type NasServiceServer struct{}

//Create call nas service creation
func (s *NasServiceServer) Create(ctx context.Context, in *pb.NasDefinition) (*pb.NasDefinition, error) {
	log.Printf("Create NAS called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	nasService := NewNasService(currentTenant.client)
	nas, err := nasService.Create(in.GetNas().GetName(), in.GetVM().GetName(), in.GetPath())

	if err != nil {
		log.Println(err)
		return nil, err
	}
	log.Printf("End Create Nas")
	return convert.ToPBNas(nas), err
}

//Delete call nas service deletion
func (s *NasServiceServer) Delete(ctx context.Context, in *pb.NasName) (*pb.NasDefinition, error) {
	log.Printf("Delete NAS called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	nasService := NewNasService(currentTenant.client)
	nas, err := nasService.Delete(in.GetName())

	if err != nil {
		log.Println(err)
		return nil, err
	}
	log.Printf("End Delete Nas")
	return convert.ToPBNas(nas), err
}

//List return the list of all available nas
func (s *NasServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.NasList, error) {
	log.Printf("List NAS called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	nasService := NewNasService(currentTenant.client)
	nass, err := nasService.List()

	if err != nil {
		log.Println(err)
		return nil, err
	}

	var pbnass []*pb.NasDefinition

	// Map api.Network to pb.Network
	for _, nas := range nass {
		pbnass = append(pbnass, convert.ToPBNas(&nas))
	}
	rv := &pb.NasList{NasList: pbnass}
	log.Printf("End List Nas")
	return rv, nil
}

//Mount mount exported directory from nas on a local directory of the given vm
func (s *NasServiceServer) Mount(ctx context.Context, in *pb.NasDefinition) (*pb.NasDefinition, error) {
	log.Printf("Mount NAS called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	nasService := NewNasService(currentTenant.client)
	nas, err := nasService.Mount(in.GetNas().GetName(), in.GetVM().GetName(), in.GetPath())

	if err != nil {
		log.Println(err)
		return nil, err
	}
	log.Printf("End mount Nas")
	return convert.ToPBNas(nas), err
}

//UMount umount exported directory from nas on a local directory of the given vm
func (s *NasServiceServer) UMount(ctx context.Context, in *pb.NasDefinition) (*pb.NasDefinition, error) {
	log.Printf("UMount NAS called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	nasService := NewNasService(currentTenant.client)
	nas, err := nasService.UMount(in.GetNas().GetName(), in.GetVM().GetName())

	if err != nil {
		log.Println(err)
		return nil, err
	}
	log.Printf("End umount Nas")
	return convert.ToPBNas(nas), err
}

//Inspect shows the detail of a nfs server and all connected clients
func (s *NasServiceServer) Inspect(ctx context.Context, in *pb.NasName) (*pb.NasList, error) {
	log.Printf("Inspect NAS called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	nasService := NewNasService(currentTenant.client)
	nass, err := nasService.Inspect(in.GetName())

	if err != nil {
		log.Println(err)
		return nil, err
	}
	var pbnass []*pb.NasDefinition

	// Map api.Network to pb.Network
	for _, nas := range nass {
		pbnass = append(pbnass, convert.ToPBNas(&nas))
	}
	rv := &pb.NasList{NasList: pbnass}
	log.Printf("End Inspect Nas")
	return rv, nil
}
