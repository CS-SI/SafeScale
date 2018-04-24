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

//Create a container
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
		VMID:     vm.ID,
		Path:     exportedPath,
		IsServer: true,
	}
	err = srv.saveNASDefinition(*nas)
	return nas, err
}

//Delete a container
func (srv *NasService) Delete(name string) (*api.Nas, error) {
	nas, err := srv.readNasDefinition(name)
	if err != nil {
		return nil, providers.ResourceNotFoundError("Nas", name)
	}

	vm, err := srv.vmService.Get(nas.VMID)
	if err != nil {
		return nil, fmt.Errorf("No VM found with name or id '%s'", nas.VMID)
	}

	data := struct {
		ExportedPath string
	}{
		ExportedPath: nas.Path,
	}
	scriptCmd, err := getBoxContent("delete_nas.sh", data)
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

	err = srv.removeNASDefinition(name)
	return nas, err

}

func (srv *NasService) saveNASDefinition(nas api.Nas) error {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(nas)
	if err != nil {
		return err
	}
	return srv.provider.PutObject(api.NasContainerName, api.Object{
		Name:    nas.Name,
		Content: bytes.NewReader(buffer.Bytes()),
	})
}

func (srv *NasService) removeNASDefinition(nasName string) error {
	return srv.provider.DeleteObject(api.NasContainerName, nasName)
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
	return convert.ToPBNas(nas), err
}
