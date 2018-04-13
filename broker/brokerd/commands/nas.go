package commands

import (
	"context"
	"fmt"
	"log"
	"path"

	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"

	pb "github.com/SafeScale/broker"
)

// broker nas create nas1 vm1 --path="/shared/data"
// broker nas delete nas1
// broker nas mount nas1 vm2 --path="/data"
// broker nas umount nas1 vm2
// broker nas list
// broker nas inspect nas1

//NasAPI defines API to manipulate NAS
type NasAPI interface {
	Create(name, vm, path string) error
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
func (srv *NasService) Create(name, vmName, path string) error {

	vm, err := srv.vmService.Get(vmName)
	if err != nil {
		return fmt.Errorf("No VM found with name or id '%s'", vmName)
	}

	// Sanitize path
	exportedPath, err := sanitize(path)
	if err != nil {
		return fmt.Errorf("Invalid path to be exposed: '%s' : '%s'", path, err)
	}

	data := struct {
		ExportedPath string
	}{
		ExportedPath: exportedPath,
	}
	scriptCmd, err := getBoxContent("create_nas.sh", data)
	if err != nil {
		// TODO Use more explicit error
		return err
	}
	// retrieve ssh config to perform some commands
	ssh, err := srv.provider.GetSSHConfig(vm.ID)
	if err != nil {
		// TODO Use more explicit error
		return err
	}

	cmd, err := ssh.SudoCommand(scriptCmd)
	if err != nil {
		// TODO Use more explicit error
		return err
	}
	_, err = cmd.Output()
	if err != nil {
		return err
	}

	return nil
}

//NasServiceServer NAS service server grpc
type NasServiceServer struct{}

//Create call nas service creation
func (s *NasServiceServer) Create(ctx context.Context, in *pb.NasDefinition) (*google_protobuf.Empty, error) {
	log.Printf("Create NAS called")
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	nasService := NewNasService(currentTenant.client)
	err := nasService.Create(in.GetNas().GetName(), in.GetVM().GetName(), in.GetPath())

	if err != nil {
		log.Println(err)
	}
	return nil, err
}
