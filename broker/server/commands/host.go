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

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/server/services"
	"github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/providers"

	conv "github.com/CS-SI/SafeScale/broker/utils"
	safeutils "github.com/CS-SI/SafeScale/utils"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/nanobox-io/golang-scribble"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"os"
)

// broker host create host1 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=true
// broker host list --all=false
// broker host inspect host1
// broker host create host2 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=false

// HostServiceServer host service server grpc
type HostServiceServer struct{}

type StoredCPUInfo struct {
	Id      string `bow:"key"`
	TenantName   string `json:"tenant_name,omitempty"`
	TemplateID   string `json:"template_id,omitempty"`
	TemplateName string `json:"template_name,omitempty"`
	ImageID      string `json:"image_id,omitempty"`
	ImageName    string `json:"image_name,omitempty"`
	LastUpdated  string `json:"last_updated,omitempty"`

	NumberOfCPU    int     `json:"number_of_cpu,omitempty"`
	NumberOfCore   int     `json:"number_of_core,omitempty"`
	NumberOfSocket int     `json:"number_of_socket,omitempty"`
	CPUFrequency   float64 `json:"cpu_frequency,omitempty"`
	CPUArch        string  `json:"cpu_arch,omitempty"`
	Hypervisor     string  `json:"hypervisor,omitempty"`
	CPUModel       string  `json:"cpu_model,omitempty"`
	RAMSize        float64 `json:"ram_size,omitempty"`
	RAMFreq        float64 `json:"ram_freq,omitempty"`
	GPU            int     `json:"gpu,omitempty"`
	GPUModel       string  `json:"gpu_model,omitempty"`
}

// Start ...
func (s *HostServiceServer) Start(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Start host called '%s'", in.Name)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't start host: no tenant set")
	}

	ref := utils.GetReference(in)
	hostAPI := services.NewHostService(providers.FromClient(currentTenant.Client))

	err := hostAPI.Start(ref)
	if err != nil {
		return nil, err
	}

	log.Printf("Host '%s' started", ref)
	return &google_protobuf.Empty{}, nil
}

// Stop ...
func (s *HostServiceServer) Stop(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Stop host called '%s'", in.Name)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't stop host: no tenant set")
	}

	ref := utils.GetReference(in)
	hostAPI := services.NewHostService(providers.FromClient(currentTenant.Client))

	err := hostAPI.Stop(ref)
	if err != nil {
		return nil, err
	}

	log.Printf("Host '%s' stopped", ref)
	return &google_protobuf.Empty{}, nil
}

// Reboot ...
func (s *HostServiceServer) Reboot(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Reboot host called, '%s'", in.Name)

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't reboot host: no tenant set")
	}

	ref := utils.GetReference(in)
	hostAPI := services.NewHostService(providers.FromClient(currentTenant.Client))

	err := hostAPI.Reboot(ref)
	if err != nil {
		return nil, err
	}

	log.Printf("Host '%s' rebooted", ref)
	return &google_protobuf.Empty{}, nil
}

// List available hosts
func (s *HostServiceServer) List(ctx context.Context, in *pb.HostListRequest) (*pb.HostList, error) {
	log.Printf("List hosts called")

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't list hosts: no tenant set")
	}

	hostAPI := services.NewHostService(providers.FromClient(currentTenant.Client))

	hosts, err := hostAPI.List(in.GetAll())
	if err != nil {
		return nil, err
	}

	var pbhost []*pb.Host

	// Map api.Host to pb.Host
	for _, host := range hosts {
		pbhost = append(pbhost, conv.ToPBHost(host))
	}
	rv := &pb.HostList{Hosts: pbhost}
	return rv, nil
}

// Create a new host
func (s *HostServiceServer) Create(ctx context.Context, in *pb.HostDefinition) (*pb.Host, error) {
	log.Printf("Create host called '%s'", in.Name)
	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot create host : No tenant set")
	}

	hostService := services.NewHostService(providers.FromClient(currentTenant.Client))

	askedForSpecificScannerInfo := in.GetGPUNumber() > 0 || in.GetFreq() != 0
	if askedForSpecificScannerInfo {
		_ = os.MkdirAll(safeutils.AbsPathify("$HOME/.safescale/scanner"), 0777)
		db, err := scribble.New(safeutils.AbsPathify("$HOME/.safescale/scanner/db"), nil)
		if err != nil {
			if !in.Force {
				fmt.Println("Problem accessing Scanner database: ignoring GPU and Freq parameters...")
				log.Warnf("Problem creating / accessing Scanner database, ignoring for now...: %v", err)
			} else {
				noHostError := fmt.Sprintf("Unable to create a host with '%d' GPUs and '%f' GHz clock frequency !, problem accessing Scanner database: %v", in.GetGPUNumber(), in.GetFreq(), err)
				log.Error(noHostError)
				return nil, errors.New(noHostError)
			}
		} else {
			image_list, err := db.ReadAll("images")
			if err != nil {
				if !in.Force {
					fmt.Println("Problem accessing Scanner database: ignoring GPU and Freq parameters...")
					log.Warnf("Error reading Scanner database: %v", err)
				} else {
					noHostError := fmt.Sprintf("Unable to create a host with '%d' GPUs and '%f' GHz clock frequency !, problem listing images from Scanner database: %v", in.GetGPUNumber(), in.GetFreq(), err)
					log.Error(noHostError)
					return nil, errors.New(noHostError)
				}
			} else {
				images := []StoredCPUInfo{}
				for _, f := range image_list {
					imageFound := StoredCPUInfo{}
					if err := json.Unmarshal([]byte(f), &imageFound); err != nil {
						fmt.Println("Error", err)
					}

					if imageFound.GPU < int(in.GetGPUNumber()) {
						continue
					}

					if imageFound.CPUFrequency < float64(in.GetFreq()) {
						continue
					}

					images = append(images, imageFound)
				}

				if !in.Force && (len(images) == 0) {
					noHostError := fmt.Sprintf("Unable to create a host with '%d' GPUs and '%f' GHz clock frequency !, no such host found with those specs !!", in.GetGPUNumber(), in.GetFreq())
					log.Error(noHostError)
					return nil, errors.New(noHostError)
				}
			}
		}
	}

	// TODO https://github.com/CS-SI/SafeScale/issues/30
	// TODO GITHUB If we have to ask for GPU requirements and FREQ requirements, pb.HostDefinition has to change and the invocation of hostService.Create too...

	host, err := hostService.Create(in.GetName(), in.GetNetwork(),
		int(in.GetCPUNumber()), in.GetRAM(), int(in.GetDisk()), in.GetImageID(), in.GetPublic())
	if err != nil {
		return nil, err
	}

	log.Printf("Host '%s' created", in.GetName())
	return conv.ToPBHost(host), nil
}

// Status of a host
func (s *HostServiceServer) Status(ctx context.Context, in *pb.Reference) (*pb.HostStatus, error) {
	log.Printf("Host Status called '%s'", in.Name)

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Can't get host status: neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't get host status: no tenant set")
	}

	hostService := services.NewHostService(providers.FromClient(currentTenant.Client))
	host, err := hostService.Get(ref)
	if err != nil {
		return nil, err
	}
	if host == nil {
		return nil, fmt.Errorf("Can't get host status: no host '%s' found", ref)
	}

	return conv.ToHostStatus(host), nil
}

// Inspect an host
func (s *HostServiceServer) Inspect(ctx context.Context, in *pb.Reference) (*pb.Host, error) {
	log.Printf("Inspect Host called '%s'", in.Name)

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Can't inspect host: neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't inspect host: no tenant set")
	}

	hostService := services.NewHostService(providers.FromClient(currentTenant.Client))
	host, err := hostService.Get(ref)
	if err != nil {
		return nil, err
	}
	if host == nil {
		return nil, fmt.Errorf("Can't inspect host: no host '%s' found", ref)
	}

	return conv.ToPBHost(host), nil
}

// Delete an host
func (s *HostServiceServer) Delete(ctx context.Context, in *pb.Reference) (*google_protobuf.Empty, error) {
	log.Printf("Delete Host called '%s'", in.Name)

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Can't delete host: neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't delete host: no tenant set")
	}
	hostService := services.NewHostService(providers.FromClient(currentTenant.Client))
	err := hostService.Delete(ref)
	if err != nil {
		return nil, err
	}
	log.Printf("Host '%s' deleted", ref)
	return &google_protobuf.Empty{}, nil
}

// SSH returns ssh parameters to access an host
func (s *HostServiceServer) SSH(ctx context.Context, in *pb.Reference) (*pb.SshConfig, error) {
	log.Printf("Ssh Host called '%s'", in.Name)

	ref := utils.GetReference(in)
	if ref == "" {
		return nil, fmt.Errorf("Can't ssh to host: neither name nor id given as reference")
	}

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Can't ssh host: no tenant set")
	}
	hostService := services.NewHostService(providers.FromClient(currentTenant.Client))
	sshConfig, err := hostService.SSH(ref)
	if err != nil {
		return nil, err
	}
	log.Printf("Got Ssh config for host '%s'", ref)
	return conv.ToPBSshConfig(sshConfig), nil
}
