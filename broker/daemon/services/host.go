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
	log "github.com/sirupsen/logrus"
	"github.com/CS-SI/SafeScale/broker/client"
	"github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/system"
)

//go:generate mockgen -destination=../mocks/mock_hostapi.go -package=mocks github.com/CS-SI/SafeScale/broker/daemon/services HostAPI


//HostAPI defines API to manipulate hosts
type HostAPI interface {
	Create(name string, net string, cpu int, ram float32, disk int, os string, public bool) (*api.Host, error)
	List(all bool) ([]api.Host, error)
	Get(ref string) (*api.Host, error)
	Status(ref string) (*api.Host, error)
	Delete(ref string) error
	SSH(ref string) (*system.SSHConfig, error)
	Reboot(ref string) error
	Start(ref string) error
	Stop(ref string) error
}

// NewHostService creates an host service
func NewHostService(api api.ClientAPI) HostAPI {
	return &HostService{
		provider: providers.FromClient(api),
		network:  NewNetworkService(api),
	}
}

// HostService host service
type HostService struct {
	provider *providers.Service
	network  NetworkAPI
}

func (svc *HostService) Start(ref string) error {
	log.Printf("Starting host '%s'...", ref)
	return svc.provider.StartHost(ref)
}

func (svc *HostService) Stop(ref string) error {
	log.Printf("Stopping host '%s'...", ref)
	return svc.provider.StopHost(ref)
}

func (svc *HostService) Reboot(ref string) error {
	log.Println("Rebooting host '%s'...", ref)
	return svc.provider.RebootHost(ref)
}

// Create creates a host
func (svc *HostService) Create(name string, net string, cpu int, ram float32, disk int, os string, public bool) (*api.Host, error) {
	log.Printf("Creating compute resource '%s' ...", name)
	networks := []string{}
	if len(net) != 0 {
		n, err := svc.network.Get(net)
		if err != nil {
			tbr := errors.Wrapf(err, "Failed to get network resource data: '%s'.", net)
			log.Errorf("%+v", tbr)
			return nil, tbr
		}
		if n == nil {
			return nil, fmt.Errorf("Failed to find network '%s'", net)
		}
		networks = append(networks, n.ID)
	}

	tpls, err := svc.provider.SelectTemplatesBySize(api.SizingRequirements{
		MinCores:    cpu,
		MinRAMSize:  ram,
		MinDiskSize: disk,
	})
	img, err := svc.provider.SearchImage(os)
	if err != nil {
		tbr := errors.Wrap(err, "Failed to find image to use on compute resource.")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	hostRequest := api.HostRequest{
		ImageID:    img.ID,
		Name:       name,
		TemplateID: tpls[0].ID,
		// IsGateway:  false,
		PublicIP:   public,
		NetworkIDs: networks,
	}
	host, err := svc.provider.CreateHost(hostRequest)
	if err != nil {
		tbr := errors.Wrapf(err, "Compute resource creation failed: '%s'.", hostRequest.Name)
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	log.Printf("Compute resource created: '%s'", host.Name)

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	log.Printf("Waiting start of SSH service on remote host '%s' ...", host.Name)
	ssh, err := svc.provider.GetSSHConfig(host.ID)
	if err != nil {
		derr := svc.provider.DeleteHost(host.ID)
		if derr != nil {
			log.Warnf("Error deleting host after failing to get its ssh config: %v", derr)
			tbr := errors.Wrap(err, "Error getting ssh configuration")
			log.Errorf("%+v", tbr)
			return nil, tbr
		}
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	err = ssh.WaitServerReady(utils.TimeoutCtxHost)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	if client.IsTimeout(err) {
		derr := svc.provider.DeleteHost(host.ID)
		if derr != nil {
			log.Warnf("Error deleting host after a timeout: %v", derr)
			tbr := errors.Wrap(err, "Timeout creating a host")
			log.Errorf("%+v", tbr)
			return nil, tbr
		}
		tbr := errors.Wrap(err, "Timeout creating a host")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	log.Printf("SSH service started on host '%s'.", host.Name)
	return host, nil
}

// List returns the host list
func (svc *HostService) List(all bool) ([]api.Host, error) {
	return svc.provider.ListHosts(all)
}

// Get returns the host identified by ref, ref can be the name or the id
func (svc *HostService) Get(ref string) (*api.Host, error) {
	return svc.provider.GetHost(ref)
}

// Get returns host status
func (svc *HostService) Status(ref string) (*api.Host, error) {
	return svc.provider.GetHost(ref)
}

// Delete deletes host referenced by ref
func (svc *HostService) Delete(ref string) error {
	return svc.provider.DeleteHost(ref)
}

// SSH returns ssh parameters to access the host referenced by ref
func (svc *HostService) SSH(ref string) (*system.SSHConfig, error) {
	host, err := svc.Get(ref)
	if err != nil {
		return nil, fmt.Errorf("failed to query host '%s'", ref)
	}
	if host == nil {
		return nil, fmt.Errorf("host '%s' not found", ref)
	}

	return svc.provider.GetSSHConfig(host.ID)
}
