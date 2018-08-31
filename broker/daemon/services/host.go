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
	"strings"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/system"
)

//HostAPI defines API to manipulate hosts
type HostAPI interface {
	Create(name string, net string, cpu int, ram float32, disk int, os string, public bool) (*api.Host, error)
	List(all bool) ([]api.Host, error)
	Get(ref string) (*api.Host, error)
	Delete(ref string) error
	SSH(ref string) (*system.SSHConfig, error)
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

// Create creates a host
func (svc *HostService) Create(name string, net string, cpu int, ram float32, disk int, os string, public bool) (*api.Host, error) {
	_host, err := svc.Get(name)
	if _host != nil || (err != nil && !strings.Contains(err.Error(), "failed to find host")) {
		return nil, fmt.Errorf("host '%s' already exists", name)
	}

	n, err := svc.network.Get(net)
	if err != nil {
		return nil, err
	}
	tpls, err := svc.provider.SelectTemplatesBySize(api.SizingRequirements{
		MinCores:    cpu,
		MinRAMSize:  ram,
		MinDiskSize: disk,
	})
	img, err := svc.provider.SearchImage(os)
	if err != nil {
		return nil, err
	}
	hostRequest := api.HostRequest{
		ImageID:    img.ID,
		Name:       name,
		TemplateID: tpls[0].ID,
		// IsGateway:  false,
		PublicIP:   public,
		NetworkIDs: []string{n.ID},
	}
	host, err := svc.provider.CreateHost(hostRequest)
	if err != nil {
		return nil, err
	}

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	ssh, err := svc.provider.GetSSHConfig(host.ID)
	if err != nil {
		svc.provider.DeleteHost(host.ID)
		return nil, err
	}
	err = ssh.WaitServerReady(5)
	if err != nil {
		svc.provider.DeleteHost(host.ID)
		return nil, err
	}
	return host, nil
}

// List returns the host list
func (svc *HostService) List(all bool) ([]api.Host, error) {
	return svc.provider.ListHosts(all)
}

// Get returns the host identified by ref, ref can be the name or the id
func (svc *HostService) Get(ref string) (*api.Host, error) {
	m := metadata.NewHost(svc.provider)
	found, err := m.ReadByName(ref)
	if err != nil {
		return nil, err
	}
	if !found {
		found, err = m.ReadByID(ref)
		if err != nil {
			return nil, err
		}
	}
	if !found {
		return nil, fmt.Errorf("failed to find host '%s'", ref)
	}
	return m.Get(), nil
}

// Delete deletes host referenced by ref
func (svc *HostService) Delete(ref string) error {
	host, err := svc.Get(ref)
	if err != nil {
		return fmt.Errorf("host '%s' does not exist", ref)
	}
	return svc.provider.DeleteHost(host.ID)
}

// SSH returns ssh parameters to access the host referenced by ref
func (svc *HostService) SSH(ref string) (*system.SSHConfig, error) {
	host, err := svc.Get(ref)
	if err != nil {
		return nil, fmt.Errorf("host '%s' does not exist", ref)
	}

	return svc.provider.GetSSHConfig(host.ID)
}
