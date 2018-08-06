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

//Create creates a network
func (srv *HostService) Create(name string, net string, cpu int, ram float32, disk int, os string, public bool) (*api.Host, error) {
	_host, err := srv.Get(name)
	if _host != nil || (err != nil && !strings.Contains(err.Error(), "does not exist")) {
		return nil, fmt.Errorf("host '%s' already exists", name)
	}

	n, err := srv.network.Get(net)
	if err != nil {
		return nil, err
	}
	tpls, err := srv.provider.SelectTemplatesBySize(api.SizingRequirements{
		MinCores:    cpu,
		MinRAMSize:  ram,
		MinDiskSize: disk,
	})
	img, err := srv.provider.SearchImage(os)
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
	host, err := srv.provider.CreateHost(hostRequest)
	if err != nil {
		return nil, err
	}
	return host, nil

}

// List returns the network list
func (srv *HostService) List(all bool) ([]api.Host, error) {
	return srv.provider.ListHosts(all)
}

// Get returns the host identified by ref, ref can be the name or the id
func (srv *HostService) Get(ref string) (*api.Host, error) {
	m, err := metadata.NewHost(srv.provider)
	if err != nil {
		return nil, err
	}
	found, err := m.ReadByName(ref)
	if !found {
		found, err = m.ReadByID(ref)
	}
	if found {
		return m.Get(), nil
	}
	return nil, fmt.Errorf("host %s does not exist", ref)
}

// Delete deletes host referenced by ref
func (srv *HostService) Delete(ref string) error {
	host, err := srv.Get(ref)
	if err != nil {
		return fmt.Errorf("host '%s' does not exist", ref)
	}
	return srv.provider.DeleteHost(host.ID)
}

// SSH returns ssh parameters to access the host referenced by ref
func (srv *HostService) SSH(ref string) (*system.SSHConfig, error) {
	host, err := srv.Get(ref)
	if err != nil {
		return nil, fmt.Errorf("host '%s' does not exist", ref)
	}

	return srv.provider.GetSSHConfig(host.ID)
}
