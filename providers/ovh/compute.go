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

package ovh

import (
	"log"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/providers/api"
	filters "github.com/CS-SI/SafeScale/providers/filters/templates"

	"github.com/CS-SI/SafeScale/system"
)

// ListImages lists available OS images
func (client *Client) ListImages(all bool) ([]api.Image, error) {
	return client.osclt.ListImages(all)
}

// GetImage returns the Image referenced by id
func (client *Client) GetImage(id string) (*api.Image, error) {
	return client.osclt.GetImage(id)
}

// GetTemplate overload OpenStack GetTemplate method to add GPU configuration
func (client *Client) GetTemplate(id string) (*api.HostTemplate, error) {
	tpl, err := client.osclt.GetTemplate(id)
	if tpl != nil {
		addGPUCfg(tpl)
	}
	return tpl, err
}

func addGPUCfg(tpl *api.HostTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

// ListTemplates overload OpenStack ListTemplate method to filter wind and flex instance and add GPU configuration
func (client *Client) ListTemplates(all bool) ([]api.HostTemplate, error) {
	allTemplates, err := client.osclt.ListTemplates(all)
	if err != nil {
		return nil, err
	}
	if all {
		return allTemplates, nil
	}

	filter := filters.NewFilter(isWindowsTemplate).Not().And(filters.NewFilter(isFlexTemplate).Not())
	return filters.FilterTemplates(allTemplates, filter), nil
}

func isWindowsTemplate(t api.HostTemplate) bool {
	return strings.HasPrefix(strings.ToLower(t.Name), "win-")
}
func isFlexTemplate(t api.HostTemplate) bool {
	return strings.HasSuffix(strings.ToLower(t.Name), "flex")
}

// CreateKeyPair creates and import a key pair
func (client *Client) CreateKeyPair(name string) (*api.KeyPair, error) {
	return client.osclt.CreateKeyPair(name)
}

// GetKeyPair returns the key pair identified by id
func (client *Client) GetKeyPair(id string) (*api.KeyPair, error) {
	return client.osclt.GetKeyPair(id)
}

// ListKeyPairs lists available key pairs
func (client *Client) ListKeyPairs() ([]api.KeyPair, error) {
	return client.osclt.ListKeyPairs()
}

// DeleteKeyPair deletes the key pair identified by id
func (client *Client) DeleteKeyPair(id string) error {
	return client.osclt.DeleteKeyPair(id)
}

// CreateHost creates an host satisfying request
func (client *Client) CreateHost(request api.HostRequest) (*api.Host, error) {
	return client.osclt.CreateHost(request)
}

// WaitHostReady waits an host achieve ready state
func (client *Client) WaitHostReady(hostID string, timeout time.Duration) (*api.Host, error) {
	return client.osclt.WaitHostReady(hostID, timeout)
}

// GetHost returns the host identified by id
func (client *Client) GetHost(ref string) (*api.Host, error) {
	return client.osclt.GetHost(ref)
}

// ListHosts lists available hosts
func (client *Client) ListHosts(all bool) ([]api.Host, error) {
	return client.osclt.ListHosts(all)
}

// DeleteHost deletes the host identified by id
func (client *Client) DeleteHost(ref string) error {
	return client.osclt.DeleteHost(ref)
}

// StopHost stops the host identified by id
func (client *Client) StopHost(id string) error {
	return client.osclt.StopHost(id)
}

func (client *Client) RebootHost(id string) error {
	log.Println("Received reboot petition OVH")
	return client.osclt.RebootHost(id)
}

// StartHost starts the host identified by id
func (client *Client) StartHost(id string) error {
	return client.osclt.StartHost(id)
}

//GetSSHConfig creates SSHConfig to connect an host
func (client *Client) GetSSHConfig(id string) (*system.SSHConfig, error) {
	return client.osclt.GetSSHConfig(id)
}
