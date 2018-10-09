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

package opentelekom

import (
	"github.com/CS-SI/SafeScale/providers/api"

	"github.com/CS-SI/SafeScale/system"
)

// CreateHost creates a new host
func (client *Client) CreateHost(request api.HostRequest) (*api.Host, error) {
	return client.feclt.CreateHost(request)
}

// GetHost returns the host identified by id
func (client *Client) GetHost(id string) (*api.Host, error) {
	return client.feclt.GetHost(id)
}

// ListHosts lists available hosts
func (client *Client) ListHosts(all bool) ([]api.Host, error) {
	return client.feclt.ListHosts(all)
}

// DeleteHost deletes the host identified by id
func (client *Client) DeleteHost(id string) error {
	return client.feclt.DeleteHost(id)
}

// GetSSHConfig creates SSHConfig to connect an host by its ID
func (client *Client) GetSSHConfig(id string) (*system.SSHConfig, error) {
	return client.feclt.GetSSHConfig(id)
}

// CreateKeyPair creates and import a key pair
func (client *Client) CreateKeyPair(name string) (*api.KeyPair, error) {
	return client.feclt.CreateKeyPair(name)
}

// GetKeyPair returns the key pair identified by id
func (client *Client) GetKeyPair(id string) (*api.KeyPair, error) {
	return client.feclt.GetKeyPair(id)
}

// ListKeyPairs lists available key pairs
func (client *Client) ListKeyPairs() ([]api.KeyPair, error) {
	return client.feclt.ListKeyPairs()
}

// DeleteKeyPair deletes the key pair identified by id
func (client *Client) DeleteKeyPair(id string) error {
	return client.feclt.DeleteKeyPair(id)
}

// GetImage returns the Image referenced by id
func (client *Client) GetImage(id string) (*api.Image, error) {
	return client.feclt.GetImage(id)
}

// ListImages lists available OS images
func (client *Client) ListImages(all bool) ([]api.Image, error) {
	return client.feclt.ListImages(all)
}

// GetTemplate returns the Template referenced by id
func (client *Client) GetTemplate(id string) (*api.HostTemplate, error) {
	return client.feclt.GetTemplate(id)
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (client *Client) ListTemplates(all bool) ([]api.HostTemplate, error) {
	return client.feclt.ListTemplates(all)
}

// StopHost stops the host identified by id
func (client *Client) StopHost(id string) error {
	return client.feclt.StopHost(id)
}

// StartHost starts the host identified by id
func (client *Client) StartHost(id string) error {
	return client.feclt.StartHost(id)
}

func (client *Client) RebootHost(id string) error {
	return client.feclt.RebootHost(id)
}
