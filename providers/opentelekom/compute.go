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

// CreateVM creates a new VM
func (client *Client) CreateVM(request api.VMRequest) (*api.VM, error) {
	return client.feclt.CreateVM(request)
}

// GetVM returns the VM identified by id
func (client *Client) GetVM(id string) (*api.VM, error) {
	return client.feclt.GetVM(id)
}

// ListVMs lists available VMs
func (client *Client) ListVMs(all bool) ([]api.VM, error) {
	return client.feclt.ListVMs(all)
}

// DeleteVM deletes the VM identified by id
func (client *Client) DeleteVM(id string) error {
	return client.feclt.DeleteVM(id)
}

// GetSSHConfig creates SSHConfig to connect a VM by its ID
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
func (client *Client) ListImages() ([]api.Image, error) {
	return client.feclt.ListImages()
}

// GetTemplate returns the Template referenced by id
func (client *Client) GetTemplate(id string) (*api.VMTemplate, error) {
	return client.feclt.GetTemplate(id)
}

// ListTemplates lists available VM templates
// VM templates are sorted using Dominant Resource Fairness Algorithm
func (client *Client) ListTemplates() ([]api.VMTemplate, error) {
	return client.feclt.ListTemplates()
}

// StopVM stops the VM identified by id
func (client *Client) StopVM(id string) error {
	return client.feclt.StopVM(id)
}

// StartVM starts the VM identified by id
func (client *Client) StartVM(id string) error {
	return client.feclt.StartVM(id)
}
