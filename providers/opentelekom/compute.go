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
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostState"
)

// CreateHost creates a new host
func (client *Client) CreateHost(request model.HostRequest) (*model.Host, error) {
	return client.feclt.CreateHost(request)
}

// GetHost returns the host identified by id or updates an already existing *model.Host instance
func (client *Client) GetHost(hostParam interface{}) (*model.Host, error) {
	return client.feclt.GetHost(hostParam)
}

// GetHostByName returns the host identified by name
func (client *Client) GetHostByName(name string) (*model.Host, error) {
	return client.feclt.GetHostByName(name)
}

// GetHostState ...
func (client *Client) GetHostState(hostParam interface{}) (HostState.Enum, error) {
	return client.feclt.GetHostState(hostParam)
}

// ListHosts lists all hosts
func (client *Client) ListHosts() ([]*model.Host, error) {
	return client.feclt.ListHosts()
}

// DeleteHost deletes the host identified by id
func (client *Client) DeleteHost(id string) error {
	return client.feclt.DeleteHost(id)
}

// CreateKeyPair creates and import a key pair
func (client *Client) CreateKeyPair(name string) (*model.KeyPair, error) {
	return client.feclt.CreateKeyPair(name)
}

// GetKeyPair returns the key pair identified by id
func (client *Client) GetKeyPair(id string) (*model.KeyPair, error) {
	return client.feclt.GetKeyPair(id)
}

// ListKeyPairs lists available key pairs
func (client *Client) ListKeyPairs() ([]model.KeyPair, error) {
	return client.feclt.ListKeyPairs()
}

// DeleteKeyPair deletes the key pair identified by id
func (client *Client) DeleteKeyPair(id string) error {
	return client.feclt.DeleteKeyPair(id)
}

// GetImage returns the Image referenced by id
func (client *Client) GetImage(id string) (*model.Image, error) {
	return client.feclt.GetImage(id)
}

// ListImages lists available OS images
func (client *Client) ListImages(all bool) ([]model.Image, error) {
	return client.feclt.ListImages(all)
}

// GetTemplate returns the Template referenced by id
func (client *Client) GetTemplate(id string) (*model.HostTemplate, error) {
	return client.feclt.GetTemplate(id)
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (client *Client) ListTemplates(all bool) ([]model.HostTemplate, error) {
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

// RebootHost ...
func (client *Client) RebootHost(id string) error {
	return client.feclt.RebootHost(id)
}
