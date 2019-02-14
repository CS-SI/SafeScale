//+build !libvirt

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

package local

import (
	"fmt"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostState"
)

var errorStr = "Libvirt Driver is not enabled, use the libvirt option while compiling (make libvirt all)"

// Client is the implementation of the local driver regarding to the api.ClientAPI
type Client struct {
}

//AuthOptions fields are the union of those recognized by each identity implementation and provider.
type AuthOptions struct {
}

// CfgOptions configuration options
type CfgOptions struct {
}

func (client *Client) Build(params map[string]interface{}) (api.ClientAPI, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) GetAuthOpts() (model.Config, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) GetCfgOpts() (model.Config, error) {
	return nil, fmt.Errorf(errorStr)
}

func (client *Client) ListAvailabilityZones(bool) (map[string]bool, error) {
	return nil, fmt.Errorf(errorStr)
}

func (client *Client) ListImages(all bool) ([]model.Image, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) GetImage(id string) (*model.Image, error) {
	return nil, fmt.Errorf(errorStr)
}

func (client *Client) GetTemplate(id string) (*model.HostTemplate, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) ListTemplates(all bool) ([]model.HostTemplate, error) {
	return nil, fmt.Errorf(errorStr)
}

func (client *Client) CreateKeyPair(name string) (*model.KeyPair, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) GetKeyPair(id string) (*model.KeyPair, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) ListKeyPairs() ([]model.KeyPair, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) DeleteKeyPair(id string) error {
	return fmt.Errorf(errorStr)
}

func (client *Client) CreateNetwork(req model.NetworkRequest) (*model.Network, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) GetNetwork(id string) (*model.Network, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) GetNetworkByName(name string) (*model.Network, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) ListNetworks() ([]*model.Network, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) DeleteNetwork(id string) error {
	return fmt.Errorf(errorStr)
}
func (client *Client) CreateGateway(req model.GatewayRequest) (*model.Host, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) DeleteGateway(string) error {
	return fmt.Errorf(errorStr)
}

func (client *Client) CreateHost(request model.HostRequest) (*model.Host, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) ResizeHost(id string, request model.SizingRequirements) (*model.Host, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) GetHost(interface{}) (*model.Host, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) GetHostByName(string) (*model.Host, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) GetHostState(interface{}) (HostState.Enum, error) {
	return HostState.ERROR, fmt.Errorf(errorStr)
}
func (client *Client) ListHosts() ([]*model.Host, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) DeleteHost(id string) error {
	return fmt.Errorf(errorStr)
}
func (client *Client) StartHost(id string) error {
	return fmt.Errorf(errorStr)
}
func (client *Client) StopHost(id string) error {
	return fmt.Errorf(errorStr)
}
func (client *Client) RebootHost(id string) error {
	return fmt.Errorf(errorStr)
}

func (client *Client) CreateVolume(request model.VolumeRequest) (*model.Volume, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) GetVolume(id string) (*model.Volume, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) ListVolumes() ([]model.Volume, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) DeleteVolume(id string) error {
	return fmt.Errorf(errorStr)
}

func (client *Client) CreateVolumeAttachment(request model.VolumeAttachmentRequest) (string, error) {
	return "", fmt.Errorf(errorStr)
}
func (client *Client) GetVolumeAttachment(serverID, id string) (*model.VolumeAttachment, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) ListVolumeAttachments(serverID string) ([]model.VolumeAttachment, error) {
	return nil, fmt.Errorf(errorStr)
}
func (client *Client) DeleteVolumeAttachment(serverID, id string) error {
	return fmt.Errorf(errorStr)
}

func init() {
	// log.Debug("Registering fake local provider")
	providers.Register("local", &Client{})
}
