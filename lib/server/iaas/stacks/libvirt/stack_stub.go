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

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostState"
)

var errorStr = "Libvirt Driver is not enabled, use the libvirt option while compiling (make libvirt all)"

// Client is the implementation of the local driver regarding to the api.ClientAPI

type Stack struct {
}

func (s *Stack) ListAvailabilityZones(bool) (map[string]bool, error) {
	return nil, fmt.Errorf(errorStr)
}

func (s *Stack) ListRegions() ([]string, error) {
	return nil, fmt.Errorf(errorStr)
}

func (s *Stack) ListImages(all bool) ([]resources.Image, error) {
	return nil, fmt.Errorf(errorStr)
}

func (s *Stack) GetImage(id string) (*resources.Image, error) {
	return nil, fmt.Errorf(errorStr)
}

func (s *Stack) GetTemplate(id string) (*resources.HostTemplate, error) {
	return nil, fmt.Errorf(errorStr)
}

func (s *Stack) ListTemplates(all bool) ([]resources.HostTemplate, error) {
	return nil, fmt.Errorf(errorStr)
}

func (s *Stack) CreateKeyPair(name string) (*resources.KeyPair, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) GetKeyPair(id string) (*resources.KeyPair, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) ListKeyPairs() ([]resources.KeyPair, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) DeleteKeyPair(id string) error {
	return fmt.Errorf(errorStr)
}

func (s *Stack) CreateNetwork(req resources.NetworkRequest) (*resources.Network, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) GetNetwork(id string) (*resources.Network, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) GetNetworkByName(name string) (*resources.Network, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) ListNetworks() ([]*resources.Network, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) DeleteNetwork(id string) error {
	return fmt.Errorf(errorStr)
}

func (s *Stack) CreateGateway(req resources.GatewayRequest) (*resources.Host, *userdata.Content, error) {
	return nil, nil, fmt.Errorf(errorStr)
}

func (s *Stack) DeleteGateway(string) error {
	return fmt.Errorf(errorStr)
}

func (s *Stack) CreateHost(request resources.HostRequest) (*resources.Host, *userdata.Content, error) {
	return nil, nil, fmt.Errorf(errorStr)
}
func (s *Stack) ResizeHost(id string, request resources.SizingRequirements) (*resources.Host, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) InspectHost(interface{}) (*resources.Host, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) GetHostByName(string) (*resources.Host, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) GetHostState(interface{}) (HostState.Enum, error) {
	return HostState.ERROR, fmt.Errorf(errorStr)
}
func (s *Stack) ListHosts() ([]*resources.Host, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) DeleteHost(id string) error {
	return fmt.Errorf(errorStr)
}
func (s *Stack) StartHost(id string) error {
	return fmt.Errorf(errorStr)
}
func (s *Stack) StopHost(id string) error {
	return fmt.Errorf(errorStr)
}
func (s *Stack) RebootHost(id string) error {
	return fmt.Errorf(errorStr)
}

func (s *Stack) CreateVolume(request resources.VolumeRequest) (*resources.Volume, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) GetVolume(id string) (*resources.Volume, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) ListVolumes() ([]resources.Volume, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) DeleteVolume(id string) error {
	return fmt.Errorf(errorStr)
}

func (s *Stack) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (string, error) {
	return "", fmt.Errorf(errorStr)
}
func (s *Stack) GetVolumeAttachment(serverID, id string) (*resources.VolumeAttachment, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) ListVolumeAttachments(serverID string) ([]resources.VolumeAttachment, error) {
	return nil, fmt.Errorf(errorStr)
}
func (s *Stack) DeleteVolumeAttachment(serverID, id string) error {
	return fmt.Errorf(errorStr)
}

// GetConfigurationOptions ...
func (s *Stack) GetConfigurationOptions() stacks.ConfigurationOptions {
	return stacks.ConfigurationOptions{}
}

// GetAuthenticationOptions ...
func (s *Stack) GetAuthenticationOptions() stacks.AuthenticationOptions {
	return stacks.AuthenticationOptions{}
}
