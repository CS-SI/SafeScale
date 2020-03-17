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
	"time"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

var gError = scerr.NewError("libvirt Driver is not enabled, use the libvirt option while compiling (make libvirt all)")

// Stack is the implementation of the local driver regarding to the api.ClientAPI
type Stack struct {
}

// WaitHostReady ...
func (s *Stack) WaitHostReady(hostParam interface{}, timeout time.Duration) (*abstract.HostCore, error) {
	return nil, gError
}

// ListAvailabilityZones stub
func (s *Stack) ListAvailabilityZones() (map[string]bool, error) {
	return nil, gError
}

// ListRegions stub
func (s *Stack) ListRegions() ([]string, error) {
	return nil, gError
}

// ListImages stub
func (s *Stack) ListImages(all bool) ([]abstract.Image, error) {
	return nil, gError
}

// GetImage stub
func (s *Stack) GetImage(id string) (*abstract.Image, error) {
	return nil, gError
}

// GetTemplate stub
func (s *Stack) GetTemplate(id string) (*abstract.HostTemplate, error) {
	return nil, gError
}

// ListTemplates stub
func (s *Stack) ListTemplates(all bool) ([]abstract.HostTemplate, error) {
	return nil, gError
}

// CreateKeyPair stub
func (s *Stack) CreateKeyPair(name string) (*abstract.KeyPair, error) {
	return nil, gError
}

// GetKeyPair stub
func (s *Stack) GetKeyPair(id string) (*abstract.KeyPair, error) {
	return nil, gError
}

// ListKeyPairs stub
func (s *Stack) ListKeyPairs() ([]abstract.KeyPair, error) {
	return nil, gError
}

// DeleteKeyPair stub
func (s *Stack) DeleteKeyPair(id string) error {
	return gError
}

// CreateNetwork stub
func (s *Stack) CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, error) {
	return nil, gError
}

// GetNetwork stub
func (s *Stack) GetNetwork(id string) (*abstract.Network, error) {
	return nil, gError
}

// GetNetworkByName stub
func (s *Stack) GetNetworkByName(name string) (*abstract.Network, error) {
	return nil, gError
}

// ListNetworks stub
func (s *Stack) ListNetworks() ([]*abstract.Network, error) {
	return nil, gError
}

// DeleteNetwork stub
func (s *Stack) DeleteNetwork(id string) error {
	return gError
}

// CreateGateway stub
func (s *Stack) CreateGateway(req abstract.GatewayRequest) (*abstract.HostFull, *userdata.Content, error) {
	return nil, nil, gError
}

// DeleteGateway stub
func (s *Stack) DeleteGateway(string) error {
	return gError
}

// CreateVIP stub
func (s *Stack) CreateVIP(networkID string, description string) (*abstract.VirtualIP, error) {
	return nil, gError
}

// AddPublicIPToVIP stub
func (s *Stack) AddPublicIPToVIP(vip *abstract.VirtualIP) error {
	return gError
}

// BindHostToVIP stub
func (s *Stack) BindHostToVIP(vip *abstract.VirtualIP, hostID string) error {
	return gError
}

// UnbindHostFromVIP stub
func (s *Stack) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) error {
	return gError
}

// DeleteVIP stub
func (s *Stack) DeleteVIP(vip *abstract.VirtualIP) error {
	return gError
}

// CreateHost stub
func (s *Stack) CreateHost(request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, error) {
	return nil, nil, gError
}

// ResizeHost stub
func (s *Stack) ResizeHost(id string, request abstract.HostSizingRequirements) (*abstract.HostFull, error) {
	return nil, gError
}

// InspectHost stub
func (s *Stack) InspectHost(interface{}) (*abstract.HostFull, error) {
	return nil, gError
}

// GetHostByName stub
func (s *Stack) GetHostByName(string) (*abstract.HostCore, error) {
	return nil, gError
}

// GetHostState stub
func (s *Stack) GetHostState(interface{}) (hoststate.Enum, error) {
	return hoststate.ERROR, gError
}

// ListHosts stub
func (s *Stack) ListHosts(details bool) (abstract.HostList, error) {
	return nil, gError
}

// DeleteHost stub
func (s *Stack) DeleteHost(id string) error {
	return gError
}

// StartHost stub
func (s *Stack) StartHost(id string) error {
	return gError
}

// StopHost stub
func (s *Stack) StopHost(id string) error {
	return gError
}

// RebootHost stub
func (s *Stack) RebootHost(id string) error {
	return gError
}

// CreateVolume stub
func (s *Stack) CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, error) {
	return nil, gError
}

// GetVolume stub
func (s *Stack) GetVolume(id string) (*abstract.Volume, error) {
	return nil, gError
}

// ListVolumes stub
func (s *Stack) ListVolumes() ([]abstract.Volume, error) {
	return nil, gError
}

// DeleteVolume stub
func (s *Stack) DeleteVolume(id string) error {
	return gError
}

// CreateVolumeAttachment stub
func (s *Stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, error) {
	return "", gError
}

// GetVolumeAttachment stub
func (s *Stack) GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, error) {
	return nil, gError
}

// ListVolumeAttachments stub
func (s *Stack) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, error) {
	return nil, gError
}

// DeleteVolumeAttachment stub
func (s *Stack) DeleteVolumeAttachment(serverID, id string) error {
	return gError
}

// GetConfigurationOptions stub
func (s *Stack) GetConfigurationOptions() stacks.ConfigurationOptions {
	return stacks.ConfigurationOptions{}
}

// GetAuthenticationOptions stub
func (s *Stack) GetAuthenticationOptions() stacks.AuthenticationOptions {
	return stacks.AuthenticationOptions{}
}
