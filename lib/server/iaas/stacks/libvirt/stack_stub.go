// +build !libvirt

/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/lib/utils/fail"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/userdata"
)

var errorStr = "libvirt Driver is not enabled, use the libvirt option while compiling (make libvirt all)"

// Stack is the implementation of the local driver regarding to the api.ClientAPI
type Stack struct {
}

// ListAvailabilityZones stub
func (s *Stack) ListAvailabilityZones() (map[string]bool, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// ListRegions stub
func (s *Stack) ListRegions() ([]string, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// ListImages stub
func (s *Stack) ListImages(all bool) ([]abstract.Image, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// GetImage stub
func (s *Stack) GetImage(id string) (*abstract.Image, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// GetTemplate stub
func (s *Stack) GetTemplate(id string) (*abstract.HostTemplate, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// ListTemplates stub
func (s *Stack) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// CreateKeyPair stub
func (s *Stack) CreateKeyPair(name string) (*abstract.KeyPair, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// GetKeyPair stub
func (s *Stack) GetKeyPair(id string) (*abstract.KeyPair, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// ListKeyPairs stub
func (s *Stack) ListKeyPairs() ([]abstract.KeyPair, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// DeleteKeyPair stub
func (s *Stack) DeleteKeyPair(id string) error {
	return fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// CreateNetwork stub
func (s *Stack) CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// GetNetwork stub
func (s *Stack) GetNetwork(id string) (*abstract.Network, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// GetNetworkByName stub
func (s *Stack) GetNetworkByName(name string) (*abstract.Network, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// ListNetworks stub
func (s *Stack) ListNetworks() ([]*abstract.Network, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// DeleteNetwork stub
func (s *Stack) DeleteNetwork(id string) error {
	return fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// CreateGateway stub
func (s *Stack) CreateGateway(req abstract.GatewayRequest, sizing *abstract.SizingRequirements) (*abstract.Host, *userdata.Content, fail.Error) {
	return nil, nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// DeleteGateway stub
func (s *Stack) DeleteGateway(string) error {
	return fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// CreateVIP stub
func (s *Stack) CreateVIP(networkID string, description string) (*abstract.VirtualIP, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// AddPublicIPToVIP stub
func (s *Stack) AddPublicIPToVIP(vip *abstract.VirtualIP) error {
	return fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// BindHostToVIP stub
func (s *Stack) BindHostToVIP(vip *abstract.VirtualIP, hostID string) error {
	return fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// UnbindHostFromVIP stub
func (s *Stack) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) error {
	return fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// DeleteVIP stub
func (s *Stack) DeleteVIP(vip *abstract.VirtualIP) error {
	return fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// CreateHost stub
func (s *Stack) CreateHost(request abstract.HostRequest) (*abstract.Host, *userdata.Content, fail.Error) {
	return nil, nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// ResizeHost stub
func (s *Stack) ResizeHost(id string, request abstract.SizingRequirements) (*abstract.Host, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// InspectHost stub
func (s *Stack) InspectHost(interface{}) (*abstract.Host, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// GetHostByName stub
func (s *Stack) GetHostByName(string) (*abstract.Host, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// GetHostByID stub
func (s *Stack) GetHostByID(string) (*abstract.Host, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// GetHostState stub
func (s *Stack) GetHostState(interface{}) (hoststate.Enum, fail.Error) {
	return hoststate.ERROR, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// ListHosts stub
func (s *Stack) ListHosts() ([]*abstract.Host, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// DeleteHost stub
func (s *Stack) DeleteHost(id string) error {
	return fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// StartHost stub
func (s *Stack) StartHost(id string) error {
	return fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// StopHost stub
func (s *Stack) StopHost(id string) error {
	return fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// RebootHost stub
func (s *Stack) RebootHost(id string) error {
	return fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// CreateVolume stub
func (s *Stack) CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// GetVolume stub
func (s *Stack) GetVolume(id string) (*abstract.Volume, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// ListVolumes stub
func (s *Stack) ListVolumes() ([]abstract.Volume, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// DeleteVolume stub
func (s *Stack) DeleteVolume(id string) error {
	return fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// CreateVolumeAttachment stub
func (s *Stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	return "", fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// GetVolumeAttachment stub
func (s *Stack) GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// ListVolumeAttachments stub
func (s *Stack) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, fail.Error) {
	return nil, fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// DeleteVolumeAttachment stub
func (s *Stack) DeleteVolumeAttachment(serverID, id string) error {
	return fail.Errorf(fmt.Sprintf(errorStr), nil)
}

// GetConfigurationOptions stub
func (s *Stack) GetConfigurationOptions() stacks.ConfigurationOptions {
	return stacks.ConfigurationOptions{}
}

// GetAuthenticationOptions stub
func (s *Stack) GetAuthenticationOptions() stacks.AuthenticationOptions {
	return stacks.AuthenticationOptions{}
}
