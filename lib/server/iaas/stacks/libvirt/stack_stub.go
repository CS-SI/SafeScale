// +build !libvirt

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
    "github.com/CS-SI/SafeScale/lib/utils/fail"
)

var gError = fail.NewError("libvirt Driver is not enabled, use the libvirt option while compiling (make libvirt all)")

// Stack is the implementation of the local driver regarding to the api.ClientAPI
type Stack struct {
}

// WaitHostReady ...
func (s *Stack) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
    return abstract.NewHostCore(), gError
}

// ListAvailabilityZones stub
func (s *Stack) ListAvailabilityZones() (map[string]bool, fail.Error) {
    return map[string]bool{}, gError
}

// ListRegions stub
func (s *Stack) ListRegions() ([]string, fail.Error) {
    return []string{}, gError
}

// ListImages stub
func (s *Stack) ListImages(all bool) ([]abstract.Image, fail.Error) {
    return []abstract.Image{}, gError
}

// GetImage stub
func (s *Stack) GetImage(id string) (*abstract.Image, fail.Error) {
    return &abstract.Image{}, gError
}

// GetTemplate stub
func (s *Stack) GetTemplate(id string) (*abstract.HostTemplate, fail.Error) {
    return &abstract.HostTemplate{}, gError
}

// ListTemplates stub
func (s *Stack) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
    return []abstract.HostTemplate{}, gError
}

// CreateKeyPair stub
func (s *Stack) CreateKeyPair(name string) (*abstract.KeyPair, fail.Error) {
    return &abstract.KeyPair{}, gError
}

// GetKeyPair stub
func (s *Stack) GetKeyPair(id string) (*abstract.KeyPair, fail.Error) {
    return &abstract.KeyPair{}, gError
}

// ListKeyPairs stub
func (s *Stack) ListKeyPairs() ([]abstract.KeyPair, fail.Error) {
    return []abstract.KeyPair{}, gError
}

// DeleteKeyPair stub
func (s *Stack) DeleteKeyPair(id string) fail.Error {
    return gError
}

// CreateNetwork stub
func (s *Stack) CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
    return &abstract.Network{}, gError
}

// GetNetwork stub
func (s *Stack) GetNetwork(id string) (*abstract.Network, fail.Error) {
    return &abstract.Network{}, gError
}

// GetNetworkByName stub
func (s *Stack) GetNetworkByName(name string) (*abstract.Network, fail.Error) {
    return &abstract.Network{}, gError
}

// ListNetworks stub
func (s *Stack) ListNetworks() ([]*abstract.Network, fail.Error) {
    return []*abstract.Network{}, gError
}

// DeleteNetwork stub
func (s *Stack) DeleteNetwork(id string) fail.Error {
    return gError
}

// // CreateGateway stub
// func (s *Stack) CreateGateway(req abstract.GatewayRequest) (*abstract.HostFull, *userdata.Content, error) {
// 	return nil, nil, gError
// }
//
// // DeleteGateway stub
// func (s *Stack) DeleteGateway(string) error {
// 	return gError
// }

// CreateVIP stub
func (s *Stack) CreateVIP(networkID string, description string) (*abstract.VirtualIP, fail.Error) {
    return &abstract.VirtualIP{}, gError
}

// AddPublicIPToVIP stub
func (s *Stack) AddPublicIPToVIP(vip *abstract.VirtualIP) fail.Error {
    return gError
}

// BindHostToVIP stub
func (s *Stack) BindHostToVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
    return gError
}

// UnbindHostFromVIP stub
func (s *Stack) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
    return gError
}

// DeleteVIP stub
func (s *Stack) DeleteVIP(vip *abstract.VirtualIP) fail.Error {
    return gError
}

// CreateHost stub
func (s *Stack) CreateHost(request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, fail.Error) {
    return abstract.NewHostFull(), userdata.NewContent(), gError
}

// ResizeHost stub
func (s *Stack) ResizeHost(hostParam stacks.HostParameter, request abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
    return abstract.NewHostFull(), gError
}

// InspectHost stub
func (s *Stack) InspectHost(hostParam stacks.HostParameter) (*abstract.HostFull, fail.Error) {
    return abstract.NewHostFull(), gError
}

// GetHostByName stub
func (s *Stack) GetHostByName(string) (*abstract.HostCore, fail.Error) {
    return abstract.NewHostCore(), gError
}

// GetHostState stub
func (s *Stack) GetHostState(hostParam stacks.HostParameter) (hoststate.Enum, fail.Error) {
    return hoststate.ERROR, gError
}

// ListHosts stub
func (s *Stack) ListHosts(details bool) (abstract.HostList, fail.Error) {
    return abstract.HostList{}, gError
}

// DeleteHost stub
func (s *Stack) DeleteHost(hostParam stacks.HostParameter) fail.Error {
    return gError
}

// StartHost stub
func (s *Stack) StartHost(hostParam stacks.HostParameter) fail.Error {
    return gError
}

// StopHost stub
func (s *Stack) StopHost(hostParam stacks.HostParameter) fail.Error {
    return gError
}

// RebootHost stub
func (s *Stack) RebootHost(hostParam stacks.HostParameter) fail.Error {
    return gError
}

// CreateVolume stub
func (s *Stack) CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
    return &abstract.Volume{}, gError
}

// GetVolume stub
func (s *Stack) GetVolume(id string) (*abstract.Volume, fail.Error) {
    return &abstract.Volume{}, gError
}

// ListVolumes stub
func (s *Stack) ListVolumes() ([]abstract.Volume, fail.Error) {
    return []abstract.Volume{}, gError
}

// DeleteVolume stub
func (s *Stack) DeleteVolume(id string) fail.Error {
    return gError
}

// CreateVolumeAttachment stub
func (s *Stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
    return "", gError
}

// GetVolumeAttachment stub
func (s *Stack) GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
    return &abstract.VolumeAttachment{}, gError
}

// ListVolumeAttachments stub
func (s *Stack) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, fail.Error) {
    return []abstract.VolumeAttachment{}, gError
}

// DeleteVolumeAttachment stub
func (s *Stack) DeleteVolumeAttachment(serverID, id string) fail.Error {
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

// BindSecurityGroupToHost ...
func (s *Stack) BindSecurityGroupToHost(hostParam stacks.HostParameter, sgParam stacks.SecurityGroupParameter) fail.Error {
    return gError
}

// UnbindSecurityGroupFromHost ...
func (s *Stack) UnbindSecurityGroupFromHost(hostParam stacks.HostParameter, sgParam stacks.SecurityGroupParameter) fail.Error {
    return gError
}
