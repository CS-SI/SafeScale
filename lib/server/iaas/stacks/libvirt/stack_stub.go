//go:build !libvirt && !ignore
// +build !libvirt,!ignore

/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
type stack struct {
}

// NullStack is not exposed through API, is needed essentially by testss
func NullStack() *stack { // nolint
	return &stack{}
}

func New(auth stacks.AuthenticationOptions, localCfg stacks.LocalConfiguration, cfg stacks.ConfigurationOptions) (*stack, fail.Error) { // nolint
	return nil, gError
}

func (s *stack) IsNull() bool {
	return false
}

// GetStackName returns the name of the stack
func (s stack) GetStackName() string {
	return "libvirt"
}

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (s stack) HasDefaultNetwork() bool {
	return false
}

// GetDefaultNetwork returns the *abstract.Network corresponding to the default network
func (s stack) GetDefaultNetwork() (*abstract.Network, fail.Error) {
	return nil, gError
}

// WaitHostReady ...
func (s stack) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	return abstract.NewHostCore(), gError
}

// ListAvailabilityZones stub
func (s stack) ListAvailabilityZones() (map[string]bool, fail.Error) {
	return map[string]bool{}, gError
}

// ListRegions stub
func (s stack) ListRegions() ([]string, fail.Error) {
	return []string{}, gError
}

// ListImages stub
func (s stack) ListImages(all bool) ([]abstract.Image, fail.Error) {
	return []abstract.Image{}, gError
}

// InspectImage stub
func (s stack) InspectImage(id string) (abstract.Image, fail.Error) {
	return abstract.Image{}, gError
}

// InspectTemplate stub
func (s stack) InspectTemplate(id string) (abstract.HostTemplate, fail.Error) {
	return abstract.HostTemplate{}, gError
}

// ListTemplates stub
func (s stack) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
	return []abstract.HostTemplate{}, gError
}

// CreateKeyPair stub
func (s stack) CreateKeyPair(name string) (*abstract.KeyPair, fail.Error) {
	return &abstract.KeyPair{}, gError
}

// InspectKeyPair stub
func (s stack) InspectKeyPair(id string) (*abstract.KeyPair, fail.Error) {
	return &abstract.KeyPair{}, gError
}

// ListKeyPairs stub
func (s stack) ListKeyPairs() ([]abstract.KeyPair, fail.Error) {
	return []abstract.KeyPair{}, gError
}

// DeleteKeyPair stub
func (s stack) DeleteKeyPair(id string) fail.Error {
	return gError
}

// CreateNetwork stub
func (s stack) CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	return &abstract.Network{}, gError
}

// InspectNetwork stub
func (s stack) InspectNetwork(id string) (*abstract.Network, fail.Error) {
	return &abstract.Network{}, gError
}

// InspectNetworkByName stub
func (s stack) InspectNetworkByName(name string) (*abstract.Network, fail.Error) {
	return &abstract.Network{}, gError
}

// ListNetworks stub
func (s stack) ListNetworks() ([]*abstract.Network, fail.Error) {
	return []*abstract.Network{}, gError
}

// DeleteNetwork stub
func (s stack) DeleteNetwork(id string) fail.Error {
	return gError
}

// CreateSubnet stub
func (s stack) CreateSubnet(req abstract.SubnetRequest) (*abstract.Subnet, fail.Error) {
	return &abstract.Subnet{}, gError
}

// InspectSubnet stub
func (s stack) InspectSubnet(id string) (*abstract.Subnet, fail.Error) {
	return &abstract.Subnet{}, gError
}

// InspectSubnetByName stub
func (s stack) InspectSubnetByName(networkRef, name string) (*abstract.Subnet, fail.Error) {
	return &abstract.Subnet{}, gError
}

// ListSubnets stub
func (s stack) ListSubnets(string) ([]*abstract.Subnet, fail.Error) {
	return []*abstract.Subnet{}, gError
}

// DeleteSubnet stub
func (s stack) DeleteSubnet(id string) fail.Error {
	return gError
}

// CreateVIP stub
func (s stack) CreateVIP(networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	return &abstract.VirtualIP{}, gError
}

// AddPublicIPToVIP stub
func (s stack) AddPublicIPToVIP(vip *abstract.VirtualIP) fail.Error {
	return gError
}

// BindHostToVIP stub
func (s stack) BindHostToVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	return gError
}

// UnbindHostFromVIP stub
func (s stack) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	return gError
}

// DeleteVIP stub
func (s stack) DeleteVIP(vip *abstract.VirtualIP) fail.Error {
	return gError
}

// CreateHost stub
func (s stack) CreateHost(request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, fail.Error) {
	return abstract.NewHostFull(), userdata.NewContent(), gError
}

// ClearHostStartupScript stub
func (s stack) ClearHostStartupScript(stacks.HostParameter) fail.Error {
	return gError
}

// ResizeHost stub
func (s stack) ResizeHost(hostParam stacks.HostParameter, request abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	return abstract.NewHostFull(), gError
}

// InspectHost stub
func (s stack) InspectHost(hostParam stacks.HostParameter) (*abstract.HostFull, fail.Error) {
	return abstract.NewHostFull(), gError
}

// InspectHostByName stub
func (s stack) InspectHostByName(string) (*abstract.HostFull, fail.Error) {
	return abstract.NewHostFull(), gError
}

// GetHostState stub
func (s stack) GetHostState(hostParam stacks.HostParameter) (hoststate.Enum, fail.Error) {
	return hoststate.Error, gError
}

// ListHosts stub
func (s stack) ListHosts(details bool) (abstract.HostList, fail.Error) {
	return abstract.HostList{}, gError
}

// DeleteHost stub
func (s stack) DeleteHost(hostParam stacks.HostParameter) fail.Error {
	return gError
}

// StartHost stub
func (s stack) StartHost(hostParam stacks.HostParameter) fail.Error {
	return gError
}

// StopHost stub
func (s stack) StopHost(hostParam stacks.HostParameter, gracefully bool) fail.Error {
	return gError
}

// RebootHost stub
func (s stack) RebootHost(hostParam stacks.HostParameter) fail.Error {
	return gError
}

// CreateVolume stub
func (s stack) CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
	return &abstract.Volume{}, gError
}

// InspectVolume stub
func (s stack) InspectVolume(id string) (*abstract.Volume, fail.Error) {
	return &abstract.Volume{}, gError
}

// ListVolumes stub
func (s stack) ListVolumes() ([]abstract.Volume, fail.Error) {
	return []abstract.Volume{}, gError
}

// DeleteVolume stub
func (s stack) DeleteVolume(id string) fail.Error {
	return gError
}

// CreateVolumeAttachment stub
func (s stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	return "", gError
}

// InspectVolumeAttachment stub
func (s stack) InspectVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	return &abstract.VolumeAttachment{}, gError
}

// ListVolumeAttachments stub
func (s stack) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, fail.Error) {
	return []abstract.VolumeAttachment{}, gError
}

// DeleteVolumeAttachment stub
func (s stack) DeleteVolumeAttachment(serverID, id string) fail.Error {
	return gError
}

// GetConfigurationOptions stub
func (s stack) GetConfigurationOptions() stacks.ConfigurationOptions {
	return stacks.ConfigurationOptions{}
}

// GetAuthenticationOptions stub
func (s stack) GetAuthenticationOptions() stacks.AuthenticationOptions {
	return stacks.AuthenticationOptions{}
}

// BindSecurityGroupToHost ...
func (s stack) BindSecurityGroupToHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	return gError
}

// UnbindSecurityGroupFromHost ...
func (s stack) UnbindSecurityGroupFromHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	return gError
}

// BindSecurityGroupToSubnet ...
func (s stack) BindSecurityGroupToSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	return gError
}

// UnbindSecurityGroupFromSubnet ...
func (s stack) UnbindSecurityGroupFromSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	return gError
}

// GetDefaultSecurityGroupName ...
func (s stack) GetDefaultSecurityGroupName() string {
	return ""
}

// AddRuleToSecurityGroup ...
func (s stack) AddRuleToSecurityGroup(stacks.SecurityGroupParameter, *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	return nil, gError
}

// DeleteRuleFromSecurityGroup ...
func (s stack) DeleteRuleFromSecurityGroup(stacks.SecurityGroupParameter, *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	return nil, gError
}

// ClearSecurityGroup ...
func (s stack) ClearSecurityGroup(stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	return nil, gError
}

// ListSecurityGroups ...
func (s stack) ListSecurityGroups(string) ([]*abstract.SecurityGroup, fail.Error) {
	return nil, gError
}

// CreateSecurityGroup ...
func (s stack) CreateSecurityGroup(string, string, string, abstract.SecurityGroupRules) (*abstract.SecurityGroup, fail.Error) {
	return nil, gError
}

// InspectSecurityGroup ...
func (s stack) InspectSecurityGroup(stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	return nil, gError
}

// DeleteSecurityGroup ...
func (s stack) DeleteSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return gError
}

// EnableSecurityGroup enables a Security Group
// Does actually nothing for openstack
func (s stack) EnableSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return gError
}

// DisableSecurityGroup disables a Security Group
// Does actually nothing for openstack
func (s stack) DisableSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return gError
}
