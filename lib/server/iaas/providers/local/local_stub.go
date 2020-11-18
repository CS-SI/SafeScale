// +build !libvirt

/*
 * Copyright 2018, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

var gReport = fail.NotAvailableError("libvirt Driver is not enabled, use the libvirt option while compiling (make libvirt all)")

// provider is the implementation of the local driver regarding to the api.Provider
type provider struct {
	tenantParameters map[string]interface{}
}

// AuthOptions fields are the union of those recognized by each identity implementation and provider.
type AuthOptions struct {
}

// CfgOptions configuration options
type CfgOptions struct {
}

func (provider *provider) IsNull() bool {
	return false
}

// WaitHostReady ...
func (provider *provider) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	return nil, gReport
}

// Build ...
func (provider *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
	provider.tenantParameters = map[string]interface{}{}
	return nil, gReport
}

// GetAuthenticationOptions ...
func (provider *provider) GetAuthenticationOptions() (providers.Config, fail.Error) {
	return nil, gReport
}

// GetConfigurationOptions ...
func (provider *provider) GetConfigurationOptions() (providers.Config, fail.Error) {
	return nil, gReport
}

// ListAvailabilityZones ...
func (provider *provider) ListAvailabilityZones() (map[string]bool, fail.Error) {
	return nil, gReport
}

// ListRegions returns a list with the regions available
func (provider *provider) ListRegions() ([]string, fail.Error) {
	return nil, gReport
}

func (provider *provider) ListImages(all bool) ([]abstract.Image, fail.Error) {
	return nil, gReport
}
func (provider *provider) InspectImage(id string) (abstract.Image, fail.Error) {
	return abstract.Image{}, gReport
}

func (provider *provider) InspectTemplate(id string) (abstract.HostTemplate, fail.Error) {
	return abstract.HostTemplate{}, gReport
}
func (provider *provider) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
	return []abstract.HostTemplate{}, gReport
}

func (provider *provider) CreateKeyPair(name string) (*abstract.KeyPair, fail.Error) {
	return nil, gReport
}
func (provider *provider) InspectKeyPair(id string) (*abstract.KeyPair, fail.Error) {
	return nil, gReport
}
func (provider *provider) ListKeyPairs() ([]abstract.KeyPair, fail.Error) {
	return nil, gReport
}
func (provider *provider) DeleteKeyPair(id string) fail.Error {
	return gReport
}

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (provider *provider) HasDefaultNetwork() bool {
	return false
}

// GetDefaultNetwork returns the *abstract.Network corresponding to the default network
func (provider *provider) GetDefaultNetwork() (*abstract.Network, fail.Error) {
	return nil, gReport
}

func (provider *provider) CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	return nil, gReport
}
func (provider *provider) InspectNetwork(id string) (*abstract.Network, fail.Error) {
	return nil, gReport
}
func (provider *provider) InspectNetworkByName(name string) (*abstract.Network, fail.Error) {
	return nil, gReport
}
func (provider *provider) ListNetworks() ([]*abstract.Network, fail.Error) {
	return nil, gReport
}
func (provider *provider) DeleteNetwork(id string) fail.Error {
	return gReport
}

func (provider *provider) CreateSubnet(req abstract.SubnetRequest) (*abstract.Subnet, fail.Error) {
	return nil, gReport
}
func (provider *provider) InspectSubnet(id string) (*abstract.Subnet, fail.Error) {
	return nil, gReport
}
func (provider *provider) InspectSubnetByName(networkRef, name string) (*abstract.Subnet, fail.Error) {
	return nil, gReport
}
func (provider *provider) ListSubnets(networkRef string) ([]*abstract.Subnet, fail.Error) {
	return nil, gReport
}
func (provider *provider) DeleteSubnet(id string) fail.Error {
	return gReport
}

func (provider *provider) CreateVIP(networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	return nil, gReport
}
func (provider *provider) AddPublicIPToVIP(vip *abstract.VirtualIP) fail.Error {
	return gReport
}
func (provider *provider) BindHostToVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	return gReport
}
func (provider *provider) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	return gReport
}
func (provider *provider) DeleteVIP(vip *abstract.VirtualIP) fail.Error {
	return gReport
}

func (provider *provider) CreateHost(request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, fail.Error) {
	return nil, nil, gReport
}
func (provider *provider) ResizeHost(hostParam stacks.HostParameter, request abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	return nil, gReport
}
func (provider *provider) InspectHost(hostParam stacks.HostParameter) (*abstract.HostFull, fail.Error) {
	return abstract.NewHostFull(), gReport
}
func (provider *provider) InspectHostByName(string) (*abstract.HostFull, fail.Error) {
	return abstract.NewHostFull(), gReport
}
func (provider *provider) GetHostState(hostParam stacks.HostParameter) (hoststate.Enum, fail.Error) {
	return hoststate.ERROR, gReport
}
func (provider *provider) ListHosts(bool) (abstract.HostList, fail.Error) {
	return nil, gReport
}
func (provider *provider) DeleteHost(hostParam stacks.HostParameter) fail.Error {
	return gReport
}
func (provider *provider) StartHost(hostParam stacks.HostParameter) fail.Error {
	return gReport
}
func (provider *provider) StopHost(hostParam stacks.HostParameter) fail.Error {
	return gReport
}
func (provider *provider) RebootHost(hostParam stacks.HostParameter) fail.Error {
	return gReport
}

func (provider *provider) CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
	return nil, gReport
}
func (provider *provider) InspectVolume(id string) (*abstract.Volume, fail.Error) {
	return nil, gReport
}
func (provider *provider) ListVolumes() ([]abstract.Volume, fail.Error) {
	return nil, gReport
}
func (provider *provider) DeleteVolume(id string) fail.Error {
	return gReport
}

func (provider *provider) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	return "", gReport
}
func (provider *provider) InspectVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	return nil, gReport
}
func (provider *provider) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, fail.Error) {
	return nil, gReport
}
func (provider *provider) DeleteVolumeAttachment(serverID, id string) fail.Error {
	return gReport
}
func (provider *provider) GetName() string {
	return "local_disabled"
}
func (provider *provider) GetTenantParameters() map[string]interface{} {
	return nil
}

// GetCapabilities returns the capabilities of the provider
func (provider *provider) GetCapabilities() providers.Capabilities {
	return providers.Capabilities{}
}

// BindSecurityGroupToHost ...
func (provider *provider) BindSecurityGroupToHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	return gReport
}

// UnbindSecurityGroupFromHost ...
func (provider *provider) UnbindSecurityGroupFromHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	return gReport
}

// BindSecurityGroupToSubnet ...
func (provider *provider) BindSecurityGroupToSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	return gReport
}

// UnbindSecurityGroupFromSubnet ...
func (provider *provider) UnbindSecurityGroupFromSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) fail.Error {
	return gReport
}

// ListSecurityGroups lists existing security groups
func (provider *provider) ListSecurityGroups(networkRef string) ([]*abstract.SecurityGroup, fail.Error) {
	return nil, gReport
}

// CreateSecurityGroup creates a security group
func (provider *provider) CreateSecurityGroup(networkRef, name, description string, rules []abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	return nil, gReport
}

// DeleteSecurityGroup deletes a security group and its rules
func (provider *provider) DeleteSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return gReport
}

// InspectSecurityGroup returns information about a security group
func (provider *provider) InspectSecurityGroup(stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	return nil, gReport
}

// ClearSecurityGroup removes all rules but keep group
func (provider *provider) ClearSecurityGroup(stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error) {
	return nil, gReport
}

// AddRuleToSecurityGroup adds a rule to a security group
func (provider *provider) AddRuleToSecurityGroup(stacks.SecurityGroupParameter, abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	return nil, gReport
}

// DeleteRuleFromSecurityGroup adds a rule to a security group
func (provider *provider) DeleteRuleFromSecurityGroup(stacks.SecurityGroupParameter, abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error) {
	return nil, gReport
}

// GetDefaultSecurityGroupName returns the name of the Security Group automatically bound to hosts
func (provider *provider) GetDefaultSecurityGroupName() string {
	return ""
}

func (provider *provider) EnableSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return gReport
}

func (provider *provider) DisableSecurityGroup(*abstract.SecurityGroup) fail.Error {
	return gReport
}

func init() {
	// log.Debug("Registering fake local provider")
	iaas.Register("local", &provider{})
}
