/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package api

import (
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// StackProxy ...
type StackProxy struct {
	FullStack
	Name string
}

func (s StackProxy) ListImages(all bool) (_ []*abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	images, xerr := s.FullStack.ListImages(all)
	return images, xerr
}

func (s StackProxy) ListTemplates(all bool) (_ []*abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	templates, xerr := s.FullStack.ListTemplates(all)
	return templates, xerr
}

func (s StackProxy) GetRawConfigurationOptions() (_ stacks.ConfigurationOptions, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.FullStack.GetRawConfigurationOptions()
	return cfg, xerr
}

func (s StackProxy) GetRawAuthenticationOptions() (_ stacks.AuthenticationOptions, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.FullStack.GetRawAuthenticationOptions()
	return cfg, xerr
}

func (s StackProxy) GetStackName() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.FullStack.GetStackName()
	return cfg, xerr
}

func (s StackProxy) ListAvailabilityZones() (_ map[string]bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	zones, xerr := s.FullStack.ListAvailabilityZones()
	return zones, xerr
}

func (s StackProxy) ListRegions() (_ []string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	regions, xerr := s.FullStack.ListRegions()
	return regions, xerr
}

func (s StackProxy) InspectImage(id string) (_ *abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	image, xerr := s.FullStack.InspectImage(id)
	return image, xerr
}

func (s StackProxy) InspectTemplate(id string) (_ *abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	template, xerr := s.FullStack.InspectTemplate(id)
	return template, xerr
}

func (s StackProxy) CreateKeyPair(name string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.FullStack.CreateKeyPair(name)
	return pair, xerr
}

func (s StackProxy) InspectKeyPair(id string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.FullStack.InspectKeyPair(id)
	return pair, xerr
}

func (s StackProxy) ListKeyPairs() (_ []*abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.FullStack.ListKeyPairs()
	return pair, xerr
}

func (s StackProxy) DeleteKeyPair(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteKeyPair(id)
	return xerr
}

func (s StackProxy) ListSecurityGroups(networkRef string) (_ []*abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.FullStack.ListSecurityGroups(networkRef)
	return groups, xerr
}

func (s StackProxy) CreateSecurityGroup(networkRef, name, description string, rules abstract.SecurityGroupRules) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.FullStack.CreateSecurityGroup(networkRef, name, description, rules)
	return groups, xerr
}

func (s StackProxy) InspectSecurityGroup(sgParam stacks.SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.FullStack.InspectSecurityGroup(sgParam)
	return groups, xerr
}

func (s StackProxy) ClearSecurityGroup(sgParam stacks.SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.FullStack.ClearSecurityGroup(sgParam)
	return groups, xerr
}

func (s StackProxy) DeleteSecurityGroup(group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteSecurityGroup(group)
	return xerr
}

func (s StackProxy) AddRuleToSecurityGroup(sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.FullStack.AddRuleToSecurityGroup(sgParam, rule)
	return group, xerr
}

func (s StackProxy) DeleteRuleFromSecurityGroup(sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.FullStack.DeleteRuleFromSecurityGroup(sgParam, rule)
	return group, xerr
}

func (s StackProxy) GetDefaultSecurityGroupName() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.FullStack.GetDefaultSecurityGroupName()
	return cfg, xerr
}

func (s StackProxy) EnableSecurityGroup(group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.EnableSecurityGroup(group)
	return xerr
}

func (s StackProxy) DisableSecurityGroup(group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DisableSecurityGroup(group)
	return xerr
}

func (s StackProxy) CreateNetwork(req abstract.NetworkRequest) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.CreateNetwork(req)
	return network, xerr
}

func (s StackProxy) InspectNetwork(id string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.InspectNetwork(id)
	return network, xerr
}

func (s StackProxy) InspectNetworkByName(name string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.InspectNetworkByName(name)
	return network, xerr
}

func (s StackProxy) ListNetworks() (_ []*abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.ListNetworks()
	return network, xerr
}

func (s StackProxy) DeleteNetwork(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteNetwork(id)
	return xerr
}

func (s StackProxy) HasDefaultNetwork() (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.FullStack.HasDefaultNetwork()
	return cfg, xerr
}

func (s StackProxy) GetDefaultNetwork() (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.GetDefaultNetwork()
	return network, xerr
}

func (s StackProxy) CreateSubnet(req abstract.SubnetRequest) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.CreateSubnet(req)
	return network, xerr
}

func (s StackProxy) InspectSubnet(id string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.InspectSubnet(id)
	return network, xerr
}

func (s StackProxy) InspectSubnetByName(networkID, name string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.InspectSubnetByName(networkID, name)
	return network, xerr
}

func (s StackProxy) ListSubnets(networkID string) (_ []*abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.ListSubnets(networkID)
	return network, xerr
}

func (s StackProxy) DeleteSubnet(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteSubnet(id)
	return xerr
}

func (s StackProxy) BindSecurityGroupToSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.BindSecurityGroupToSubnet(sgParam, subnetID)
	return xerr
}

func (s StackProxy) UnbindSecurityGroupFromSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.UnbindSecurityGroupFromSubnet(sgParam, subnetID)
	return xerr
}

func (s StackProxy) CreateVIP(networkID, subnetID, name string, securityGroups []string) (_ *abstract.VirtualIP, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.CreateVIP(networkID, subnetID, name, securityGroups)
	return network, xerr
}

func (s StackProxy) AddPublicIPToVIP(ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.AddPublicIPToVIP(ip)
	return xerr
}

func (s StackProxy) BindHostToVIP(ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.BindHostToVIP(ip, s2)
	return xerr
}

func (s StackProxy) UnbindHostFromVIP(ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.UnbindHostFromVIP(ip, s2)
	return xerr
}

func (s StackProxy) DeleteVIP(ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteVIP(ip)
	return xerr
}

func (s StackProxy) CreateHost(request abstract.HostRequest) (_ *abstract.HostFull, _ *userdata.Content, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, content, xerr := s.FullStack.CreateHost(request)
	return host, content, xerr
}

func (s StackProxy) ClearHostStartupScript(parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.ClearHostStartupScript(parameter)
	return xerr
}

func (s StackProxy) InspectHost(parameter stacks.HostParameter) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.FullStack.InspectHost(parameter)
	return host, xerr
}

func (s StackProxy) GetHostState(parameter stacks.HostParameter) (_ hoststate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.FullStack.GetHostState(parameter)
	return host, xerr
}

func (s StackProxy) ListHosts(b bool) (_ abstract.HostList, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.FullStack.ListHosts(b)
	return host, xerr
}

func (s StackProxy) DeleteHost(parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteHost(parameter)
	return xerr
}

func (s StackProxy) StopHost(host stacks.HostParameter, gracefully bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.StopHost(host, gracefully)
	return xerr
}

func (s StackProxy) StartHost(parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.StartHost(parameter)
	return xerr
}

func (s StackProxy) RebootHost(parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.RebootHost(parameter)
	return xerr
}

func (s StackProxy) ResizeHost(parameter stacks.HostParameter, requirements abstract.HostSizingRequirements) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.FullStack.ResizeHost(parameter, requirements)
	return host, xerr
}

func (s StackProxy) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (_ *abstract.HostCore, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.FullStack.WaitHostReady(hostParam, timeout)
	return host, xerr
}

func (s StackProxy) BindSecurityGroupToHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.BindSecurityGroupToHost(sgParam, hostParam)
	return xerr
}

func (s StackProxy) UnbindSecurityGroupFromHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.UnbindSecurityGroupFromHost(sgParam, hostParam)
	return xerr
}

func (s StackProxy) CreateVolume(request abstract.VolumeRequest) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.FullStack.CreateVolume(request)
	return volume, xerr
}

func (s StackProxy) InspectVolume(id string) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.FullStack.InspectVolume(id)
	return volume, xerr
}

func (s StackProxy) ListVolumes() (_ []*abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.FullStack.ListVolumes()
	return volume, xerr
}

func (s StackProxy) DeleteVolume(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteVolume(id)
	return xerr
}

func (s StackProxy) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.FullStack.CreateVolumeAttachment(request)
	return volume, xerr
}

func (s StackProxy) InspectVolumeAttachment(serverID, id string) (_ *abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.FullStack.InspectVolumeAttachment(serverID, id)
	return volume, xerr
}

func (s StackProxy) ListVolumeAttachments(serverID string) (_ []*abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.FullStack.ListVolumeAttachments(serverID)
	return volume, xerr
}

func (s StackProxy) DeleteVolumeAttachment(serverID, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteVolumeAttachment(serverID, id)
	return xerr
}

func (s StackProxy) Migrate(operation string, params map[string]interface{}) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.Migrate(operation, params)
	return xerr
}
