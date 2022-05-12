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

package providers

import (
	"context"
	"regexp"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/server/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/v22/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ProviderProxy ...
type ProviderProxy struct {
	Provider
	Name string
}

func (s ProviderProxy) GetAuthenticationOptions() (_ Config, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	config, xerr := s.Provider.GetAuthenticationOptions()
	return config, xerr
}

func (s ProviderProxy) GetConfigurationOptions() (_ Config, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	config, xerr := s.Provider.GetConfigurationOptions()
	return config, xerr
}

func (s ProviderProxy) GetRawConfigurationOptions() (_ stacks.ConfigurationOptions, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	asta, xerr := s.Provider.GetStack()
	if xerr != nil {
		return stacks.ConfigurationOptions{}, xerr
	}
	return asta.(api.ReservedForProviderUse).GetRawConfigurationOptions()
}

func (s ProviderProxy) GetRawAuthenticationOptions() (_ stacks.AuthenticationOptions, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	asta, xerr := s.Provider.GetStack()
	if xerr != nil {
		return stacks.AuthenticationOptions{}, xerr
	}
	return asta.(api.ReservedForProviderUse).GetRawAuthenticationOptions()
}

func (s ProviderProxy) Build(m map[string]interface{}) (_ Provider, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	build, xerr := s.Provider.Build(m)
	return build, xerr
}

func (s ProviderProxy) GetName() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	name, xerr := s.Provider.GetName()
	if xerr != nil {
		return "", xerr
	}
	return name, nil
}

func (s ProviderProxy) GetStack() (_ api.Stack, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	aStack, xerr := s.Provider.GetStack()
	return aStack, xerr
}

func (s ProviderProxy) GetRegexpsOfTemplatesWithGPU() (_ []*regexp.Regexp, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	regexps, xerr := s.Provider.GetRegexpsOfTemplatesWithGPU()
	return regexps, xerr
}

func (s ProviderProxy) GetCapabilities() (_ Capabilities, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	capabilities, xerr := s.Provider.GetCapabilities()
	return capabilities, xerr
}

func (s ProviderProxy) GetTenantParameters() (_ map[string]interface{}, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	tenantParameters, xerr := s.Provider.GetTenantParameters()
	return tenantParameters, xerr
}

func (s ProviderProxy) ListImages(all bool) (_ []*abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	images, xerr := s.Provider.ListImages(all)
	return images, xerr
}

func (s ProviderProxy) ListTemplates(all bool) (_ []*abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	templates, xerr := s.Provider.ListTemplates(all)
	return templates, xerr
}

func (s ProviderProxy) GetStackName() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.Provider.GetStackName()
	return cfg, xerr
}

func (s ProviderProxy) ListAvailabilityZones() (_ map[string]bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	zones, xerr := s.Provider.ListAvailabilityZones()
	return zones, xerr
}

func (s ProviderProxy) ListRegions() (_ []string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	regions, xerr := s.Provider.ListRegions()
	return regions, xerr
}

func (s ProviderProxy) InspectImage(id string) (_ *abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	image, xerr := s.Provider.InspectImage(id)
	return image, xerr
}

func (s ProviderProxy) InspectTemplate(id string) (_ *abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	template, xerr := s.Provider.InspectTemplate(id)
	return template, xerr
}

func (s ProviderProxy) CreateKeyPair(name string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.Provider.CreateKeyPair(name)
	return pair, xerr
}

func (s ProviderProxy) InspectKeyPair(id string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.Provider.InspectKeyPair(id)
	return pair, xerr
}

func (s ProviderProxy) ListKeyPairs() (_ []*abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.Provider.ListKeyPairs()
	return pair, xerr
}

func (s ProviderProxy) DeleteKeyPair(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteKeyPair(id)
	return xerr
}

func (s ProviderProxy) ListSecurityGroups(ctx context.Context, networkRef string) (_ []*abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Provider.ListSecurityGroups(ctx, networkRef)
	return groups, xerr
}

func (s ProviderProxy) CreateSecurityGroup(ctx context.Context, networkRef, name, description string, rules abstract.SecurityGroupRules) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Provider.CreateSecurityGroup(ctx, networkRef, name, description, rules)
	return groups, xerr
}

func (s ProviderProxy) InspectSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Provider.InspectSecurityGroup(ctx, sgParam)
	return groups, xerr
}

func (s ProviderProxy) ClearSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Provider.ClearSecurityGroup(ctx, sgParam)
	return groups, xerr
}

func (s ProviderProxy) DeleteSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteSecurityGroup(ctx, group)
	return xerr
}

func (s ProviderProxy) AddRuleToSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.Provider.AddRuleToSecurityGroup(ctx, sgParam, rule)
	return group, xerr
}

func (s ProviderProxy) DeleteRuleFromSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.Provider.DeleteRuleFromSecurityGroup(ctx, sgParam, rule)
	return group, xerr
}

func (s ProviderProxy) GetDefaultSecurityGroupName(ctx context.Context) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.Provider.GetDefaultSecurityGroupName(ctx)
	return cfg, xerr
}

func (s ProviderProxy) EnableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.EnableSecurityGroup(ctx, group)
	return xerr
}

func (s ProviderProxy) DisableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DisableSecurityGroup(ctx, group)
	return xerr
}

func (s ProviderProxy) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.CreateNetwork(ctx, req)
	return network, xerr
}

func (s ProviderProxy) InspectNetwork(ctx context.Context, id string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.InspectNetwork(ctx, id)
	return network, xerr
}

func (s ProviderProxy) InspectNetworkByName(ctx context.Context, name string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.InspectNetworkByName(ctx, name)
	return network, xerr
}

func (s ProviderProxy) ListNetworks(ctx context.Context) (_ []*abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.ListNetworks(ctx)
	return network, xerr
}

func (s ProviderProxy) DeleteNetwork(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteNetwork(ctx, id)
	return xerr
}

func (s ProviderProxy) HasDefaultNetwork(ctx context.Context) (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.Provider.HasDefaultNetwork(ctx)
	return cfg, xerr
}

func (s ProviderProxy) GetDefaultNetwork(ctx context.Context) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.GetDefaultNetwork(ctx)
	return network, xerr
}

func (s ProviderProxy) CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.CreateSubnet(ctx, req)
	return network, xerr
}

func (s ProviderProxy) InspectSubnet(ctx context.Context, id string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.InspectSubnet(ctx, id)
	return network, xerr
}

func (s ProviderProxy) InspectSubnetByName(ctx context.Context, networkID, name string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.InspectSubnetByName(ctx, networkID, name)
	return network, xerr
}

func (s ProviderProxy) ListSubnets(ctx context.Context, networkID string) (_ []*abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.ListSubnets(ctx, networkID)
	return network, xerr
}

func (s ProviderProxy) DeleteSubnet(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteSubnet(ctx, id)
	return xerr
}

func (s ProviderProxy) BindSecurityGroupToSubnet(ctx context.Context, sgParam stacks.SecurityGroupParameter, subnetID string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.BindSecurityGroupToSubnet(ctx, sgParam, subnetID)
	return xerr
}

func (s ProviderProxy) UnbindSecurityGroupFromSubnet(ctx context.Context, sgParam stacks.SecurityGroupParameter, subnetID string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.UnbindSecurityGroupFromSubnet(ctx, sgParam, subnetID)
	return xerr
}

func (s ProviderProxy) CreateVIP(ctx context.Context, networkID, subnetID, name string, securityGroups []string) (_ *abstract.VirtualIP, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.CreateVIP(ctx, networkID, subnetID, name, securityGroups)
	return network, xerr
}

func (s ProviderProxy) AddPublicIPToVIP(ctx context.Context, ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.AddPublicIPToVIP(ctx, ip)
	return xerr
}

func (s ProviderProxy) BindHostToVIP(ctx context.Context, ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.BindHostToVIP(ctx, ip, s2)
	return xerr
}

func (s ProviderProxy) UnbindHostFromVIP(ctx context.Context, ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.UnbindHostFromVIP(ctx, ip, s2)
	return xerr
}

func (s ProviderProxy) DeleteVIP(ctx context.Context, ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteVIP(ctx, ip)
	return xerr
}

func (s ProviderProxy) CreateHost(ctx context.Context, request abstract.HostRequest) (_ *abstract.HostFull, _ *userdata.Content, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, content, xerr := s.Provider.CreateHost(ctx, request)
	return host, content, xerr
}

func (s ProviderProxy) ClearHostStartupScript(ctx context.Context, parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.ClearHostStartupScript(ctx, parameter)
	return xerr
}

func (s ProviderProxy) InspectHost(ctx context.Context, parameter stacks.HostParameter) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Provider.InspectHost(ctx, parameter)
	return host, xerr
}

func (s ProviderProxy) GetHostState(ctx context.Context, parameter stacks.HostParameter) (_ hoststate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Provider.GetHostState(ctx, parameter)
	return host, xerr
}

func (s ProviderProxy) ListHosts(ctx context.Context, b bool) (_ abstract.HostList, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Provider.ListHosts(ctx, b)
	return host, xerr
}

func (s ProviderProxy) DeleteHost(ctx context.Context, parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteHost(ctx, parameter)
	return xerr
}

func (s ProviderProxy) StopHost(ctx context.Context, host stacks.HostParameter, gracefully bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.StopHost(ctx, host, gracefully)
	return xerr
}

func (s ProviderProxy) StartHost(ctx context.Context, parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.StartHost(ctx, parameter)
	return xerr
}

func (s ProviderProxy) RebootHost(ctx context.Context, parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.RebootHost(ctx, parameter)
	return xerr
}

func (s ProviderProxy) ResizeHost(ctx context.Context, parameter stacks.HostParameter, requirements abstract.HostSizingRequirements) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Provider.ResizeHost(ctx, parameter, requirements)
	return host, xerr
}

func (s ProviderProxy) WaitHostReady(ctx context.Context, hostParam stacks.HostParameter, timeout time.Duration) (_ *abstract.HostCore, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Provider.WaitHostReady(ctx, hostParam, timeout)
	return host, xerr
}

func (s ProviderProxy) BindSecurityGroupToHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.BindSecurityGroupToHost(ctx, sgParam, hostParam)
	return xerr
}

func (s ProviderProxy) UnbindSecurityGroupFromHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.UnbindSecurityGroupFromHost(ctx, sgParam, hostParam)
	return xerr
}

func (s ProviderProxy) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.CreateVolume(ctx, request)
	return volume, xerr
}

func (s ProviderProxy) InspectVolume(ctx context.Context, id string) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.InspectVolume(ctx, id)
	return volume, xerr
}

func (s ProviderProxy) ListVolumes(ctx context.Context) (_ []*abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.ListVolumes(ctx)
	return volume, xerr
}

func (s ProviderProxy) DeleteVolume(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteVolume(ctx, id)
	return xerr
}

func (s ProviderProxy) CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.CreateVolumeAttachment(ctx, request)
	return volume, xerr
}

func (s ProviderProxy) InspectVolumeAttachment(ctx context.Context, serverID, id string) (_ *abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.InspectVolumeAttachment(ctx, serverID, id)
	return volume, xerr
}

func (s ProviderProxy) ListVolumeAttachments(ctx context.Context, serverID string) (_ []*abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.ListVolumeAttachments(ctx, serverID)
	return volume, xerr
}

func (s ProviderProxy) DeleteVolumeAttachment(ctx context.Context, serverID, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteVolumeAttachment(ctx, serverID, id)
	return xerr
}

func (s ProviderProxy) Migrate(operation string, params map[string]interface{}) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.Migrate(operation, params)
	return xerr
}
