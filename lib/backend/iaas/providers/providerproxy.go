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

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ProviderProxy ...
type ProviderProxy struct {
	Provider
	Name string
}

func (s ProviderProxy) GetAuthenticationOptions(ctx context.Context) (_ Config, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	config, xerr := s.Provider.GetAuthenticationOptions(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return config, xerr
}

func (s ProviderProxy) GetConfigurationOptions(ctx context.Context) (_ Config, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	config, xerr := s.Provider.GetConfigurationOptions(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return config, xerr
}

func (s ProviderProxy) GetRawConfigurationOptions(ctx context.Context) (_ stacks.ConfigurationOptions, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	asta, xerr := s.Provider.GetStack()
	if xerr != nil {
		xerr.WithContext(ctx)
		return stacks.ConfigurationOptions{}, xerr
	}
	return asta.(api.ReservedForProviderUse).GetRawConfigurationOptions(ctx)
}

func (s ProviderProxy) GetRawAuthenticationOptions(ctx context.Context) (_ stacks.AuthenticationOptions, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	asta, xerr := s.Provider.GetStack()
	if xerr != nil {
		xerr.WithContext(ctx)
		return stacks.AuthenticationOptions{}, xerr
	}
	return asta.(api.ReservedForProviderUse).GetRawAuthenticationOptions(ctx)
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

func (s ProviderProxy) GetCapabilities(ctx context.Context) (_ Capabilities, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	capabilities, xerr := s.Provider.GetCapabilities(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return capabilities, xerr
}

func (s ProviderProxy) GetTenantParameters() (_ map[string]interface{}, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	tenantParameters, xerr := s.Provider.GetTenantParameters()
	return tenantParameters, xerr
}

func (s ProviderProxy) ListImages(ctx context.Context, all bool) (_ []*abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	images, xerr := s.Provider.ListImages(ctx, all)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return images, xerr
}

func (s ProviderProxy) ListTemplates(ctx context.Context, all bool) (_ []*abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	templates, xerr := s.Provider.ListTemplates(ctx, all)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return templates, xerr
}

func (s ProviderProxy) GetStackName() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.Provider.GetStackName()
	return cfg, xerr
}

func (s ProviderProxy) ListAvailabilityZones(ctx context.Context) (_ map[string]bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	zones, xerr := s.Provider.ListAvailabilityZones(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return zones, xerr
}

func (s ProviderProxy) ListRegions(ctx context.Context) (_ []string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	regions, xerr := s.Provider.ListRegions(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return regions, xerr
}

func (s ProviderProxy) InspectImage(ctx context.Context, id string) (_ *abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	image, xerr := s.Provider.InspectImage(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return image, xerr
}

func (s ProviderProxy) InspectTemplate(ctx context.Context, id string) (_ *abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	template, xerr := s.Provider.InspectTemplate(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return template, xerr
}

func (s ProviderProxy) CreateKeyPair(ctx context.Context, name string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.Provider.CreateKeyPair(ctx, name)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return pair, xerr
}

func (s ProviderProxy) InspectKeyPair(ctx context.Context, id string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.Provider.InspectKeyPair(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return pair, xerr
}

func (s ProviderProxy) ListKeyPairs(ctx context.Context) (_ []*abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.Provider.ListKeyPairs(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return pair, xerr
}

func (s ProviderProxy) DeleteKeyPair(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteKeyPair(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) ListSecurityGroups(ctx context.Context, networkRef string) (_ []*abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Provider.ListSecurityGroups(ctx, networkRef)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s ProviderProxy) CreateSecurityGroup(ctx context.Context, networkRef, name, description string, rules abstract.SecurityGroupRules) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Provider.CreateSecurityGroup(ctx, networkRef, name, description, rules)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s ProviderProxy) InspectSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Provider.InspectSecurityGroup(ctx, sgParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s ProviderProxy) ClearSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Provider.ClearSecurityGroup(ctx, sgParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s ProviderProxy) DeleteSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteSecurityGroup(ctx, group)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) AddRuleToSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.Provider.AddRuleToSecurityGroup(ctx, sgParam, rule)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return group, xerr
}

func (s ProviderProxy) DeleteRuleFromSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.Provider.DeleteRuleFromSecurityGroup(ctx, sgParam, rule)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return group, xerr
}

func (s ProviderProxy) GetDefaultSecurityGroupName(ctx context.Context) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.Provider.GetDefaultSecurityGroupName(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return cfg, xerr
}

func (s ProviderProxy) EnableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.EnableSecurityGroup(ctx, group)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) DisableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DisableSecurityGroup(ctx, group)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.CreateNetwork(ctx, req)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s ProviderProxy) InspectNetwork(ctx context.Context, id string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.InspectNetwork(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s ProviderProxy) InspectNetworkByName(ctx context.Context, name string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.InspectNetworkByName(ctx, name)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s ProviderProxy) ListNetworks(ctx context.Context) (_ []*abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.ListNetworks(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s ProviderProxy) DeleteNetwork(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteNetwork(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) HasDefaultNetwork(ctx context.Context) (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.Provider.HasDefaultNetwork(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return cfg, xerr
}

func (s ProviderProxy) GetDefaultNetwork(ctx context.Context) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.GetDefaultNetwork(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s ProviderProxy) CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.CreateSubnet(ctx, req)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s ProviderProxy) InspectSubnet(ctx context.Context, id string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.InspectSubnet(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s ProviderProxy) InspectSubnetByName(ctx context.Context, networkID, name string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.InspectSubnetByName(ctx, networkID, name)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s ProviderProxy) ListSubnets(ctx context.Context, networkID string) (_ []*abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.ListSubnets(ctx, networkID)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s ProviderProxy) DeleteSubnet(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteSubnet(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) CreateVIP(ctx context.Context, networkID, subnetID, name string, securityGroups []string) (_ *abstract.VirtualIP, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.CreateVIP(ctx, networkID, subnetID, name, securityGroups)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s ProviderProxy) AddPublicIPToVIP(ctx context.Context, ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.AddPublicIPToVIP(ctx, ip)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) BindHostToVIP(ctx context.Context, ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.BindHostToVIP(ctx, ip, s2)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) UnbindHostFromVIP(ctx context.Context, ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.UnbindHostFromVIP(ctx, ip, s2)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) DeleteVIP(ctx context.Context, ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteVIP(ctx, ip)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) CreateHost(ctx context.Context, request abstract.HostRequest, extra interface{}) (_ *abstract.HostFull, _ *userdata.Content, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, content, xerr := s.Provider.CreateHost(ctx, request, extra)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, content, xerr
}

func (s ProviderProxy) ClearHostStartupScript(ctx context.Context, parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.ClearHostStartupScript(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) ChangeSecurityGroupSecurity(ctx context.Context, b bool, b2 bool, net string, s2 string) fail.Error {
	xerr := s.Provider.ChangeSecurityGroupSecurity(ctx, b, b2, net, "")
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) InspectHost(ctx context.Context, parameter stacks.HostParameter) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Provider.InspectHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s ProviderProxy) GetHostState(ctx context.Context, parameter stacks.HostParameter) (_ hoststate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Provider.GetHostState(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s ProviderProxy) GetTrueHostState(ctx context.Context, parameter stacks.HostParameter) (_ hoststate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Provider.GetTrueHostState(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s ProviderProxy) ListHosts(ctx context.Context, b bool) (_ abstract.HostList, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Provider.ListHosts(ctx, b)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s ProviderProxy) DeleteHost(ctx context.Context, parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) StopHost(ctx context.Context, host stacks.HostParameter, gracefully bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.StopHost(ctx, host, gracefully)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) StartHost(ctx context.Context, parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.StartHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) RebootHost(ctx context.Context, parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.RebootHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) WaitHostReady(ctx context.Context, hostParam stacks.HostParameter, timeout time.Duration) (_ *abstract.HostCore, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Provider.WaitHostReady(ctx, hostParam, timeout)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s ProviderProxy) BindSecurityGroupToHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.BindSecurityGroupToHost(ctx, sgParam, hostParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) UnbindSecurityGroupFromHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.UnbindSecurityGroupFromHost(ctx, sgParam, hostParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.CreateVolume(ctx, request)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s ProviderProxy) InspectVolume(ctx context.Context, id string) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.InspectVolume(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s ProviderProxy) ListVolumes(ctx context.Context) (_ []*abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.ListVolumes(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s ProviderProxy) DeleteVolume(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteVolume(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s ProviderProxy) CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.CreateVolumeAttachment(ctx, request)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s ProviderProxy) InspectVolumeAttachment(ctx context.Context, serverID, id string) (_ *abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.InspectVolumeAttachment(ctx, serverID, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s ProviderProxy) ListVolumeAttachments(ctx context.Context, serverID string) (_ []*abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.ListVolumeAttachments(ctx, serverID)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s ProviderProxy) DeleteVolumeAttachment(ctx context.Context, serverID, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteVolumeAttachment(ctx, serverID, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}
