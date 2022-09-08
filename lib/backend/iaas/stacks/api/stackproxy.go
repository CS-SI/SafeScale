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
	"context"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// StackProxy ...
type StackProxy struct {
	FullStack
	Name string
}

func (s StackProxy) ListImages(ctx context.Context, all bool) (_ []*abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	images, xerr := s.FullStack.ListImages(ctx, all)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return images, xerr
}

func (s StackProxy) ListTemplates(ctx context.Context, all bool) (_ []*abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	templates, xerr := s.FullStack.ListTemplates(ctx, all)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return templates, xerr
}

func (s StackProxy) GetRawConfigurationOptions(ctx context.Context) (_ stacks.ConfigurationOptions, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.FullStack.GetRawConfigurationOptions(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return cfg, xerr
}

func (s StackProxy) GetRawAuthenticationOptions(ctx context.Context) (_ stacks.AuthenticationOptions, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.FullStack.GetRawAuthenticationOptions(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return cfg, xerr
}

func (s StackProxy) GetStackName() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.FullStack.GetStackName()
	return cfg, xerr
}

func (s StackProxy) ListAvailabilityZones(ctx context.Context) (_ map[string]bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	zones, xerr := s.FullStack.ListAvailabilityZones(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return zones, xerr
}

func (s StackProxy) ListRegions(ctx context.Context) (_ []string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	regions, xerr := s.FullStack.ListRegions(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return regions, xerr
}

func (s StackProxy) InspectImage(ctx context.Context, id string) (_ *abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	image, xerr := s.FullStack.InspectImage(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return image, xerr
}

func (s StackProxy) InspectTemplate(ctx context.Context, id string) (_ *abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	template, xerr := s.FullStack.InspectTemplate(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return template, xerr
}

func (s StackProxy) CreateKeyPair(ctx context.Context, name string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.FullStack.CreateKeyPair(ctx, name)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return pair, xerr
}

func (s StackProxy) InspectKeyPair(ctx context.Context, id string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.FullStack.InspectKeyPair(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return pair, xerr
}

func (s StackProxy) ListKeyPairs(ctx context.Context) (_ []*abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.FullStack.ListKeyPairs(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return pair, xerr
}

func (s StackProxy) DeleteKeyPair(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteKeyPair(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) ListSecurityGroups(ctx context.Context, networkRef string) (_ []*abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.FullStack.ListSecurityGroups(ctx, networkRef)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s StackProxy) CreateSecurityGroup(ctx context.Context, networkRef, name, description string, rules abstract.SecurityGroupRules) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.FullStack.CreateSecurityGroup(ctx, networkRef, name, description, rules)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s StackProxy) InspectSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.FullStack.InspectSecurityGroup(ctx, sgParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s StackProxy) ClearSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.FullStack.ClearSecurityGroup(ctx, sgParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s StackProxy) DeleteSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteSecurityGroup(ctx, group)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) AddRuleToSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.FullStack.AddRuleToSecurityGroup(ctx, sgParam, rule)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return group, xerr
}

func (s StackProxy) DeleteRuleFromSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.FullStack.DeleteRuleFromSecurityGroup(ctx, sgParam, rule)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return group, xerr
}

func (s StackProxy) GetDefaultSecurityGroupName(ctx context.Context) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.FullStack.GetDefaultSecurityGroupName(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return cfg, xerr
}

func (s StackProxy) EnableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.EnableSecurityGroup(ctx, group)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) DisableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DisableSecurityGroup(ctx, group)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.CreateNetwork(ctx, req)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s StackProxy) InspectNetwork(ctx context.Context, id string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.InspectNetwork(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s StackProxy) InspectNetworkByName(ctx context.Context, name string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.InspectNetworkByName(ctx, name)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s StackProxy) ListNetworks(ctx context.Context) (_ []*abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.ListNetworks(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s StackProxy) DeleteNetwork(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteNetwork(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) HasDefaultNetwork(ctx context.Context) (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.FullStack.HasDefaultNetwork(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return cfg, xerr
}

func (s StackProxy) GetDefaultNetwork(ctx context.Context) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.GetDefaultNetwork(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s StackProxy) CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.CreateSubnet(ctx, req)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s StackProxy) InspectSubnet(ctx context.Context, id string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.InspectSubnet(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s StackProxy) InspectSubnetByName(ctx context.Context, networkID, name string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.InspectSubnetByName(ctx, networkID, name)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s StackProxy) ListSubnets(ctx context.Context, networkID string) (_ []*abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.ListSubnets(ctx, networkID)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s StackProxy) DeleteSubnet(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteSubnet(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) CreateVIP(ctx context.Context, networkID, subnetID, name string, securityGroups []string) (_ *abstract.VirtualIP, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.FullStack.CreateVIP(ctx, networkID, subnetID, name, securityGroups)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s StackProxy) AddPublicIPToVIP(ctx context.Context, ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.AddPublicIPToVIP(ctx, ip)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) BindHostToVIP(ctx context.Context, ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.BindHostToVIP(ctx, ip, s2)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) UnbindHostFromVIP(ctx context.Context, ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.UnbindHostFromVIP(ctx, ip, s2)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) DeleteVIP(ctx context.Context, ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteVIP(ctx, ip)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) CreateHost(ctx context.Context, request abstract.HostRequest) (_ *abstract.HostFull, _ *userdata.Content, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, content, xerr := s.FullStack.CreateHost(ctx, request)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, content, xerr
}

func (s StackProxy) ClearHostStartupScript(ctx context.Context, parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.ClearHostStartupScript(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) ChangeSecurityGroupSecurity(ctx context.Context, b bool, b2 bool, net string, s2 string) fail.Error {
	xerr := s.FullStack.ChangeSecurityGroupSecurity(ctx, b, b2, net, "")
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) InspectHost(ctx context.Context, parameter stacks.HostParameter) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.FullStack.InspectHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s StackProxy) GetHostState(ctx context.Context, parameter stacks.HostParameter) (_ hoststate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.FullStack.GetHostState(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s StackProxy) ListHosts(ctx context.Context, b bool) (_ abstract.HostList, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.FullStack.ListHosts(ctx, b)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s StackProxy) DeleteHost(ctx context.Context, parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) StopHost(ctx context.Context, host stacks.HostParameter, gracefully bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.StopHost(ctx, host, gracefully)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) StartHost(ctx context.Context, parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.StartHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) RebootHost(ctx context.Context, parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.RebootHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) ResizeHost(ctx context.Context, parameter stacks.HostParameter, requirements abstract.HostSizingRequirements) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.FullStack.ResizeHost(ctx, parameter, requirements)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s StackProxy) WaitHostReady(ctx context.Context, hostParam stacks.HostParameter, timeout time.Duration) (_ *abstract.HostCore, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.FullStack.WaitHostReady(ctx, hostParam, timeout)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s StackProxy) BindSecurityGroupToHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.BindSecurityGroupToHost(ctx, sgParam, hostParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) UnbindSecurityGroupFromHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.UnbindSecurityGroupFromHost(ctx, sgParam, hostParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.FullStack.CreateVolume(ctx, request)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s StackProxy) InspectVolume(ctx context.Context, id string) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.FullStack.InspectVolume(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s StackProxy) ListVolumes(ctx context.Context) (_ []*abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.FullStack.ListVolumes(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s StackProxy) DeleteVolume(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteVolume(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s StackProxy) CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.FullStack.CreateVolumeAttachment(ctx, request)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s StackProxy) InspectVolumeAttachment(ctx context.Context, serverID, id string) (_ *abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.FullStack.InspectVolumeAttachment(ctx, serverID, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s StackProxy) ListVolumeAttachments(ctx context.Context, serverID string) (_ []*abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.FullStack.ListVolumeAttachments(ctx, serverID)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s StackProxy) DeleteVolumeAttachment(ctx context.Context, serverID, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.FullStack.DeleteVolumeAttachment(ctx, serverID, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}
