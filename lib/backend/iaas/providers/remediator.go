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

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
)

// Remediator encapsulates Provider interface to catch panic, to prevent panic from halting the app
type Remediator struct {
	iaasapi.Provider
	Name string
}

// HasDefaultNetwork tells if the stack has a default network (defined in tenant settings)
func (s Remediator) HasDefaultNetwork() (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	return s.Provider.HasDefaultNetwork()
}

// DefaultNetwork returns the abstract.Network used as default Network
func (s Remediator) DefaultNetwork(ctx context.Context) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	return s.Provider.DefaultNetwork(ctx)
}

func (s Remediator) AuthenticationOptions() (iaasoptions.Authentication, fail.Error) {
	return s.Provider.AuthenticationOptions()
}

func (s Remediator) ConfigurationOptions() (iaasoptions.Configuration, fail.Error) {
	return s.Provider.ConfigurationOptions()
}

func (s Remediator) Build(m map[string]interface{}, opts ...options.Mutator) (_ iaasapi.Provider, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	build, xerr := s.Provider.Build(m, opts...)
	return build, xerr
}

func (s Remediator) GetName() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	name, xerr := s.Provider.GetName()
	if xerr != nil {
		return "", xerr
	}
	return name, nil
}

func (s Remediator) GetStack() (_ iaasapi.Stack, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	aStack, xerr := s.Provider.GetStack()
	return aStack, xerr
}

func (s Remediator) GetRegexpsOfTemplatesWithGPU() (_ []*regexp.Regexp, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	regexps, xerr := s.Provider.GetRegexpsOfTemplatesWithGPU()
	return regexps, xerr
}

func (s Remediator) Capabilities() (_ iaasapi.Capabilities) {
	return s.Provider.Capabilities()
}

func (s Remediator) TenantParameters() (_ map[string]interface{}, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	tenantParameters, xerr := s.Provider.TenantParameters()
	return tenantParameters, xerr
}

func (s Remediator) ListImages(ctx context.Context, all bool) (_ []*abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	images, xerr := s.Provider.ListImages(ctx, all)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return images, xerr
}

func (s Remediator) ListTemplates(ctx context.Context, all bool) (_ []*abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	templates, xerr := s.Provider.ListTemplates(ctx, all)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return templates, xerr
}

func (s Remediator) GetStackName() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.Provider.GetStackName()
	return cfg, xerr
}

func (s Remediator) ListAvailabilityZones(ctx context.Context) (_ map[string]bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	zones, xerr := s.Provider.ListAvailabilityZones(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return zones, xerr
}

func (s Remediator) ListRegions(ctx context.Context) (_ []string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	regions, xerr := s.Provider.ListRegions(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return regions, xerr
}

func (s Remediator) InspectImage(ctx context.Context, id string) (_ *abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	image, xerr := s.Provider.InspectImage(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return image, xerr
}

func (s Remediator) InspectTemplate(ctx context.Context, id string) (_ *abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	template, xerr := s.Provider.InspectTemplate(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return template, xerr
}

func (s Remediator) CreateKeyPair(ctx context.Context, name string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.Provider.CreateKeyPair(ctx, name)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return pair, xerr
}

func (s Remediator) InspectKeyPair(ctx context.Context, id string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.Provider.InspectKeyPair(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return pair, xerr
}

func (s Remediator) ListKeyPairs(ctx context.Context) (_ []*abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.Provider.ListKeyPairs(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return pair, xerr
}

func (s Remediator) DeleteKeyPair(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteKeyPair(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) ListSecurityGroups(ctx context.Context, networkRef string) (_ []*abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Provider.ListSecurityGroups(ctx, networkRef)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s Remediator) CreateSecurityGroup(ctx context.Context, networkRef, name, description string, rules abstract.SecurityGroupRules) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Provider.CreateSecurityGroup(ctx, networkRef, name, description, rules)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s Remediator) InspectSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Provider.InspectSecurityGroup(ctx, sgParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s Remediator) ClearSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Provider.ClearSecurityGroup(ctx, sgParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s Remediator) DeleteSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteSecurityGroup(ctx, group)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) AddRuleToSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.Provider.AddRuleToSecurityGroup(ctx, sgParam, rule)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return group, xerr
}

func (s Remediator) DeleteRuleFromSecurityGroup(ctx context.Context, sgParam iaasapi.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.Provider.DeleteRuleFromSecurityGroup(ctx, sgParam, rule)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return group, xerr
}

func (s Remediator) GetDefaultSecurityGroupName(ctx context.Context) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.Provider.GetDefaultSecurityGroupName(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return cfg, xerr
}

func (s Remediator) EnableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.EnableSecurityGroup(ctx, group)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) DisableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DisableSecurityGroup(ctx, group)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.CreateNetwork(ctx, req)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) InspectNetwork(ctx context.Context, id string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.InspectNetwork(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) InspectNetworkByName(ctx context.Context, name string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.InspectNetworkByName(ctx, name)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) ListNetworks(ctx context.Context) (_ []*abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.ListNetworks(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) DeleteNetwork(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteNetwork(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.CreateSubnet(ctx, req)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) InspectSubnet(ctx context.Context, id string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.InspectSubnet(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) InspectSubnetByName(ctx context.Context, networkID, name string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.InspectSubnetByName(ctx, networkID, name)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) ListSubnets(ctx context.Context, networkID string) (_ []*abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.ListSubnets(ctx, networkID)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) DeleteSubnet(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteSubnet(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) CreateVIP(ctx context.Context, networkID, subnetID, name string, securityGroups []string) (_ *abstract.VirtualIP, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Provider.CreateVIP(ctx, networkID, subnetID, name, securityGroups)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) AddPublicIPToVIP(ctx context.Context, ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.AddPublicIPToVIP(ctx, ip)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) BindHostToVIP(ctx context.Context, ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.BindHostToVIP(ctx, ip, s2)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) UnbindHostFromVIP(ctx context.Context, ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.UnbindHostFromVIP(ctx, ip, s2)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) DeleteVIP(ctx context.Context, ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteVIP(ctx, ip)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) CreateHost(ctx context.Context, request abstract.HostRequest) (_ *abstract.HostFull, _ *userdata.Content, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, content, xerr := s.Provider.CreateHost(ctx, request)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, content, xerr
}

func (s Remediator) ClearHostStartupScript(ctx context.Context, parameter iaasapi.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.ClearHostStartupScript(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) ChangeSecurityGroupSecurity(ctx context.Context, b bool, b2 bool, net string, _ string) fail.Error {
	xerr := s.Provider.ChangeSecurityGroupSecurity(ctx, b, b2, net, "")
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) InspectHost(ctx context.Context, parameter iaasapi.HostParameter) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Provider.InspectHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s Remediator) GetHostState(ctx context.Context, parameter iaasapi.HostParameter) (_ hoststate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Provider.GetHostState(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s Remediator) ListHosts(ctx context.Context, b bool) (_ abstract.HostList, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Provider.ListHosts(ctx, b)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s Remediator) DeleteHost(ctx context.Context, parameter iaasapi.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) StopHost(ctx context.Context, host iaasapi.HostParameter, gracefully bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.StopHost(ctx, host, gracefully)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) StartHost(ctx context.Context, parameter iaasapi.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.StartHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) RebootHost(ctx context.Context, parameter iaasapi.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.RebootHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) ResizeHost(ctx context.Context, parameter iaasapi.HostParameter, requirements abstract.HostSizingRequirements) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Provider.ResizeHost(ctx, parameter, requirements)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s Remediator) WaitHostReady(ctx context.Context, hostParam iaasapi.HostParameter, timeout time.Duration) (_ *abstract.HostCore, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Provider.WaitHostReady(ctx, hostParam, timeout)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s Remediator) BindSecurityGroupToHost(ctx context.Context, sgParam iaasapi.SecurityGroupParameter, hostParam iaasapi.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.BindSecurityGroupToHost(ctx, sgParam, hostParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) UnbindSecurityGroupFromHost(ctx context.Context, sgParam iaasapi.SecurityGroupParameter, hostParam iaasapi.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.UnbindSecurityGroupFromHost(ctx, sgParam, hostParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.CreateVolume(ctx, request)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s Remediator) InspectVolume(ctx context.Context, id string) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.InspectVolume(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s Remediator) ListVolumes(ctx context.Context) (_ []*abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.ListVolumes(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s Remediator) DeleteVolume(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteVolume(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.CreateVolumeAttachment(ctx, request)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s Remediator) InspectVolumeAttachment(ctx context.Context, serverID, id string) (_ *abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.InspectVolumeAttachment(ctx, serverID, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s Remediator) ListVolumeAttachments(ctx context.Context, serverID string) (_ []*abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Provider.ListVolumeAttachments(ctx, serverID)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s Remediator) DeleteVolumeAttachment(ctx context.Context, serverID, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Provider.DeleteVolumeAttachment(ctx, serverID, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}
