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

package stacks

import (
	"context"
	"time"

	stackoptions "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// Remediator ...
type Remediator struct {
	Stack
	Name string
}

func (s Remediator) ListImages(ctx context.Context, all bool) (_ []*abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	images, xerr := s.Stack.ListImages(ctx, all)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return images, xerr
}

func (s Remediator) ListTemplates(ctx context.Context, all bool) (_ []*abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	templates, xerr := s.Stack.ListTemplates(ctx, all)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return templates, xerr
}

func (s Remediator) AuthenticationOptions() (stackoptions.Authentication, fail.Error) {
	return s.Stack.AuthenticationOptions()
}

func (s Remediator) ConfigurationOptions() (stackoptions.Configuration, fail.Error) {
	return s.Stack.ConfigurationOptions()
}

func (s Remediator) GetStackName() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.Stack.GetStackName()
	return cfg, xerr
}

func (s Remediator) ListAvailabilityZones(ctx context.Context) (_ map[string]bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	zones, xerr := s.Stack.ListAvailabilityZones(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return zones, xerr
}

func (s Remediator) ListRegions(ctx context.Context) (_ []string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	regions, xerr := s.Stack.ListRegions(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return regions, xerr
}

func (s Remediator) InspectImage(ctx context.Context, id string) (_ *abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	image, xerr := s.Stack.InspectImage(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return image, xerr
}

func (s Remediator) InspectTemplate(ctx context.Context, id string) (_ *abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	template, xerr := s.Stack.InspectTemplate(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return template, xerr
}

func (s Remediator) CreateKeyPair(ctx context.Context, name string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.Stack.CreateKeyPair(ctx, name)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return pair, xerr
}

func (s Remediator) InspectKeyPair(ctx context.Context, id string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.Stack.InspectKeyPair(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return pair, xerr
}

func (s Remediator) ListKeyPairs(ctx context.Context) (_ []*abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.Stack.ListKeyPairs(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return pair, xerr
}

func (s Remediator) DeleteKeyPair(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.DeleteKeyPair(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) ListSecurityGroups(ctx context.Context, networkRef string) (_ []*abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Stack.ListSecurityGroups(ctx, networkRef)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s Remediator) CreateSecurityGroup(ctx context.Context, networkRef, name, description string, rules abstract.SecurityGroupRules) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Stack.CreateSecurityGroup(ctx, networkRef, name, description, rules)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s Remediator) InspectSecurityGroup(ctx context.Context, sgParam SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Stack.InspectSecurityGroup(ctx, sgParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s Remediator) ClearSecurityGroup(ctx context.Context, sgParam SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.Stack.ClearSecurityGroup(ctx, sgParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return groups, xerr
}

func (s Remediator) DeleteSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.DeleteSecurityGroup(ctx, group)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) AddRuleToSecurityGroup(ctx context.Context, sgParam SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.Stack.AddRuleToSecurityGroup(ctx, sgParam, rule)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return group, xerr
}

func (s Remediator) DeleteRuleFromSecurityGroup(ctx context.Context, sgParam SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.Stack.DeleteRuleFromSecurityGroup(ctx, sgParam, rule)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return group, xerr
}

func (s Remediator) GetDefaultSecurityGroupName(ctx context.Context) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.Stack.GetDefaultSecurityGroupName(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return cfg, xerr
}

func (s Remediator) EnableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.EnableSecurityGroup(ctx, group)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) DisableSecurityGroup(ctx context.Context, group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.DisableSecurityGroup(ctx, group)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Stack.CreateNetwork(ctx, req)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) InspectNetwork(ctx context.Context, id string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Stack.InspectNetwork(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) InspectNetworkByName(ctx context.Context, name string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Stack.InspectNetworkByName(ctx, name)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) ListNetworks(ctx context.Context) (_ []*abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Stack.ListNetworks(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) DeleteNetwork(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.DeleteNetwork(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Stack.CreateSubnet(ctx, req)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) InspectSubnet(ctx context.Context, id string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Stack.InspectSubnet(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) InspectSubnetByName(ctx context.Context, networkID, name string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Stack.InspectSubnetByName(ctx, networkID, name)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) ListSubnets(ctx context.Context, networkID string) (_ []*abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Stack.ListSubnets(ctx, networkID)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) DeleteSubnet(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.DeleteSubnet(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) CreateVIP(ctx context.Context, networkID, subnetID, name string, securityGroups []string) (_ *abstract.VirtualIP, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.Stack.CreateVIP(ctx, networkID, subnetID, name, securityGroups)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return network, xerr
}

func (s Remediator) AddPublicIPToVIP(ctx context.Context, ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.AddPublicIPToVIP(ctx, ip)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) BindHostToVIP(ctx context.Context, ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.BindHostToVIP(ctx, ip, s2)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) UnbindHostFromVIP(ctx context.Context, ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.UnbindHostFromVIP(ctx, ip, s2)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) DeleteVIP(ctx context.Context, ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.DeleteVIP(ctx, ip)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) CreateHost(ctx context.Context, request abstract.HostRequest) (_ *abstract.HostFull, _ *userdata.Content, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, content, xerr := s.Stack.CreateHost(ctx, request)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, content, xerr
}

func (s Remediator) ClearHostStartupScript(ctx context.Context, parameter HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.ClearHostStartupScript(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) ChangeSecurityGroupSecurity(ctx context.Context, b bool, b2 bool, net string, _ string) fail.Error {
	xerr := s.Stack.ChangeSecurityGroupSecurity(ctx, b, b2, net, "")
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) InspectHost(ctx context.Context, parameter HostParameter) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Stack.InspectHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s Remediator) GetHostState(ctx context.Context, parameter HostParameter) (_ hoststate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Stack.GetHostState(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s Remediator) ListHosts(ctx context.Context, b bool) (_ abstract.HostList, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Stack.ListHosts(ctx, b)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s Remediator) DeleteHost(ctx context.Context, parameter HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.DeleteHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) StopHost(ctx context.Context, host HostParameter, gracefully bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.StopHost(ctx, host, gracefully)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) StartHost(ctx context.Context, parameter HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.StartHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) RebootHost(ctx context.Context, parameter HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.RebootHost(ctx, parameter)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) ResizeHost(ctx context.Context, parameter HostParameter, requirements abstract.HostSizingRequirements) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Stack.ResizeHost(ctx, parameter, requirements)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s Remediator) WaitHostReady(ctx context.Context, hostParam HostParameter, timeout time.Duration) (_ *abstract.HostCore, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.Stack.WaitHostReady(ctx, hostParam, timeout)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return host, xerr
}

func (s Remediator) BindSecurityGroupToHost(ctx context.Context, sgParam SecurityGroupParameter, hostParam HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.BindSecurityGroupToHost(ctx, sgParam, hostParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) UnbindSecurityGroupFromHost(ctx context.Context, sgParam SecurityGroupParameter, hostParam HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.UnbindSecurityGroupFromHost(ctx, sgParam, hostParam)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Stack.CreateVolume(ctx, request)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s Remediator) InspectVolume(ctx context.Context, id string) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Stack.InspectVolume(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s Remediator) ListVolumes(ctx context.Context) (_ []*abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Stack.ListVolumes(ctx)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s Remediator) DeleteVolume(ctx context.Context, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.DeleteVolume(ctx, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

func (s Remediator) CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Stack.CreateVolumeAttachment(ctx, request)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s Remediator) InspectVolumeAttachment(ctx context.Context, serverID, id string) (_ *abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Stack.InspectVolumeAttachment(ctx, serverID, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s Remediator) ListVolumeAttachments(ctx context.Context, serverID string) (_ []*abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.Stack.ListVolumeAttachments(ctx, serverID)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return volume, xerr
}

func (s Remediator) DeleteVolumeAttachment(ctx context.Context, serverID, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.Stack.DeleteVolumeAttachment(ctx, serverID, id)
	if xerr != nil {
		xerr.WithContext(ctx)
	}
	return xerr
}

// func (s Remediator) Migrate(ctx context.Context, operation string, params map[string]interface{}) (ferr fail.Error) {
// 	defer fail.OnPanic(&ferr)
//
// 	xerr := s.Stack.Migrate(ctx, operation, params)
// 	if xerr != nil {
// 		xerr.WithContext(ctx)
// 	}
// 	return xerr
// }

func (s Remediator) Timings() (_ temporal.Timings, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	return s.Stack.Timings()
}

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
// No default network settings supported by GCP
func (s Remediator) HasDefaultNetwork() (bool, fail.Error) {
	return s.Stack.HasDefaultNetwork()
}

// DefaultNetwork returns the *abstract.Network corresponding to the default network
func (s Remediator) DefaultNetwork(ctx context.Context) (*abstract.Network, fail.Error) {
	return s.Stack.DefaultNetwork(ctx)
}
