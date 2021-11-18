package api

import (
	"time"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

type StackProxy WrappedStack

func (s StackProxy) ListImages(p bool) (_ []abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	images, xerr := s.InnerStack.ListImages(p)
	return images, xerr
}

func (s StackProxy) ListTemplates(p bool) (_ []abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	templates, xerr := s.InnerStack.ListTemplates(p)
	return templates, xerr
}

func (s StackProxy) GetRawConfigurationOptions() (_ stacks.ConfigurationOptions, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.InnerStack.GetRawConfigurationOptions()
	return cfg, xerr
}

func (s StackProxy) GetRawAuthenticationOptions() (_ stacks.AuthenticationOptions, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.InnerStack.GetRawAuthenticationOptions()
	return cfg, xerr
}

func (s StackProxy) GetStackName() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.InnerStack.GetStackName()
	return cfg, xerr
}

func (s StackProxy) ListAvailabilityZones() (_ map[string]bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	zones, xerr := s.InnerStack.ListAvailabilityZones()
	return zones, xerr
}

func (s StackProxy) ListRegions() (_ []string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	regions, xerr := s.InnerStack.ListRegions()
	return regions, xerr
}

func (s StackProxy) InspectImage(id string) (_ abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	image, xerr := s.InnerStack.InspectImage(id)
	return image, xerr
}

func (s StackProxy) InspectTemplate(id string) (_ abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	template, xerr := s.InnerStack.InspectTemplate(id)
	return template, xerr
}

func (s StackProxy) CreateKeyPair(name string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.InnerStack.CreateKeyPair(name)
	return pair, xerr
}

func (s StackProxy) InspectKeyPair(id string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.InnerStack.InspectKeyPair(id)
	return pair, xerr
}

func (s StackProxy) ListKeyPairs() (_ []abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.InnerStack.ListKeyPairs()
	return pair, xerr
}

func (s StackProxy) DeleteKeyPair(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.DeleteKeyPair(id)
	return xerr
}

func (s StackProxy) ListSecurityGroups(networkRef string) (_ []*abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.InnerStack.ListSecurityGroups(networkRef)
	return groups, xerr
}

func (s StackProxy) CreateSecurityGroup(networkRef, name, description string, rules abstract.SecurityGroupRules) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.InnerStack.CreateSecurityGroup(networkRef, name, description, rules)
	return groups, xerr
}

func (s StackProxy) InspectSecurityGroup(sgParam stacks.SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.InnerStack.InspectSecurityGroup(sgParam)
	return groups, xerr
}

func (s StackProxy) ClearSecurityGroup(sgParam stacks.SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.InnerStack.ClearSecurityGroup(sgParam)
	return groups, xerr
}

func (s StackProxy) DeleteSecurityGroup(group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.DeleteSecurityGroup(group)
	return xerr
}

func (s StackProxy) AddRuleToSecurityGroup(sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.InnerStack.AddRuleToSecurityGroup(sgParam, rule)
	return group, xerr
}

func (s StackProxy) DeleteRuleFromSecurityGroup(sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.InnerStack.DeleteRuleFromSecurityGroup(sgParam, rule)
	return group, xerr
}

func (s StackProxy) GetDefaultSecurityGroupName() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.InnerStack.GetDefaultSecurityGroupName()
	return cfg, xerr
}

func (s StackProxy) EnableSecurityGroup(group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.EnableSecurityGroup(group)
	return xerr
}

func (s StackProxy) DisableSecurityGroup(group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.DisableSecurityGroup(group)
	return xerr
}

func (s StackProxy) CreateNetwork(req abstract.NetworkRequest) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerStack.CreateNetwork(req)
	return network, xerr
}

func (s StackProxy) InspectNetwork(id string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerStack.InspectNetwork(id)
	return network, xerr
}

func (s StackProxy) InspectNetworkByName(name string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerStack.InspectNetworkByName(name)
	return network, xerr
}

func (s StackProxy) ListNetworks() (_ []*abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerStack.ListNetworks()
	return network, xerr
}

func (s StackProxy) DeleteNetwork(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.DeleteNetwork(id)
	return xerr
}

func (s StackProxy) HasDefaultNetwork() (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.InnerStack.HasDefaultNetwork()
	return cfg, xerr
}

func (s StackProxy) GetDefaultNetwork() (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerStack.GetDefaultNetwork()
	return network, xerr
}

func (s StackProxy) CreateSubnet(req abstract.SubnetRequest) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerStack.CreateSubnet(req)
	return network, xerr
}

func (s StackProxy) InspectSubnet(id string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerStack.InspectSubnet(id)
	return network, xerr
}

func (s StackProxy) InspectSubnetByName(networkID, name string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerStack.InspectSubnetByName(networkID, name)
	return network, xerr
}

func (s StackProxy) ListSubnets(networkID string) (_ []*abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerStack.ListSubnets(networkID)
	return network, xerr
}

func (s StackProxy) DeleteSubnet(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.DeleteSubnet(id)
	return xerr
}

func (s StackProxy) BindSecurityGroupToSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.BindSecurityGroupToSubnet(sgParam, subnetID)
	return xerr
}

func (s StackProxy) UnbindSecurityGroupFromSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.UnbindSecurityGroupFromSubnet(sgParam, subnetID)
	return xerr
}

func (s StackProxy) CreateVIP(networkID, subnetID, name string, securityGroups []string) (_ *abstract.VirtualIP, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerStack.CreateVIP(networkID, subnetID, name, securityGroups)
	return network, xerr
}

func (s StackProxy) AddPublicIPToVIP(ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.AddPublicIPToVIP(ip)
	return xerr
}

func (s StackProxy) BindHostToVIP(ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.BindHostToVIP(ip, s2)
	return xerr
}

func (s StackProxy) UnbindHostFromVIP(ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.UnbindHostFromVIP(ip, s2)
	return xerr
}

func (s StackProxy) DeleteVIP(ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.DeleteVIP(ip)
	return xerr
}

func (s StackProxy) CreateHost(request abstract.HostRequest) (_ *abstract.HostFull, _ *userdata.Content, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, content, xerr := s.InnerStack.CreateHost(request)
	return host, content, xerr
}

func (s StackProxy) ClearHostStartupScript(parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.ClearHostStartupScript(parameter)
	return xerr
}

func (s StackProxy) InspectHost(parameter stacks.HostParameter) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.InnerStack.InspectHost(parameter)
	return host, xerr
}

func (s StackProxy) GetHostState(parameter stacks.HostParameter) (_ hoststate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.InnerStack.GetHostState(parameter)
	return host, xerr
}

func (s StackProxy) ListHosts(b bool) (_ abstract.HostList, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.InnerStack.ListHosts(b)
	return host, xerr
}

func (s StackProxy) DeleteHost(parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.DeleteHost(parameter)
	return xerr
}

func (s StackProxy) StopHost(host stacks.HostParameter, gracefully bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.StopHost(host, gracefully)
	return xerr
}

func (s StackProxy) StartHost(parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.StartHost(parameter)
	return xerr
}

func (s StackProxy) RebootHost(parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.RebootHost(parameter)
	return xerr
}

func (s StackProxy) ResizeHost(parameter stacks.HostParameter, requirements abstract.HostSizingRequirements) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.InnerStack.ResizeHost(parameter, requirements)
	return host, xerr
}

func (s StackProxy) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (_ *abstract.HostCore, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.InnerStack.WaitHostReady(hostParam, timeout)
	return host, xerr
}

func (s StackProxy) BindSecurityGroupToHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.BindSecurityGroupToHost(sgParam, hostParam)
	return xerr
}

func (s StackProxy) UnbindSecurityGroupFromHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.UnbindSecurityGroupFromHost(sgParam, hostParam)
	return xerr
}

func (s StackProxy) CreateVolume(request abstract.VolumeRequest) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.InnerStack.CreateVolume(request)
	return volume, xerr
}

func (s StackProxy) InspectVolume(id string) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.InnerStack.InspectVolume(id)
	return volume, xerr
}

func (s StackProxy) ListVolumes() (_ []abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.InnerStack.ListVolumes()
	return volume, xerr
}

func (s StackProxy) DeleteVolume(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.DeleteVolume(id)
	return xerr
}

func (s StackProxy) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.InnerStack.CreateVolumeAttachment(request)
	return volume, xerr
}

func (s StackProxy) InspectVolumeAttachment(serverID, id string) (_ *abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.InnerStack.InspectVolumeAttachment(serverID, id)
	return volume, xerr
}

func (s StackProxy) ListVolumeAttachments(serverID string) (_ []abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.InnerStack.ListVolumeAttachments(serverID)
	return volume, xerr
}

func (s StackProxy) DeleteVolumeAttachment(serverID, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.DeleteVolumeAttachment(serverID, id)
	return xerr
}

func (s StackProxy) Migrate(operation string, params map[string]interface{}) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerStack.Migrate(operation, params)
	return xerr
}
