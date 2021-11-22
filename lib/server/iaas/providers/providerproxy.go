package providers

import (
	"regexp"
	"time"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

type ProviderProxy WrappedProvider

func (s ProviderProxy) GetAuthenticationOptions() (_ Config, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	config, xerr := s.InnerProvider.GetAuthenticationOptions()
	return config, xerr
}

func (s ProviderProxy) GetConfigurationOptions() (_ Config, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	config, xerr := s.InnerProvider.GetConfigurationOptions()
	return config, xerr
}

func (s ProviderProxy) GetRawConfigurationOptions() (_ stacks.ConfigurationOptions, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	asta, xerr := s.InnerProvider.GetStack()
	if xerr != nil {
		return stacks.ConfigurationOptions{}, xerr
	}
	return asta.(api.ReservedForProviderUse).GetRawConfigurationOptions()
}

func (s ProviderProxy) GetRawAuthenticationOptions() (_ stacks.AuthenticationOptions, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	asta, xerr := s.InnerProvider.GetStack()
	if xerr != nil {
		return stacks.AuthenticationOptions{}, xerr
	}
	return asta.(api.ReservedForProviderUse).GetRawAuthenticationOptions()
}

func (s ProviderProxy) Build(m map[string]interface{}) (_ Provider, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	build, xerr := s.InnerProvider.Build(m)
	return build, xerr
}

func (s ProviderProxy) GetName() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	name, xerr := s.InnerProvider.GetName()
	if xerr != nil {
		return "", xerr
	}
	return name, nil
}

func (s ProviderProxy) GetStack() (_ api.Stack, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	aStack, xerr := s.InnerProvider.GetStack()
	return aStack, xerr
}

func (s ProviderProxy) GetRegexpsOfTemplatesWithGPU() (_ []*regexp.Regexp, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	regexps, xerr := s.InnerProvider.GetRegexpsOfTemplatesWithGPU()
	return regexps, xerr
}

func (s ProviderProxy) GetCapabilities() (_ Capabilities, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	capabilities, xerr := s.InnerProvider.GetCapabilities()
	return capabilities, xerr
}

func (s ProviderProxy) GetTenantParameters() (_ map[string]interface{}, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	tenantParameters, xerr := s.InnerProvider.GetTenantParameters()
	return tenantParameters, xerr
}

func (s ProviderProxy) ListImages(p bool) (_ []abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	images, xerr := s.InnerProvider.ListImages(p)
	return images, xerr
}

func (s ProviderProxy) ListTemplates(p bool) (_ []abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	templates, xerr := s.InnerProvider.ListTemplates(p)
	return templates, xerr
}

func (s ProviderProxy) GetStackName() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.InnerProvider.GetStackName()
	return cfg, xerr
}

func (s ProviderProxy) ListAvailabilityZones() (_ map[string]bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	zones, xerr := s.InnerProvider.ListAvailabilityZones()
	return zones, xerr
}

func (s ProviderProxy) ListRegions() (_ []string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	regions, xerr := s.InnerProvider.ListRegions()
	return regions, xerr
}

func (s ProviderProxy) InspectImage(id string) (_ abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	image, xerr := s.InnerProvider.InspectImage(id)
	return image, xerr
}

func (s ProviderProxy) InspectTemplate(id string) (_ abstract.HostTemplate, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	template, xerr := s.InnerProvider.InspectTemplate(id)
	return template, xerr
}

func (s ProviderProxy) CreateKeyPair(name string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.InnerProvider.CreateKeyPair(name)
	return pair, xerr
}

func (s ProviderProxy) InspectKeyPair(id string) (_ *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.InnerProvider.InspectKeyPair(id)
	return pair, xerr
}

func (s ProviderProxy) ListKeyPairs() (_ []abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	pair, xerr := s.InnerProvider.ListKeyPairs()
	return pair, xerr
}

func (s ProviderProxy) DeleteKeyPair(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.DeleteKeyPair(id)
	return xerr
}

func (s ProviderProxy) ListSecurityGroups(networkRef string) (_ []*abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.InnerProvider.ListSecurityGroups(networkRef)
	return groups, xerr
}

func (s ProviderProxy) CreateSecurityGroup(networkRef, name, description string, rules abstract.SecurityGroupRules) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.InnerProvider.CreateSecurityGroup(networkRef, name, description, rules)
	return groups, xerr
}

func (s ProviderProxy) InspectSecurityGroup(sgParam stacks.SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.InnerProvider.InspectSecurityGroup(sgParam)
	return groups, xerr
}

func (s ProviderProxy) ClearSecurityGroup(sgParam stacks.SecurityGroupParameter) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	groups, xerr := s.InnerProvider.ClearSecurityGroup(sgParam)
	return groups, xerr
}

func (s ProviderProxy) DeleteSecurityGroup(group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.DeleteSecurityGroup(group)
	return xerr
}

func (s ProviderProxy) AddRuleToSecurityGroup(sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.InnerProvider.AddRuleToSecurityGroup(sgParam, rule)
	return group, xerr
}

func (s ProviderProxy) DeleteRuleFromSecurityGroup(sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (_ *abstract.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	group, xerr := s.InnerProvider.DeleteRuleFromSecurityGroup(sgParam, rule)
	return group, xerr
}

func (s ProviderProxy) GetDefaultSecurityGroupName() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.InnerProvider.GetDefaultSecurityGroupName()
	return cfg, xerr
}

func (s ProviderProxy) EnableSecurityGroup(group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.EnableSecurityGroup(group)
	return xerr
}

func (s ProviderProxy) DisableSecurityGroup(group *abstract.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.DisableSecurityGroup(group)
	return xerr
}

func (s ProviderProxy) CreateNetwork(req abstract.NetworkRequest) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerProvider.CreateNetwork(req)
	return network, xerr
}

func (s ProviderProxy) InspectNetwork(id string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerProvider.InspectNetwork(id)
	return network, xerr
}

func (s ProviderProxy) InspectNetworkByName(name string) (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerProvider.InspectNetworkByName(name)
	return network, xerr
}

func (s ProviderProxy) ListNetworks() (_ []*abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerProvider.ListNetworks()
	return network, xerr
}

func (s ProviderProxy) DeleteNetwork(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.DeleteNetwork(id)
	return xerr
}

func (s ProviderProxy) HasDefaultNetwork() (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	cfg, xerr := s.InnerProvider.HasDefaultNetwork()
	return cfg, xerr
}

func (s ProviderProxy) GetDefaultNetwork() (_ *abstract.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerProvider.GetDefaultNetwork()
	return network, xerr
}

func (s ProviderProxy) CreateSubnet(req abstract.SubnetRequest) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerProvider.CreateSubnet(req)
	return network, xerr
}

func (s ProviderProxy) InspectSubnet(id string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerProvider.InspectSubnet(id)
	return network, xerr
}

func (s ProviderProxy) InspectSubnetByName(networkID, name string) (_ *abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerProvider.InspectSubnetByName(networkID, name)
	return network, xerr
}

func (s ProviderProxy) ListSubnets(networkID string) (_ []*abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerProvider.ListSubnets(networkID)
	return network, xerr
}

func (s ProviderProxy) DeleteSubnet(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.DeleteSubnet(id)
	return xerr
}

func (s ProviderProxy) BindSecurityGroupToSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.BindSecurityGroupToSubnet(sgParam, subnetID)
	return xerr
}

func (s ProviderProxy) UnbindSecurityGroupFromSubnet(sgParam stacks.SecurityGroupParameter, subnetID string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.UnbindSecurityGroupFromSubnet(sgParam, subnetID)
	return xerr
}

func (s ProviderProxy) CreateVIP(networkID, subnetID, name string, securityGroups []string) (_ *abstract.VirtualIP, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	network, xerr := s.InnerProvider.CreateVIP(networkID, subnetID, name, securityGroups)
	return network, xerr
}

func (s ProviderProxy) AddPublicIPToVIP(ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.AddPublicIPToVIP(ip)
	return xerr
}

func (s ProviderProxy) BindHostToVIP(ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.BindHostToVIP(ip, s2)
	return xerr
}

func (s ProviderProxy) UnbindHostFromVIP(ip *abstract.VirtualIP, s2 string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.UnbindHostFromVIP(ip, s2)
	return xerr
}

func (s ProviderProxy) DeleteVIP(ip *abstract.VirtualIP) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.DeleteVIP(ip)
	return xerr
}

func (s ProviderProxy) CreateHost(request abstract.HostRequest) (_ *abstract.HostFull, _ *userdata.Content, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, content, xerr := s.InnerProvider.CreateHost(request)
	return host, content, xerr
}

func (s ProviderProxy) ClearHostStartupScript(parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.ClearHostStartupScript(parameter)
	return xerr
}

func (s ProviderProxy) InspectHost(parameter stacks.HostParameter) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.InnerProvider.InspectHost(parameter)
	return host, xerr
}

func (s ProviderProxy) GetHostState(parameter stacks.HostParameter) (_ hoststate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.InnerProvider.GetHostState(parameter)
	return host, xerr
}

func (s ProviderProxy) ListHosts(b bool) (_ abstract.HostList, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.InnerProvider.ListHosts(b)
	return host, xerr
}

func (s ProviderProxy) DeleteHost(parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.DeleteHost(parameter)
	return xerr
}

func (s ProviderProxy) StopHost(host stacks.HostParameter, gracefully bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.StopHost(host, gracefully)
	return xerr
}

func (s ProviderProxy) StartHost(parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.StartHost(parameter)
	return xerr
}

func (s ProviderProxy) RebootHost(parameter stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.RebootHost(parameter)
	return xerr
}

func (s ProviderProxy) ResizeHost(parameter stacks.HostParameter, requirements abstract.HostSizingRequirements) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.InnerProvider.ResizeHost(parameter, requirements)
	return host, xerr
}

func (s ProviderProxy) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (_ *abstract.HostCore, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	host, xerr := s.InnerProvider.WaitHostReady(hostParam, timeout)
	return host, xerr
}

func (s ProviderProxy) BindSecurityGroupToHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.BindSecurityGroupToHost(sgParam, hostParam)
	return xerr
}

func (s ProviderProxy) UnbindSecurityGroupFromHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.UnbindSecurityGroupFromHost(sgParam, hostParam)
	return xerr
}

func (s ProviderProxy) CreateVolume(request abstract.VolumeRequest) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.InnerProvider.CreateVolume(request)
	return volume, xerr
}

func (s ProviderProxy) InspectVolume(id string) (_ *abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.InnerProvider.InspectVolume(id)
	return volume, xerr
}

func (s ProviderProxy) ListVolumes() (_ []abstract.Volume, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.InnerProvider.ListVolumes()
	return volume, xerr
}

func (s ProviderProxy) DeleteVolume(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.DeleteVolume(id)
	return xerr
}

func (s ProviderProxy) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.InnerProvider.CreateVolumeAttachment(request)
	return volume, xerr
}

func (s ProviderProxy) InspectVolumeAttachment(serverID, id string) (_ *abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.InnerProvider.InspectVolumeAttachment(serverID, id)
	return volume, xerr
}

func (s ProviderProxy) ListVolumeAttachments(serverID string) (_ []abstract.VolumeAttachment, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	volume, xerr := s.InnerProvider.ListVolumeAttachments(serverID)
	return volume, xerr
}

func (s ProviderProxy) DeleteVolumeAttachment(serverID, id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.DeleteVolumeAttachment(serverID, id)
	return xerr
}

func (s ProviderProxy) Migrate(operation string, params map[string]interface{}) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := s.InnerProvider.Migrate(operation, params)
	return xerr
}
