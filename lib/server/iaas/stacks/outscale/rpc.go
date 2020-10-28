/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package outscale

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
	"github.com/antihax/optional"

	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

func (s stack) rpcReadSecurityGroups(networkID string, sgIDs []string) ([]osc.SecurityGroup, fail.Error) {
	var filters osc.FiltersSecurityGroup
	if len(sgIDs) > 0 {
		filters.SecurityGroupIds = sgIDs
	}
	request := osc.ReadSecurityGroupsOpts{
		ReadSecurityGroupsRequest: optional.NewInterface(osc.ReadSecurityGroupsRequest{
			Filters: filters,
		}),
	}
	var resp osc.ReadSecurityGroupsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			resp, _, innerErr = s.client.SecurityGroupApi.ReadSecurityGroups(s.auth, &request)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.SecurityGroup{}, xerr
	}
	if len(resp.SecurityGroups) == 0 {
		return []osc.SecurityGroup{}, fail.NotFoundError("failed to find Security Groups")
	}

	var out []osc.SecurityGroup
	if networkID != "" {
		for _, sg := range resp.SecurityGroups {
			if sg.NetId == networkID {
				out = append(out, sg)
			}
		}
	} else {
		out = resp.SecurityGroups
	}
	return out, nil
}

func (s stack) rpcReadSecurityGroupByID(id string) (osc.SecurityGroup, fail.Error) {
	if id == "" {
		return osc.SecurityGroup{}, fail.InvalidParameterError("id", "cannot be empty string")
	}

	groups, xerr := s.rpcReadSecurityGroups("", []string{id})
	if xerr != nil {
		return osc.SecurityGroup{}, xerr
	}
	if len(groups) > 1 {
		return osc.SecurityGroup{}, fail.InconsistentError("found more than one Security Group with ID %s", id)
	}

	return groups[0], nil
}

func (s stack) rpcReadSecurityGroupByName(networkID, name string) (osc.SecurityGroup, fail.Error) {
	if networkID == "" {
		return osc.SecurityGroup{}, fail.InvalidParameterError("networkID", "cannot be empty string")
	}
	if name == "" {
		return osc.SecurityGroup{}, fail.InvalidParameterError("name", "cannot be empty string")
	}

	request := osc.ReadSecurityGroupsOpts{
		ReadSecurityGroupsRequest: optional.NewInterface(osc.ReadSecurityGroupsRequest{
			Filters: osc.FiltersSecurityGroup{
				SecurityGroupNames: []string{name},
			},
		}),
	}
	var resp osc.ReadSecurityGroupsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			resp, _, innerErr = s.client.SecurityGroupApi.ReadSecurityGroups(s.auth, &request)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.SecurityGroup{}, xerr
	}

	for _, sg := range resp.SecurityGroups {
		if sg.NetId == networkID {
			return sg, nil
		}
	}
	return osc.SecurityGroup{}, fail.NotFoundError("failed to find a Security Group named '%s' in Network %s", name, networkID)
}

func (s stack) rpcDeleteSecurityGroupRules(id string, direction securitygroupruledirection.Enum, rules []osc.SecurityGroupRule) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}
	if len(rules) == 0 {
		return nil
	}

	var flow string
	switch direction {
	case securitygroupruledirection.INGRESS:
		flow = "Inbound"
	case securitygroupruledirection.EGRESS:
		flow = "Outbound"
	default:
		return fail.InvalidParameterError("direction", "invalid value '%d'", direction)
	}

	query := osc.DeleteSecurityGroupRuleOpts{
		DeleteSecurityGroupRuleRequest: optional.NewInterface(osc.DeleteSecurityGroupRuleRequest{
			SecurityGroupId: id,
			Flow:            flow,
			Rules:           rules,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, innerErr := s.client.SecurityGroupRuleApi.DeleteSecurityGroupRule(s.auth, &query)
			return innerErr
		},
		normalizeError,
	)
}

// rpcReadVms gets VM information from provider
func (s stack) rpcReadVms(vmIDs []string) ([]osc.Vm, fail.Error) {
	query := osc.ReadVmsOpts{}
	if len(vmIDs) > 0 {
		query.ReadVmsRequest = optional.NewInterface(osc.ReadVmsRequest{
			Filters: osc.FiltersVm{
				VmIds: vmIDs,
			},
		})
	}
	var resp osc.ReadVmsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			resp, _, innerErr = s.client.VmApi.ReadVms(s.auth, &query)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.Vm{}, xerr
	}
	if len(resp.Vms) == 0 {
		return nil, fail.NotFoundError("failed to find Hosts")
	}
	return resp.Vms, nil
}

// rpcReadVmByID gets VM information from provider
func (s stack) rpcReadVmByID(vmID string) (osc.Vm, fail.Error) {
	vms, xerr := s.rpcReadVms([]string{vmID})
	if xerr != nil {
		return osc.Vm{}, xerr
	}
	if len(vms) > 1 {
		return osc.Vm{}, fail.InconsistentError("found more than 1 Host with ID %s", vmID)
	}
	return vms[0], nil
}

func (s stack) rpcReadVmByName(name string) (osc.Vm, fail.Error) {
	request := osc.ReadVmsOpts{
		ReadVmsRequest: optional.NewInterface(osc.ReadVmsRequest{
			Filters: osc.FiltersVm{
				Tags: []string{"name=" + name},
			},
		}),
	}
	var resp osc.ReadVmsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			resp, _, innerErr = s.client.VmApi.ReadVms(s.auth, &request)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.Vm{}, xerr
	}
	if len(resp.Vms) == 0 {
		return osc.Vm{}, fail.NotFoundError("failed to find Host")
	}
	if len(resp.Vms) > 1 {
		return osc.Vm{}, fail.InconsistentError("found more than 1 Host named '%s'", name)
	}
	vm := resp.Vms[0]
	if vm.State == "terminated" {
		return osc.Vm{}, fail.NotFoundError("failed to find a Host named '%s'", name)
	}
	return vm, nil
}

// rpcDeleteHosts ...
func (s stack) rpcDeleteHosts(vmIDs []string) fail.Error {
	request := osc.DeleteVmsOpts{
		DeleteVmsRequest: optional.NewInterface(osc.DeleteVmsRequest{
			VmIds: vmIDs,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, innerErr := s.client.VmApi.DeleteVms(s.auth, &request)
			return innerErr
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteNetwork(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	request := osc.DeleteNetOpts{
		DeleteNetRequest: optional.NewInterface(osc.DeleteNetRequest{
			NetId: id,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, innerErr := s.client.NetApi.DeleteNet(s.auth, &request)
			return innerErr
		},
		normalizeError,
	)
}

func (s stack) rpcCreateTags(id string, tags map[string]string) ([]osc.ResourceTag, fail.Error) {
	var tagList []osc.ResourceTag
	for k, v := range tags {
		tagList = append(tagList, osc.ResourceTag{
			Key:   k,
			Value: v,
		})
	}
	request := osc.CreateTagsOpts{
		CreateTagsRequest: optional.NewInterface(osc.CreateTagsRequest{
			ResourceIds: []string{id},
			Tags:        tagList,
		}),
	}
	xerr := stacks.RetryableRemoteCall(
		func() error {
			_, _, innerErr := s.client.TagApi.CreateTags(s.auth, &request)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.ResourceTag{}, xerr
	}
	return tagList, nil
}

func (s stack) rpcDeleteSubnet(id string) fail.Error {
	request := osc.CreateSubnetOpts{
		CreateSubnetRequest: optional.NewInterface(osc.DeleteSubnetRequest{
			SubnetId: id,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, innerErr := s.client.SubnetApi.CreateSubnet(s.auth, &request)
			return innerErr
		},
		normalizeError,
	)
}

func (s stack) rpcCreateSubnet(name, vpcID, CIDR string) (osc.CreateSubnetResponse, fail.Error) {
	createRequest := osc.CreateSubnetOpts{
		CreateSubnetRequest: optional.NewInterface(osc.CreateSubnetRequest{
			IpRange:       CIDR,
			NetId:         vpcID,
			SubregionName: s.Options.Compute.Subregion,
		}),
	}
	var resp osc.CreateSubnetResponse
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			resp, _, innerErr = s.client.SubnetApi.CreateSubnet(s.auth, &createRequest)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.CreateSubnetResponse{}, xerr
	}

	defer func() {
		if xerr != nil {
			if derr := s.rpcDeleteSubnet(resp.Subnet.SubnetId); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Subnet '%s'", name))
			}
		}
	}()

	updateRequest := osc.UpdateSubnetOpts{
		UpdateSubnetRequest: optional.NewInterface(osc.UpdateSubnetRequest{
			MapPublicIpOnLaunch: false,
			SubnetId:            resp.Subnet.SubnetId,
		}),
	}
	xerr = stacks.RetryableRemoteCall(
		func() error {
			_, _, innerErr := s.client.SubnetApi.UpdateSubnet(s.auth, &updateRequest)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.CreateSubnetResponse{}, xerr
	}

	_, xerr = s.rpcCreateTags(resp.Subnet.SubnetId, map[string]string{
		"name": name,
	})
	if xerr != nil {
		return osc.CreateSubnetResponse{}, xerr
	}

	return resp, nil
}

func (s stack) rpcReadSubnets(networkID string, ids []string) ([]osc.Subnet, fail.Error) {
	var filters osc.FiltersSubnet
	if len(ids) > 0 {
		filters.SubnetIds = ids
	}
	if networkID != "" {
		filters.NetIds = []string{networkID}
	}

	request := osc.ReadSubnetsOpts{
		ReadSubnetsRequest: optional.NewInterface(osc.ReadSubnetsRequest{
			Filters: filters,
		}),
	}
	var resp osc.ReadSubnetsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			resp, _, innerErr = s.client.SubnetApi.ReadSubnets(s.auth, &request)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.Subnet{}, xerr
	}
	if len(ids) > 0 && len(resp.Subnets) == 0 {
		return resp.Subnets, fail.NotFoundError("failed to find Subnets")
	}
	return resp.Subnets, nil
}

func (s stack) rpcReadSubnetByID(id string) (osc.Subnet, fail.Error) {
	subnets, xerr := s.rpcReadSubnets("", []string{id})
	if xerr != nil {
		return osc.Subnet{}, xerr
	}
	if len(subnets) > 1 {
		return osc.Subnet{}, fail.InconsistentError("more than 1 Subnet with ID %s found", id)
	}
	return subnets[0], nil
}

func (s stack) rpcReadTags(id string) (map[string]string, fail.Error) {
	tags := make(map[string]string)
	request := osc.ReadTagsOpts{
		ReadTagsRequest: optional.NewInterface(osc.ReadTagsRequest{
			Filters: osc.FiltersTag{ResourceIds: []string{id}},
		}),
	}
	var resp osc.ReadTagsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (innerErr error) {
			resp, _, innerErr = s.client.TagApi.ReadTags(s.auth, &request)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return tags, xerr
	}
	for _, tag := range resp.Tags {
		tags[tag.Key] = tag.Value
	}
	return tags, nil
}

func (s stack) rpcReadNics(subnetID, hostID string) ([]osc.Nic, fail.Error) {
	var filters osc.FiltersNic
	if subnetID != "" {
		filters.SubnetIds = []string{subnetID}
	}
	if hostID != "" {
		filters.LinkNicVmIds = []string{hostID}
	}
	request := osc.ReadNicsOpts{
		ReadNicsRequest: optional.NewInterface(osc.ReadNicsRequest{
			Filters: filters,
		}),
	}
	var resp osc.ReadNicsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, _, err = s.client.NicApi.ReadNics(s.auth, &request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.Nic{}, xerr
	}
	return resp.Nics, nil
}

func (s stack) rpcCreateSecurityGroupRule(id string, flow string, rules []osc.SecurityGroupRule) fail.Error {
	request := osc.CreateSecurityGroupRuleOpts{
		CreateSecurityGroupRuleRequest: optional.NewInterface(osc.CreateSecurityGroupRuleRequest{
			SecurityGroupId: id,
			Rules:           rules,
			Flow:            flow,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, innerErr := s.client.SecurityGroupRuleApi.CreateSecurityGroupRule(s.auth, &request)
			return innerErr
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteNic(nic osc.Nic) fail.Error {
	request := osc.DeleteNicOpts{
		DeleteNicRequest: optional.NewInterface(osc.DeleteNicRequest{
			NicId: nic.NicId,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, err := s.client.NicApi.DeleteNic(s.auth, &request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcCreateNic(subnetID, description string) (osc.Nic, fail.Error) {
	request := osc.CreateNicOpts{
		CreateNicRequest: optional.NewInterface(osc.CreateNicRequest{
			Description: description,
			SubnetId:    subnetID,
		}),
	}
	var resp osc.CreateNicResponse
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (err error) {
			resp, _, err = s.client.NicApi.CreateNic(s.auth, &request)
			return err
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return osc.Nic{}, xerr
	}
	return resp.Nic, nil
}

func (s stack) rpcCreateNetwork(name, cidr string) (osc.Net, fail.Error) {
	if cidr == "" {
		return osc.Net{}, fail.InvalidParameterError("cidr", "cannot be empty string")
	}

	request := osc.CreateNetOpts{
		CreateNetRequest: optional.NewInterface(osc.CreateNetRequest{
			IpRange: cidr,
			Tenancy: s.Options.Compute.DefaultTenancy,
		}),
	}
	var resp osc.CreateNetResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, _, err = s.client.NetApi.CreateNet(s.auth, &request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.Net{}, xerr
	}

	defer func() {
		if xerr != nil {
			if derr := s.rpcDeleteNetwork(resp.Net.NetId); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Network '%s'", name))
			}
		}
	}()

	tags, xerr := s.rpcCreateTags(resp.Net.NetId, map[string]string{
		tagNameLabel: name,
	})
	if xerr != nil {
		return osc.Net{}, xerr
	}
	resp.Net.Tags = tags

	return resp.Net, nil
}

func (s stack) rpcUpdateNet(networkID, dhcpOptionsSetID string) fail.Error {
	request := osc.UpdateNetOpts{
		UpdateNetRequest: optional.NewInterface(osc.UpdateNetRequest{
			NetId:            networkID,
			DhcpOptionsSetId: dhcpOptionsSetID,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, err := s.client.NetApi.UpdateNet(s.auth, &request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcCreateDhcpOptions(name string, dnsServers, ntpServers []string) (osc.DhcpOptionsSet, fail.Error) {
	request := osc.CreateDhcpOptionsOpts{
		CreateDhcpOptionsRequest: optional.NewInterface(osc.CreateDhcpOptionsRequest{
			NtpServers:        ntpServers,
			DomainNameServers: dnsServers,
		}),
	}
	var resp osc.CreateDhcpOptionsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, _, err = s.client.DhcpOptionApi.CreateDhcpOptions(s.auth, &request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.DhcpOptionsSet{}, xerr
	}

	_, xerr = s.rpcCreateTags(resp.DhcpOptionsSet.DhcpOptionsSetId, map[string]string{
		"name": name,
	})
	if xerr != nil {
		return osc.DhcpOptionsSet{}, xerr
	}

	return resp.DhcpOptionsSet, nil
}

func (s stack) rpcReadDhcpOptions(id string) ([]osc.DhcpOptionsSet, fail.Error) {
	if id == "" {
		return []osc.DhcpOptionsSet{}, fail.InvalidParameterError("id", "cannot be empty string")
	}

	request := osc.ReadDhcpOptionsOpts{
		ReadDhcpOptionsRequest: optional.NewInterface(osc.ReadDhcpOptionsRequest{
			Filters: osc.FiltersDhcpOptions{
				DhcpOptionsSetIds: []string{id},
			},
		}),
	}
	var resp osc.ReadDhcpOptionsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, _, err = s.client.DhcpOptionApi.ReadDhcpOptions(s.auth, &request)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.DhcpOptionsSet{}, xerr
	}
	return resp.DhcpOptionsSets, nil
}

func (s stack) rpcDeleteDhcpOptions(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	request := osc.DeleteDhcpOptionsOpts{
		DeleteDhcpOptionsRequest: optional.NewInterface(osc.DeleteDhcpOptionsRequest{
			DhcpOptionsSetId: id,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, err := s.client.DhcpOptionApi.DeleteDhcpOptions(s.auth, &request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcLinkNic(vmID, nicID string, order int32) fail.Error {
	if vmID == "" {
		return fail.InvalidParameterError("vmID", "cannot be empty string")
	}
	if nicID == "" {
		return fail.InvalidParameterError("nicID", "cannot be empty string")
	}

	request := osc.LinkNicOpts{
		LinkNicRequest: optional.NewInterface(osc.LinkNicRequest{
			VmId:         vmID,
			NicId:        nicID,
			DeviceNumber: order,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, err := s.client.NicApi.LinkNic(s.auth, &request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteFlexibleGpu(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	request := osc.DeleteFlexibleGpuOpts{
		DeleteFlexibleGpuRequest: optional.NewInterface(osc.DeleteFlexibleGpuRequest{
			FlexibleGpuId: id,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, err := s.client.FlexibleGpuApi.DeleteFlexibleGpu(s.auth, &request)
			return err
		},
		normalizeError,
	)

}
func (s stack) rpcLinkFlexibleGpu(gpuID, vmID string) fail.Error {
	request := osc.LinkFlexibleGpuOpts{
		LinkFlexibleGpuRequest: optional.NewInterface(osc.LinkFlexibleGpuRequest{
			VmId:          vmID,
			FlexibleGpuId: gpuID,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, _, err := s.client.FlexibleGpuApi.LinkFlexibleGpu(s.auth, &request)
			return err
		},
		normalizeError,
	)
}

func (s stack) rpcCreateFlexibleGpu(model string) (osc.FlexibleGpu, fail.Error) {
	createFlexibleGpuOpts := osc.CreateFlexibleGpuOpts{
		CreateFlexibleGpuRequest: optional.NewInterface(osc.CreateFlexibleGpuRequest{
			DeleteOnVmDeletion: true,
			Generation:         "",
			ModelName:          model,
			SubregionName:      s.Options.Compute.Subregion,
		}),
	}
	var resp osc.CreateFlexibleGpuResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, _, err = s.client.FlexibleGpuApi.CreateFlexibleGpu(s.auth, &createFlexibleGpuOpts)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.FlexibleGpu{}, xerr
	}
	return resp.FlexibleGpu, nil
}
