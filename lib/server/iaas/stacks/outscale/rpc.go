/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/antihax/optional"
	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

func (s stack) rpcReadSecurityGroups(networkID string, sgIDs []string) ([]osc.SecurityGroup, fail.Error) {
	var filters osc.FiltersSecurityGroup
	if len(sgIDs) > 0 {
		filters.SecurityGroupIds = sgIDs
	}
	opts := osc.ReadSecurityGroupsOpts{
		ReadSecurityGroupsRequest: optional.NewInterface(osc.ReadSecurityGroupsRequest{
			Filters: filters,
		}),
	}
	var resp osc.ReadSecurityGroupsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			dr, hr, innerErr := s.client.SecurityGroupApi.ReadSecurityGroups(s.auth, &opts)
			if innerErr != nil {
				return newOutscaleError(hr, innerErr)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.SecurityGroup{}, xerr
	}
	if len(resp.SecurityGroups) == 0 {
		if len(sgIDs) > 0 {
			return []osc.SecurityGroup{}, fail.NotFoundError("failed to find Security Groups")
		}
		return []osc.SecurityGroup{}, nil
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

	opts := osc.ReadSecurityGroupsOpts{
		ReadSecurityGroupsRequest: optional.NewInterface(osc.ReadSecurityGroupsRequest{
			Filters: osc.FiltersSecurityGroup{
				SecurityGroupNames: []string{name},
			},
		}),
	}
	var resp osc.ReadSecurityGroupsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			dr, hr, innerErr := s.client.SecurityGroupApi.ReadSecurityGroups(s.auth, &opts)
			if innerErr != nil {
				return newOutscaleError(hr, innerErr)
			}
			resp = dr
			return nil
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

// rpcReadVMs gets VM information from provider
func (s stack) rpcReadVMs(vmIDs []string) ([]osc.Vm, fail.Error) {
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
		func() (err error) {
			dr, hr, innerErr := s.client.VmApi.ReadVms(s.auth, &query)
			if innerErr != nil {
				return newOutscaleError(hr, innerErr)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.Vm{}, xerr
	}
	if len(resp.Vms) == 0 {
		if len(vmIDs) > 0 {
			return []osc.Vm{}, fail.NotFoundError("failed to Vms")
		}
		return []osc.Vm{}, nil
	}
	return resp.Vms, nil
}

// rpcReadVMByID gets VM information from provider
func (s stack) rpcReadVMByID(id string) (osc.Vm, fail.Error) {
	if id == "" {
		return osc.Vm{}, fail.InvalidParameterError("id", "cannot be empty string")
	}

	vms, xerr := s.rpcReadVMs([]string{id})
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return osc.Vm{}, fail.NotFoundError("failed to read Vm with ID %s", id)
		default:
			return osc.Vm{}, xerr
		}
	}

	vm, xerr := localizeInstance(vms)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return osc.Vm{}, fail.NotFoundError("failed to read Vm with ID %s", id)
		case *fail.ErrInconsistent:
			return osc.Vm{}, fail.InconsistentError("found more than one Host with ID %s", id)
		default:
			return osc.Vm{}, xerr
		}
	}
	return vm, nil
}

func localizeInstance(instances []osc.Vm) (osc.Vm, fail.Error) {
	var instance osc.Vm
	found := false
	if len(instances) > 0 {
		for _, v := range instances {
			if v.State != "terminated" {
				if found {
					return osc.Vm{}, fail.InconsistentError("found more than one Host")
				}
				instance = v
				found = true
			}
		}
	}
	if !found {
		return osc.Vm{}, fail.NotFoundError("failed to find Host")
	}
	return instance, nil
}

func (s stack) rpcReadVMByName(name string) (osc.Vm, fail.Error) {
	if name == "" {
		return osc.Vm{}, fail.InvalidParameterError("name", "cannot be empty string")
	}

	opts := osc.ReadVmsOpts{
		ReadVmsRequest: optional.NewInterface(osc.ReadVmsRequest{
			Filters: osc.FiltersVm{
				Tags: []string{"name=" + name},
			},
		}),
	}
	var resp osc.ReadVmsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			dr, hr, innerErr := s.client.VmApi.ReadVms(s.auth, &opts)
			if innerErr != nil {
				return newOutscaleError(hr, innerErr)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return osc.Vm{}, fail.NotFoundError("failed to find Host named '%s'", name)
		default:
			return osc.Vm{}, xerr
		}
	}
	if len(resp.Vms) == 0 {
		return osc.Vm{}, fail.NotFoundError("failed to find Host")
	}

	vm, xerr := localizeInstance(resp.Vms)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return osc.Vm{}, fail.NotFoundError("failed to find Host named '%s'", name)
		case *fail.ErrInconsistent:
			return osc.Vm{}, fail.InconsistentError("found more than one Host named '%s'", name)
		}
	}
	return vm, nil
}

// rpcDeleteVms ...
func (s stack) rpcDeleteVms(vmIDs []string) fail.Error {
	opts := osc.DeleteVmsOpts{
		DeleteVmsRequest: optional.NewInterface(osc.DeleteVmsRequest{
			VmIds: vmIDs,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, innerErr := s.client.VmApi.DeleteVms(s.auth, &opts)
			if innerErr != nil {
				return newOutscaleError(hr, innerErr)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcCreateNetwork(name, cidr string) (osc.Net, fail.Error) {
	if cidr == "" {
		return osc.Net{}, fail.InvalidParameterError("cidr", "cannot be empty string")
	}

	opts := osc.CreateNetOpts{
		CreateNetRequest: optional.NewInterface(osc.CreateNetRequest{
			IpRange: cidr,
			Tenancy: s.Options.Compute.DefaultTenancy,
		}),
	}
	var resp osc.CreateNetResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			dr, hr, innerXerr := s.client.NetApi.CreateNet(s.auth, &opts)
			if innerXerr != nil {
				return newOutscaleError(hr, innerXerr)
			}
			resp = dr
			return nil
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
	opts := osc.UpdateNetOpts{
		UpdateNetRequest: optional.NewInterface(osc.UpdateNetRequest{
			NetId:            networkID,
			DhcpOptionsSetId: dhcpOptionsSetID,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.NetApi.UpdateNet(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteNetwork(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	opts := osc.DeleteNetOpts{
		DeleteNetRequest: optional.NewInterface(osc.DeleteNetRequest{
			NetId: id,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, innerErr := s.client.NetApi.DeleteNet(s.auth, &opts)
			if innerErr != nil {
				return newOutscaleError(hr, innerErr)
			}
			return nil
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
	opts := osc.CreateTagsOpts{
		CreateTagsRequest: optional.NewInterface(osc.CreateTagsRequest{
			ResourceIds: []string{id},
			Tags:        tagList,
		}),
	}
	xerr := stacks.RetryableRemoteCall(
		func() error {
			_, hr, innerErr := s.client.TagApi.CreateTags(s.auth, &opts)
			if innerErr != nil {
				return newOutscaleError(hr, innerErr)
			}
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.ResourceTag{}, xerr
	}
	return tagList, nil
}

func (s stack) rpcDeleteSubnet(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	opts := osc.DeleteSubnetOpts{
		DeleteSubnetRequest: optional.NewInterface(osc.DeleteSubnetRequest{
			SubnetId: id,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.SubnetApi.DeleteSubnet(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcCreateSubnet(name, vpcID, cidr string) (osc.Subnet, fail.Error) {
	if name == "" {
		return osc.Subnet{}, fail.InvalidParameterError("name", "cannot be empty string")
	}
	if vpcID == "" {
		return osc.Subnet{}, fail.InvalidParameterError("vpcID", "cannot be empty string")
	}
	if cidr == "" {
		return osc.Subnet{}, fail.InvalidParameterError("cidr", "cannot be empty string")
	}

	createRequest := osc.CreateSubnetOpts{
		CreateSubnetRequest: optional.NewInterface(osc.CreateSubnetRequest{
			IpRange:       cidr,
			NetId:         vpcID,
			SubregionName: s.Options.Compute.Subregion,
		}),
	}
	var resp osc.CreateSubnetResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			dr, hr, innerXerr := s.client.SubnetApi.CreateSubnet(s.auth, &createRequest)
			if innerXerr != nil {
				return newOutscaleError(hr, innerXerr)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.Subnet{}, xerr
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
			_, hr, err := s.client.SubnetApi.UpdateSubnet(s.auth, &updateRequest)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.Subnet{}, xerr
	}

	_, xerr = s.rpcCreateTags(resp.Subnet.SubnetId, map[string]string{
		"name": name,
	})
	if xerr != nil {
		return osc.Subnet{}, xerr
	}

	return resp.Subnet, nil
}

func (s stack) rpcReadSubnets(networkID string, ids []string) ([]osc.Subnet, fail.Error) {
	var filters osc.FiltersSubnet
	if len(ids) > 0 {
		filters.SubnetIds = ids
	}
	if networkID != "" {
		filters.NetIds = []string{networkID}
	}

	opts := osc.ReadSubnetsOpts{
		ReadSubnetsRequest: optional.NewInterface(osc.ReadSubnetsRequest{
			Filters: filters,
		}),
	}
	var resp osc.ReadSubnetsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			dr, hr, innerXerr := s.client.SubnetApi.ReadSubnets(s.auth, &opts)
			if innerXerr != nil {
				return newOutscaleError(hr, innerXerr)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.Subnet{}, xerr
	}
	if len(resp.Subnets) == 0 {
		if len(ids) > 0 {
			return []osc.Subnet{}, fail.NotFoundError("failed to find Subnets")
		}
		return []osc.Subnet{}, nil
	}
	return resp.Subnets, nil
}

func (s stack) rpcReadSubnetByID(id string) (osc.Subnet, fail.Error) {
	if id == "" {
		return osc.Subnet{}, fail.InvalidParameterError("id", "cannot be empty string")
	}

	subnets, xerr := s.rpcReadSubnets("", []string{id})
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return osc.Subnet{}, fail.NotFoundError("failed to find a Subnet with ID %s", id)
		default:
			return osc.Subnet{}, xerr
		}
	}
	if len(subnets) > 1 {
		return osc.Subnet{}, fail.InconsistentError("more than 1 Subnet with ID %s found", id)
	}
	if len(subnets) == 0 {
		return osc.Subnet{}, fail.NotFoundError("failed to find Subnet %s", id)
	}
	return subnets[0], nil
}

func (s stack) rpcReadTagsOfResource(resourceID string) (map[string]string, fail.Error) {
	if resourceID == "" {
		return map[string]string{}, fail.InvalidParameterError("resourceID", "cannot be empty string")
	}

	tags := make(map[string]string)
	opts := osc.ReadTagsOpts{
		ReadTagsRequest: optional.NewInterface(osc.ReadTagsRequest{
			Filters: osc.FiltersTag{ResourceIds: []string{resourceID}},
		}),
	}
	var resp osc.ReadTagsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			dr, hr, innerXerr := s.client.TagApi.ReadTags(s.auth, &opts)
			if innerXerr != nil {
				return newOutscaleError(hr, innerXerr)
			}
			resp = dr
			return nil
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
	opts := osc.ReadNicsOpts{
		ReadNicsRequest: optional.NewInterface(osc.ReadNicsRequest{
			Filters: filters,
		}),
	}
	var resp osc.ReadNicsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			dr, hr, innerXerr := s.client.NicApi.ReadNics(s.auth, &opts)
			if innerXerr != nil {
				return newOutscaleError(hr, innerXerr)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.Nic{}, xerr
	}
	if len(resp.Nics) == 0 {
		if subnetID != "" && hostID != "" {
			return []osc.Nic{}, fail.NotFoundError("failed to read Nics on Subnet with ID %s of Host with ID %s", subnetID, hostID)
		}
		if subnetID != "" {
			return []osc.Nic{}, fail.NotFoundError("failed to read Nics on Subnet with ID %s", subnetID)
		}
		if hostID != "" {
			return []osc.Nic{}, fail.NotFoundError("failed to read Nics of Host with ID %s", hostID)
		}
		return []osc.Nic{}, nil
	}
	return resp.Nics, nil
}

func (s stack) rpcCreateNic(subnetID, name, description string, sgs []string) (osc.Nic, fail.Error) {
	if subnetID == "" {
		return osc.Nic{}, fail.InvalidParameterError("subnetID", "cannot be empty string")
	}
	if name == "" {
		return osc.Nic{}, fail.InvalidParameterError("name", "cannot be empty string")
	}

	request := osc.CreateNicRequest{
		Description: description,
		SubnetId:    subnetID,
	}
	if len(sgs) > 0 {
		request.SecurityGroupIds = sgs
	}
	opts := osc.CreateNicOpts{
		CreateNicRequest: optional.NewInterface(request),
	}

	var resp osc.CreateNicResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			dr, hr, innerXerr := s.client.NicApi.CreateNic(s.auth, &opts)
			if innerXerr != nil {
				return newOutscaleError(hr, innerXerr)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.Nic{}, xerr
	}

	defer func() {
		if xerr != nil {
			if derr := s.rpcDeleteNic(resp.Nic.NicId); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Nic '%s'", name))
			}
		}
	}()

	tags, xerr := s.rpcCreateTags(resp.Nic.NicId, map[string]string{
		tagNameLabel: name,
	})
	if xerr != nil {
		return osc.Nic{}, xerr
	}

	resp.Nic.Tags = tags
	return resp.Nic, nil
}

func (s stack) rpcDeleteNic(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	opts := osc.DeleteNicOpts{
		DeleteNicRequest: optional.NewInterface(osc.DeleteNicRequest{
			NicId: id,
		}),
	}
	xerr := stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.NicApi.DeleteNic(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}
	return nil
}

func (s stack) rpcLinkNic(vmID, nicID string, order int32) fail.Error {
	if vmID == "" {
		return fail.InvalidParameterError("vmID", "cannot be empty string")
	}
	if nicID == "" {
		return fail.InvalidParameterError("nicID", "cannot be empty string")
	}

	opts := osc.LinkNicOpts{
		LinkNicRequest: optional.NewInterface(osc.LinkNicRequest{
			VmId:         vmID,
			NicId:        nicID,
			DeviceNumber: order,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.NicApi.LinkNic(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcCreateDhcpOptions(name string, dnsServers, ntpServers []string) (osc.DhcpOptionsSet, fail.Error) {
	opts := osc.CreateDhcpOptionsOpts{
		CreateDhcpOptionsRequest: optional.NewInterface(osc.CreateDhcpOptionsRequest{
			NtpServers:        ntpServers,
			DomainNameServers: dnsServers,
		}),
	}
	var resp osc.CreateDhcpOptionsResponse
	xerr := stacks.RetryableRemoteCall(
		func() error {
			dr, hr, innerXerr := s.client.DhcpOptionApi.CreateDhcpOptions(s.auth, &opts)
			if innerXerr != nil {
				return newOutscaleError(hr, innerXerr)
			}
			resp = dr
			return nil
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

func (s stack) rpcReadDhcpOptionsByID(id string) ([]osc.DhcpOptionsSet, fail.Error) {
	if id == "" {
		return []osc.DhcpOptionsSet{}, fail.InvalidParameterError("id", "cannot be empty string")
	}

	opts := osc.ReadDhcpOptionsOpts{
		ReadDhcpOptionsRequest: optional.NewInterface(osc.ReadDhcpOptionsRequest{
			Filters: osc.FiltersDhcpOptions{
				DhcpOptionsSetIds: []string{id},
			},
		}),
	}
	var resp osc.ReadDhcpOptionsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			dr, hr, innerXerr := s.client.DhcpOptionApi.ReadDhcpOptions(s.auth, &opts)
			if innerXerr != nil {
				return newOutscaleError(hr, innerXerr)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.DhcpOptionsSet{}, xerr
	}
	if len(resp.DhcpOptionsSets) == 0 {
		return []osc.DhcpOptionsSet{}, fail.NotFoundError("failed to read DhcpOptions with ID %s", id)
	}
	return resp.DhcpOptionsSets, nil
}

func (s stack) rpcDeleteDhcpOptions(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	opts := osc.DeleteDhcpOptionsOpts{
		DeleteDhcpOptionsRequest: optional.NewInterface(osc.DeleteDhcpOptionsRequest{
			DhcpOptionsSetId: id,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.DhcpOptionApi.DeleteDhcpOptions(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
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
			dr, hr, innerXerr := s.client.FlexibleGpuApi.CreateFlexibleGpu(s.auth, &createFlexibleGpuOpts)
			if innerXerr != nil {
				return newOutscaleError(hr, innerXerr)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.FlexibleGpu{}, xerr
	}
	return resp.FlexibleGpu, nil
}

func (s stack) rpcLinkFlexibleGpu(gpuID, vmID string) fail.Error {
	opts := osc.LinkFlexibleGpuOpts{
		LinkFlexibleGpuRequest: optional.NewInterface(osc.LinkFlexibleGpuRequest{
			VmId:          vmID,
			FlexibleGpuId: gpuID,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.FlexibleGpuApi.LinkFlexibleGpu(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteFlexibleGpu(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	opts := osc.DeleteFlexibleGpuOpts{
		DeleteFlexibleGpuRequest: optional.NewInterface(osc.DeleteFlexibleGpuRequest{
			FlexibleGpuId: id,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.FlexibleGpuApi.DeleteFlexibleGpu(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)

}

func (s stack) rpcUpdateVMSecurityGroups(id string, sgs []string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}
	if len(sgs) == 0 {
		return fail.InvalidParameterError("sgs", "cannot be empty slice")
	}

	opts := osc.UpdateVmOpts{
		UpdateVmRequest: optional.NewInterface(osc.UpdateVmRequest{
			VmId:             id,
			SecurityGroupIds: sgs,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.VmApi.UpdateVm(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcCreateVolume(name string, size int32, iops int32, speed string) (osc.Volume, fail.Error) {
	createVolumeOpts := osc.CreateVolumeOpts{
		CreateVolumeRequest: optional.NewInterface(osc.CreateVolumeRequest{
			Iops:          iops,
			Size:          size,
			SnapshotId:    "",
			SubregionName: s.Options.Compute.Subregion,
			VolumeType:    speed,
		}),
	}
	var resp osc.CreateVolumeResponse
	xerr := stacks.RetryableRemoteCall(
		func() error {
			dr, hr, err := s.client.VolumeApi.CreateVolume(s.auth, &createVolumeOpts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.Volume{}, xerr
	}

	defer func() {
		if xerr != nil {
			if derr := s.rpcDeleteVolume(resp.Volume.VolumeId); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Volume '%s'", name))
			}
		}
	}()

	_, xerr = s.rpcCreateTags(resp.Volume.VolumeId, map[string]string{
		tagNameLabel: name,
	})
	if xerr != nil {
		return osc.Volume{}, xerr
	}

	return resp.Volume, nil
}

func (s stack) rpcReadVolumes(ids []string) ([]osc.Volume, fail.Error) {
	filters := osc.FiltersVolume{
		SubregionNames: []string{s.Options.Compute.Subregion},
	}
	if len(ids) > 0 {
		filters.VolumeIds = ids
	}
	opts := osc.ReadVolumesOpts{
		ReadVolumesRequest: optional.NewInterface(osc.ReadVolumesRequest{
			Filters: filters,
		}),
	}
	var resp osc.ReadVolumesResponse
	xerr := stacks.RetryableRemoteCall(
		func() error {
			dr, hr, err := s.client.VolumeApi.ReadVolumes(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.Volume{}, xerr
	}
	if len(resp.Volumes) == 0 {
		if len(ids) > 0 {
			return []osc.Volume{}, fail.NotFoundError("failed to find Volumes")
		}
		return []osc.Volume{}, nil
	}

	return resp.Volumes, nil
}

func (s stack) rpcReadVolumeByID(id string) (osc.Volume, fail.Error) {
	if id == "" {
		return osc.Volume{}, fail.InvalidParameterError("id", "cannot be empty string")
	}

	resp, xerr := s.rpcReadVolumes([]string{id})
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return osc.Volume{}, fail.NotFoundError("failed to find volume with ID %s", id)
		default:
			return osc.Volume{}, xerr
		}
	}
	if len(resp) > 1 {
		return osc.Volume{}, fail.InconsistentError("found more than one Volume with ID %s", id)
	}
	return resp[0], nil
}

func (s stack) rpcReadVolumeByName(name string) (osc.Volume, fail.Error) {
	if name == "" {
		return osc.Volume{}, fail.InvalidParameterError("name", "cannot be empty string")
	}

	opts := osc.ReadVolumesOpts{
		ReadVolumesRequest: optional.NewInterface(osc.ReadVolumesRequest{
			Filters: osc.FiltersVolume{
				Tags:           []string{"name=" + name},
				SubregionNames: []string{s.Options.Compute.Subregion},
			},
		}),
	}
	var resp osc.ReadVolumesResponse
	xerr := stacks.RetryableRemoteCall(
		func() error {
			dr, hr, err := s.client.VolumeApi.ReadVolumes(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.Volume{}, xerr
	}
	if len(resp.Volumes) == 0 {
		return osc.Volume{}, fail.NotFoundError("failed to find a Volume named '%s'", name)
	}
	if len(resp.Volumes) > 1 {
		return osc.Volume{}, fail.InconsistentError("found more than one Volume named '%s'", name)
	}
	return resp.Volumes[0], nil
}

func (s stack) rpcDeleteVolume(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	opts := osc.DeleteVolumeOpts{
		DeleteVolumeRequest: optional.NewInterface(osc.DeleteVolumeRequest{
			VolumeId: id,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.VolumeApi.DeleteVolume(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcLinkVolume(volumeID, hostID, deviceName string) fail.Error {
	if volumeID == "" {
		return fail.InvalidParameterError("volumeID", "cannot be empty string")
	}
	if hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}
	if deviceName == "" {
		return fail.InvalidParameterError("deviceName", "cannot be empty string")
	}
	opts := osc.LinkVolumeOpts{
		LinkVolumeRequest: optional.NewInterface(osc.LinkVolumeRequest{
			DeviceName: deviceName,
			VmId:       hostID,
			VolumeId:   volumeID,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.VolumeApi.LinkVolume(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcUnlinkVolume(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	opts := osc.UnlinkVolumeOpts{
		UnlinkVolumeRequest: optional.NewInterface(osc.UnlinkVolumeRequest{
			VolumeId: id,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.VolumeApi.UnlinkVolume(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcLinkInternetService(networkID, internetServiceID string) fail.Error {
	if networkID == "" {
		return fail.InvalidParameterError("networkID", "cannot be empty string")
	}
	if internetServiceID == "" {
		return fail.InvalidParameterError("internetServiceID", "cannot be empty string")
	}

	opts := osc.LinkInternetServiceOpts{
		LinkInternetServiceRequest: optional.NewInterface(osc.LinkInternetServiceRequest{
			InternetServiceId: internetServiceID,
			NetId:             networkID,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.InternetServiceApi.LinkInternetService(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteInternetService(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	opts := osc.DeleteInternetServiceOpts{
		DeleteInternetServiceRequest: optional.NewInterface(osc.DeleteInternetServiceRequest{
			InternetServiceId: id,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.InternetServiceApi.DeleteInternetService(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcCreateInternetService(name string) (osc.InternetService, fail.Error) {
	if name == "" {
		return osc.InternetService{}, fail.InvalidParameterError("name", "cannot be empty string")
	}

	var resp osc.CreateInternetServiceResponse
	xerr := stacks.RetryableRemoteCall(
		func() error {
			dr, hr, err := s.client.InternetServiceApi.CreateInternetService(s.auth, nil)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.InternetService{}, xerr
	}

	defer func() {
		if xerr != nil {
			if derr := s.rpcDeleteInternetService(resp.InternetService.InternetServiceId); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete internet service '%s'", name))
			}
		}
	}()

	_, xerr = s.rpcCreateTags(resp.InternetService.InternetServiceId, map[string]string{
		tagNameLabel: name,
	})
	if xerr != nil {
		return osc.InternetService{}, xerr
	}

	return resp.InternetService, nil
}

func (s stack) rpcUnlinkInternetService(networkID, internetServiceID string) fail.Error {
	if networkID == "" {
		return fail.InvalidParameterError("networkID", "cannot be empty string")
	}
	if internetServiceID == "" {
		return fail.InvalidParameterError("internetServiceID", "cannot be empty string")
	}

	opts := osc.UnlinkInternetServiceOpts{
		UnlinkInternetServiceRequest: optional.NewInterface(osc.UnlinkInternetServiceRequest{
			InternetServiceId: internetServiceID,
			NetId:             networkID,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.InternetServiceApi.UnlinkInternetService(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcReadInternetServices(ids []string) ([]osc.InternetService, fail.Error) {
	var filters osc.FiltersInternetService
	if len(ids) > 0 {
		filters.InternetServiceIds = ids
	}
	opts := osc.ReadInternetServicesOpts{
		ReadInternetServicesRequest: optional.NewInterface(osc.ReadInternetServicesRequest{
			Filters: filters,
		}),
	}
	var resp osc.ReadInternetServicesResponse
	xerr := stacks.RetryableRemoteCall(
		func() error {
			dr, hr, err := s.client.InternetServiceApi.ReadInternetServices(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.InternetService{}, xerr
	}

	if len(resp.InternetServices) == 0 {
		if len(ids) > 0 {
			return []osc.InternetService{}, fail.NotFoundError("failed to read Internet Services")
		}
		return []osc.InternetService{}, nil
	}

	return resp.InternetServices, nil
}

func (s stack) rpcCreateRoute(internetServiceID, routeTableID, destination string) fail.Error {
	opts := osc.CreateRouteOpts{
		CreateRouteRequest: optional.NewInterface(osc.CreateRouteRequest{
			DestinationIpRange: destination,
			GatewayId:          internetServiceID,
			RouteTableId:       routeTableID,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.RouteApi.CreateRoute(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcReadRouteTablesOfNetworks(networkIDs []string) ([]osc.RouteTable, fail.Error) {
	var filters osc.FiltersRouteTable
	if len(networkIDs) > 0 {
		filters.NetIds = networkIDs
	}
	opts := osc.ReadRouteTablesOpts{
		ReadRouteTablesRequest: optional.NewInterface(osc.ReadRouteTablesRequest{
			Filters: filters,
		}),
	}
	var resp osc.ReadRouteTablesResponse
	xerr := stacks.RetryableRemoteCall(
		func() error {
			dr, hr, err := s.client.RouteTableApi.ReadRouteTables(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.RouteTable{}, xerr
	}

	if len(resp.RouteTables) == 0 {
		if len(networkIDs) > 0 {
			return []osc.RouteTable{}, fail.NotFoundError("failed to read RouteTables")
		}
		return []osc.RouteTable{}, nil
	}

	return resp.RouteTables, nil
}

func (s stack) rpcReadRouteTableOfNetwork(id string) (osc.RouteTable, fail.Error) {
	if id == "" {
		return osc.RouteTable{}, fail.InvalidParameterError("id", "cannot be empty string")
	}

	resp, xerr := s.rpcReadRouteTablesOfNetworks([]string{id})
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return osc.RouteTable{}, fail.NotFoundError("failed to read RouteTable with ID %s", id)
		default:
			return osc.RouteTable{}, xerr
		}
	}
	if len(resp) > 1 {
		return osc.RouteTable{}, fail.InconsistentError("found more than one RouteTable with ID %s", id)
	}
	return resp[0], nil
}

func (s stack) rpcReadNets(ids []string) ([]osc.Net, fail.Error) {
	var filters osc.FiltersNet
	if len(ids) > 0 {
		filters.NetIds = ids
	}
	opts := osc.ReadNetsOpts{
		ReadNetsRequest: optional.NewInterface(osc.ReadNetsRequest{
			Filters: filters,
		}),
	}
	var (
		emptySlice []osc.Net
		resp       osc.ReadNetsResponse
	)
	xerr := stacks.RetryableRemoteCall(
		func() error {
			dr, hr, err := s.client.NetApi.ReadNets(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return emptySlice, xerr
	}
	if len(resp.Nets) == 0 {
		if len(ids) > 0 {
			return emptySlice, fail.NotFoundError("failed to read Networks")
		}
		return emptySlice, nil
	}
	return resp.Nets, nil
}

func (s stack) rpcReadNetByID(id string) (osc.Net, fail.Error) {
	if id == "" {
		return osc.Net{}, fail.InvalidParameterError("id", "cannot be nil")
	}

	resp, xerr := s.rpcReadNets([]string{id})
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return osc.Net{}, fail.NotFoundError("failed to read Network with ID %s", id)
		default:
			return osc.Net{}, xerr
		}
	}
	if len(resp) > 1 {
		return osc.Net{}, fail.InconsistentError("found more than one Network with ID %s", id)
	}
	return resp[0], nil
}

func (s stack) rpcReadNetByName(name string) (osc.Net, fail.Error) {
	if name == "" {
		return osc.Net{}, fail.InvalidParameterError("name", "cannot be empty string")
	}

	opts := osc.ReadNetsOpts{
		ReadNetsRequest: optional.NewInterface(osc.ReadNetsRequest{
			Filters: osc.FiltersNet{
				Tags: []string{tagNameLabel + "=" + name},
			},
		}),
	}
	var resp osc.ReadNetsResponse
	xerr := stacks.RetryableRemoteCall(
		func() error {
			dr, hr, err := s.client.NetApi.ReadNets(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.Net{}, xerr
	}
	if len(resp.Nets) == 0 {
		return osc.Net{}, fail.NotFoundError("failed to read Network named '%s'", name)
	}
	if len(resp.Nets) > 1 {
		return osc.Net{}, fail.InconsistentError("found more than one Network named '%s'", name)
	}

	return resp.Nets[0], nil
}

func (s stack) rpcCreateSecurityGroup(networkID, name, description string) (osc.SecurityGroup, fail.Error) {
	if networkID == "" {
		return osc.SecurityGroup{}, fail.InvalidParameterError("networkID", "cannot be empty string")
	}
	if name == "" {
		return osc.SecurityGroup{}, fail.InvalidParameterError("name", "cannot be empty string")
	}

	opts := osc.CreateSecurityGroupOpts{
		CreateSecurityGroupRequest: optional.NewInterface(osc.CreateSecurityGroupRequest{
			NetId:             networkID,
			Description:       description,
			SecurityGroupName: name,
		}),
	}
	var resp osc.CreateSecurityGroupResponse
	xerr := stacks.RetryableRemoteCall(
		func() error {
			dr, hr, err := s.client.SecurityGroupApi.CreateSecurityGroup(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.SecurityGroup{}, xerr
	}
	return resp.SecurityGroup, nil
}

func (s stack) rpcDeleteSecurityGroup(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	opts := osc.DeleteSecurityGroupOpts{
		DeleteSecurityGroupRequest: optional.NewInterface(osc.DeleteSecurityGroupRequest{
			SecurityGroupId: id,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.SecurityGroupApi.DeleteSecurityGroup(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcCreateSecurityGroupRules(id, flow string, rules []osc.SecurityGroupRule) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}
	if flow == "" {
		return fail.InvalidParameterError("flow", "cannot be empty string")
	}
	if len(rules) == 0 {
		return fail.InvalidParameterError("rules", "cannot be empty slice")
	}

	opts := osc.CreateSecurityGroupRuleOpts{
		CreateSecurityGroupRuleRequest: optional.NewInterface(osc.CreateSecurityGroupRuleRequest{
			SecurityGroupId: id,
			Rules:           rules,
			Flow:            flow,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.SecurityGroupRuleApi.CreateSecurityGroupRule(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcDeleteSecurityGroupRules(id, flow string, rules []osc.SecurityGroupRule) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}
	if flow == "" {
		return fail.InvalidParameterError("flow", "cannot be empty string")
	}

	request := osc.DeleteSecurityGroupRuleRequest{
		SecurityGroupId: id,
		Flow:            flow,
	}
	if len(rules) > 0 {
		request.Rules = rules
	}
	opts := osc.DeleteSecurityGroupRuleOpts{
		DeleteSecurityGroupRuleRequest: optional.NewInterface(osc.DeleteSecurityGroupRuleRequest{
			SecurityGroupId: id,
			Rules:           rules,
			Flow:            flow,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.SecurityGroupRuleApi.DeleteSecurityGroupRule(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcCreateKeypair(name string, publicKey string) fail.Error {
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}
	if publicKey == "" {
		return fail.InvalidParameterError("publicKey", "cannot be empty string")
	}

	opts := osc.CreateKeypairOpts{
		CreateKeypairRequest: optional.NewInterface(osc.CreateKeypairRequest{
			KeypairName: name,
			PublicKey:   publicKey,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.KeypairApi.CreateKeypair(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcReadKeypairs(names []string) ([]osc.Keypair, fail.Error) {
	var filters osc.FiltersKeypair
	if len(names) > 0 {
		filters.KeypairNames = names
	}
	opts := osc.ReadKeypairsOpts{
		ReadKeypairsRequest: optional.NewInterface(osc.ReadKeypairsRequest{
			Filters: filters,
		}),
	}
	var resp osc.ReadKeypairsResponse
	xerr := stacks.RetryableRemoteCall(
		func() error {
			dr, hr, err := s.client.KeypairApi.ReadKeypairs(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.Keypair{}, xerr
	}
	if len(resp.Keypairs) == 0 {
		if len(names) > 0 {
			return []osc.Keypair{}, fail.NotFoundError("failed to read Keypairs")
		}
		return []osc.Keypair{}, nil
	}
	return resp.Keypairs, nil
}

func (s stack) rpcReadKeypairByName(name string) (osc.Keypair, fail.Error) {
	if name == "" {
		return osc.Keypair{}, fail.InvalidParameterError("name", "cannot be empty string")
	}

	resp, xerr := s.rpcReadKeypairs([]string{name})
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return osc.Keypair{}, fail.NotFoundError("failed to read Keypair named '%s'", name)
		default:
			return osc.Keypair{}, xerr
		}
	}
	if len(resp) > 1 {
		return osc.Keypair{}, fail.InconsistentError("found more than one Keypair named '%s'", name)
	}
	return resp[0], nil
}

func (s stack) rpcDeleteKeypair(name string) fail.Error {
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	opts := osc.DeleteKeypairOpts{
		DeleteKeypairRequest: optional.NewInterface(osc.DeleteKeypairRequest{
			KeypairName: name,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.KeypairApi.DeleteKeypair(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcReadImages(ids []string) ([]osc.Image, fail.Error) {
	var filters osc.FiltersImage
	if len(ids) > 0 {
		filters.ImageIds = ids
	}
	opts := osc.ReadImagesOpts{
		ReadImagesRequest: optional.NewInterface(osc.ReadImagesRequest{
			Filters: filters,
		}),
	}
	var resp osc.ReadImagesResponse
	xerr := stacks.RetryableRemoteCall(
		func() error {
			dr, hr, err := s.client.ImageApi.ReadImages(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.Image{}, xerr
	}
	if len(resp.Images) == 0 {
		if len(ids) > 0 {
			return []osc.Image{}, fail.NotFoundError("failed to read Images")
		}
		return []osc.Image{}, nil
	}
	return resp.Images, nil
}

func (s stack) rpcReadImageByID(id string) (osc.Image, fail.Error) {
	if id == "" {
		return osc.Image{}, fail.InvalidParameterError("id", "cannot be empty string")
	}

	resp, xerr := s.rpcReadImages([]string{id})
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return osc.Image{}, fail.NotFoundError("failed to read Image with ID %s", id)
		default:
			return osc.Image{}, xerr
		}
	}
	if len(resp) > 1 {
		return osc.Image{}, fail.InconsistentError("found more than one Image with ID %s", id)
	}
	return resp[0], nil
}

func (s stack) rpcLinkPublicIP(ipID, nicID string) fail.Error {
	if ipID == "" {
		return fail.InvalidParameterError("ipID", "cannot be empty string")
	}
	if nicID == "" {
		return fail.InvalidParameterError("nicID", "cannot be empty string")
	}

	opts := osc.LinkPublicIpOpts{
		LinkPublicIpRequest: optional.NewInterface(osc.LinkPublicIpRequest{
			NicId:      nicID,
			PublicIpId: ipID,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.PublicIpApi.LinkPublicIp(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcDeletePublicIPByID(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	opts := osc.DeletePublicIpOpts{
		DeletePublicIpRequest: optional.NewInterface(osc.DeletePublicIpRequest{
			PublicIpId: id,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.PublicIpApi.DeletePublicIp(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcDeletePublicIPByIP(ip string) fail.Error {
	opts := osc.DeletePublicIpOpts{
		DeletePublicIpRequest: optional.NewInterface(osc.DeletePublicIpRequest{
			PublicIp: ip,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.PublicIpApi.DeletePublicIp(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcCreatePublicIP() (osc.PublicIp, fail.Error) {
	var resp osc.CreatePublicIpResponse
	xerr := stacks.RetryableRemoteCall(
		func() error {
			dr, hr, err := s.client.PublicIpApi.CreatePublicIp(s.auth, nil)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return osc.PublicIp{}, xerr
	}
	return resp.PublicIp, nil
}

func (s stack) rpcCreateVMs(request osc.CreateVmsRequest) ([]osc.Vm, fail.Error) {
	var resp osc.CreateVmsResponse
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			dr, hr, innerErr := s.client.VmApi.CreateVms(s.auth, &osc.CreateVmsOpts{
				CreateVmsRequest: optional.NewInterface(request),
			})
			if innerErr != nil {
				return newOutscaleError(hr, innerErr)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.Vm{}, xerr
	}
	if len(resp.Vms) == 0 {
		return []osc.Vm{}, nil
	}
	return resp.Vms, nil
}

func (s stack) rpcReadPublicIPsOfVM(id string) ([]osc.PublicIp, fail.Error) {
	if id == "" {
		return []osc.PublicIp{}, fail.InvalidParameterError("id", "cannot be empty string")
	}

	opts := osc.ReadPublicIpsOpts{
		ReadPublicIpsRequest: optional.NewInterface(osc.ReadPublicIpsRequest{
			Filters: osc.FiltersPublicIp{VmIds: []string{id}},
		}),
	}
	var resp osc.ReadPublicIpsResponse
	xerr := stacks.RetryableRemoteCall(
		func() error {
			dr, hr, err := s.client.PublicIpApi.ReadPublicIps(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.PublicIp{}, xerr
	}
	if len(resp.PublicIps) == 0 {
		return []osc.PublicIp{}, nil
	}
	return resp.PublicIps, nil
}

func (s stack) rpcStopVMs(ids []string) fail.Error {
	if len(ids) == 0 {
		return fail.InvalidParameterError("ids", "cannot be empty slice")
	}

	opts := osc.StopVmsOpts{
		StopVmsRequest: optional.NewInterface(osc.StopVmsRequest{
			VmIds:     ids,
			ForceStop: true,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.VmApi.StopVms(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcStartVMs(ids []string) fail.Error {
	if len(ids) == 0 {
		return fail.InvalidParameterError("ids", "cannot be empty slice")
	}

	opts := osc.StartVmsOpts{
		StartVmsRequest: optional.NewInterface(osc.StartVmsRequest{
			VmIds: ids,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.VmApi.StartVms(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)

}

func (s stack) rpcRebootVMs(ids []string) fail.Error {
	if len(ids) == 0 {
		return fail.InvalidParameterError("ids", "cannot be empty slice")
	}

	opts := osc.RebootVmsOpts{
		RebootVmsRequest: optional.NewInterface(osc.RebootVmsRequest{
			VmIds: ids,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.VmApi.RebootVms(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcUpdateVMType(id string, typ string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}
	if typ == "" {
		return fail.InvalidParameterError("typ", "cannot be empty string")
	}

	opts := osc.UpdateVmOpts{
		UpdateVmRequest: optional.NewInterface(osc.UpdateVmRequest{
			VmId:   id,
			VmType: typ,
		}),
	}
	return stacks.RetryableRemoteCall(
		func() error {
			_, hr, err := s.client.VmApi.UpdateVm(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			return nil
		},
		normalizeError,
	)
}

func (s stack) rpcReadNicsOfVM(id string) ([]osc.Nic, fail.Error) {
	opts := osc.ReadNicsOpts{
		ReadNicsRequest: optional.NewInterface(osc.ReadNicsRequest{
			Filters: osc.FiltersNic{
				LinkNicVmIds: []string{id},
			},
		}),
	}
	var resp osc.ReadNicsResponse
	xerr := stacks.RetryableRemoteCall(
		func() error {
			dr, hr, err := s.client.NicApi.ReadNics(s.auth, &opts)
			if err != nil {
				return newOutscaleError(hr, err)
			}
			resp = dr
			return nil
		},
		normalizeError,
	)
	if xerr != nil {
		return []osc.Nic{}, xerr
	}
	if len(resp.Nics) == 0 {
		return []osc.Nic{}, nil
	}
	return resp.Nics, nil
}
