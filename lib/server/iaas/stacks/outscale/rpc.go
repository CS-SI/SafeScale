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
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	"github.com/antihax/optional"

	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

func (s stack) rpcReadSecurityGroups(groupIDs []string) ([]osc.SecurityGroup, fail.Error) {
	query := osc.ReadSecurityGroupsOpts{}
	if len(groupIDs) > 0 {
		query.ReadSecurityGroupsRequest = optional.NewInterface(osc.ReadSecurityGroupsRequest{
			Filters: osc.FiltersSecurityGroup{
				SecurityGroupIds: groupIDs,
			},
		})
	}
	var resp osc.ReadSecurityGroupsResponse
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.SecurityGroupApi.ReadSecurityGroups(s.auth, &query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return []osc.SecurityGroup{}, xerr
	}
	if len(resp.SecurityGroups) == 0 {
		return []osc.SecurityGroup{}, fail.NotFoundError("failed to find Security Groups")
	}

	return resp.SecurityGroups, nil
}

func (s stack) rpcReadSecurityGroup(id string) (osc.SecurityGroup, fail.Error) {
	if id == "" {
		return osc.SecurityGroup{}, fail.InvalidParameterError("id", "cannot be empty string")
	}

	groups, xerr := s.rpcReadSecurityGroups([]string{id})
	if xerr != nil {
		return osc.SecurityGroup{}, xerr
	}
	if len(groups) > 1 {
		return osc.SecurityGroup{}, fail.InconsistentError("found more than one Security Group with ID %s", id)
	}

	return groups[0], nil
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
	return netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, _, innerErr := s.client.SecurityGroupRuleApi.DeleteSecurityGroupRule(s.auth, &query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
}

// rpcReadVm gets VM information from provider
func (s stack) rpcReadVm(vmID string) (osc.Vm, fail.Error) {
	vms, xerr := s.rpcReadVms([]string{vmID})
	if xerr != nil {
		return osc.Vm{}, xerr
	}
	if len(vms) > 1 {
		return osc.Vm{}, fail.InconsistentError("found more than 1 Host with ID %s", vmID)
	}
	return vms[0], nil
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
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			resp, _, innerErr = s.client.VmApi.ReadVms(s.auth, &query)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}
	if len(resp.Vms) == 0 {
		return nil, fail.NotFoundError("failed to find Hosts")
	}
	return resp.Vms, nil
}
