/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"fmt"

	"github.com/antihax/optional"

	"github.com/outscale-dev/osc-sdk-go/osc"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

func (s *Stack) checkDHCPOptionsName(onet *osc.Net) (bool, error) {
	tags, err := s.getResourceTags(onet.DhcpOptionsSetId)
	if err != nil {
		return false, err
	}
	_, ok := tags["name"]
	return ok, nil
}

func (s *Stack) deleteDhcpOptions(onet *osc.Net, checkName bool) error {
	// Delete DHCP options
	namedDHCPOptions, err := s.checkDHCPOptionsName(onet)
	// prevent deleting default dhcp options
	if checkName && !namedDHCPOptions {
		return nil
	}

	deleteDhcpOptionsRequest := osc.DeleteDhcpOptionsRequest{
		DhcpOptionsSetId: onet.DhcpOptionsSetId,
	}
	_, _, err = s.client.DhcpOptionApi.DeleteDhcpOptions(
		s.auth, &osc.DeleteDhcpOptionsOpts{
			DeleteDhcpOptionsRequest: optional.NewInterface(deleteDhcpOptionsRequest),
		},
	)
	return normalizeError(err)
}

func (s *Stack) deleteInternetService(onet *osc.Net) error {
	// Unlink and delete internet service
	resIS, _, err := s.client.InternetServiceApi.ReadInternetServices(s.auth, nil)
	if err != nil || len(resIS.InternetServices) <= 0 {
		// internet service not found
		logrus.Warnf("no internet service linked to network '%s': %v", onet.NetId, normalizeError(err))
		return nil
	}

	// internet service found
	for _, ois := range resIS.InternetServices {
		tags := unwrapTags(ois.Tags)
		if _, ok := tags["name"]; ois.NetId != onet.NetId || !ok {
			continue
		}
		unlinkInternetServiceRequest := osc.UnlinkInternetServiceRequest{
			InternetServiceId: ois.InternetServiceId,
			NetId:             onet.NetId,
		}
		_, _, err := s.client.InternetServiceApi.UnlinkInternetService(
			s.auth, &osc.UnlinkInternetServiceOpts{
				UnlinkInternetServiceRequest: optional.NewInterface(unlinkInternetServiceRequest),
			},
		)
		if err != nil {
			err = normalizeError(err)
			logrus.Errorf(
				"cannot unlink internet service '%s' from network '%s': %v", ois.InternetServiceId, onet.NetId, err,
			)
			return err
		}
		deleteInternetServiceRequest := osc.DeleteInternetServiceRequest{
			InternetServiceId: ois.InternetServiceId,
		}
		_, _, err = s.client.InternetServiceApi.DeleteInternetService(
			s.auth, &osc.DeleteInternetServiceOpts{
				DeleteInternetServiceRequest: optional.NewInterface(deleteInternetServiceRequest),
			},
		)
		if err != nil {
			err = normalizeError(err)
			logrus.Errorf(
				"internet service %s linked to network %s cannot be deleted: %v", ois.InternetServiceId, onet.NetId, err,
			)
			return err
		}
		break
	}

	return nil
}

func (s *Stack) getDefaultRouteTable(onet *osc.Net) (*osc.RouteTable, error) {
	readRouteTablesRequest := osc.ReadRouteTablesRequest{
		Filters: osc.FiltersRouteTable{
			NetIds: []string{onet.NetId},
		},
	}
	res, _, err := s.client.RouteTableApi.ReadRouteTables(
		s.auth, &osc.ReadRouteTablesOpts{
			ReadRouteTablesRequest: optional.NewInterface(readRouteTablesRequest),
		},
	)
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(res.RouteTables) != 1 {
		return nil, scerr.InconsistentError("Inconsistent provider response")
	}
	return &res.RouteTables[0], nil
}

func (s *Stack) updateRouteTable(onet *osc.Net, is *osc.InternetService) error {
	table, err := s.getDefaultRouteTable(onet)
	if err != nil {
		return err
	}
	createRouteRequest := osc.CreateRouteRequest{
		DestinationIpRange: "0.0.0.0/0",
		GatewayId:          is.InternetServiceId,
		RouteTableId:       table.RouteTableId,
	}
	_, _, err = s.client.RouteApi.CreateRoute(
		s.auth, &osc.CreateRouteOpts{
			CreateRouteRequest: optional.NewInterface(createRouteRequest),
		},
	)
	return normalizeError(err)
}

func (s *Stack) createInternetService(req resources.NetworkRequest, onet *osc.Net) error {
	// Create internet service to allow internet access from VMs attached to the network
	isResp, _, err := s.client.InternetServiceApi.CreateInternetService(s.auth, nil)
	if err != nil {
		return normalizeError(err)
	}

	err = s.setResourceTags(
		isResp.InternetService.InternetServiceId, map[string]string{
			"name": req.Name,
		},
	)
	if err != nil {
		return normalizeError(err)
	}

	linkInternetServiceRequest := osc.LinkInternetServiceRequest{
		InternetServiceId: isResp.InternetService.InternetServiceId,
		NetId:             onet.NetId,
	}
	_, _, err = s.client.InternetServiceApi.LinkInternetService(
		s.auth, &osc.LinkInternetServiceOpts{
			LinkInternetServiceRequest: optional.NewInterface(linkInternetServiceRequest),
		},
	)
	if err != nil {
		return normalizeError(err)
	}
	return s.updateRouteTable(onet, &isResp.InternetService)
}

// open all ports, ingress is controlled by the vm firewall
func (s *Stack) createTCPPermissions() []osc.SecurityGroupRule {
	rule := osc.SecurityGroupRule{
		FromPortRange: 1,
		ToPortRange:   65535,
		IpRanges:      []string{"0.0.0.0/0"},
		IpProtocol:    "tcp",
	}
	return []osc.SecurityGroupRule{rule}
}

// open all ports, ingress is controlled by the vm firewall
func (s *Stack) createUDPPermissions() []osc.SecurityGroupRule {
	rule := osc.SecurityGroupRule{
		FromPortRange: 1,
		ToPortRange:   65535,
		IpRanges:      []string{"0.0.0.0/0"},
		IpProtocol:    "udp",
	}
	return []osc.SecurityGroupRule{rule}
}

// ingress is controlled by the vm firewall
func (s *Stack) createICMPPermissions() []osc.SecurityGroupRule {
	var rules []osc.SecurityGroupRule
	// Echo reply
	rules = append(
		rules, osc.SecurityGroupRule{
			FromPortRange: -1,
			ToPortRange:   -1,
			IpRanges:      []string{"0.0.0.0/0"},
			IpProtocol:    "icmp",
		},
	)
	return rules
}

func (s *Stack) removeDefaultSecurityRules(sg *osc.SecurityGroup) error {
	deleteSecurityGroupRuleRequest := osc.DeleteSecurityGroupRuleRequest{
		SecurityGroupId: sg.SecurityGroupId,
		Rules:           sg.InboundRules,
		Flow:            "Inbound",
	}
	_, _, err := s.client.SecurityGroupRuleApi.DeleteSecurityGroupRule(
		s.auth, &osc.DeleteSecurityGroupRuleOpts{
			DeleteSecurityGroupRuleRequest: optional.NewInterface(deleteSecurityGroupRuleRequest),
		},
	)
	if err != nil {
		return normalizeError(err)
	}
	securityGroupRuleRequest := osc.DeleteSecurityGroupRuleRequest{
		SecurityGroupId: sg.SecurityGroupId,
		Rules:           sg.OutboundRules,
		Flow:            "Outbound",
	}
	_, _, err = s.client.SecurityGroupRuleApi.DeleteSecurityGroupRule(
		s.auth, &osc.DeleteSecurityGroupRuleOpts{
			DeleteSecurityGroupRuleRequest: optional.NewInterface(securityGroupRuleRequest),
		},
	)
	return normalizeError(err)
}

func (s *Stack) updateDefaultSecurityRules(sg *osc.SecurityGroup) error {
	rules := append(s.createTCPPermissions(), s.createUDPPermissions()...)
	rules = append(rules, s.createICMPPermissions()...)
	createSecurityGroupRuleRequest := osc.CreateSecurityGroupRuleRequest{
		SecurityGroupId: sg.SecurityGroupId,
		Rules:           rules,
		Flow:            "Inbound",
	}
	_, _, err := s.client.SecurityGroupRuleApi.CreateSecurityGroupRule(
		s.auth, &osc.CreateSecurityGroupRuleOpts{
			CreateSecurityGroupRuleRequest: optional.NewInterface(createSecurityGroupRuleRequest),
		},
	)
	if err != nil {
		return normalizeError(err)
	}
	createSecurityGroupRuleRequest = osc.CreateSecurityGroupRuleRequest{
		SecurityGroupId: sg.SecurityGroupId,
		Rules:           rules,
		Flow:            "Outbound",
	}
	_, _, err = s.client.SecurityGroupRuleApi.CreateSecurityGroupRule(
		s.auth, &osc.CreateSecurityGroupRuleOpts{
			CreateSecurityGroupRuleRequest: optional.NewInterface(createSecurityGroupRuleRequest),
		},
	)
	return normalizeError(err)
}

func (s *Stack) getNetworkSecurityGroup(netID string) (*osc.SecurityGroup, error) {
	readSecurityGroupsRequest := osc.ReadSecurityGroupsRequest{
		Filters: osc.FiltersSecurityGroup{
			SecurityGroupNames: []string{"default"},
		},
	}
	res, _, err := s.client.SecurityGroupApi.ReadSecurityGroups(
		s.auth, &osc.ReadSecurityGroupsOpts{
			ReadSecurityGroupsRequest: optional.NewInterface(readSecurityGroupsRequest),
		},
	)
	if err != nil {
		return nil, normalizeError(err)
	}

	for _, sg := range res.SecurityGroups {
		if sg.NetId == netID {
			return &sg, nil
		}
	}
	// should never go there, in case this means that the network do not have a default security group
	return nil, scerr.InconsistentError("invalid provider response")
}

func (s *Stack) createVpc(name, cidr string) (_ *osc.Net, err error) {

	createNetRequest := osc.CreateNetRequest{
		IpRange: cidr,
		Tenancy: s.Options.Compute.DefaultTenancy,
	}
	respNet, _, err := s.client.NetApi.CreateNet(
		s.auth, &osc.CreateNetOpts{
			CreateNetRequest: optional.NewInterface(createNetRequest),
		},
	)
	if err != nil {
		return nil, normalizeError(err)
	}
	onet := respNet.Net

	defer func() {
		if err != nil {
			if !scerr.ImplementsCauser(err) {
				err = scerr.Wrap(err, "")
			}

			derr := s.DeleteNetwork(onet.NetId)
			if derr != nil {
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	err = s.setResourceTags(
		onet.NetId, map[string]string{
			"name": name,
		},
	)
	if err != nil {
		return nil, err
	}

	req := resources.NetworkRequest{
		CIDR:       cidr,
		DNSServers: s.configurationOptions.DNSList,
		Name:       name,
	}
	// update default security group to allow external traffic
	securityGroup, err := s.getNetworkSecurityGroup(onet.NetId)
	if err != nil {
		return nil, err
	}
	if securityGroup == nil {
		return nil, scerr.InconsistentError("no default security group")
	}

	err = s.updateDefaultSecurityRules(securityGroup)
	if err != nil {
		return nil, err
	}

	err = s.createDHCPOptionSet(req, &onet)
	if err != nil {
		return nil, err
	}

	err = s.createInternetService(req, &onet)
	if err != nil {
		return nil, err
	}

	return &onet, nil
}

func (s *Stack) getVpc(id string) (*osc.Net, error) {
	readNetsRequest := osc.ReadNetsRequest{
		Filters: osc.FiltersNet{
			NetIds: []string{id},
		},
	}
	resNet, _, err := s.client.NetApi.ReadNets(
		s.auth, &osc.ReadNetsOpts{
			ReadNetsRequest: optional.NewInterface(readNetsRequest),
		},
	)
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(resNet.Nets) == 0 {
		return nil, nil
	}
	return &resNet.Nets[0], nil
}

// GetNetworkByName returns the network identified by name)
func (s *Stack) getVpcByName(name string) (*osc.Net, error) {
	readNetsRequest := osc.ReadNetsRequest{
		Filters: osc.FiltersNet{
			Tags: []string{fmt.Sprintf("%s=%s", "name", name)},
		},
	}
	res, _, err := s.client.NetApi.ReadNets(
		s.auth, &osc.ReadNetsOpts{
			ReadNetsRequest: optional.NewInterface(readNetsRequest),
		},
	)
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(res.Nets) == 0 {
		return nil, nil
	}
	return &res.Nets[0], nil

}

func (s *Stack) getDefaultDhcpNptpServers(net *osc.Net) ([]string, error) {
	readDhcpOptionsRequest := osc.ReadDhcpOptionsRequest{
		Filters: osc.FiltersDhcpOptions{
			DhcpOptionsSetIds: []string{net.DhcpOptionsSetId},
		},
	}
	res, _, err := s.client.DhcpOptionApi.ReadDhcpOptions(
		s.auth, &osc.ReadDhcpOptionsOpts{
			ReadDhcpOptionsRequest: optional.NewInterface(readDhcpOptionsRequest),
		},
	)
	if err != nil {
		return nil, normalizeError(err)
	}
	if len(res.DhcpOptionsSets) != 1 {
		return nil, scerr.InconsistentError("Inconsistent provider response")
	}
	return res.DhcpOptionsSets[0].NtpServers, err
}

func (s *Stack) createDHCPOptionSet(req resources.NetworkRequest, net *osc.Net) (err error) {
	if len(req.DNSServers) == 0 {
		return nil
	}
	ntpServers, err := s.getDefaultDhcpNptpServers(net)
	if err != nil {
		return err
	}
	createDhcpOptionsRequest := osc.CreateDhcpOptionsRequest{
		NtpServers:        ntpServers,
		DomainNameServers: req.DNSServers,
	}
	dhcpOptions, _, err := s.client.DhcpOptionApi.CreateDhcpOptions(
		s.auth, &osc.CreateDhcpOptionsOpts{
			CreateDhcpOptionsRequest: optional.NewInterface(createDhcpOptionsRequest),
		},
	)
	if err != nil {
		return normalizeError(err)
	}

	defer func() {
		if err != nil {
			if !scerr.ImplementsCauser(err) {
				err = scerr.Wrap(err, "")
			}

			derr := s.deleteDhcpOptions(net, false)
			if derr != nil {
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	dhcpOptionID := dhcpOptions.DhcpOptionsSet.DhcpOptionsSetId
	err = s.setResourceTags(
		dhcpOptionID, map[string]string{
			"name": req.Name,
		},
	)
	if err != nil {
		return err
	}
	updateNetRequest := osc.UpdateNetRequest{
		DhcpOptionsSetId: dhcpOptionID,
	}
	_, _, err = s.client.NetApi.ReadNets(
		s.auth, &osc.ReadNetsOpts{
			ReadNetsRequest: optional.NewInterface(updateNetRequest),
		},
	)
	return normalizeError(err)
}
