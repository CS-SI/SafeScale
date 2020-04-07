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

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/outscale/osc-sdk-go/oapi"
	"github.com/sirupsen/logrus"
)

func (s *Stack) checkDhcpOptionsName(onet *oapi.Net) (bool, error) {
	tags, err := s.getResourceTags(onet.DhcpOptionsSetId)
	if err != nil {
		return false, err
	}
	_, ok := tags["name"]
	return ok, nil
}
func (s *Stack) deleteDhcpOptions(onet *oapi.Net, checkName bool) error {
	//Delete DHCP options
	namedDhcpOptions, err := s.checkDhcpOptionsName(onet)
	//prevent deleting default dhcp options
	if checkName && !namedDhcpOptions {
		return nil
	}
	_, err = s.client.POST_DeleteDhcpOptions(oapi.DeleteDhcpOptionsRequest{
		DhcpOptionsSetId: onet.DhcpOptionsSetId,
	})
	return err

}

func (s *Stack) deleteInternetService(onet *oapi.Net) error {
	//Unlink and delete internet service
	resIS, err := s.client.POST_ReadInternetServices(oapi.ReadInternetServicesRequest{})

	if err == nil && resIS != nil && resIS.OK != nil && len(resIS.OK.InternetServices) > 0 { //internet service found
		for _, ois := range resIS.OK.InternetServices {
			tags := unwrapTags(ois.Tags)
			if _, ok := tags["name"]; ois.NetId != onet.NetId || !ok {
				continue
			}
			_, err := s.client.POST_UnlinkInternetService(oapi.UnlinkInternetServiceRequest{
				InternetServiceId: ois.InternetServiceId,
				NetId:             onet.NetId,
			})
			if err != nil {
				logrus.Errorf("cannot unlink internet service %s from network %s", ois.InternetServiceId, onet.NetId)
				return err
			}
			_, err = s.client.POST_DeleteInternetService(oapi.DeleteInternetServiceRequest{
				InternetServiceId: ois.InternetServiceId,
			})
			if err != nil {
				logrus.Errorf("internet service %s linked to network %s cannot be deleted: %v", ois.InternetServiceId, onet.NetId, err)
				return err
			}
			break
		}

	} else { //internet service not found
		logrus.Warnf("no internet service linked to network %s: %v", onet.NetId, err)
	}
	return nil
}

func (s *Stack) getDefaultRouteTable(onet *oapi.Net) (*oapi.RouteTable, error) {
	res, err := s.client.POST_ReadRouteTables(oapi.ReadRouteTablesRequest{
		Filters: oapi.FiltersRouteTable{
			NetIds: []string{onet.NetId},
		},
	})
	if err != nil {
		return nil, err
	}
	if res == nil || res.OK == nil || len(res.OK.RouteTables) != 1 {
		return nil, scerr.InconsistentError("Inconsistent provider response")
	}
	return &res.OK.RouteTables[0], nil
}

func (s *Stack) updateRouteTable(onet *oapi.Net, is *oapi.InternetService) error {
	table, err := s.getDefaultRouteTable(onet)
	if err != nil {
		return err
	}
	_, err = s.client.POST_CreateRoute(oapi.CreateRouteRequest{
		DestinationIpRange: "0.0.0.0/0",
		GatewayId:          is.InternetServiceId,
		RouteTableId:       table.RouteTableId,
	})

	return err
}

func (s *Stack) createInternetService(req resources.NetworkRequest, onet *oapi.Net) error {
	//Create internet service to allow internet access from VMs attached to the network
	isResp, err := s.client.POST_CreateInternetService(oapi.CreateInternetServiceRequest{})
	if err != nil {
		return err
	}
	if isResp == nil || isResp.OK == nil {
		return scerr.InconsistentError("invalid provider response")
	}
	err = s.setResourceTags(isResp.OK.InternetService.InternetServiceId, map[string]string{
		"name": req.Name,
	})
	if err != nil {
		return err
	}
	_, err = s.client.POST_LinkInternetService(oapi.LinkInternetServiceRequest{
		InternetServiceId: isResp.OK.InternetService.InternetServiceId,
		NetId:             onet.NetId,
	})
	if err != nil {
		return err
	}
	return s.updateRouteTable(onet, &isResp.OK.InternetService)
}

//open all ports, ingress is controlled by the vm firewall
func (s *Stack) createTCPPermissions() []oapi.SecurityGroupRule {
	rule := oapi.SecurityGroupRule{
		FromPortRange: 1,
		ToPortRange:   65535,
		IpRanges:      []string{"0.0.0.0/0"},
		IpProtocol:    "tcp",
	}
	return []oapi.SecurityGroupRule{rule}
}

//open all ports, ingress is controlled by the vm firewall
func (s *Stack) createUDPPermissions() []oapi.SecurityGroupRule {
	rule := oapi.SecurityGroupRule{
		FromPortRange: 1,
		ToPortRange:   65535,
		IpRanges:      []string{"0.0.0.0/0"},
		IpProtocol:    "udp",
	}
	return []oapi.SecurityGroupRule{rule}
}

//ingress is controlled by the vm firewall
func (s *Stack) createICMPPermissions() []oapi.SecurityGroupRule {
	var rules []oapi.SecurityGroupRule
	//Echo reply
	rules = append(rules, oapi.SecurityGroupRule{
		FromPortRange: -1,
		ToPortRange:   -1,
		IpRanges:      []string{"0.0.0.0/0"},
		IpProtocol:    "icmp",
	})
	return rules
}

func (s *Stack) removeDefaultSecurityRules(sg *oapi.SecurityGroup) error {
	_, err := s.client.POST_DeleteSecurityGroupRule(oapi.DeleteSecurityGroupRuleRequest{
		SecurityGroupId: sg.SecurityGroupId,
		Rules:           sg.InboundRules,
		Flow:            "Inbound",
	})
	if err != nil {
		return err
	}
	_, err = s.client.POST_DeleteSecurityGroupRule(oapi.DeleteSecurityGroupRuleRequest{
		SecurityGroupId: sg.SecurityGroupId,
		Rules:           sg.OutboundRules,
		Flow:            "Outbound",
	})
	return err
}

func (s *Stack) updateDefaultSecurityRules(sg *oapi.SecurityGroup) error {
	rules := append(s.createTCPPermissions(), s.createUDPPermissions()...)
	rules = append(rules, s.createICMPPermissions()...)
	_, err := s.client.POST_CreateSecurityGroupRule(oapi.CreateSecurityGroupRuleRequest{
		SecurityGroupId: sg.SecurityGroupId,
		Rules:           rules,
		Flow:            "Inbound",
	})
	if err != nil {
		return err
	}
	_, err = s.client.POST_CreateSecurityGroupRule(oapi.CreateSecurityGroupRuleRequest{
		SecurityGroupId: sg.SecurityGroupId,
		Rules:           rules,
		Flow:            "Outbound",
	})
	return err
}

func (s *Stack) getNetworkSecurityGroup(netID string) (*oapi.SecurityGroup, error) {
	res, err := s.client.POST_ReadSecurityGroups(oapi.ReadSecurityGroupsRequest{
		Filters: oapi.FiltersSecurityGroup{
			NetIds:             []string{netID},
			SecurityGroupNames: []string{"default"},
		},
	})
	if err != nil {
		return nil, err
	}

	if res == nil || res.OK == nil {
		return nil, scerr.InconsistentError("invalid provider response")
	}
	// POST_ReadSecurityGroups should return only one security group
	// but NetIds filter is not yet implemented
	for _, sg := range res.OK.SecurityGroups {
		if sg.NetId == netID {
			return &sg, nil
		}
	}
	// should never go there, in case this means that the network do not have a default security group
	return nil, scerr.InconsistentError("invalid provider response")

}

func (s *Stack) deleteNetworkOnError(err error, onet *oapi.Net) error {

	err2 := s.DeleteNetwork(onet.NetId)
	if err2 != nil {
		return scerr.Wrap(err, err2.Error())
	}
	return err
}

func (s *Stack) createVpc(name, cidr string) (*oapi.Net, error) {

	respNet, err := s.client.POST_CreateNet(oapi.CreateNetRequest{
		IpRange: cidr,
		Tenancy: s.Options.Compute.DefaultTenancy,
	})
	if err != nil {
		return nil, err
	}
	if respNet == nil || respNet.OK == nil {
		return nil, scerr.InconsistentError("invalid provider response")
	}
	onet := respNet.OK.Net

	err = s.setResourceTags(onet.NetId, map[string]string{
		"name": name,
	})
	if err != nil {
		return nil, s.deleteNetworkOnError(err, &onet)
	}

	req := resources.NetworkRequest{
		CIDR:       cidr,
		DNSServers: s.configrationOptions.DNSList,
		Name:       name,
	}
	//update defaut security group to allow external trafic
	secgroup, err := s.getNetworkSecurityGroup(onet.NetId)
	if err != nil {
		return nil, s.deleteNetworkOnError(err, &onet)
	}
	if secgroup == nil {
		return nil, s.deleteNetworkOnError(scerr.InconsistentError("no default security group"), &onet)
	}

	err = s.updateDefaultSecurityRules(secgroup)
	if err != nil {
		return nil, s.deleteNetworkOnError(err, &onet)
	}

	err = s.createDHCPOptionSet(req, &onet)
	if err != nil {
		return nil, s.deleteNetworkOnError(err, &onet)
	}

	err = s.createInternetService(req, &onet)
	if err != nil {
		return nil, s.deleteNetworkOnError(err, &onet)
	}

	return &onet, nil
}

func (s *Stack) getVpc(id string) (*oapi.Net, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	resNet, err := s.client.POST_ReadNets(oapi.ReadNetsRequest{
		Filters: oapi.FiltersNet{
			NetIds: []string{id},
		},
	})
	if err != nil {
		return nil, err
	}
	if resNet == nil || resNet.OK == nil || len(resNet.OK.Nets) == 0 {
		return nil, nil
	}
	return &resNet.OK.Nets[0], nil
}

// GetNetworkByName returns the network identified by name)
func (s *Stack) getVpcByName(name string) (*oapi.Net, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	res, err := s.client.POST_ReadNets(oapi.ReadNetsRequest{
		Filters: oapi.FiltersNet{
			Tags: []string{fmt.Sprintf("%s=%s", "name", name)},
		},
	})
	if err != nil {
		return nil, err
	}
	if res == nil || len(res.OK.Nets) == 0 {
		return nil, nil
	}
	return &res.OK.Nets[0], nil

}

func (s *Stack) getDefaultDhcpNptpServers(net *oapi.Net) ([]string, error) {
	res, err := s.client.POST_ReadDhcpOptions(oapi.ReadDhcpOptionsRequest{
		Filters: oapi.FiltersDhcpOptions{
			DhcpOptionsSetIds: []string{net.DhcpOptionsSetId},
		},
	})
	if err != nil {
		return nil, err
	}
	if res == nil || res.OK == nil || len(res.OK.DhcpOptionsSets) != 1 {
		return nil, scerr.InconsistentError("Inconsistent provider response")
	}
	return res.OK.DhcpOptionsSets[0].NtpServers, err
}

func (s *Stack) createDHCPOptionSet(req resources.NetworkRequest, net *oapi.Net) error {
	if len(req.DNSServers) == 0 {
		return nil
	}
	ntpServers, err := s.getDefaultDhcpNptpServers(net)
	if err != nil {
		return err
	}
	dhcpOptions, err := s.client.POST_CreateDhcpOptions(oapi.CreateDhcpOptionsRequest{
		NtpServers:        ntpServers,
		DomainNameServers: req.DNSServers,
	})
	if err != nil {
		return err
	}
	if dhcpOptions == nil || dhcpOptions.OK == nil {
		err2 := s.deleteDhcpOptions(net, false)
		return scerr.Wrap(err, err2.Error())
	}

	dhcpOptionID := dhcpOptions.OK.DhcpOptionsSet.DhcpOptionsSetId
	err = s.setResourceTags(dhcpOptionID, map[string]string{
		"name": req.Name,
	})
	if err != nil {
		err2 := s.deleteDhcpOptions(net, false)
		return scerr.Wrap(err, err2.Error())
	}
	_, err = s.client.POST_UpdateNet(oapi.UpdateNetRequest{
		DhcpOptionsSetId: dhcpOptionID,
	})
	return err
}
