/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package gcp

import (
	"context"
	"fmt"
	"strconv"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostProperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/IPVersion"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	timeouts "github.com/CS-SI/SafeScale/lib/utils"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"

	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
)

// CreateNetwork creates a network named name
func (s *Stack) CreateNetwork(req resources.NetworkRequest) (*resources.Network, error) {
	// disable subnetwork auto-creation
	ne := compute.Network{
		Name:                  "safescale",
		AutoCreateSubnetworks: false,
		ForceSendFields:       []string{"AutoCreateSubnetworks"},
	}

	compuService := s.ComputeService

	recreateSafescaleNetwork := true
	recnet, err := compuService.Networks.Get(s.GcpConfig.ProjectId, ne.Name).Do()
	if recnet != nil && err == nil {
		recreateSafescaleNetwork = false
	} else {
		if err != nil {
			if gerr, ok := err.(*googleapi.Error); ok {
				if gerr.Code != 404 {
					return nil, err
				}
			} else {
				return nil, err
			}
		}
	}

	if recreateSafescaleNetwork {
		opp, err := compuService.Networks.Insert(s.GcpConfig.ProjectId, &ne).Context(context.Background()).Do()
		if err != nil {
			return nil, err
		}

		oco := OpContext{
			Operation:    opp,
			ProjectId:    s.GcpConfig.ProjectId,
			Service:      compuService,
			DesiredState: "DONE",
		}

		err = waitUntilOperationIsSuccessfulOrTimeout(oco, timeouts.GetMinDelay(), 2*timeouts.GetContextTimeout())
		if err != nil {
			return nil, err
		}
	}

	necreated, err := compuService.Networks.Get(s.GcpConfig.ProjectId, ne.Name).Do()
	if err != nil {
		return nil, err
	}

	net := resources.NewNetwork()
	net.ID = strconv.FormatUint(necreated.Id, 10)
	net.Name = necreated.Name

	// Create subnetwork

	theRegion := s.GcpConfig.Region

	subnetReq := compute.Subnetwork{
		IpCidrRange: req.CIDR,
		Name:        req.Name,
		Network:     fmt.Sprintf("projects/%s/global/networks/%s", s.GcpConfig.ProjectId, "safescale"),
		Region:      theRegion,
	}

	opp, err := compuService.Subnetworks.Insert(s.GcpConfig.ProjectId, theRegion, &subnetReq).Context(context.Background()).Do()
	if err != nil {
		return nil, err
	}

	oco := OpContext{
		Operation:    opp,
		ProjectId:    s.GcpConfig.ProjectId,
		Service:      compuService,
		DesiredState: "DONE",
	}

	err = waitUntilOperationIsSuccessfulOrTimeout(oco, timeouts.GetMinDelay(), 2*timeouts.GetContextTimeout())
	if err != nil {
		return nil, err
	}

	gcpSubNet, err := compuService.Subnetworks.Get(s.GcpConfig.ProjectId, theRegion, req.Name).Do()
	if err != nil {
		return nil, err
	}

	// FIXME Add properties and GatewayID
	subnet := resources.NewNetwork()
	subnet.ID = strconv.FormatUint(gcpSubNet.Id, 10)
	subnet.Name = gcpSubNet.Name
	subnet.CIDR = gcpSubNet.IpCidrRange
	subnet.IPVersion = IPVersion.IPv4

	buildNewRule := true
	firewallRuleName := fmt.Sprintf("%s-%s-all-in", "safescale", gcpSubNet.Name)

	fws, err := compuService.Firewalls.Get(s.GcpConfig.ProjectId, firewallRuleName).Do()
	if fws != nil && err == nil {
		buildNewRule = false
	} else {
		if err != nil {
			if gerr, ok := err.(*googleapi.Error); ok {
				if gerr.Code != 404 {
					return nil, err
				}
			} else {
				return nil, err
			}
		}
	}

	if buildNewRule {
		// FIXME Create more firewall rules
		fiw := compute.Firewall{
			Allowed: []*compute.FirewallAllowed{
				{
					IPProtocol: "all",
				},
			},
			Direction:    "INGRESS",
			Disabled:     false,
			Name:         firewallRuleName,
			Network:      fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/global/networks/%s", s.GcpConfig.ProjectId, "safescale"),
			Priority:     999,
			SourceRanges: []string{"0.0.0.0/0"},
		}

		opp, err = compuService.Firewalls.Insert(s.GcpConfig.ProjectId, &fiw).Do()
		if err != nil {
			return nil, err
		}
		oco = OpContext{
			Operation:    opp,
			ProjectId:    s.GcpConfig.ProjectId,
			Service:      compuService,
			DesiredState: "DONE",
		}

		err = waitUntilOperationIsSuccessfulOrTimeout(oco, timeouts.GetMinDelay(), timeouts.GetHostTimeout())
		if err != nil {
			return nil, err
		}
	}

	// FIXME Replace project name "safescale", use network name from configuration
	buildNewNATRule := true
	natRuleName := fmt.Sprintf("%s-%s-nat-allowed", "safescale", gcpSubNet.Name)

	rfs, err := compuService.Routes.Get(s.GcpConfig.ProjectId, natRuleName).Do()
	if rfs != nil && err == nil {
		buildNewNATRule = false
	} else {
		if err != nil {
			if gerr, ok := err.(*googleapi.Error); ok {
				if gerr.Code != 404 {
					return nil, err
				}
			} else {
				return nil, err
			}
		}
	}

	if buildNewNATRule {
		route := &compute.Route{
			DestRange:       "0.0.0.0/0",
			Name:            natRuleName,
			Network:         fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/global/networks/%s", s.GcpConfig.ProjectId, "safescale"),
			NextHopInstance: fmt.Sprintf("projects/%s/zones/%s/instances/gw-%s", s.GcpConfig.ProjectId, s.GcpConfig.Zone, req.Name),
			Priority:        800,
			Tags:            []string{fmt.Sprintf("no-ip-%s", gcpSubNet.Name)},
		}
		opp, err := compuService.Routes.Insert(s.GcpConfig.ProjectId, route).Do()
		if err != nil {
			return nil, err
		}
		oco = OpContext{
			Operation:    opp,
			ProjectId:    s.GcpConfig.ProjectId,
			Service:      compuService,
			DesiredState: "DONE",
		}

		err = waitUntilOperationIsSuccessfulOrTimeout(oco, timeouts.GetMinDelay(), 2*timeouts.GetContextTimeout())
		if err != nil {
			return nil, err
		}

	}

	// FIXME Validation before return...
	return subnet, nil
}

// GetNetwork returns the network identified by ref (id or name)
func (s *Stack) GetNetwork(ref string) (*resources.Network, error) {
	nets, err := s.ListNetworks()
	if err != nil {
		return nil, err
	}
	for _, net := range nets {
		if net.ID == ref {
			return net, nil
		}
	}

	return nil, resources.ResourceNotFoundError("network", ref)
}

// GetNetworkByName returns the network identified by ref (id or name)
func (s *Stack) GetNetworkByName(ref string) (*resources.Network, error) {
	nets, err := s.ListNetworks()
	if err != nil {
		return nil, err
	}
	for _, net := range nets {
		if net.Name == ref {
			return net, nil
		}
	}

	return nil, resources.ResourceNotFoundError("network", ref)
}

// ListNetworks lists available networks
func (s *Stack) ListNetworks() ([]*resources.Network, error) {
	logrus.Debug(">>> stacks.gcp::ListNetworks() called")
	defer logrus.Debug("<<< stacks.gcp::ListNetworks() done")

	if s == nil {
		panic("Calling s.ListNetworks with s==nil!")
	}

	var networks []*resources.Network

	compuService := s.ComputeService

	token := ""
	for paginate := true; paginate; {
		resp, err := compuService.Networks.List(s.GcpConfig.ProjectId).PageToken(token).Do()
		if err != nil {
			return networks, fmt.Errorf("can't list networks ...: %s", err)
		}

		for _, nett := range resp.Items {
			newNet := resources.NewNetwork()
			newNet.Name = nett.Name
			newNet.ID = strconv.FormatUint(nett.Id, 10)
			newNet.CIDR = nett.IPv4Range

			networks = append(networks, newNet)
		}
		token := resp.NextPageToken
		paginate = token != ""
	}

	token = ""
	for paginate := true; paginate; {
		resp, err := compuService.Subnetworks.List(s.GcpConfig.ProjectId, s.GcpConfig.Region).PageToken(token).Do()
		if err != nil {
			return networks, fmt.Errorf("can't list subnetworks ...: %s", err)
		}

		for _, nett := range resp.Items {
			newNet := resources.NewNetwork()
			newNet.Name = nett.Name
			newNet.ID = strconv.FormatUint(nett.Id, 10)
			newNet.CIDR = nett.IpCidrRange

			networks = append(networks, newNet)
		}
		token := resp.NextPageToken
		paginate = token != ""
	}

	return networks, nil
}

// DeleteNetwork deletes the network identified by id
func (s *Stack) DeleteNetwork(ref string) (err error) {
	theNetwork, err := s.GetNetwork(ref)
	if err != nil {
		if gerr, ok := err.(*googleapi.Error); ok {
			if gerr.Code != 404 {
				return err
			}
		} else {
			return err
		}
	}

	compuService := s.ComputeService
	subnetwork, err := compuService.Subnetworks.Get(s.GcpConfig.ProjectId, s.GcpConfig.Region, theNetwork.Name).Do()
	if err != nil {
		return err
	}

	opp, err := compuService.Subnetworks.Delete(s.GcpConfig.ProjectId, s.GcpConfig.Region, subnetwork.Name).Do()
	if err != nil {
		return err
	}

	oco := OpContext{
		Operation:    opp,
		ProjectId:    s.GcpConfig.ProjectId,
		Service:      compuService,
		DesiredState: "DONE",
	}

	err = waitUntilOperationIsSuccessfulOrTimeout(oco, timeouts.GetMinDelay(), 2*timeouts.GetContextTimeout())
	if err != nil {
		return err
	}

	// Delete routes and firewall
	firewallRuleName := fmt.Sprintf("%s-%s-all-in", "safescale", subnetwork.Name)
	fws, err := compuService.Firewalls.Get(s.GcpConfig.ProjectId, firewallRuleName).Do()
	if fws != nil && err == nil {
		opp, err := compuService.Firewalls.Delete(s.GcpConfig.ProjectId, firewallRuleName).Do()
		if err == nil {
			oco := OpContext{
				Operation:    opp,
				ProjectId:    s.GcpConfig.ProjectId,
				Service:      compuService,
				DesiredState: "DONE",
			}

			err = waitUntilOperationIsSuccessfulOrTimeout(oco, timeouts.GetMinDelay(), 2*timeouts.GetContextTimeout())
		}
	}

	if err != nil {
		logrus.Warn(err)
	}

	natRuleName := fmt.Sprintf("%s-%s-nat-allowed", "safescale", subnetwork.Name)
	nws, err := compuService.Routes.Get(s.GcpConfig.ProjectId, natRuleName).Do()
	if nws != nil && err == nil {
		opp, err := compuService.Routes.Delete(s.GcpConfig.ProjectId, natRuleName).Do()
		if err == nil {
			oco := OpContext{
				Operation:    opp,
				ProjectId:    s.GcpConfig.ProjectId,
				Service:      compuService,
				DesiredState: "DONE",
			}

			err = waitUntilOperationIsSuccessfulOrTimeout(oco, timeouts.GetMinDelay(), 2*timeouts.GetContextTimeout())
		}
	}

	if err != nil {
		logrus.Warn(err)
	}

	return nil
}

// CreateGateway creates a public Gateway for a private network
func (s *Stack) CreateGateway(req resources.GatewayRequest) (*resources.Host, *userdata.Content, error) {
	if req.Network == nil {
		panic("req.Network is nil!")
	}
	gwname := req.Name
	if gwname == "" {
		gwname = "gw-" + req.Network.Name
	}

	hostReq := resources.HostRequest{
		ImageID:      req.ImageID,
		KeyPair:      req.KeyPair,
		ResourceName: gwname,
		TemplateID:   req.TemplateID,
		Networks:     []*resources.Network{req.Network},
		PublicIP:     true,
	}

	host, userData, err := s.CreateHost(hostReq)
	if err != nil {
		switch err.(type) {
		case resources.ErrResourceInvalidRequest:
			return nil, userData, err
		default:
			return nil, userData, fmt.Errorf("Error creating gateway : %s", err)
		}
	}

	// Updates Host Property propsv1.HostSizing
	err = host.Properties.LockForWrite(HostProperty.SizingV1).ThenUse(func(v interface{}) error {
		hostSizingV1 := v.(*propsv1.HostSizing)
		hostSizingV1.Template = req.TemplateID
		return nil
	})
	if err != nil {
		return nil, userData, errors.Wrap(err, fmt.Sprintf("Error creating gateway : %s", err))
	}

	return host, userData, err
}

// DeleteGateway delete the public gateway referenced by ref (id or name)
func (s *Stack) DeleteGateway(ref string) error {
	return s.DeleteHost(ref)
}
