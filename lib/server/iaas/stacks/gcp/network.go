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

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"

	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// CreateNetwork creates a network named name
func (s *Stack) CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, debug.IfTrace("stack.network"), "(%s)", req.Name).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()

	// disable subnetwork auto-creation
	ne := compute.Network{
		Name:                  s.GcpConfig.NetworkName,
		AutoCreateSubnetworks: false,
		ForceSendFields:       []string{"AutoCreateSubnetworks"},
	}

	compuService := s.ComputeService

	recreateSafescaleNetwork := true
	recnet, err := compuService.Networks.Get(s.GcpConfig.ProjectID, ne.Name).Do()
	if recnet != nil && err == nil {
		recreateSafescaleNetwork = false
	} else if err != nil {
		if gerr, ok := err.(*googleapi.Error); ok {
			if gerr.Code != 404 {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	if recreateSafescaleNetwork {
		opp, err := compuService.Networks.Insert(s.GcpConfig.ProjectID, &ne).Context(context.Background()).Do()
		if err != nil {
			return nil, err
		}

		oco := OpContext{
			Operation:    opp,
			ProjectID:    s.GcpConfig.ProjectID,
			Service:      compuService,
			DesiredState: "DONE",
		}

		err = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
		if err != nil {
			return nil, err
		}
	}

	necreated, err := compuService.Networks.Get(s.GcpConfig.ProjectID, ne.Name).Do()
	if err != nil {
		return nil, err
	}

	net := abstract.NewNetwork()
	net.ID = strconv.FormatUint(necreated.Id, 10)
	net.Name = necreated.Name

	// Checks if CIDR is valid...
	if req.CIDR == "" {
		tracer.Trace("CIDR is empty, choosing one...")
		req.CIDR = "192.168.1.0/24"
		tracer.Trace("CIDR chosen for network is '%s'", req.CIDR)
	}

	// Create subnetwork

	theRegion := s.GcpConfig.Region

	subnetReq := compute.Subnetwork{
		IpCidrRange: req.CIDR,
		Name:        req.Name,
		Network:     fmt.Sprintf("projects/%s/global/networks/%s", s.GcpConfig.ProjectID, s.GcpConfig.NetworkName),
		Region:      theRegion,
	}

	opp, err := compuService.Subnetworks.Insert(s.GcpConfig.ProjectID, theRegion, &subnetReq).Context(context.Background()).Do()
	if err != nil {
		return nil, err
	}

	oco := OpContext{
		Operation:    opp,
		ProjectID:    s.GcpConfig.ProjectID,
		Service:      compuService,
		DesiredState: "DONE",
	}

	err = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
	if err != nil {
		return nil, err
	}

	gcpSubNet, err := compuService.Subnetworks.Get(s.GcpConfig.ProjectID, theRegion, req.Name).Do()
	if err != nil {
		return nil, err
	}

	// FIXME: Add properties and GatewayID
	subnet := abstract.NewNetwork()
	subnet.ID = strconv.FormatUint(gcpSubNet.Id, 10)
	subnet.Name = gcpSubNet.Name
	subnet.CIDR = gcpSubNet.IpCidrRange
	subnet.IPVersion = ipversion.IPv4

	buildNewRule := true
	firewallRuleName := fmt.Sprintf("%s-%s-all-in", s.GcpConfig.NetworkName, gcpSubNet.Name)

	fws, err := compuService.Firewalls.Get(s.GcpConfig.ProjectID, firewallRuleName).Do()
	if fws != nil && err == nil {
		buildNewRule = false
	} else if err != nil {
		if gerr, ok := err.(*googleapi.Error); ok {
			if gerr.Code != 404 {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	if buildNewRule {
		fiw := compute.Firewall{
			Allowed: []*compute.FirewallAllowed{
				{
					IPProtocol: "all",
				},
			},
			Direction:    "INGRESS",
			Disabled:     false,
			Name:         firewallRuleName,
			Network:      fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/global/networks/%s", s.GcpConfig.ProjectID, s.GcpConfig.NetworkName),
			Priority:     999,
			SourceRanges: []string{"0.0.0.0/0"},
		}

		opp, err = compuService.Firewalls.Insert(s.GcpConfig.ProjectID, &fiw).Do()
		if err != nil {
			return nil, err
		}
		oco = OpContext{
			Operation:    opp,
			ProjectID:    s.GcpConfig.ProjectID,
			Service:      compuService,
			DesiredState: "DONE",
		}

		err = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
		if err != nil {
			return nil, err
		}
	}

	buildNewNATRule := true
	natRuleName := fmt.Sprintf("%s-%s-nat-allowed", s.GcpConfig.NetworkName, gcpSubNet.Name)

	rfs, err := compuService.Routes.Get(s.GcpConfig.ProjectID, natRuleName).Do()
	if rfs != nil && err == nil {
		buildNewNATRule = false
	} else if err != nil {
		if gerr, ok := err.(*googleapi.Error); ok {
			if gerr.Code != 404 {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	if buildNewNATRule {
		route := &compute.Route{
			DestRange:       "0.0.0.0/0",
			Name:            natRuleName,
			Network:         fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/global/networks/%s", s.GcpConfig.ProjectID, s.GcpConfig.NetworkName),
			NextHopInstance: fmt.Sprintf("projects/%s/zones/%s/instances/gw-%s", s.GcpConfig.ProjectID, s.GcpConfig.Zone, req.Name),
			Priority:        800,
			Tags:            []string{fmt.Sprintf("no-ip-%s", gcpSubNet.Name)},
		}
		opp, err := compuService.Routes.Insert(s.GcpConfig.ProjectID, route).Do()
		if err != nil {
			return nil, err
		}
		oco = OpContext{
			Operation:    opp,
			ProjectID:    s.GcpConfig.ProjectID,
			Service:      compuService,
			DesiredState: "DONE",
		}

		err = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), 2*temporal.GetContextTimeout())
		if err != nil {
			return nil, err
		}

	}

	_ = subnet.OK()

	return subnet, nil
}

// GetNetwork returns the network identified by ref (id or name)
func (s *Stack) GetNetwork(ref string) (*abstract.Network, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	nets, err := s.ListNetworks()
	if err != nil {
		return nil, err
	}
	for _, net := range nets {
		if net.ID == ref {
			return net, nil
		}
	}

	return nil, abstract.ResourceNotFoundError("network", ref)
}

// GetNetworkByName returns the network identified by ref (id or name)
func (s *Stack) GetNetworkByName(ref string) (*abstract.Network, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	nets, err := s.ListNetworks()
	if err != nil {
		return nil, err
	}
	for _, net := range nets {
		if net.Name == ref {
			return net, nil
		}
	}

	return nil, abstract.ResourceNotFoundError("network", ref)
}

// ListNetworks lists available networks
func (s *Stack) ListNetworks() ([]*abstract.Network, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	var networks []*abstract.Network

	compuService := s.ComputeService

	token := ""
	for paginate := true; paginate; {
		resp, err := compuService.Networks.List(s.GcpConfig.ProjectID).PageToken(token).Do()
		if err != nil {
			return networks, scerr.Wrap(err, "cannot list networks")
		}

		for _, nett := range resp.Items {
			newNet := abstract.NewNetwork()
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
		resp, err := compuService.Subnetworks.List(s.GcpConfig.ProjectID, s.GcpConfig.Region).PageToken(token).Do()
		if err != nil {
			return networks, scerr.Wrap(err, "cannot list subnetworks")
		}

		for _, nett := range resp.Items {
			newNet := abstract.NewNetwork()
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
	if s == nil {
		return scerr.InvalidInstanceError()
	}

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

	if theNetwork == nil {
		return scerr.NewError("delete network failed: unexpected nil network when looking for '%s'", ref)
	}

	if !theNetwork.OK() {
		logrus.Warnf("Missing data in network: %s", spew.Sdump(theNetwork))
	}

	compuService := s.ComputeService
	subnetwork, err := compuService.Subnetworks.Get(s.GcpConfig.ProjectID, s.GcpConfig.Region, theNetwork.Name).Do()
	if err != nil {
		return err
	}

	opp, err := compuService.Subnetworks.Delete(s.GcpConfig.ProjectID, s.GcpConfig.Region, subnetwork.Name).Do()
	if err != nil {
		return err
	}

	oco := OpContext{
		Operation:    opp,
		ProjectID:    s.GcpConfig.ProjectID,
		Service:      compuService,
		DesiredState: "DONE",
	}

	err = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostCleanupTimeout())
	if err != nil {
		switch err.(type) {
		case scerr.ErrTimeout:
			logrus.Warnf("Timeout waiting for subnetwork deletion")
			return err
		default:
			return err
		}
	}

	// Delete routes and firewall
	firewallRuleName := fmt.Sprintf("%s-%s-all-in", s.GcpConfig.NetworkName, subnetwork.Name)
	fws, err := compuService.Firewalls.Get(s.GcpConfig.ProjectID, firewallRuleName).Do()
	if err != nil {
		logrus.Warn(err)
		return err
	}

	if fws != nil {
		opp, operr := compuService.Firewalls.Delete(s.GcpConfig.ProjectID, firewallRuleName).Do()
		if operr == nil {
			oco := OpContext{
				Operation:    opp,
				ProjectID:    s.GcpConfig.ProjectID,
				Service:      compuService,
				DesiredState: "DONE",
			}

			operr = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostCleanupTimeout())
			if operr != nil {
				logrus.Warn(operr)
				return operr
			}
		} else {
			return operr
		}
	}

	natRuleName := fmt.Sprintf("%s-%s-nat-allowed", s.GcpConfig.NetworkName, subnetwork.Name)
	nws, err := compuService.Routes.Get(s.GcpConfig.ProjectID, natRuleName).Do()
	if err != nil {
		logrus.Warn(err)
		return err
	}

	if nws != nil {
		opp, operr := compuService.Routes.Delete(s.GcpConfig.ProjectID, natRuleName).Do()
		if operr == nil {
			oco := OpContext{
				Operation:    opp,
				ProjectID:    s.GcpConfig.ProjectID,
				Service:      compuService,
				DesiredState: "DONE",
			}

			operr = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostCleanupTimeout())
			if operr != nil {
				logrus.Warn(operr)
				return operr
			}
		} else {
			return operr
		}
	}

	return nil
}

// CreateGateway creates a public Gateway for a private network
func (s *Stack) CreateGateway(req abstract.GatewayRequest) (_ *abstract.HostFull, _ *userdata.Content, err error) {
	if s == nil {
		return nil, nil, scerr.InvalidInstanceError()
	}
	if req.Network == nil {
		return nil, nil, scerr.InvalidParameterError("req.Network", "cannot be nil")
	}

	defer scerr.OnPanic(&err)()

	gwname := req.Name
	if gwname == "" {
		gwname = "gw-" + req.Network.Name
	}

	hostReq := abstract.HostRequest{
		ImageID:      req.ImageID,
		KeyPair:      req.KeyPair,
		ResourceName: gwname,
		TemplateID:   req.TemplateID,
		Networks:     []*abstract.Network{req.Network},
		PublicIP:     true,
	}

	host, userData, err := s.CreateHost(hostReq)
	if err != nil {
		switch err.(type) {
		case scerr.ErrInvalidRequest:
			return nil, userData, err
		default:
			return nil, userData, scerr.Wrap(err, "error creating gateway")
		}
	}

	// VPL: Moved in objects.Host
	// // Updates Host Property propertiesv1.HostSizing
	// err = host.Properties.Alter(HostProperty.SizingV1, func(v interface{}) error {
	// 	hostSizingV1 := v.(*propertiesv1.HostSizing)
	// 	hostSizingV1.Template = req.TemplateID
	// 	return nil
	// })
	// if err != nil {
	// 	return nil, userData, err
	// }

	return host, userData, err
}

// DeleteGateway delete the public gateway referenced by ref (id or name)
func (s *Stack) DeleteGateway(ref string) error {
	return s.DeleteHost(ref)
}

// CreateVIP creates a private virtual IP
// If public is set to true,
func (s *Stack) CreateVIP(networkID string, description string) (*abstract.VirtualIP, error) {
	return nil, scerr.NotImplementedError("CreateVIP() not implemented yet") // FIXME: Technical debt
}

// AddPublicIPToVIP adds a public IP to VIP
func (s *Stack) AddPublicIPToVIP(vip *abstract.VirtualIP) error {
	return scerr.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (s *Stack) BindHostToVIP(vip *abstract.VirtualIP, hostID string) error {
	return scerr.NotImplementedError("BindHostToVIP() not implemented yet") // FIXME: Technical debt
}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (s *Stack) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) error {
	return scerr.NotImplementedError("UnbindHostFromVIP() not implemented yet") // FIXME: Technical debt
}

// DeleteVIP deletes the port corresponding to the VIP
func (s *Stack) DeleteVIP(vip *abstract.VirtualIP) error {
	return scerr.NotImplementedError("DeleteVIP() not implemented yet") // FIXME: Technical debt
}
