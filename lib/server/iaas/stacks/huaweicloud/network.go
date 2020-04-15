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

package huaweicloud

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/pengux/check"
	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// VPCRequest defines a request to create a VPC
type VPCRequest struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

// VPC contains information about a VPC
type VPC struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	CIDR    string `json:"cidr,omitempty"`
	Status  string `json:"status,omitempty"`
	Network *networks.Network
	Router  *routers.Router
}

type vpcCommonResult struct {
	gophercloud.Result
}

// Extract is a function that accepts a result and extracts a Network/VPC from FlexibleEngine response.
func (r vpcCommonResult) Extract() (*VPC, error) {
	var s struct {
		VPC *VPC `json:"vpc"`
	}
	err := r.ExtractInto(&s)
	return s.VPC, err
}

type vpcCreateResult struct {
	vpcCommonResult
}
type vpcGetResult struct {
	vpcCommonResult
}
type vpcDeleteResult struct { // nolint
	gophercloud.ErrResult
}

// CreateVPC creates a network, which is managed by VPC in FlexibleEngine
func (s *Stack) CreateVPC(req VPCRequest) (*VPC, error) {
	// Only one VPC allowed by client instance
	if s.vpc != nil {
		return nil, scerr.DuplicateError("failed to create VPC '%s', a VPC with this name already exists", req.Name)
	}

	b, err := gophercloud.BuildRequestBody(req, "vpc")
	if err != nil {
		return nil, scerr.NewError("failed to create VPC '%s': %s", req.Name, openstack.ProviderErrorToString(err))
	}

	resp := vpcCreateResult{}
	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/vpcs"
	opts := gophercloud.RequestOpts{
		JSONBody:     b,
		JSONResponse: &resp.Body,
		OkCodes:      []int{200, 201},
	}
	_, err = s.Stack.Driver.Request("POST", url, &opts)
	if err != nil {
		return nil, scerr.NewError("failed to send a POST request to provider '%s': %s", req.Name, openstack.ProviderErrorToString(err))
	}
	vpc, err := resp.Extract()
	if err != nil {
		return nil, scerr.NewError("failed to create VPC '%s': %s", req.Name, openstack.ProviderErrorToString(err))
	}

	// Searching for the OpenStack Router corresponding to the VPC (router.id == vpc.id)
	router, err := routers.Get(s.Stack.NetworkClient, vpc.ID).Extract()
	if err != nil {
		nerr := s.DeleteVPC(vpc.ID)
		if nerr != nil {
			logrus.Warnf("Error deleting VPC: %v", nerr)
		}
		return nil, scerr.NewError("failed to create VPC '%s': %s", req.Name, openstack.ProviderErrorToString(err))
	}
	vpc.Router = router

	// Searching for the Network binded to the VPC
	network, err := s.findVPCBindedNetwork(vpc.Name)
	if err != nil {
		return nil, scerr.NewError("failed to create VPC '%s': %s", req.Name, openstack.ProviderErrorToString(err))
	}
	vpc.Network = network

	return vpc, nil
}

func (s *Stack) findVPCBindedNetwork(vpcName string) (*networks.Network, error) {
	var router *openstack.Router
	found := false
	routerList, err := s.Stack.ListRouters()
	if err != nil {
		return nil, scerr.NewError("failed to list routers: %s", openstack.ProviderErrorToString(err))
	}
	for _, r := range routerList {
		if r.Name == vpcName {
			found = true
			router = &r
			break
		}
	}
	if !found || router == nil {
		return nil, scerr.NotFoundError(nil, nil, "failed to find router associated to VPC '%s'", vpcName)
	}

	network, err := networks.Get(s.Stack.NetworkClient, router.NetworkID).Extract()
	if err != nil {
		return nil, scerr.NotFoundError("failed to find binded network of VPC '%s': %s", vpcName, openstack.ProviderErrorToString(err))
	}
	return network, nil
}

// GetVPC returns the information about a VPC identified by 'id'
func (s *Stack) GetVPC(id string) (*VPC, error) {
	r := vpcGetResult{}
	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/vpcs/" + id
	opts := gophercloud.RequestOpts{
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	_, err := s.Stack.Driver.Request("GET", url, &opts)
	r.Err = err
	vpc, err := r.Extract()
	if err != nil {
		return nil, scerr.NewError("error getting Network %s: %s", id, openstack.ProviderErrorToString(err))
	}
	return vpc, nil
}

// ListVPCs lists all the VPC created
func (s *Stack) ListVPCs() ([]VPC, error) {
	var vpcList []VPC
	return vpcList, scerr.NotImplementedError("huaweicloud.Stack::ListVPCs() not implemented yet") // FIXME Technical debt
}

// DeleteVPC deletes a Network (ie a VPC in Huawei Cloud) identified by 'id'
func (s *Stack) DeleteVPC(id string) error {
	return scerr.NotImplementedError("huaweicloud.Stack::DeleteVPC() not implemented yet") // FIXME Technical debt
}

// CreateNetwork creates a network (ie a subnet in the network associated to VPC in FlexibleEngine
func (s *Stack) CreateNetwork(req abstract.NetworkRequest) (network *abstract.Network, err error) {
	tracer := concurrency.NewTracer(nil, true, "(%s)", req.Name).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()

	subnet, err := s.findSubnetByName(req.Name)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return nil, err
		}
	}
	if subnet != nil {
		return nil, scerr.DuplicateError("network '%s' already exists", req.Name)
	}

	if ok, err := validateNetworkName(req); !ok {
		return nil, scerr.Wrap(err, "network name '%s' invalid", req.Name)
	}

	// Checks if CIDR is valid...
	_, vpcnetDesc, _ := net.ParseCIDR(s.vpc.CIDR)
	if req.CIDR != "" {
		_, networkDesc, err := net.ParseCIDR(req.CIDR)
		if err != nil {
			return nil, scerr.Wrap(err, "failed to create subnet '%s (%s)'", req.Name, req.CIDR)
		}
		// ... and if CIDR is inside VPC's one
		if !utils.CIDROverlap(*vpcnetDesc, *networkDesc) {
			return nil, scerr.InvalidRequestError("cannot create subnet with CIDR '%s': not inside VPC CIDR '%s'", req.CIDR, s.vpc.CIDR)
		}
		if vpcnetDesc.IP.Equal(networkDesc.IP) {
			return nil, scerr.InvalidRequestError("cannot create subnet with CIDR '%s': network part of CIDR is equal to VPC one (%s)", req.CIDR, networkDesc.IP.String())
		}
	} else { // CIDR is empty, choose the first Class C one possible
		tracer.Trace("CIDR is empty, choosing one...")

		mask, _ := vpcnetDesc.Mask.Size()
		var bitShift uint8
		if mask >= 24 {
			bitShift = 1
		} else {
			bitShift = 24 - uint8(mask)
		}
		ipNet, err := utils.FirstIncludedSubnet(*vpcnetDesc, bitShift)
		if err != nil {
			return nil, scerr.Wrap(err, "failed to choose a CIDR for the subnet")
		}
		req.CIDR = ipNet.String()
		tracer.Trace("CIDR chosen for network is '%s'", req.CIDR)
	}

	// Creates the subnet
	subnet, err = s.createSubnet(req.Name, req.CIDR)
	if err != nil {
		return nil, scerr.NewError("error creating network '%s': %s", req.Name, openstack.ProviderErrorToString(err))
	}

	// starting from here delete network
	defer func() {
		if err != nil {
			derr := s.deleteSubnet(subnet.ID)
			if derr != nil {
				logrus.Errorf("failed to delete subnet '%s': %v", subnet.Name, derr)
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	network = abstract.NewNetwork()
	network.ID = subnet.ID
	network.Name = subnet.Name
	network.CIDR = subnet.CIDR
	network.IPVersion = fromIntIPVersion(subnet.IPVersion)

	return network, nil
}

// validateNetworkName validates the name of a Network based on known FlexibleEngine requirements
func validateNetworkName(req abstract.NetworkRequest) (bool, error) {
	s := check.Struct{
		"Name": check.Composite{
			check.NonEmpty{},
			check.Regex{Constraint: `^[a-zA-Z0-9_-]+$`},
			check.MaxChar{Constraint: 64},
		},
	}

	e := s.Validate(req)
	if e.HasErrors() {
		errors, _ := e.GetErrorsByKey("Name")
		var errs []string
		for _, msg := range errors {
			errs = append(errs, msg.Error())
		}
		return false, fmt.Errorf(strings.Join(errs, "; "))
	}
	return true, nil
}

// GetNetworkByName ...
func (s *Stack) GetNetworkByName(name string) (*abstract.Network, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	// Gophercloud doesn't propose the way to get a host by name, but OpenStack knows how to do it...
	r := networks.GetResult{}
	_, r.Err = s.Stack.NetworkClient.Get(s.Stack.NetworkClient.ServiceURL("subnets?name="+name), &r.Body, &gophercloud.RequestOpts{
		OkCodes: []int{200, 203},
	})
	if r.Err != nil {
		if _, ok := r.Err.(gophercloud.ErrDefault403); ok {
			return nil, abstract.ResourceForbiddenError("network", name)
		}
		return nil, scerr.NewError("query for network '%s' failed: %v", name, r.Err)
	}
	subnetworks, found := r.Body.(map[string]interface{})["subnets"].([]interface{})
	if found && len(subnetworks) > 0 {
		var (
			entry map[string]interface{}
			id    string
		)
		for _, s := range subnetworks {
			entry = s.(map[string]interface{})
			id = entry["id"].(string)
		}
		return s.GetNetwork(id)
	}
	return nil, abstract.ResourceNotFoundError("network", name)
}

// GetNetwork returns the network identified by id
func (s *Stack) GetNetwork(id string) (*abstract.Network, error) {
	subnet, err := s.getSubnet(id)
	if err != nil {
		spew.Dump(err)
		if !strings.Contains(err.Error(), id) {
			return nil, scerr.NewError("failed getting network id '%s': %s", id, openstack.ProviderErrorToString(err))
		}
	}
	if subnet == nil || subnet.ID == "" {
		return nil, abstract.ResourceNotFoundError("subnet", id)
	}

	newNet := abstract.NewNetwork()
	newNet.ID = subnet.ID
	newNet.Name = subnet.Name
	newNet.CIDR = subnet.CIDR
	newNet.IPVersion = fromIntIPVersion(subnet.IPVersion)
	return newNet, nil
}

// ListNetworks lists networks
func (s *Stack) ListNetworks() ([]*abstract.Network, error) {
	subnetList, err := s.listSubnets()
	if err != nil {
		return nil, scerr.NewError("failed to get networks list: %s", openstack.ProviderErrorToString(err))
	}
	var networkList []*abstract.Network
	for _, subnet := range *subnetList {
		newNet := abstract.NewNetwork()
		newNet.ID = subnet.ID
		newNet.Name = subnet.Name
		newNet.CIDR = subnet.CIDR
		newNet.IPVersion = fromIntIPVersion(subnet.IPVersion)
		networkList = append(networkList, newNet)
	}
	return networkList, nil
}

// DeleteNetwork consists to delete subnet in FlexibleEngine VPC
func (s *Stack) DeleteNetwork(id string) error {
	return s.deleteSubnet(id)
}

type subnetRequest struct {
	Name             string   `json:"name"`
	CIDR             string   `json:"cidr"`
	GatewayIP        string   `json:"gateway_ip"`
	DHCPEnable       *bool    `json:"dhcp_enable,omitempty"`
	PrimaryDNS       string   `json:"primary_dns,omitempty"`
	SecondaryDNS     string   `json:"secondary_dns,omitempty"`
	DNSList          []string `json:"dnsList,omitempty"`
	AvailabilityZone string   `json:"availability_zone,omitempty"`
	VPCID            string   `json:"vpc_id"`
}

type subnetCommonResult struct {
	gophercloud.Result
}

type subnetEx struct {
	subnets.Subnet
	Status string `json:"status"`
}

// Extract is a function that accepts a result and extracts a Subnet from FlexibleEngine response.
func (r subnetCommonResult) Extract() (*subnetEx, error) {
	var s struct {
		//		Subnet *subnets.Subnet `json:"subnet"`
		Subnet *subnetEx `json:"subnet"`
	}
	err := r.ExtractInto(&s)
	return s.Subnet, err
}

type subnetCreateResult struct {
	subnetCommonResult
}
type subnetGetResult struct {
	subnetCommonResult
}
type subnetDeleteResult struct {
	gophercloud.ErrResult
}

// createSubnet creates a subnet using native FlexibleEngine API
func (s *Stack) createSubnet(name string, cidr string) (*subnets.Subnet, error) {
	const CANNOT = "cannot create subnet"

	network, networkDesc, _ := net.ParseCIDR(cidr)

	// Validates CIDR regarding the existing subnets
	subnetworks, err := s.listSubnets()
	if err != nil {
		return nil, err
	}
	for _, s := range *subnetworks {
		_, sDesc, _ := net.ParseCIDR(s.CIDR)
		if utils.CIDROverlap(*networkDesc, *sDesc) {
			return nil, scerr.Wrap(err, "would intersect with '%s (%s)'", s.Name, s.CIDR)
		}
	}

	// Calculate IP address for gateway
	n := utils.IPv4ToUInt32(network)
	gw := utils.UInt32ToIPv4(n + 1)

	dnsList := s.cfgOpts.DNSList
	if len(dnsList) == 0 {
		dnsList = []string{"1.1.1.1"}
	}
	var (
		primaryDNS   string
		secondaryDNS string
	)
	if len(dnsList) >= 1 {
		primaryDNS = dnsList[0]
	}
	if len(dnsList) >= 2 {
		secondaryDNS = dnsList[1]
	}
	bYes := true
	req := subnetRequest{
		Name:         name,
		CIDR:         cidr,
		VPCID:        s.vpc.ID,
		DHCPEnable:   &bYes,
		GatewayIP:    gw.String(),
		PrimaryDNS:   primaryDNS,
		SecondaryDNS: secondaryDNS,
		DNSList:      dnsList,
	}
	b, err := gophercloud.BuildRequestBody(req, "subnet")
	if err != nil {
		return nil, scerr.NewError("error preparing subnet %s creation: %s", req.Name, openstack.ProviderErrorToString(err))
	}

	respCreate := subnetCreateResult{}
	url := fmt.Sprintf("%sv1/%s/subnets", s.Stack.NetworkClient.Endpoint, s.authOpts.ProjectID)
	opts := gophercloud.RequestOpts{
		JSONBody:     b,
		JSONResponse: &respCreate.Body,
		OkCodes:      []int{200, 201},
	}
	_, err = s.Stack.Driver.Request("POST", url, &opts)
	if err != nil {
		tErr := openstack.TranslateProviderError(err)
		switch tErr.(type) { // nolint
		case scerr.ErrInvalidRequest:
			body := map[string]interface{}{}
			err = json.Unmarshal([]byte(tErr.Error()), &body)
			if err != nil {
				err = scerr.InconsistentError("response is not json")
			} else {
				code, _ := body["code"].(string)
				switch code {
				case "VPC.0003":
					err = scerr.NotFoundError("VPC has vanished")
				default:
					err = scerr.Wrap(tErr, fmt.Sprintf("response code '%s' is not handled", code))
				}
			}
			return nil, scerr.Wrap(err, CANNOT)
		}
		return nil, scerr.Wrap(tErr, CANNOT)
	}

	subnet, err := respCreate.Extract()
	if err != nil {
		return nil, scerr.Wrap(err, CANNOT)
	}

	// Subnet creation started, need to wait the subnet to reach the status ACTIVE
	respGet := subnetGetResult{}
	opts.JSONResponse = &respGet.Body
	opts.JSONBody = nil

	retryErr := retry.WhileUnsuccessfulDelay1SecondWithNotify(
		func() error {
			_, err = s.Stack.Driver.Request("GET", fmt.Sprintf("%s/%s", url, subnet.ID), &opts)
			if err == nil {
				subnet, err = respGet.Extract()
				if err == nil && subnet.Status == "ACTIVE" {
					return nil
				}
			}
			return err
		},
		temporal.GetContextTimeout(),
		func(try retry.Try, v verdict.Enum) {
			if v != verdict.Done {
				logrus.Debugf("Network '%s' is not in 'ACTIVE' state, retrying...", name)
			}
		},
	)
	return &subnet.Subnet, retryErr
}

// ListSubnets lists available subnet in VPC
func (s *Stack) listSubnets() (*[]subnets.Subnet, error) {
	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/subnets?vpc_id=" + s.vpc.ID
	pager := pagination.NewPager(s.Stack.NetworkClient, url, func(r pagination.PageResult) pagination.Page {
		return subnets.SubnetPage{LinkedPageBase: pagination.LinkedPageBase{PageResult: r}}
	})
	var subnetList []subnets.Subnet
	paginationErr := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := subnets.ExtractSubnets(page)
		if err != nil {
			return false, scerr.NewError("error listing subnets: %s", openstack.ProviderErrorToString(err))
		}

		subnetList = append(subnetList, list...)

		return true, nil
	})

	// TODO previously we ignored the error here, consider returning nil, paginationErr
	if paginationErr != nil {
		logrus.Warnf("We have a pagination error: %v", paginationErr)
	}

	return &subnetList, nil
}

// getSubnet lists available subnet in VPC
func (s *Stack) getSubnet(id string) (*subnets.Subnet, error) {
	r := subnetGetResult{}
	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/subnets/" + id
	opts := gophercloud.RequestOpts{
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	_, err := s.Stack.Driver.Request("GET", url, &opts)
	r.Err = err
	subnet, err := r.Extract()
	if err != nil {
		return nil, scerr.NewError("failed to get information for subnet id '%s': %s", id, openstack.ProviderErrorToString(err))
	}
	return &subnet.Subnet, nil
}

// deleteSubnet deletes a subnet
func (s *Stack) deleteSubnet(id string) error {
	resp := subnetDeleteResult{}
	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/vpcs/" + s.vpc.ID + "/subnets/" + id
	opts := gophercloud.RequestOpts{
		OkCodes: []int{204},
	}

	// FlexibleEngine has the curious behavior to be able to tell us all Hosts are deleted, but
	// cannot delete the subnet because there is still at least one host...
	// So we retry subnet deletion until all hosts are really deleted and subnet can be deleted
	err := retry.Action(
		func() error {
			r, _ := s.Stack.Driver.Request("DELETE", url, &opts)
			if r == nil {
				return scerr.NewError("failed to acknowledge DELETE command submission")
			}
			switch r.StatusCode {
			case 404:
				logrus.Infof("subnet '%s' not found, considered as success", id)
				fallthrough
			case 200, 204:
				return nil
			case 409:
				return fmt.Errorf("409")
			default:
				return fmt.Errorf("DELETE command failed with status %d", r.StatusCode)
			}
		},
		retry.PrevailDone(retry.Unsuccessful(), retry.Timeout(temporal.GetHostCleanupTimeout())),
		retry.Constant(temporal.GetDefaultDelay()),
		nil, nil,
		func(t retry.Try, verdict verdict.Enum) {
			if t.Err != nil {
				switch t.Err.Error() {
				case "409":
					logrus.Debugf("network still owns host(s), retrying in %s...", temporal.GetDefaultDelay())
				default:
					logrus.Debugf("error submitting network deletion (status=%s), retrying in %s...", t.Err.Error(), temporal.GetDefaultDelay())
				}
			}
		},
	)
	if err != nil {
		return scerr.Wrap(err, "failed to submit deletion of subnet '%s'", id)
	}
	// Deletion submit has been executed, checking returned error code
	err = resp.ExtractErr()
	if err != nil {
		return scerr.NewError("error deleting subnet '%s': %s", id, openstack.ProviderErrorToString(err))
	}
	return nil
}

// findSubnetByName returns a subnets.Subnet if subnet named as 'name' exists
func (s *Stack) findSubnetByName(name string) (*subnets.Subnet, error) {
	subnetList, err := s.listSubnets()
	if err != nil {
		return nil, scerr.Wrap(err, "failed to find 'name' in subnets")
	}
	found := false
	var subnet subnets.Subnet
	for _, s := range *subnetList {
		if s.Name == name {
			found = true
			subnet = s
			break
		}
	}
	if !found {
		return nil, abstract.ResourceNotFoundError("subnet", name)
	}
	return &subnet, nil
}

func fromIntIPVersion(v int) ipversion.Enum {
	if v == 6 {
		return ipversion.IPv6
	}
	return ipversion.IPv4
}

// CreateGateway creates a gateway for a network.
// By current implementation, only one gateway can exist by Network because the object is intended
// to contain only one hostID
func (s *Stack) CreateGateway(req abstract.GatewayRequest) (*abstract.HostFull, *userdata.Content, error) {
	if s == nil {
		return nil, nil, scerr.InvalidInstanceError()
	}
	if req.Network == nil {
		return nil, nil, scerr.InvalidParameterError("req.Network", "cannot be nil")
	}

	gwname := req.Name
	if gwname == "" {
		gwname = "gw-" + req.Network.Name
	}

	tracer := concurrency.NewTracer(nil, true, "(%s)", gwname).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()

	hostReq := abstract.HostRequest{
		ImageID:      req.ImageID,
		KeyPair:      req.KeyPair,
		ResourceName: gwname,
		TemplateID:   req.TemplateID,
		Networks:     []*abstract.Network{req.Network},
		PublicIP:     true,
		Password:     "safescale", //VPL: for debug purposes, remove when not used anymore
	}
	host, userData, err := s.CreateHost(hostReq)
	if err != nil {
		switch err.(type) {
		case scerr.ErrInvalidRequest:
			return nil, userData, err
		default:
			return nil, userData, scerr.NewError("error creating gateway: %s", openstack.ProviderErrorToString(err))
		}
	}
	return host, userData, err
}

// DeleteGateway deletes the gateway associated with network identified by ID
func (s *Stack) DeleteGateway(id string) error {
	return s.DeleteHost(id)
}

// CreateVIP creates a private virtual IP
// If public is set to true,
func (s *Stack) CreateVIP(networkID string, name string) (*abstract.VirtualIP, error) {
	asu := true
	sg := []string{s.SecurityGroup.ID}
	options := ports.CreateOpts{
		NetworkID:      networkID,
		AdminStateUp:   &asu,
		Name:           name,
		SecurityGroups: &sg,
	}
	port, err := ports.Create(s.NetworkClient, options).Extract()
	if err != nil {
		return nil, err
	}
	vip := abstract.VirtualIP{
		ID:        port.ID,
		Name:      name,
		NetworkID: networkID,
		PrivateIP: port.FixedIPs[0].IPAddress,
	}
	return &vip, nil
}
