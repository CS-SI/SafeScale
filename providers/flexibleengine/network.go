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

package flexibleengine

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/api/IPVersion"
	metadata "github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/utils/retry"
	"github.com/CS-SI/SafeScale/utils/retry/Verdict"

	gc "github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/pengux/check"
)

//VPCRequest defines a request to create a VPC
type VPCRequest struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

//VPC contains information about a VPC
type VPC struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	CIDR    string `json:"cidr,omitempty"`
	Status  string `json:"status,omitempty"`
	Network *networks.Network
	Router  *routers.Router
}

type vpcCommonResult struct {
	gc.Result
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
type vpcDeleteResult struct {
	gc.ErrResult
}

//CreateVPC creates a network, which is managed by VPC in FlexibleEngine
func (client *Client) CreateVPC(req VPCRequest) (*VPC, error) {
	// Only one VPC allowed by client instance
	if client.vpc != nil {
		return nil, fmt.Errorf("failed to create VPC '%s', a VPC named '%s' is already in use", req.Name, client.vpc.Name)
	}

	b, err := gc.BuildRequestBody(req, "vpc")
	if err != nil {
		return nil, fmt.Errorf("Error creating VPC %s: %s", req.Name, providerError(err))
	}

	resp := vpcCreateResult{}
	url := client.osclt.Network.Endpoint + "v1/" + client.Opts.ProjectID + "/vpcs"
	opts := gc.RequestOpts{
		JSONBody:     b,
		JSONResponse: &resp.Body,
		OkCodes:      []int{200, 201},
	}
	_, err = client.osclt.Provider.Request("POST", url, &opts)
	vpc, err := resp.Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating VPC %s: %s", req.Name, providerError(err))
	}

	// Searching for the OpenStack Router corresponding to the VPC (router.id == vpc.id)
	router, err := routers.Get(client.osclt.Network, vpc.ID).Extract()
	if err != nil {
		client.DeleteVPC(vpc.ID)
		return nil, fmt.Errorf("Error creating VPC %s: %s", req.Name, providerError(err))
	}
	vpc.Router = router

	// Searching for the OpenStack Network corresponding to the VPC (network.name == vpc.id)
	network, err := client.findOpenstackNetworkByName(vpc.ID)
	if err != nil {
		return nil, fmt.Errorf("Error creating VPC %s: %s", req.Name, providerError(err))
	}
	vpc.Network = network

	return vpc, nil
}

func (client *Client) findOpenstackNetworkByName(name string) (*networks.Network, error) {
	// Searching for the network corresponding to the VPC (network.name == vpc.id)
	pager := networks.List(client.osclt.Network, networks.ListOpts{
		Name: name,
	})
	var network networks.Network
	found := false
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := networks.ExtractNetworks(page)
		if err != nil {
			return false, fmt.Errorf("Error finding Openstack Network named '%s': %s", name, providerError(err))
		}
		for _, n := range list {
			if n.Name == name {
				found = true
				network = n
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to find Openstack Network named '%s': %s", name, providerError(err))
	}
	if found {
		return &network, nil
	}
	return nil, fmt.Errorf("Openstack Network named '%s' not found", name)
}

// GetVPC returns the information about a VPC identified by 'id'
func (client *Client) GetVPC(id string) (*VPC, error) {
	r := vpcGetResult{}
	url := client.osclt.Network.Endpoint + "v1/" + client.Opts.ProjectID + "/vpcs/" + id
	opts := gc.RequestOpts{
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	_, err := client.osclt.Provider.Request("GET", url, &opts)
	r.Err = err
	vpc, err := r.Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting Network %s: %s", id, providerError(err))
	}
	return vpc, nil
}

// ListVPCs lists all the VPC created
func (client *Client) ListVPCs() ([]VPC, error) {
	var vpcList []VPC
	return vpcList, fmt.Errorf("flexibleengine.ListVPCs() not yet implemented")
}

// DeleteVPC deletes a Network (ie a VPC in Flexible Engine) identified by 'id'
func (client *Client) DeleteVPC(id string) error {
	return fmt.Errorf("flexibleengine.DeleteVPC() not implemented yet")
}

// CreateNetwork creates a network (ie a subnet in the network associated to VPC in FlexibleEngine
func (client *Client) CreateNetwork(req api.NetworkRequest) (*api.Network, error) {
	subnet, err := client.findSubnetByName(req.Name)
	if subnet == nil && err != nil {
		return nil, err
	}
	if subnet != nil {
		return nil, fmt.Errorf("network '%s' already exists", req.Name)
	}

	if ok, err := validateNetworkName(req); !ok {
		return nil, fmt.Errorf("network name '%s' invalid: %s", req.Name, err)
	}

	subnet, err = client.createSubnet(req.Name, req.CIDR)
	if err != nil {
		return nil, fmt.Errorf("error creating network '%s': %s", req.Name, providerError(err))
	}

	// Creates metadata for the subnet
	network := &api.Network{
		ID:        subnet.ID,
		Name:      subnet.Name,
		CIDR:      subnet.CIDR,
		IPVersion: fromIntIPVersion(subnet.IPVersion),
	}
	err = metadata.SaveNetwork(providers.FromClient(client), network)
	if err != nil {
		client.DeleteNetwork(subnet.ID)
		return nil, err
	}

	return network, nil
}

// validateNetworkName validates the name of a Network based on known FlexibleEngine requirements
func validateNetworkName(req api.NetworkRequest) (bool, error) {
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

// GetNetwork returns the network identified by id
func (client *Client) GetNetwork(id string) (*api.Network, error) {
	m, err := metadata.LoadNetwork(providers.FromClient(client), id)
	if err != nil {
		return nil, err
	}
	if m != nil {
		return m.Get(), nil
	}

	subnet, err := client.getSubnet(id)
	if err != nil {
		return nil, fmt.Errorf("failed getting network id '%s': %s", id, providerError(err))
	}
	return &api.Network{
		ID:        subnet.ID,
		Name:      subnet.Name,
		CIDR:      subnet.CIDR,
		IPVersion: fromIntIPVersion(subnet.IPVersion),
	}, nil
}

// ListNetworks lists available networks
func (client *Client) ListNetworks(all bool) ([]api.Network, error) {
	if all {
		return client.listAllNetworks()
	}
	return client.listMonitoredNetworks()
}

// listAllNetworks lists available networks
func (client *Client) listAllNetworks() ([]api.Network, error) {
	subnetList, err := client.listSubnets()
	if err != nil {
		return nil, fmt.Errorf("Failed to get networks list: %s", providerError(err))
	}
	var networkList []api.Network
	for _, subnet := range *subnetList {
		networkList = append(networkList, api.Network{
			ID:        subnet.ID,
			Name:      subnet.Name,
			CIDR:      subnet.CIDR,
			IPVersion: fromIntIPVersion(subnet.IPVersion),
		})
	}
	return networkList, nil
}

// listMonitoredNetworks lists available networks created by SafeScale (ie those registered in object storage)
func (client *Client) listMonitoredNetworks() ([]api.Network, error) {
	var netList []api.Network
	m, err := metadata.NewNetwork(providers.FromClient(client))
	if err != nil {
		return netList, err
	}
	err = m.Browse(func(net *api.Network) error {
		netList = append(netList, *net)
		return nil
	})
	if len(netList) == 0 && err != nil {
		return nil, fmt.Errorf("Error listing networks: %s", providerError(err))
	}
	return netList, nil
}

// DeleteNetwork consists to delete subnet in FlexibleEngine VPC
func (client *Client) DeleteNetwork(id string) error {
	m, err := metadata.LoadNetwork(providers.FromClient(client), id)
	if err != nil {
		return err
	}
	if m == nil {
		return fmt.Errorf("failed to find network '%s' metadata", id)
	}
	vms, err := m.ListHosts()
	if err != nil {
		return err
	}
	gwID := m.Get().GatewayID
	if len(vms) > 0 {
		var allvms []string
		for _, i := range vms {
			if gwID != i.ID {
				allvms = append(allvms, i.Name)
			}
		}
		if len(allvms) > 0 {
			var lenS string
			if len(allvms) > 1 {
				lenS = "s"
			}
			return fmt.Errorf("network '%s' still has %d host%s attached (%s)", id, len(allvms), lenS, strings.Join(allvms, ","))
		}
	}

	err = client.DeleteGateway(id)
	if err != nil {
		return fmt.Errorf("failed to delete gateway of network '%s': %s", m.Get().Name, providerError(err))
	}
	err = client.deleteSubnet(id)
	if err != nil {
		return err
	}
	return m.Delete()
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
	gc.Result
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
	gc.ErrResult
}

// convertIPv4ToNumber converts a net.IP to a uint32 representation
func convertIPv4ToNumber(IP net.IP) (uint32, error) {
	if IP.To4() == nil {
		return 0, fmt.Errorf("Not an IPv4")
	}
	n := uint32(IP[0])*0x1000000 + uint32(IP[1])*0x10000 + uint32(IP[2])*0x100 + uint32(IP[3])
	return n, nil
}

// convertNumberToIPv4 converts a uint32 representation of an IPv4 Address to net.IP
func convertNumberToIPv4(n uint32) net.IP {
	a := byte(n >> 24)
	b := byte((n & 0xff0000) >> 16)
	c := byte((n & 0xff00) >> 8)
	d := byte(n & 0xff)
	IP := net.IPv4(a, b, c, d)
	return IP
}

// cidrIntersects tells if the 2 CIDR passed as parameter intersect
func cidrIntersects(n1, n2 *net.IPNet) bool {
	return n2.Contains(n1.IP) || n1.Contains(n2.IP)
}

// createSubnet creates a subnet using native FlexibleEngine API
func (client *Client) createSubnet(name string, cidr string) (*subnets.Subnet, error) {
	// Checks if subnet is inside CIDR of VPC
	_, vpcnetDesc, _ := net.ParseCIDR(client.vpc.CIDR)
	network, networkDesc, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to create subnet '%s (%s)': %s", name, cidr, providerError(err))
	}
	if !cidrIntersects(vpcnetDesc, networkDesc) {
		return nil, fmt.Errorf("can't create subnet with CIDR '%s': not inside network CIDR '%s'", cidr, client.vpc.CIDR)
	}

	// Validates CIDR regarding the existing subnets
	subnets, err := client.listSubnets()
	if err != nil {
		return nil, err
	}
	for _, s := range *subnets {
		_, sDesc, _ := net.ParseCIDR(s.CIDR)
		if cidrIntersects(networkDesc, sDesc) {
			return nil, fmt.Errorf("can't create subnet '%s (%s)', would intersect with '%s (%s)'", name, cidr, s.Name, s.CIDR)
		}
	}

	// Calculate IP address for gateway
	n, err := convertIPv4ToNumber(network.To4())
	if err != nil {
		return nil, fmt.Errorf("failed to choose gateway IP address for the subnet: %s", providerError(err))
	}
	gw := convertNumberToIPv4(n + 1)

	bYes := true
	req := subnetRequest{
		Name:         name,
		CIDR:         cidr,
		VPCID:        client.vpc.ID,
		DHCPEnable:   &bYes,
		GatewayIP:    gw.String(),
		PrimaryDNS:   "100.125.0.41",
		SecondaryDNS: "100.126.0.41",
		DNSList: []string{
			"100.125.0.41",
			"100.126.0.41",
		},
	}
	b, err := gc.BuildRequestBody(req, "subnet")
	if err != nil {
		return nil, fmt.Errorf("error preparing Subnet %s creation: %s", req.Name, providerError(err))
	}

	respCreate := subnetCreateResult{}
	url := fmt.Sprintf("%sv1/%s/subnets", client.osclt.Network.Endpoint, client.Opts.ProjectID)
	opts := gc.RequestOpts{
		JSONBody:     b,
		JSONResponse: &respCreate.Body,
		OkCodes:      []int{200, 201},
	}
	_, err = client.osclt.Provider.Request("POST", url, &opts)
	if err != nil {
		return nil, fmt.Errorf("error requesting Subnet %s creation: %s", req.Name, providerError(err))
	}
	subnet, err := respCreate.Extract()
	if err != nil {
		return nil, fmt.Errorf("error creating Subnet %s: %s", req.Name, providerError(err))
	}

	// Subnet creation started, need to wait the subnet to reach the status ACTIVE
	respGet := subnetGetResult{}
	opts.JSONResponse = &respGet.Body
	opts.JSONBody = nil

	retryErr := retry.WhileUnsuccessfulDelay1SecondWithNotify(
		func() error {
			_, err = client.osclt.Provider.Request("GET", fmt.Sprintf("%s/%s", url, subnet.ID), &opts)
			if err == nil {
				subnet, err = respGet.Extract()
				if err == nil && subnet.Status == "ACTIVE" {
					return nil
				}
			}
			return err
		},
		time.Minute,
		func(try retry.Try, verdict Verdict.Enum) {
			log.Printf("FlexibleEngine.Client.createSubnet(%s): try #%d: verdict=%s, err=%v", name, try.Count, verdict.String(), try.Err)
		},
	)
	return &subnet.Subnet, retryErr
}

// ListSubnets lists available subnet in VPC
func (client *Client) listSubnets() (*[]subnets.Subnet, error) {
	url := client.osclt.Network.Endpoint + "v1/" + client.Opts.ProjectID + "/subnets?vpc_id=" + client.vpc.ID
	pager := pagination.NewPager(client.osclt.Network, url, func(r pagination.PageResult) pagination.Page {
		return subnets.SubnetPage{LinkedPageBase: pagination.LinkedPageBase{PageResult: r}}
	})
	var subnetList []subnets.Subnet
	pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := subnets.ExtractSubnets(page)
		if err != nil {
			return false, fmt.Errorf("Error listing subnets: %s", providerError(err))
		}

		for _, subnet := range list {
			subnetList = append(subnetList, subnet)
		}
		return true, nil
	})
	return &subnetList, nil
}

// getSubnet lists available subnet in VPC
func (client *Client) getSubnet(id string) (*subnets.Subnet, error) {
	r := subnetGetResult{}
	url := client.osclt.Network.Endpoint + "v1/" + client.Opts.ProjectID + "/subnets/" + id
	opts := gc.RequestOpts{
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	_, err := client.osclt.Provider.Request("GET", url, &opts)
	r.Err = err
	subnet, err := r.Extract()
	if err != nil {
		return nil, fmt.Errorf("Failed to get information for subnet id '%s': %s", id, providerError(err))
	}
	return &subnet.Subnet, nil
}

// deleteSubnet deletes a subnet
func (client *Client) deleteSubnet(id string) error {
	resp := subnetDeleteResult{}
	url := client.osclt.Network.Endpoint + "v1/" + client.Opts.ProjectID + "/vpcs/" + client.vpc.ID + "/subnets/" + id
	opts := gc.RequestOpts{
		OkCodes: []int{204},
	}

	// FlexibleEngine has the curious behavior to be able to tell us all Hosts are deleted, but
	// can't delete the subnet because there is still at least one host...
	// So we retry subnet deletion until all hosts are really deleted and subnet can be deleted
	err := retry.Action(
		func() error {
			_, err := client.osclt.Provider.Request("DELETE", url, &opts)
			return err
		},
		retry.PrevailDone(retry.Unsuccessful(), retry.Timeout(time.Minute*5)),
		retry.Constant(time.Second*3),
		nil, nil,
		func(t retry.Try, verdict Verdict.Enum) {
			if r, ok := t.Err.(gc.ErrDefault500); ok {
				var v map[string]string
				jsonErr := json.Unmarshal(r.Body, &v)
				if jsonErr == nil {
					log.Printf("flexibleengine.Client.deleteSubnet(%s): try #%d, verdict=%s,  err: '%s'", id, t.Count, verdict.String(), v["message"])
					return
				}
			}
			log.Printf("flexibleengine.Client.deleteSubnet(%s): try #%d, verdict=%s, err: '%v'", id, t.Count, verdict.String(), t.Err)
		},
	)
	if err != nil {
		return fmt.Errorf("failed to submit deletion of subnet id '%s': '%s", id, err.Error())
	}
	// Deletion submit has been executed, checking returned error code
	err = resp.ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting subnet id '%s': %s", id, providerError(err))
	}
	return nil
}

// findSubnetByName returns a subnets.Subnet if subnet named as 'name' exists
func (client *Client) findSubnetByName(name string) (*subnets.Subnet, error) {
	subnetList, err := client.listSubnets()
	if err != nil {
		return nil, fmt.Errorf("Failed to find in Subnets: %s", providerError(err))
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
		return nil, nil
	}
	return &subnet, nil
}

func fromIntIPVersion(v int) IPVersion.Enum {
	if v == 4 {
		return IPVersion.IPv4
	}
	if v == 6 {
		return IPVersion.IPv6
	}
	return -1
}

// CreateGateway creates a gateway for a network.
// By current implementation, only one gateway can exist by Network because the object is intended
// to contain only one vmID
func (client *Client) CreateGateway(req api.GWRequest) error {
	net, err := client.GetNetwork(req.NetworkID)
	if err != nil {
		return fmt.Errorf("Network %s not found: %s", req.NetworkID, providerError(err))
	}
	gwname := req.GWName
	if gwname == "" {
		gwname = "gw-" + net.Name
	}
	vmReq := api.VMRequest{
		ImageID:    req.ImageID,
		KeyPair:    req.KeyPair,
		Name:       gwname,
		TemplateID: req.TemplateID,
		NetworkIDs: []string{req.NetworkID},
		PublicIP:   true,
	}
	vm, err := client.createVM(vmReq, true)
	if err != nil {
		return fmt.Errorf("error creating gateway : %s", providerError(err))
	}
	svc := providers.FromClient(client)
	m, err := metadata.NewGateway(svc, req.NetworkID)
	if err == nil {
		err = m.Carry(vm).Write(svc)
	}
	if err != nil {
		client.DeleteVM(vm.ID)
		return fmt.Errorf("error creating gateway : %s", err.Error())
	}
	return nil
}

// GetGateway returns the name of the gateway of a network
func (client *Client) GetGateway(networkID string) (*api.VM, error) {
	m, err := metadata.LoadGateway(providers.FromClient(client), networkID)
	if err != nil {
		return nil, err
	}
	if m != nil {
		return m.Get(), nil
	}
	return nil, fmt.Errorf("failed to load gateway metadata")
}

// DeleteGateway deletes the gateway associated with network identified by ID
func (client *Client) DeleteGateway(networkID string) error {
	m, err := metadata.LoadGateway(providers.FromClient(client), networkID)
	if err != nil {
		return err
	}
	if m != nil {
		err = client.DeleteVM(m.Get().ID)
		if err != nil {
			return err
		}
		return m.Delete()
	}
	return fmt.Errorf("failed to load gateway metadata")
}
