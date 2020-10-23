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

package huaweicloud

import (
	"fmt"
	"net"
	"strings"

	"github.com/pengux/check"
	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/retry/enums/verdict"
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

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (s *Stack) HasDefaultNetwork() bool {
	if s == nil {
		return false
	}
	return s.vpc != nil
}

// GetDefaultNetwork returns the *abstract.Network corresponding to the default network
func (s *Stack) GetDefaultNetwork() (*abstract.Network, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if s.vpc == nil {
		return nil, fail.NotFoundError("no default Network in Stack")
	}
	return s.vpc, nil
}

// CreateNetwork creates a Network, which corresponds to a VPC in FlexibleEngine terminology
func (s Stack) CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	gcReq := VPCRequest{
		Name: req.Name,
		CIDR: req.CIDR,
	}
	b, err := gophercloud.BuildRequestBody(gcReq, "vpc")
	if err != nil {
		return nil, normalizeError(err)
	}

	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/vpcs"
	resp := vpcCreateResult{}
	opts := gophercloud.RequestOpts{
		JSONBody:     b,
		JSONResponse: &resp.Body,
		OkCodes:      []int{200, 201},
	}
	commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, err = s.Stack.Driver.Request("POST", url, &opts)
			return normalizeError(err)
		},
		temporal.GetCommunicationTimeout(),
	)
	if commRetryErr != nil {
		return nil, fail.Wrap(commRetryErr, "query to create VPC failed")
	}
	vpc, err := resp.Extract()
	if err != nil {
		return nil, normalizeError(err)
	}

	// Searching for the OpenStack Router corresponding to the VPC (router.id == vpc.id)
	//var router *routers.Router
	//commRetryErr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
	//	func() (innerErr error) {
	//		router, innerErr = routers.Get(s.Stack.NetworkClient, vpc.ID).Extract()
	//		return normalizeError(innerErr)
	//	},
	//	temporal.GetCommunicationTimeout(),
	//)
	//if commRetryErr != nil {
	//	derr := s.DeleteNetwork(vpc.ID)
	//	if derr != nil {
	//		logrus.Warnf("Error deleting VPC: %v", derr)
	//		_ = commRetryErr.AddConsequence(derr)
	//	}
	//	return nil, fail.Wrap(commRetryErr, "failed to find OpenStack router of VPC")
	//}
	//vpc.Router = router

	// Searching for the Openstack Network bound to the VPC
	network, xerr := s.findOpenStackNetworkBoundToVPC(vpc.Name)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to find network binded to VPC")
	}
	_ = network.ID
	//vpc.Network = network

	an := abstract.NewNetwork()
	an.ID = vpc.ID
	an.Name = req.Name
	an.CIDR = req.CIDR
	an.DNSServers = req.DNSServers

	return an, nil
}

// findVPCBoundOpenstackNetwork finds the Openstack Network resource associated to Huaweicloud VPC
func (s *Stack) findOpenStackNetworkBoundToVPC(vpcName string) (*networks.Network, fail.Error) {
	var router *openstack.Router
	found := false
	routerList, xerr := s.Stack.ListRouters()
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to list routers")
	}
	for _, r := range routerList {
		if r.Name == vpcName {
			found = true
			router = &r
			break
		}
	}
	if !found || router == nil {
		return nil, fail.NotFoundError(nil, nil, "failed to find router associated to VPC '%s'", vpcName)
	}

	var network *networks.Network
	commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			network, innerErr = networks.Get(s.Stack.NetworkClient, router.NetworkID).Extract()
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if commRetryErr != nil {
		return nil, fail.Wrap(commRetryErr, "failed to get information of binded network")
	}
	return network, nil
}

// InspectNetwork returns the information about a VPC identified by 'id'
func (s *Stack) InspectNetwork(id string) (*abstract.Network, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if id = strings.TrimSpace(id); id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	r := vpcGetResult{}
	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/vpcs/" + id
	opts := gophercloud.RequestOpts{
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	var vpc *VPC
	commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			if _, innerErr = s.Stack.Driver.Request("GET", url, &opts); innerErr == nil {
				vpc, innerErr = r.Extract()
			}
			if innerErr != nil {
				return normalizeError(fail.Wrap(innerErr, "failed to query VPC %s", id))
			}
			return nil
		},
		temporal.GetCommunicationTimeout(),
	)
	if commRetryErr != nil {
		return nil, commRetryErr
	}

	//subnets, xerr := s.ListSubnets(an.ID)
	//if xerr != nil {
	//	return nil, fail.Wrap(xerr, "failed to list subnets of Network/VPC")
	//}
	//an.Subnets = make([]string, 0, len(subnets))
	//for _, v := range subnets {
	//	an.Subnets = append(an.Subnets, v.ID)
	//}
	return convertVPCToNetwork(*vpc), nil
}

//convertVPCToNetwork converts a VPC to an *abstract.Network
func convertVPCToNetwork(vpc VPC) *abstract.Network {
	an := abstract.NewNetwork()
	an.ID = vpc.ID
	an.Name = vpc.Name
	an.CIDR = vpc.CIDR
	return an
}

// InspectNetworkByName returns the information about a Network/VPC identified by 'name'
func (s *Stack) InspectNetworkByName(name string) (an *abstract.Network, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	nets, xerr := s.ListNetworks()
	if xerr != nil {
		return nil, xerr
	}

	an = nil
	for _, v := range nets {
		if v.Name == name {
			an = v
			break
		}
	}
	if an == nil {
		return nil, fail.NotFoundError("failed to find VPC named '%s'", name)
	}

	//subnets, xerr := s.ListSubnets(an.ID)
	//if xerr != nil {
	//	return nil, fail.Wrap(xerr, "failed to list subnets of Network/VPC")
	//}
	//an.Subnets = make([]string, 0, len(subnets))
	//for _, v := range subnets {
	//	an.Subnets = append(an.Subnets, v.ID)
	//}
	return an, nil
}

// ListNetworks lists all the Network/VPC created
func (s *Stack) ListNetworks() ([]*abstract.Network, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	r := vpcCommonResult{}
	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/vpcs"
	opts := gophercloud.RequestOpts{
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	xerr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			if _, innerErr = s.Stack.Driver.Request("GET", url, &opts); innerErr != nil {
				return normalizeError(fail.Wrap(innerErr, "failed to query VPCs"))
			}
			return nil
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		return nil, xerr
	}

	var list []*abstract.Network
	if vpcs, ok := r.Body.(map[string]interface{})["vpcs"].([]interface{}); ok {
		for _, v := range vpcs {
			item := v.(map[string]interface{})
			an := abstract.NewNetwork()
			an.Name = item["name"].(string)
			an.ID = item["id"].(string)
			//an.Description = item["description"].(string)
			an.CIDR = item["cidr"].(string)
			list = append(list, an)
		}
	}
	return list, nil
}

// DeleteNetwork deletes a Network/VPC identified by 'id'
func (s *Stack) DeleteNetwork(id string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	r := vpcCommonResult{}
	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/vpcs/" + id
	opts := gophercloud.RequestOpts{
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	return netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() (innerErr error) {
			if _, innerErr = s.Stack.Driver.Request("DELETE", url, &opts); innerErr == nil {
				return normalizeError(fail.Wrap(innerErr, "failed to delete VPC %s", id))
			}
			return nil
		},
		temporal.GetCommunicationTimeout(),
	)
}

// CreateSubnet creates a network (ie a subnet in the network associated to VPC in FlexibleEngine
func (s *Stack) CreateSubnet(req abstract.SubnetRequest) (subnet *abstract.Subnet, xerr fail.Error) {
	tracer := debug.NewTracer(nil, true, "(%s)", req.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	as, xerr := s.InspectSubnetByName(req.Network, req.Name)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return nil, xerr
		}
	}
	if as != nil {
		return nil, fail.DuplicateError("subnet '%s' already exists", req.Name)
	}

	if ok, xerr := validateNetworkName(req.Network); !ok {
		return nil, fail.Wrap(xerr, "network name '%s' invalid", req.Name)
	}

	an, xerr := s.InspectNetwork(req.Network)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			an, xerr = s.InspectNetworkByName(req.Network)
		}
	}
	if xerr != nil {
		return nil, xerr
	}

	// Checks if CIDR is valid...
	xerr = s.validateCIDR(&req, an)
	if xerr != nil {
		return nil, xerr
	}

	// Creates the subnet
	resp, xerr := s.createSubnet(req)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "error creating subnet '%s'", req.Name)
	}

	// starting from here delete network
	defer func() {
		if xerr != nil {
			derr := s.DeleteSubnet(resp.ID)
			if derr != nil {
				logrus.Errorf("failed to delete subnet '%s': %v", resp.Name, derr)
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	subnet = abstract.NewSubnet()
	subnet.ID = resp.ID
	subnet.Name = resp.Name
	subnet.CIDR = resp.CIDR
	subnet.IPVersion = fromIntIPVersion(resp.IPVersion)
	subnet.Network = an.ID

	return subnet, nil
}

func (s *Stack) validateCIDR(req *abstract.SubnetRequest, network *abstract.Network) fail.Error {
	_, networkDesc, _ := net.ParseCIDR(network.CIDR)
	if req.CIDR != "" {
		_, subnetDesc, err := net.ParseCIDR(req.CIDR)
		if err != nil {
			return fail.Wrap(err, "failed to validate CIDR '%s' for Subnet '%s'", req.CIDR, req.Name)
		}
		// ... and if CIDR is inside VPC's one
		if !netretry.CIDROverlap(*networkDesc, *subnetDesc) {
			return fail.InvalidRequestError("failed to validate CIDR '%s' for Subnet '%s': not inside VPC CIDR '%s'", req.CIDR, req.Name, s.vpc.CIDR)
		}
		if networkDesc.IP.Equal(subnetDesc.IP) && networkDesc.Mask.String() == subnetDesc.Mask.String() {
			return fail.InvalidRequestError("cannot create Subnet with CIDR '%s': equal to VPC one", req.CIDR)
		}
		return nil
	}

	// CIDR is empty, choose the first Class C available one
	logrus.Debugf("CIDR is empty, choosing one...")

	subnets, xerr := s.ListSubnets(req.Network)
	if xerr != nil {
		return xerr
	}

	var (
		bitShift uint8
		i, limit uint
		newIPNet net.IPNet
	)
	mask, _ := networkDesc.Mask.Size()
	if mask >= 24 {
		bitShift = 1
	} else {
		bitShift = 24 - uint8(mask)
	}
	limit = 1 << bitShift

	for i = uint(1); i < limit; i++ {
		newIPNet, xerr = netretry.NthIncludedSubnet(*networkDesc, bitShift, i)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to choose a CIDR for the subnet")
		}
		if wouldOverlap(subnets, newIPNet) == nil {
			break
		}
	}
	if i >= limit {
		return fail.OverflowError(nil, limit-1, "failed to find a free available CIDR ")
	}

	req.CIDR = newIPNet.String()
	logrus.Debugf("CIDR chosen for Subnet '%s' is '%s'", req.Name, req.CIDR)
	return nil
}

// validateNetworkName validates the name of a Network based on known FlexibleEngine requirements
func validateNetworkName(name string) (bool, fail.Error) {
	type checker struct{ Name string }
	s := check.Struct{
		"Name": check.Composite{
			check.NonEmpty{},
			check.Regex{Constraint: `^[a-zA-Z0-9_-]+$`},
			check.MaxChar{Constraint: 64},
		},
	}

	c := checker{Name: name}
	e := s.Validate(c)
	if e.HasErrors() {
		errors, _ := e.GetErrorsByKey("Name")
		var errs []string
		for _, msg := range errors {
			errs = append(errs, msg.Error())
		}
		return false, fail.NewError(strings.Join(errs, "; "))
	}
	return true, nil
}

// wouldOverlap returns fail.ErrOverloadError if subnet overlaps one of the subnets in allSubnets
// TODO: there is room for optimization here, 'allSubnets' is walked through at each call...
func wouldOverlap(allSubnets []*abstract.Subnet, subnet net.IPNet) fail.Error {
	for _, s := range allSubnets {
		_, sDesc, _ := net.ParseCIDR(s.CIDR)
		if netretry.CIDROverlap(subnet, *sDesc) {
			return fail.OverloadError("would intersect with '%s (%s)'", s.Name, s.CIDR)
		}
	}
	return nil
}

// InspectSubnetByName ...
func (s *Stack) InspectSubnetByName(networkRef, name string) (*abstract.Subnet, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	// Gophercloud doesn't propose the way to get a host by name, but OpenStack knows how to do it...
	r := networks.GetResult{}
	commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, r.Err = s.Stack.NetworkClient.Get(s.Stack.NetworkClient.ServiceURL("subnets?name="+name), &r.Body, &gophercloud.RequestOpts{
				OkCodes: []int{200, 203},
			})
			return normalizeError(r.Err)
		},
		temporal.GetCommunicationTimeout(),
	)
	if commRetryErr != nil {
		switch commRetryErr.(type) {
		case *fail.ErrForbidden:
			return nil, abstract.ResourceForbiddenError("network", name)
		default:
			return nil, commRetryErr
		}
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
		return s.InspectSubnet(id)
	}
	return nil, abstract.ResourceNotFoundError("network", name)
}

// InspectSubnet returns the subnet identified by id
func (s Stack) InspectSubnet(id string) (*abstract.Subnet, fail.Error) {
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	r := subnetGetResult{}
	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/subnets/" + id
	opts := gophercloud.RequestOpts{
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	var resp *subnetEx
	commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.Stack.Driver.Request("GET", url, &opts)
			r.Err = innerErr
			resp, innerErr = r.Extract()
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if commRetryErr != nil {
		return nil, commRetryErr
	}

	as := abstract.NewSubnet()
	as.ID = resp.Subnet.ID
	as.Name = resp.Subnet.Name
	as.CIDR = resp.Subnet.CIDR
	as.Network = resp.VpcId
	as.IPVersion = fromIntIPVersion(resp.IPVersion)
	return as, nil
}

// ListSubnets lists networks
func (s Stack) ListSubnets(networkRef string) ([]*abstract.Subnet, fail.Error) {
	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/subnets"
	if networkRef != "" {
		url += "?vpc_id=" + networkRef
	}

	pager := pagination.NewPager(s.Stack.NetworkClient, url, func(r pagination.PageResult) pagination.Page {
		return subnets.SubnetPage{LinkedPageBase: pagination.LinkedPageBase{PageResult: r}}
	})
	var subnetList []*abstract.Subnet
	commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			innerErr := pager.EachPage(func(page pagination.Page) (bool, error) {
				list, err := subnets.ExtractSubnets(page)
				if err != nil {
					return false, normalizeError(err)
				}

				for _, v := range list {
					item := abstract.NewSubnet()
					item.ID = v.ID
					item.Name = v.Name
					item.CIDR = v.CIDR
					item.Network = networkRef
					item.IPVersion = ipversion.Enum(v.IPVersion)
					item.DNSServers = v.DNSNameservers
					subnetList = append(subnetList, item)
				}
				return true, nil
			})
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if commRetryErr != nil {
		return nil, commRetryErr
	}
	return subnetList, nil

	//var list []*abstract.Subnet
	//for _, subnet := range subnetList {
	//	newNet := abstract.NewNetwork()
	//	newNet.ID = subnet.ID
	//	newNet.Name = subnet.Name
	//	newNet.CIDR = subnet.CIDR
	//	newNet.IPVersion = fromIntIPVersion(subnet.IPVersion)
	//	list = append(list, newNet)
	//}
	//return list, nil
}

// DeleteSubnet consists to delete subnet in FlexibleEngine VPC
func (s Stack) DeleteSubnet(id string) fail.Error {
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	as, xerr := s.InspectSubnet(id)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// If subnet is not found, consider as a success
			return nil
		default:
			return xerr
		}
	}

	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/vpcs/" + as.Network + "/subnets/" + id
	opts := gophercloud.RequestOpts{
		OkCodes: []int{204},
	}

	// FlexibleEngine has the curious behavior to be able to tell us all Hosts are deleted, but
	// cannot delete the subnet because there is still at least one host...
	// So we retry subnet deletion until all hosts are really deleted and subnet can be deleted
	return retry.Action(
		func() error {
			return netretry.WhileCommunicationUnsuccessfulDelay1Second(
				func() error {
					r, innerErr := s.Stack.Driver.Request("DELETE", url, &opts)
					if innerErr != nil {
						return normalizeError(innerErr)
					}
					if r != nil {
						switch r.StatusCode {
						case 404:
							logrus.Infof("subnet '%s' not found, considered as success", id)
							fallthrough
						case 200, 204:
							return nil
						case 409:
							return fail.NewError("409")
						default:
							return fail.NewError("DELETE command failed with status %d", r.StatusCode)
						}
					}
					return nil
				},
				temporal.GetCommunicationTimeout(),
			)
		},
		retry.PrevailDone(retry.Unsuccessful(), retry.Timeout(temporal.GetHostCleanupTimeout())),
		retry.Constant(temporal.GetDefaultDelay()),
		nil, nil,
		func(t retry.Try, verdict verdict.Enum) {
			if t.Err != nil {
				switch t.Err.Error() {
				case "409":
					logrus.Debugf("Subnet still owns host(s), retrying in %s...", temporal.GetDefaultDelay())
				default:
					logrus.Debugf("error submitting Subnet deletion (status=%s), retrying in %s...", t.Err.Error(), temporal.GetDefaultDelay())
				}
			}
		},
	)
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
	VpcId  string `json:"vpc_id"`
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
func (s Stack) createSubnet(req abstract.SubnetRequest) (*subnets.Subnet, fail.Error) {
	network, networkDesc, _ := net.ParseCIDR(req.CIDR)

	// Validates IPRanges regarding the existing subnets
	subnetworks, xerr := s.ListSubnets(req.Network)
	if xerr != nil {
		return nil, xerr
	}
	if xerr = wouldOverlap(subnetworks, *networkDesc); xerr != nil {
		return nil, xerr
	}
	// for _, s := range subnetworks {
	// 	_, sDesc, _ := net.ParseCIDR(s.IPRanges)
	// 	if utils.CIDROverlap(*networkDesc, *sDesc) {
	// 		return nil, fail.Wrap(err, "would intersect with '%s (%s)'", s.Name, s.IPRanges)
	// 	}
	// }

	// Calculate IP address for gateway
	n := netretry.IPv4ToUInt32(network)
	gw := netretry.UInt32ToIPv4(n + 1)

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
	request := subnetRequest{
		Name:         req.Name,
		CIDR:         req.CIDR,
		VPCID:        req.Network,
		DHCPEnable:   &bYes,
		GatewayIP:    gw.String(),
		PrimaryDNS:   primaryDNS,
		SecondaryDNS: secondaryDNS,
		DNSList:      dnsList,
	}
	b, err := gophercloud.BuildRequestBody(request, "subnet")
	if err != nil {
		return nil, normalizeError(err)
	}

	respCreate := subnetCreateResult{}
	url := fmt.Sprintf("%sv1/%s/subnets", s.Stack.NetworkClient.Endpoint, s.authOpts.ProjectID)
	opts := gophercloud.RequestOpts{
		JSONBody:     b,
		JSONResponse: &respCreate.Body,
		OkCodes:      []int{200, 201},
	}
	commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			_, innerErr := s.Stack.Driver.Request("POST", url, &opts)
			return normalizeError(innerErr)
		},
		temporal.GetCommunicationTimeout(),
	)
	if commRetryErr != nil {
		return nil, commRetryErr
	}

	subnet, err := respCreate.Extract()
	if err != nil {
		return nil, normalizeError(err)
	}

	// Subnet creation started, need to wait the subnet to reach the status ACTIVE
	respGet := subnetGetResult{}
	opts.JSONResponse = &respGet.Body
	opts.JSONBody = nil

	retryErr := retry.WhileUnsuccessfulDelay1SecondWithNotify(
		func() error {
			innerXErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
				func() error {
					_, err = s.Stack.Driver.Request("GET", fmt.Sprintf("%s/%s", url, subnet.ID), &opts)
					return normalizeError(err)
				},
				temporal.GetCommunicationTimeout(),
			)
			if innerXErr == nil {
				subnet, err = respGet.Extract()
				if err == nil && subnet.Status == "ACTIVE" {
					return nil
				}
			}
			return normalizeError(err)
		},
		temporal.GetContextTimeout(),
		func(try retry.Try, v verdict.Enum) {
			if v != verdict.Done {
				logrus.Debugf("Network '%s' is not in 'ACTIVE' state, retrying...", req.Name)
			}
		},
	)
	return &subnet.Subnet, retryErr
}

//// ListSubnets lists available subnet in VPC
//func (s *Stack) listSubnets() ([]subnets.Subnet, fail.Error) {
//	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/subnets?vpc_id=" + s.vpc.ID
//	pager := pagination.NewPager(s.Stack.NetworkClient, url, func(r pagination.PageResult) pagination.Page {
//		return subnets.SubnetPage{LinkedPageBase: pagination.LinkedPageBase{PageResult: r}}
//	})
//	var subnetList []subnets.Subnet
//	commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
//		func() error {
//			innerErr := pager.EachPage(func(page pagination.Page) (bool, error) {
//				list, err := subnets.ExtractSubnets(page)
//				if err != nil {
//					return false, normalizeError(err)
//				}
//
//				subnetList = append(subnetList, list...)
//				return true, nil
//			})
//			return normalizeError(innerErr)
//		},
//		temporal.GetCommunicationTimeout(),
//	)
//	if commRetryErr != nil {
//		return nil, commRetryErr
//	}
//	return subnetList, nil
//}
//
//// getSubnet lists available subnet in VPC
//func (s *Stack) getSubnet(id string) (*subnets.Subnet, fail.Error) {
//	r := subnetGetResult{}
//	url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/subnets/" + id
//	opts := gophercloud.RequestOpts{
//		JSONResponse: &r.Body,
//		OkCodes:      []int{200, 201},
//	}
//	var subnet *subnetEx
//	commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
//		func() error {
//			_, innerErr := s.Stack.Driver.Request("GET", url, &opts)
//			r.Err = innerErr
//			subnet, innerErr = r.Extract()
//			return normalizeError(innerErr)
//		},
//		temporal.GetCommunicationTimeout(),
//	)
//	if commRetryErr != nil {
//		return nil, commRetryErr
//	}
//	return &subnet.Subnet, nil
//}
//
//// findSubnetByName returns a subnets.Subnet if subnet named as 'name' exists
//func (s *Stack) findSubnetByName(name string) (*subnets.Subnet, fail.Error) {
//	subnetList, xerr := s.listSubnets()
//	if xerr != nil {
//		return nil, fail.Wrap(xerr, "failed to find 'name' in subnets")
//	}
//	found := false
//	var subnet subnets.Subnet
//	for _, s := range subnetList {
//		if s.Name == name {
//			found = true
//			subnet = s
//			break
//		}
//	}
//	if !found {
//		return nil, abstract.ResourceNotFoundError("subnet", name)
//	}
//	return &subnet, nil
//}

func fromIntIPVersion(v int) ipversion.Enum {
	if v == 6 {
		return ipversion.IPv6
	}
	return ipversion.IPv4
}

// CreateVIP creates a private virtual IP
// If public is set to true,
func (s Stack) CreateVIP(networkID, subnetID, name string, sgs []string) (*abstract.VirtualIP, fail.Error) {
	if subnetID == "" {
		return nil, fail.InvalidParameterError("subnetID", "cannot be empty string")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	//sgName := name + abstract.VIPDefaultSecurityGroupNameSuffix
	//asg, xerr := s.InspectSecurityGroup(name + abstract.VIPDefaultSecurityGroupNameSuffix)
	//if xerr != nil {
	//	return nil, fail.Wrap(xerr, "failed to load VIP default Security Group '%s'; must be created first", sgName)
	//}

	//sg := []string{asg.ID}
	asu := true
	options := ports.CreateOpts{
		NetworkID:      subnetID,
		AdminStateUp:   &asu,
		Name:           name,
		SecurityGroups: &sgs,
		FixedIPs:       []ports.IP{{SubnetID: subnetID}},
	}
	port, err := ports.Create(s.NetworkClient, options).Extract()
	if err != nil {
		return nil, fail.ToError(err)
	}
	vip := abstract.VirtualIP{
		ID:        port.ID,
		Name:      name,
		NetworkID: networkID,
		SubnetID:  subnetID,
		PrivateIP: port.FixedIPs[0].IPAddress,
	}
	return &vip, nil
}
