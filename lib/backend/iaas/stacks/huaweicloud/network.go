/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/davecgh/go-spew/spew"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry/enums/verdict"
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

// Router represents a router
type Router struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	// NetworkID is the Network ID which the router gateway is connected to.
	NetworkID string `json:"network_id,omitempty"`
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

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (s stack) HasDefaultNetwork(context.Context) (bool, fail.Error) {
	if valid.IsNil(s) {
		return false, fail.InvalidInstanceError()
	}
	return s.vpc != nil, nil
}

// GetDefaultNetwork returns the *abstract.Network corresponding to the default network
func (s stack) GetDefaultNetwork(context.Context) (*abstract.Network, fail.Error) {
	if valid.IsNil(s) {
		return abstract.NewNetwork(), fail.InvalidInstanceError()
	}
	if s.vpc == nil {
		return abstract.NewNetwork(), fail.NotFoundError("no default Network in stack")
	}
	return s.vpc, nil
}

// CreateNetwork creates a Network, which corresponds to a VPC in FlexibleEngine terminology
func (s stack) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	gcReq := VPCRequest{
		Name: req.Name,
		CIDR: req.CIDR,
	}
	b, err := gophercloud.BuildRequestBody(gcReq, "vpc")
	if err != nil {
		return nil, normalizeError(err)
	}

	url := s.NetworkClient.Endpoint + s.versions["networkclient"] + "/" + s.authOpts.ProjectID + "/vpcs"
	resp := vpcCreateResult{}
	opts := gophercloud.RequestOpts{
		JSONBody:     b,
		JSONResponse: &resp.Body,
		OkCodes:      []int{200, 201},
	}
	commRetryErr := stacks.RetryableRemoteCall(ctx,
		func() error {
			var hr *http.Response
			hr, innerErr := s.Driver.Request("POST", url, &opts) // nolint
			defer closer(hr)
			return innerErr
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return nil, fail.Wrap(commRetryErr, "query to create VPC failed")
	}
	vpc, err := resp.Extract()
	if err != nil {
		return nil, normalizeError(err)
	}

	an := abstract.NewNetwork()
	an.ID = vpc.ID
	an.Name = req.Name
	an.CIDR = req.CIDR
	an.DNSServers = req.DNSServers

	return an, nil
}

// ListRouters lists available routers
func (s stack) ListRouters(ctx context.Context) ([]Router, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	var ns []Router
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			return routers.List(s.NetworkClient, routers.ListOpts{}).EachPage(
				func(page pagination.Page) (bool, error) {
					list, err := routers.ExtractRouters(page)
					if err != nil {
						return false, err
					}
					for _, r := range list {
						an := Router{
							ID:        r.ID,
							Name:      r.Name,
							NetworkID: r.GatewayInfo.NetworkID,
						}
						ns = append(ns, an)
					}
					return true, nil
				},
			)
		},
		NormalizeError,
	)
	return ns, xerr
}

// findVPCBoundOpenstackNetwork finds the Openstack Network resource associated to Huaweicloud VPC
func (s stack) findOpenStackNetworkBoundToVPC(ctx context.Context, vpcName string) (*networks.Network, fail.Error) {
	var router *Router
	found := false
	routerList, xerr := s.ListRouters(ctx)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to list routers")
	}
	for _, r := range routerList {
		local := r
		if r.Name == vpcName {
			found = true
			router = &local
			break
		}
	}
	if !found || router == nil {
		return nil, fail.NotFoundError(nil, nil, "failed to find router associated to VPC '%s'", vpcName)
	}

	var network *networks.Network
	commRetryErr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			network, innerErr = networks.Get(s.NetworkClient, router.NetworkID).Extract()
			return innerErr
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return nil, fail.Wrap(commRetryErr, "failed to get information of bound network")
	}
	return network, nil
}

// InspectNetwork returns the information about a VPC identified by 'id'
func (s stack) InspectNetwork(ctx context.Context, id string) (*abstract.Network, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id = strings.TrimSpace(id); id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	r := vpcGetResult{}
	url := s.NetworkClient.Endpoint + s.versions["networkclient"] + "/" + s.authOpts.ProjectID + "/vpcs/" + id
	opts := gophercloud.RequestOpts{
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	var vpc *VPC
	commRetryErr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			var hr *http.Response
			hr, innerErr = s.Driver.Request("GET", url, &opts) // nolint
			defer closer(hr)
			if innerErr != nil {
				return innerErr
			}
			vpc, innerErr = r.Extract()
			return innerErr
		},
		normalizeError,
	)
	if commRetryErr != nil {
		switch commRetryErr.(type) { // nolint
		case *fail.ErrInvalidRequest: // In case of VPC, when id does not exist, huaweicloud returns InvalidRequest... which cannot be the case because we validated that id is not empty
			return nil, fail.NotFoundError("failed to find Network with id %s", id)
		}
		return nil, commRetryErr
	}

	return toAbstractNetwork(*vpc), nil
}

// toAbstractNetwork converts a VPC to an *abstract.Network
func toAbstractNetwork(vpc VPC) *abstract.Network {
	an := abstract.NewNetwork()
	an.ID = vpc.ID
	an.Name = vpc.Name
	an.CIDR = vpc.CIDR
	return an
}

// InspectNetworkByName returns the information about a Network/VPC identified by 'name'
func (s stack) InspectNetworkByName(ctx context.Context, name string) (_ *abstract.Network, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	nets, xerr := s.ListNetworks(ctx)
	if xerr != nil {
		return nil, xerr
	}

	var an *abstract.Network
	for _, v := range nets {
		if v.Name == name {
			an = v
			break
		}
	}
	if an == nil {
		return nil, fail.NotFoundError("failed to find VPC named '%s'", name)
	}

	return an, nil
}

// ListNetworks lists all the Network/VPC created
func (s stack) ListNetworks(ctx context.Context) ([]*abstract.Network, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	r := vpcCommonResult{}
	url := s.NetworkClient.Endpoint + s.versions["networkclient"] + "/" + s.authOpts.ProjectID + "/vpcs"
	opts := gophercloud.RequestOpts{
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			var hr *http.Response
			hr, innerErr := s.Driver.Request("GET", url, &opts) // nolint
			defer closer(hr)
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	var list []*abstract.Network
	if vpcs, ok := r.Body.(map[string]interface{})["vpcs"].([]interface{}); ok {
		for _, v := range vpcs {
			item, ok := v.(map[string]interface{})
			if !ok {
				return nil, fail.InconsistentError("vpc should be a map[string]interface{}")
			}

			an := abstract.NewNetwork()
			an.Name, ok = item["name"].(string)
			if !ok {
				return nil, fail.InconsistentError("name should NOT be empty")
			}
			an.ID, ok = item["id"].(string)
			if !ok {
				return nil, fail.InconsistentError("id should NOT be empty")
			}
			an.CIDR, ok = item["cidr"].(string)
			if !ok {
				return nil, fail.InconsistentError("cidr should NOT be empty")
			}
			if an.Name == "" || an.ID == "" || an.CIDR == "" {
				continue
			}

			list = append(list, an)
		}
	}
	return list, nil
}

// DeleteNetwork deletes a Network/VPC identified by 'id'
func (s stack) DeleteNetwork(ctx context.Context, id string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	r := vpcCommonResult{}
	url := s.NetworkClient.Endpoint + s.versions["networkclient"] + "/" + s.authOpts.ProjectID + "/vpcs/" + id
	opts := gophercloud.RequestOpts{
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201, 204},
	}
	return stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			var r *http.Response
			r, innerErr = s.Driver.Request("DELETE", url, &opts) // nolint
			defer closer(r)
			return innerErr
		},
		normalizeError,
	)
}

// CreateSubnet creates a network (ie a subnet in the network associated to VPC in FlexibleEngine
func (s stack) CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (subnet *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	var xerr fail.Error
	if _, xerr = s.InspectSubnetByName(ctx, req.NetworkID, req.Name); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError2(ctx, xerr)
		default:
			return nil, xerr
		}
	} else {
		return nil, fail.DuplicateError("subnet '%s' already exists", req.Name)
	}

	if ok, xerr := validateNetwork(req); !ok {
		return nil, fail.Wrap(xerr, "network name '%s' invalid", req.Name)
	}

	an, xerr := s.InspectNetwork(ctx, req.NetworkID)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			an, xerr = s.InspectNetworkByName(ctx, req.NetworkID)
			if xerr != nil {
				return nil, xerr
			}
		default:
			return nil, xerr
		}
	}

	// Checks if CIDR is valid for huaweicloud
	xerr = s.validateCIDR(&req, an)
	if xerr != nil {
		return nil, xerr
	}

	// Creates the subnet
	resp, xerr := s.createSubnet(ctx, req)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "error creating subnet '%s'", req.Name)
	}

	subnet = abstract.NewSubnet()
	subnet.ID = resp.ID
	subnet.Name = resp.Name
	subnet.CIDR = resp.CIDR
	subnet.IPVersion = fromIntIPVersion(resp.IPVersion)
	subnet.Network = an.ID

	return subnet, nil
}

func (s stack) validateCIDR(req *abstract.SubnetRequest, network *abstract.Network) fail.Error {
	_, networkDesc, _ := net.ParseCIDR(network.CIDR)
	_, subnetDesc, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return fail.Wrap(err, "failed to validate CIDR '%s' for Subnet '%s'", req.CIDR, req.Name)
	}
	if networkDesc.IP.Equal(subnetDesc.IP) && networkDesc.Mask.String() == subnetDesc.Mask.String() {
		return fail.InvalidRequestError("cannot create Subnet with CIDR '%s': equal to Network one", req.CIDR)
	}
	return nil
}

// validateNetwork validates the name of a Network based on known FlexibleEngine requirements
func validateNetwork(req abstract.SubnetRequest) (bool, fail.Error) {
	err := validation.ValidateStruct(&req,
		validation.Field(&req.Name, validation.Required, validation.Length(1, 64)),
		validation.Field(&req.Name, validation.Required, validation.Match(regexp.MustCompile(`^[a-zA-Z0-9_-]+$`))),
	)
	if err != nil {
		return false, fail.Wrap(err, "validation issue")
	}

	return true, nil
}

// InspectSubnetByName ...
func (s stack) InspectSubnetByName(ctx context.Context, networkID, name string) (*abstract.Subnet, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	// Gophercloud doesn't propose the way to get a host by name, but OpenStack knows how to do it...
	r := networks.GetResult{}
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			var hr *http.Response
			hr, r.Err = s.NetworkClient.Get(s.NetworkClient.ServiceURL("subnets?name="+name), &r.Body, &gophercloud.RequestOpts{ // nolint
				OkCodes: []int{200, 203},
			})
			defer closer(hr)
			return r.Err
		},
		normalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrForbidden:
			return nil, abstract.ResourceForbiddenError("network", name)
		default:
			return nil, xerr
		}
	}

	subnetworks, found := r.Body.(map[string]interface{})["subnets"].([]interface{})
	if found && len(subnetworks) > 0 {
		var (
			entry map[string]interface{}
			id    string
		)
		for _, s := range subnetworks {
			var ok bool
			entry, ok = s.(map[string]interface{})
			if !ok {
				return nil, fail.InconsistentError("subnet should be a map[string]interface{}")
			}
			id, ok = entry["id"].(string)
			if !ok {
				return nil, fail.InconsistentError("id should be a string")
			}
		}
		return s.inspectOpenstackSubnet(ctx, id)
	}
	return nil, abstract.ResourceNotFoundError("subnet", name)
}

// InspectSubnet returns the subnet identified by id
func (s stack) InspectSubnet(ctx context.Context, id string) (*abstract.Subnet, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	r := subnetGetResult{}
	url := s.NetworkClient.Endpoint + s.versions["networkclient"] + "/" + s.authOpts.ProjectID + "/subnets/" + id
	opts := gophercloud.RequestOpts{
		JSONResponse: &r.Body,
		OkCodes:      []int{200, 201},
	}
	var resp *subnetEx
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			var hr *http.Response
			hr, innerErr := s.Driver.Request("GET", url, &opts) // nolint
			defer closer(hr)
			r.Err = innerErr
			resp, innerErr = r.Extract()
			return innerErr
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	as := abstract.NewSubnet()
	as.ID = resp.Subnet.ID
	as.Name = resp.Subnet.Name
	as.CIDR = resp.Subnet.CIDR
	as.Network = resp.VpcID
	as.IPVersion = fromIntIPVersion(resp.IPVersion)
	return as, nil
}

func (s stack) inspectOpenstackSubnet(ctx context.Context, id string) (*abstract.Subnet, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	as := abstract.NewSubnet()
	var sn *subnets.Subnet
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			sn, innerErr = subnets.Get(s.NetworkClient, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	as.ID = sn.ID
	as.Name = sn.Name
	as.Network = sn.NetworkID
	as.IPVersion = openstack.ToAbstractIPVersion(sn.IPVersion)
	as.CIDR = sn.CIDR
	as.DNSServers = sn.DNSNameservers

	return as, nil
}

// ListSubnets lists networks
func (s stack) ListSubnets(ctx context.Context, networkRef string) ([]*abstract.Subnet, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	url := s.NetworkClient.Endpoint + s.versions["networkclient"] + "/" + s.authOpts.ProjectID + "/subnets"
	if networkRef != "" {
		url += "?vpc_id=" + networkRef
	}

	pager := pagination.NewPager(s.NetworkClient, url, func(r pagination.PageResult) pagination.Page {
		return subnets.SubnetPage{LinkedPageBase: pagination.LinkedPageBase{PageResult: r}}
	})
	var subnetList []*abstract.Subnet
	commRetryErr := stacks.RetryableRemoteCall(ctx,
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
			return innerErr
		},
		normalizeError,
	)
	if commRetryErr != nil {
		return nil, commRetryErr
	}
	return subnetList, nil
}

// DeleteSubnet consists to delete subnet in FlexibleEngine VPC
func (s stack) DeleteSubnet(ctx context.Context, id string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	as, xerr := s.InspectSubnet(ctx, id)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// If subnet is not found, considered as a success
			debug.IgnoreError2(ctx, xerr)
			return nil
		default:
			return xerr
		}
	}

	url := s.NetworkClient.Endpoint + s.versions["networkclient"] + "/" + s.authOpts.ProjectID + "/vpcs/" + as.Network + "/subnets/" + id
	opts := gophercloud.RequestOpts{
		OkCodes: []int{204},
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	// FlexibleEngine has the curious behavior to be able to tell us all Hosts are deleted, but
	// cannot delete the subnet because there is still at least one host...
	// So we retry subnet deletion until all hosts are really deleted and subnet can be deleted
	return retry.Action(
		func() error {
			return stacks.RetryableRemoteCall(ctx,
				func() error {
					var hr *http.Response
					hr, innerErr := s.Driver.Request("DELETE", url, &opts) // nolint
					defer closer(hr)
					return innerErr
				},
				normalizeError,
			)
		},
		retry.PrevailDone(retry.Unsuccessful(), retry.Timeout(2*temporal.MaxTimeout(timings.HostCleanupTimeout(), timings.CommunicationTimeout()))),
		retry.Constant(timings.NormalDelay()),
		nil,
		nil,
		func(t retry.Try, verdict verdict.Enum) {
			if t.Err != nil {
				switch t.Err.Error() {
				case "409":
					logrus.WithContext(ctx).Debugf("Subnet still owns host(s), retrying in %s...", timings.NormalDelay())
				default:
					logrus.WithContext(ctx).Warnf("unexpected error: %s", spew.Sdump(t.Err))
					logrus.WithContext(ctx).Debugf("error submitting Subnet deletion (status=%s), retrying in %s...", t.Err.Error(), timings.NormalDelay())
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
	VpcID  string `json:"vpc_id"`
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

// createSubnet creates a subnet using native FlexibleEngine API
func (s stack) createSubnet(ctx context.Context, req abstract.SubnetRequest) (*subnets.Subnet, fail.Error) {
	network, _ /*networkDesc*/, _ := net.ParseCIDR(req.CIDR)

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
		VPCID:        req.NetworkID,
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
	url := fmt.Sprintf("%s%s/%s/subnets", s.NetworkClient.Endpoint, s.versions["networkclient"], s.authOpts.ProjectID)
	opts := gophercloud.RequestOpts{
		JSONBody:     b,
		JSONResponse: &respCreate.Body,
		OkCodes:      []int{200, 201},
	}
	commRetryErr := stacks.RetryableRemoteCall(ctx,
		func() error {
			var hr *http.Response
			hr, innerErr := s.Driver.Request("POST", url, &opts) // nolint
			defer closer(hr)
			return innerErr
		},
		normalizeError,
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

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	retryErr := retry.WhileUnsuccessfulWithNotify(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			innerXErr := stacks.RetryableRemoteCall(ctx,
				func() error {
					var hr *http.Response
					hr, innerErr := s.Driver.Request("GET", fmt.Sprintf("%s/%s", url, subnet.ID), &opts) // nolint
					defer closer(hr)
					return innerErr
				},
				normalizeError,
			)
			if innerXErr != nil {
				return normalizeError(innerXErr)
			}
			subnet, err = respGet.Extract()
			if err != nil {
				return normalizeError(err)
			}
			if subnet.Status != "ACTIVE" {
				return fmt.Errorf("not active yet")
			}
			return nil
		},
		timings.SmallDelay(),
		timings.ContextTimeout(),
		func(try retry.Try, v verdict.Enum) {
			if v != verdict.Done {
				logrus.WithContext(ctx).Debugf("Network '%s' is not in 'ACTIVE' state, retrying...", req.Name)
			}
		},
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry: // here it should never happen
			return nil, fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return nil, fail.Wrap(fail.Cause(retryErr), "timeout")
		default:
			return nil, retryErr
		}
	}

	return &subnet.Subnet, nil
}

func fromIntIPVersion(v int) ipversion.Enum {
	if v == 6 {
		return ipversion.IPv6
	}
	return ipversion.IPv4
}

// CreateVIP creates a private virtual IP
// If public is set to true,
func (s stack) CreateVIP(ctx context.Context, networkID, subnetID, name string, sgs []string) (*abstract.VirtualIP, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if subnetID == "" {
		return nil, fail.InvalidParameterError("subnetID", "cannot be empty string")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	// It seems FlexibleEngine encapsulates openstack subnet inside an openstack network; SubnetID is, in openstack context, a network ID.
	// So, we need to recover the real openstack network and subnet IDs for this call to succeed
	as, xerr := s.InspectSubnet(ctx, subnetID)
	if xerr != nil {
		return nil, xerr
	}

	openstackAS, xerr := s.InspectSubnetByName(ctx, networkID, as.Name)
	if xerr != nil {
		return nil, xerr
	}

	asu := true
	options := ports.CreateOpts{
		NetworkID:      openstackAS.Network,
		AdminStateUp:   &asu,
		Name:           name,
		SecurityGroups: &sgs,
		FixedIPs:       []ports.IP{{SubnetID: openstackAS.ID}},
	}
	port, err := ports.Create(s.NetworkClient, options).Extract()
	if err != nil {
		return nil, fail.ConvertError(err)
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
