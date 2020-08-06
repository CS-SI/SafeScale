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

// CreateVPC creates a network, which is managed by VPC in FlexibleEngine
func (s *Stack) CreateVPC(req VPCRequest) (*VPC, fail.Error) {
    // Only one VPC allowed by client instance
    if s.vpc != nil {
        return nil, fail.DuplicateError("failed to create VPC '%s', a VPC with this name already exists", req.Name)
    }

    b, err := gophercloud.BuildRequestBody(req, "vpc")
    if err != nil {
        return nil, openstack.NormalizeError(err)
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
            return openstack.NormalizeError(err)
        },
        2*temporal.GetDefaultDelay(),
    )
    if commRetryErr != nil {
        return nil, fail.Prepend(commRetryErr, "query to create VPC failed")
    }
    vpc, err := resp.Extract()
    if err != nil {
        return nil, openstack.NormalizeError(err)
    }

    // Searching for the OpenStack Router corresponding to the VPC (router.id == vpc.id)
    var router *routers.Router
    commRetryErr = netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() (innerErr error) {
            router, innerErr = routers.Get(s.Stack.NetworkClient, vpc.ID).Extract()
            return openstack.NormalizeError(innerErr)
        },
        temporal.GetDefaultDelay(),
    )
    if commRetryErr != nil {
        derr := s.DeleteVPC(vpc.ID)
        if derr != nil {
            logrus.Warnf("Error deleting VPC: %v", derr)
            commRetryErr.AddConsequence(derr)
        }
        return nil, fail.Prepend(commRetryErr, "failed to find OpenStack router of VPC")
    }
    vpc.Router = router

    // Searching for the Network binded to the VPC
    network, xerr := s.findVPCBindedNetwork(vpc.Name)
    if xerr != nil {
        return nil, fail.Prepend(xerr, "failed to find network binded to VPC")
    }
    vpc.Network = network

    return vpc, nil
}

func (s *Stack) findVPCBindedNetwork(vpcName string) (*networks.Network, fail.Error) {
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
            return openstack.NormalizeError(innerErr)
        },
        temporal.GetDefaultDelay(),
    )
    if commRetryErr != nil {
        return nil, fail.Prepend(commRetryErr, "failed to get information of binded network")
    }
    return network, nil
}

// GetVPC returns the information about a VPC identified by 'id'
func (s *Stack) GetVPC(id string) (*VPC, fail.Error) {
    r := vpcGetResult{}
    url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/vpcs/" + id
    opts := gophercloud.RequestOpts{
        JSONResponse: &r.Body,
        OkCodes:      []int{200, 201},
    }
    commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            _, err := s.Stack.Driver.Request("GET", url, &opts)
            r.Err = err
            return openstack.NormalizeError(err)
        },
        temporal.GetDefaultDelay(),
    )
    if commRetryErr != nil {
        return nil, commRetryErr
    }

    vpc, err := r.Extract()
    if err != nil {
        return nil, openstack.NormalizeError(err)
    }
    return vpc, nil
}

// ListVPCs lists all the VPC created
func (s *Stack) ListVPCs() ([]VPC, fail.Error) {
    var vpcList []VPC
    return vpcList, fail.NotImplementedError("huaweicloud.Stack::ListVPCs() not implemented yet") // FIXME Technical debt
}

// DeleteVPC deletes a Network (ie a VPC in Huawei Cloud) identified by 'id'
func (s *Stack) DeleteVPC(id string) fail.Error {
    return fail.NotImplementedError("huaweicloud.Stack::DeleteVPC() not implemented yet") // FIXME Technical debt
}

// CreateNetwork creates a network (ie a subnet in the network associated to VPC in FlexibleEngine
func (s *Stack) CreateNetwork(req abstract.NetworkRequest) (network *abstract.Network, xerr fail.Error) {
    tracer := debug.NewTracer(nil, true, "(%s)", req.Name).WithStopwatch().Entering()
    defer tracer.Exiting()

    subnet, xerr := s.findSubnetByName(req.Name)
    if xerr != nil {
        if _, ok := xerr.(*fail.ErrNotFound); !ok {
            return nil, xerr
        }
    }
    if subnet != nil {
        return nil, fail.DuplicateError("network '%s' already exists", req.Name)
    }

    if ok, xerr := validateNetworkName(req); !ok {
        return nil, fail.Wrap(xerr, "network name '%s' invalid", req.Name)
    }

    // Validates CIDR regarding the existing subnets
    subnetworks, xerr := s.listSubnets()
    if xerr != nil {
        return nil, xerr
    }

    // Checks if CIDR is valid...
    _, vpcnetDesc, _ := net.ParseCIDR(s.vpc.CIDR)
    if req.CIDR != "" {
        _, networkDesc, err := net.ParseCIDR(req.CIDR)
        if err != nil {
            return nil, fail.Wrap(err, "failed to create subnet '%s (%s)'", req.Name, req.CIDR)
        }
        // ... and if CIDR is inside VPC's one
        if !netretry.CIDROverlap(*vpcnetDesc, *networkDesc) {
            return nil, fail.InvalidRequestError("cannot create subnet with CIDR '%s': not inside VPC CIDR '%s'", req.CIDR, s.vpc.CIDR)
        }
        if vpcnetDesc.IP.Equal(networkDesc.IP) {
            return nil, fail.InvalidRequestError("cannot create subnet with CIDR '%s': network part of CIDR is equal to VPC one (%s)", req.CIDR, networkDesc.IP.String())
        }
    } else { // CIDR is empty, choose the first Class C available one
        tracer.Trace("CIDR is empty, choosing one...")

        var (
            bitShift uint8
            i, limit uint
            newIPNet net.IPNet
        )
        mask, _ := vpcnetDesc.Mask.Size()
        if mask >= 24 {
            bitShift = 1
        } else {
            bitShift = 24 - uint8(mask)
        }
        limit = 1 << bitShift

        for i = uint(1); i < limit; i++ {
            newIPNet, xerr = netretry.NthIncludedSubnet(*vpcnetDesc, bitShift, i)
            if xerr != nil {
                return nil, fail.Wrap(xerr, "failed to choose a CIDR for the subnet")
            }
            if wouldOverlap(subnetworks, newIPNet) == nil {
                break
            }
        }
        if i >= limit {
            return nil, fail.OverflowError(nil, limit-1, "failed to find a free available subnet ")
        }

        req.CIDR = newIPNet.String()
        tracer.Trace("CIDR chosen for network is '%s'", req.CIDR)
    }

    // Creates the subnet
    subnet, xerr = s.createSubnet(req.Name, req.CIDR)
    if xerr != nil {
        return nil, fail.NewError("error creating network '%s'", req.Name)
    }

    // starting from here delete network
    defer func() {
        if xerr != nil {
            derr := s.deleteSubnet(subnet.ID)
            if derr != nil {
                logrus.Errorf("failed to delete subnet '%s': %v", subnet.Name, derr)
                _ = xerr.AddConsequence(derr)
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
func validateNetworkName(req abstract.NetworkRequest) (bool, fail.Error) {
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
        return false, fail.NewError(strings.Join(errs, "; "))
    }
    return true, nil
}

// wouldOverlap returns fail.ErrOverloadError if subnet overlaps one of the subnets in allSubnets
// TODO: there is room for optimization here, 'allSubnets' is walked through at each call...
func wouldOverlap(allSubnets []subnets.Subnet, subnet net.IPNet) fail.Error {
    for _, s := range allSubnets {
        _, sDesc, _ := net.ParseCIDR(s.CIDR)
        if netretry.CIDROverlap(subnet, *sDesc) {
            return fail.OverloadError("would intersect with '%s (%s)'", s.Name, s.CIDR)
        }
    }
    return nil
}

// GetNetworkByName ...
func (s *Stack) GetNetworkByName(name string) (*abstract.Network, fail.Error) {
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
            return openstack.NormalizeError(r.Err)
        },
        temporal.GetDefaultDelay(),
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
        return s.GetNetwork(id)
    }
    return nil, abstract.ResourceNotFoundError("network", name)
}

// GetNetwork returns the network identified by id
func (s *Stack) GetNetwork(id string) (*abstract.Network, fail.Error) {
    subnet, xerr := s.getSubnet(id)
    if xerr != nil {
        spew.Dump(xerr)
        if !strings.Contains(xerr.Error(), id) {
            return nil, fail.Wrap(xerr, "failed to get information about network '%s'", id)
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
func (s *Stack) ListNetworks() ([]*abstract.Network, fail.Error) {
    subnetList, xerr := s.listSubnets()
    if xerr != nil {
        return nil, fail.Wrap(xerr, "failed to get networks list")
    }
    var networkList []*abstract.Network
    for _, subnet := range subnetList {
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
func (s *Stack) DeleteNetwork(id string) fail.Error {
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
func (s *Stack) createSubnet(name string, cidr string) (*subnets.Subnet, fail.Error) {
    network, networkDesc, _ := net.ParseCIDR(cidr)

    // Validates CIDR regarding the existing subnets
    subnetworks, xerr := s.listSubnets()
    if xerr != nil {
        return nil, xerr
    }
    if xerr = wouldOverlap(subnetworks, *networkDesc); xerr != nil {
        return nil, xerr
    }
    // for _, s := range subnetworks {
    // 	_, sDesc, _ := net.ParseCIDR(s.CIDR)
    // 	if utils.CIDROverlap(*networkDesc, *sDesc) {
    // 		return nil, fail.Wrap(err, "would intersect with '%s (%s)'", s.Name, s.CIDR)
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
        return nil, openstack.NormalizeError(err)
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
            return openstack.NormalizeError(innerErr)
        },
        temporal.GetDefaultDelay(),
    )
    if commRetryErr != nil {
        switch commRetryErr.(type) { // nolint
        case *fail.ErrInvalidRequest:
            body := map[string]interface{}{}
            err = json.Unmarshal([]byte(commRetryErr.Error()), &body)
            if err != nil {
                err = fail.InconsistentError("response is not json")
            } else {
                code, _ := body["code"].(string)
                switch code {
                case "VPC.0003":
                    err = fail.NotFoundError("VPC has vanished")
                default:
                    err = fail.Prepend(commRetryErr, "response code '%s' is not handled", code)
                }
            }
            return nil, fail.ToError(err)
        }
        return nil, commRetryErr
    }

    subnet, err := respCreate.Extract()
    if err != nil {
        return nil, openstack.NormalizeError(err)
    }

    // Subnet creation started, need to wait the subnet to reach the status ACTIVE
    respGet := subnetGetResult{}
    opts.JSONResponse = &respGet.Body
    opts.JSONBody = nil

    retryErr := retry.WhileUnsuccessfulDelay1SecondWithNotify(
        func() error {
            commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
                func() error {
                    _, err = s.Stack.Driver.Request("GET", fmt.Sprintf("%s/%s", url, subnet.ID), &opts)
                    return openstack.NormalizeError(err)
                },
                temporal.GetDefaultDelay(),
            )
            if commRetryErr == nil {
                subnet, err = respGet.Extract()
                if err == nil && subnet.Status == "ACTIVE" {
                    return nil
                }
            }
            return openstack.NormalizeError(err)
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
func (s *Stack) listSubnets() ([]subnets.Subnet, fail.Error) {
    url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/subnets?vpc_id=" + s.vpc.ID
    pager := pagination.NewPager(s.Stack.NetworkClient, url, func(r pagination.PageResult) pagination.Page {
        return subnets.SubnetPage{LinkedPageBase: pagination.LinkedPageBase{PageResult: r}}
    })
    var subnetList []subnets.Subnet
    commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            innerErr := pager.EachPage(func(page pagination.Page) (bool, error) {
                list, err := subnets.ExtractSubnets(page)
                if err != nil {
                    return false, openstack.NormalizeError(err)
                }

                subnetList = append(subnetList, list...)
                return true, nil
            })
            return openstack.NormalizeError(innerErr)
        },
        temporal.GetDefaultDelay(),
    )
    if commRetryErr != nil {
        return nil, commRetryErr
    }
    return subnetList, nil
}

// getSubnet lists available subnet in VPC
func (s *Stack) getSubnet(id string) (*subnets.Subnet, fail.Error) {
    r := subnetGetResult{}
    url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/subnets/" + id
    opts := gophercloud.RequestOpts{
        JSONResponse: &r.Body,
        OkCodes:      []int{200, 201},
    }
    var subnet *subnetEx
    commRetryErr := netretry.WhileCommunicationUnsuccessfulDelay1Second(
        func() error {
            _, innerErr := s.Stack.Driver.Request("GET", url, &opts)
            r.Err = innerErr
            subnet, innerErr = r.Extract()
            return openstack.NormalizeError(innerErr)
        },
        temporal.GetDefaultDelay(),
    )
    if commRetryErr != nil {
        return nil, commRetryErr
    }
    return &subnet.Subnet, nil
}

// deleteSubnet deletes a subnet
func (s *Stack) deleteSubnet(id string) fail.Error {
    url := s.Stack.NetworkClient.Endpoint + "v1/" + s.authOpts.ProjectID + "/vpcs/" + s.vpc.ID + "/subnets/" + id
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
                        return openstack.NormalizeError(innerErr)
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
                temporal.GetDefaultDelay(),
            )
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
}

// findSubnetByName returns a subnets.Subnet if subnet named as 'name' exists
func (s *Stack) findSubnetByName(name string) (*subnets.Subnet, fail.Error) {
    subnetList, xerr := s.listSubnets()
    if xerr != nil {
        return nil, fail.Wrap(xerr, "failed to find 'name' in subnets")
    }
    found := false
    var subnet subnets.Subnet
    for _, s := range subnetList {
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

// CreateVIP creates a private virtual IP
// If public is set to true,
func (s *Stack) CreateVIP(networkID string, name string) (*abstract.VirtualIP, fail.Error) {
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
        return nil, fail.ToError(err)
    }
    vip := abstract.VirtualIP{
        ID:        port.ID,
        Name:      name,
        NetworkID: networkID,
        PrivateIP: port.FixedIPs[0].IPAddress,
    }
    return &vip, nil
}
