// +build ignore
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

package vclouddirector

import (
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/vmware/go-vcloud-director/govcd"
	"github.com/vmware/go-vcloud-director/types/v56"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

func (s *Stack) getOrgVdc() (govcd.Org, govcd.Vdc, fail.Error) {
	org, err := govcd.GetOrgByName(s.EbrcService, s.AuthOptions.ProjectName)
	if err != nil {
		return govcd.Org{}, govcd.Vdc{}, normalizeError(err)
	}

	vdc, err := org.GetVdcByName(s.AuthOptions.ProjectID)
	if err != nil {
		return govcd.Org{}, govcd.Vdc{}, normalizeError(err)
	}

	return org, vdc, nil
}

func (s *Stack) findVAppNames() ([]string, fail.Error) {
	_, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return []string{}, xerr
	}

	var vappNames []string

	res, err := vdc.Query(map[string]string{"type": "vApp", "format": "records"})
	if err != nil {
		return vappNames, normalizeError(err)
	}

	if res.Results != nil {
		r := res.Results
		for _, app := range r.VAppRecord {
			vappNames = append(vappNames, app.Name)
		}
	}

	return vappNames, nil
}

// TODO: move to compute.go
func (s *Stack) findVmNames() ([]string, fail.Error) {
	_, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return []string{}, xerr
	}

	var vmNames []string

	res, err := vdc.Query(map[string]string{"type": "vm", "format": "records"})
	if err != nil {
		return vmNames, normalizeError(err)
	}
	if res.Results != nil {
		r := res.Results
		for _, vm := range r.VMRecord {
			vmNames = append(vmNames, vm.Name)
		}
	}

	return vmNames, nil
}

// TODO: move to compute.go
func (s *Stack) findVMByID(id string) (govcd.VM, fail.Error) {
	var vm govcd.VM

	if strings.Contains(id, ":vapp:") {
		return s.findVMByIDS(id)
	}

	vmnames, err := s.findVmNames()
	if err != nil {
		return vm, nil
	}

	for _, vmname := range vmnames {
		vm, err := s.findVMByName(vmname)
		if err != nil {
			continue
		}
		if vm.VM != nil {
			if vm.VM.ID == id {
				return vm, nil
			}
		}
	}

	return vm, nil
}

// TODO: move to compute.go
func (s *Stack) findVMByIDS(id string) (govcd.VM, fail.Error) {
	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return govcd.VM{}, normalizeError(err)
	}

	vm, err := vdc.FindDefaultVMByVAppID(id)
	if err != nil {
		return govcd.VM{}, normalizeError(err)
	}

	return vm, nil
}

// TODO: move to compute.go
func (s *Stack) findVMByName(id string) (govcd.VM, fail.Error) {
	_, vdc, err := s.getOrgVdc()

	appNames, err := s.findVAppNames()
	if err != nil {
		return govcd.VM{}, normalizeError(err)
	}

	var vm govcd.VM

	for _, appName := range appNames {
		nvapp, err := vdc.FindVAppByName(appName)
		if err != nil {
			continue
		}
		vm, err = vdc.FindVMByName(nvapp, id)
		if err != nil || utils.IsEmpty(vm) {
			continue
		}
		break
	}

	return vm, nil
}

// TODO: move to compute.go
func (s *Stack) findDiskByID(id string) (*govcd.Disk, fail.Error) {
	_, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return nil, xerr
	}

	res, err := vdc.Query(map[string]string{"type": "disk", "format": "records"})
	if err != nil {
		return nil, normalizeError(err)
	}
	if res.Results != nil {
		r := res.Results
		for _, drec := range r.DiskRecord {
			fdi, err := vdc.FindDiskByHREF(drec.HREF)
			if err != nil {
				continue
			}
			if fdi.Disk.Id == id {
				return fdi, nil
			}
		}
	}

	return nil, fail.NewError("disk with id '%s' not found", id)
}

// TODO: move to compute.go
func (s *Stack) findDiskByName(name string) (*govcd.Disk, fail.Error) {
	_, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return nil, xerr
	}

	res, err := vdc.Query(map[string]string{"type": "disk", "format": "records"})
	if err != nil {
		return nil, normalizeError(err)
	}
	if res.Results != nil {
		r := res.Results
		for _, drec := range r.DiskRecord {
			if drec.Name == name {
				return normalizeError(vdc.FindDiskByHREF(drec.HREF))
			}
		}
	}

	return nil, fail.NewError("disk with name '%s' not found", name)
}

func (s *Stack) findEdgeGatewayNames() ([]string, fail.Error) {
	_, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return []string{}, xerr
	}

	var gateways []string

	res, err := vdc.Query(map[string]string{"type": "edgeGateway", "format": "records"})
	if err != nil {
		return gateways, normalizeError(err)
	}
	if res.Results != nil {
		r := res.Results
		for _, egr := range r.EdgeGatewayRecord {
			gateways = append(gateways, egr.Name)
		}
	}

	return gateways, nil
}

func (s *Stack) getPublicIPs() (types.IPRanges, error) {
	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return types.IPRanges{}, err
	}

	names, err := s.findEdgeGatewayNames()
	if err != nil {
		return types.IPRanges{}, err
	}
	if len(names) == 0 {
		return types.IPRanges{}, fail.NewError("No edge gateway found")
	}

	eg, err := vdc.FindEdgeGateway(names[0])
	if err != nil {
		return types.IPRanges{}, normalizeError(err)
	}

	gins := eg.EdgeGateway.Configuration.GatewayInterfaces
	for _, gif := range gins.GatewayInterface {
		if gif.SubnetParticipation.IPRanges != nil {
			return *gif.SubnetParticipation.IPRanges, nil
		}
	}

	return types.IPRanges{}, fail.NewError("No public IPs found")
}

func ipv4MaskString(m []byte) (string, fail.Error) {
	if len(m) != 4 {
		return "", fail.InvalidParameterError("m", "must be 4 bytes")
	}

	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3]), nil
}

func toIPRange(cidr string) (types.IPRanges, fail.Error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return types.IPRanges{}, fail.ToError(err)
	}
	var first net.IP
	var last net.IP
	found := false
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		if !found {
			found = true
			first = dupIP(ip)
		}
		last = dupIP(ip)
	}

	ipRange := make([]*types.IPRange, 0, 1)

	if first == nil || last == nil {
		return types.IPRanges{}, fail.NewError("error processing network mask")
	}

	ipr := types.IPRange{
		StartAddress: first.String(),
		EndAddress:   last.String(),
	}

	ipRange = append(ipRange, &ipr)

	ipRanges := types.IPRanges{
		IPRange: ipRange,
	}

	return ipRanges, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func dupIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func getGateway(cidr string) (net.IP, fail.Error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return net.IP{}, fail.ToError(err)
	}
	var first net.IP
	found := false
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		if !found && isGatewayIP(ip) {
			found = true
			first = dupIP(ip)
			break
		}
	}

	return first, nil
}

func toValidIPRange(cidr string) (types.IPRanges, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return types.IPRanges{}, fail.ToError(err)
	}
	var first net.IP
	var last net.IP
	found := false
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		if !found && !isReservedIP(ip) {
			found = true
			first = dupIP(ip)
		}
		if !isReservedIP(ip) {
			last = dupIP(ip)
		}
	}

	ipRange := make([]*types.IPRange, 0, 1)

	if first == nil || last == nil {
		return types.IPRanges{}, fail.NewError("error processing network mask")
	}

	ipr := types.IPRange{
		StartAddress: first.String(),
		EndAddress:   last.String(),
	}

	ipRange = append(ipRange, &ipr)

	ipRanges := types.IPRanges{
		IPRange: ipRange,
	}

	return ipRanges, nil
}

func isGatewayIP(ip net.IP) bool {
	gwip := false
	if ip[len(ip)-1] == 1 {
		gwip = true
	}
	return gwip
}

func isReservedIP(ip net.IP) bool {
	reserved := false
	if ip[len(ip)-1] == 0 || ip[len(ip)-1] == 1 || ip[len(ip)-1] == 255 {
		reserved = true
	}
	return reserved
}

func getLinks(org govcd.Org, typed string) ([]types.Link, fail.Error) {
	var result []types.Link

	for _, item := range org.Org.Link {
		if strings.Contains(item.Type, typed) {
			result = append(result, *item)
		}
	}

	return result, nil
}

// CreateNetwork creates a network named name
func (s *Stack) CreateNetwork(req abstract.NetworkRequest) (network *abstract.Network, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debug("vclouddirector.Client.CreateSubnet() called")
	defer logrus.Debug("vclouddirector.Client.CreateSubnet() done")

	org, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return nil, xerr
	}
	if utils.IsEmpty(org) || utils.IsEmpty(vdc) {
		return nil, fail.NewError("Error recovering information")
	}

	// Check if network is already there
	refs, xerr := getLinks(org, "vcloud.orgNetwork")
	if xerr != nil {
		return nil, xerr
	}
	for _, ref := range refs {
		if req.Name == ref.Name {
			return nil, fail.DuplicateError("network '%s' already exists", req.Name)
		}
	}

	// Get edge gateway name
	edgeGatewayName := ""
	res, err := vdc.Query(map[string]string{"type": "edgeGateway", "format": "records"})
	if err != nil {
		return nil, normalizeError(err)
	}
	if res.Results != nil {
		r := res.Results
		for _, egr := range r.EdgeGatewayRecord {
			edgeGatewayName = egr.Name
		}
	}

	var edgeGateway govcd.EdgeGateway
	if edgeGatewayName != "" {
		edgeGateway, err = vdc.FindEdgeGateway(edgeGatewayName)
		if err != nil {
			return nil, fail.Wrap(err, "unable to recover gateway")
		}
	}

	// Checks if Targets is valid...
	_, networkDesc, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return nil, fail.Wrap(err, "failed to create subnet '%s (%s)'", req.Name, req.CIDR)
	}

	stringMask, err := ipv4MaskString(networkDesc.Mask)
	if err != nil {
		return nil, fail.Wrap(err, "Invalid ipv4 mask")
	}

	gwIP, _ := getGateway(req.CIDR)

	var dns []string
	for _, adns := range s.Config.DNSList {
		if adns != "" {
			dns = append(dns, adns)
		}
	}

	dns = append(dns, "8.8.4.4")
	dns = append(dns, "1.1.1.1")

	orgVDCNetwork := &types.OrgVDCNetwork{
		Xmlns: "http://www.vmware.com/vcloud/v1.5",
		Name:  req.Name,
		EdgeGateway: &types.Reference{
			HREF: edgeGateway.EdgeGateway.HREF,
		},
		Configuration: &types.NetworkConfiguration{
			FenceMode: "natRouted",
			IPScopes: &types.IPScopes{
				IPScope: types.IPScope{
					IsInherited: false,
					Gateway:     gwIP.String(),
					Netmask:     stringMask,
					DNS1:        dns[0],
					DNS2:        dns[1],
					DNSSuffix:   "",
					IPRanges:    &types.IPRanges{},
				},
			},
			BackwardCompatibilityMode: true,
		},
		IsShared: false,
	}

	err = vdc.CreateOrgVDCNetworkWait(orgVDCNetwork)
	if err != nil {
		return nil, normalizeError(err)
	}

	// Starting from here, delete network if exit with error
	defer func() {
		if err != nil {
			createdNet, derr := vdc.FindVDCNetwork(req.Name)
			if derr != nil {
				logrus.Errorf("failed to delete network during cleanup '%s' : '%v'", req.Name, normalizeError(derr))
			}

			cleanTask, derr := createdNet.Delete()
			if derr != nil {
				logrus.Errorf("failed to delete network during cleanup '%s' : '%v'", req.Name, normalizeError(derr))
			}

			derr = cleanTask.WaitTaskCompletion()
			if derr != nil {
				logrus.Errorf("failed to delete network during cleanup '%s' : '%v'", req.Name, normalizeError(derr))
			}
		}
	}()

	createdNetwork, err := vdc.FindVDCNetwork(req.Name)
	if err != nil {
		return nil, normalizeError(err)
	}

	ran, xerr := toValidIPRange(req.CIDR)
	if xerr != nil {
		return nil, xerr
	}

	var dhcpPool []interface{}
	item := make(map[string]interface{})

	item["start_address"] = ran.IPRange[0].StartAddress
	item["end_address"] = ran.IPRange[0].EndAddress

	dhcpPool = append(dhcpPool, item)

	dhcpthing, err := edgeGateway.AddDhcpPool(createdNetwork.OrgVDCNetwork, dhcpPool)
	if err != nil {
		return nil, normalizeError(err)
	}
	err = dhcpthing.WaitTaskCompletion()
	if err != nil {
		return nil, normalizeError(err)
	}

	defer func() {
		if err != nil {
			var flush []interface{}
			dtask, derr := edgeGateway.DeleteDhcpPool(createdNetwork.OrgVDCNetwork, flush)
			if derr != nil {
				logrus.Errorf("failed to delete network during cleanup '%s' : '%v'", req.Name, normalizeError(derr))
			}
			derr = dtask.WaitTaskCompletion()
			if derr != nil {
				logrus.Errorf("failed to delete network during cleanup '%s' : '%v'", req.Name, normalizeError(derr))
			}
		}
	}()

	// FIXME: Configure SNAT before powering on

	iprange, xerr := s.getPublicIPs()
	if xerr != nil {
		return nil, xerr
	}
	natTask, err := edgeGateway.AddNATMapping("SNAT", req.CIDR, iprange.IPRange[0].StartAddress)
	if err != nil {
		return nil, normalizeError(err)
	}
	err = natTask.WaitTaskCompletion()
	if err != nil {
		return nil, normalizeError(err)
	}

	defer func() {
		if xerr != nil {
			dtask, derr := edgeGateway.RemoveNATMapping("SNAT", req.CIDR, iprange.IPRange[0].StartAddress, "")
			if derr != nil {
				logrus.Errorf("failed to delete network during cleanup '%s' : '%v'", req.Name, normalizeError(derr))
			}
			derr = dtask.WaitTaskCompletion()
			if derr != nil {
				logrus.Errorf("failed to delete network during cleanup '%s' : '%v'", req.Name, normalizeError(derr))
			}
		}
	}()

	network = abstract.NewNetwork()

	// FIXME Remove this, get info from recently created network
	network.ID = createdNetwork.OrgVDCNetwork.ID
	network.Name = req.Name
	network.CIDR = req.CIDR

	return network, nil
}

// InspectNetwork returns the network identified by ref (id or name)
func (s *Stack) InspectNetwork(ref string) (*abstract.Network, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debug("vclouddirector.Client.InspectNetwork() called")
	defer logrus.Debug("vclouddirector.Client.InspectNetwork() done")

	org, err := govcd.GetOrgByName(s.EbrcService, s.AuthOptions.ProjectName)
	if err != nil {
		return nil, normalizeError(err)
	}

	vdc, err := org.GetVdcByName(s.AuthOptions.ProjectID)
	if err != nil {
		return nil, normalizeError(err)
	}

	res, err := vdc.Query(map[string]string{"type": "orgNetwork", "format": "records"})
	if err != nil {
		return nil, normalizeError(err)
	}
	if res.Results != nil {
		for _, li := range res.Results.Link {
			if li.Name == ref {
				newnet := &abstract.Network{
					ID:        li.ID,
					Name:      li.Name,
					CIDR:      "",
					GatewayID: "",
					IPVersion: 0,
				}
				return newnet, nil
			}
		}
	}

	return nil, abstract.ResourceNotFoundError("network", ref)
}

// GetNetworkByName returns the network identified by ref (id or name)
func (s *Stack) GetNetworkByName(ref string) (*abstract.Network, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debug("vclouddirector.Client.InspectSubnetByName() called")
	defer logrus.Debug("vclouddirector.Client.InspectSubnetByName() done")

	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return nil, normalizeError(err)
	}

	onet, err := vdc.FindVDCNetwork(ref)
	if err != nil {
		if strings.Contains(err.Error(), "can't find") {
			return nil, abstract.ResourceNotFoundError("network", ref)
		} else {
			return nil, normalizeError(err)
		}
	}

	newnet := &abstract.Network{
		ID:   onet.OrgVDCNetwork.ID,
		Name: onet.OrgVDCNetwork.Name,
	}
	return newnet, nil
}

// ListNetworks lists available networks
func (s *Stack) ListNetworks() ([]*abstract.Network, fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debug("vclouddirector.Client.ListSubnets() called")
	defer logrus.Debug("vclouddirector.Client.ListSubnets() done")

	org, err := govcd.GetOrgByName(s.EbrcService, s.AuthOptions.ProjectName)
	if err != nil {
		return nil, normalizeError(err)
	}

	refs, xerr := getLinks(org, "vcloud.orgNetwork")
	if xerr != nil {
		return nil, xerr
	}

	var nets []*abstract.Network
	for _, ref := range refs {
		newnet := &abstract.Network{
			ID:        ref.ID,
			Name:      ref.Name,
			CIDR:      "",
			GatewayID: "",
			IPVersion: 0,
		}
		nets = append(nets, newnet)
	}

	return nets, nil
}

// DeleteNetwork deletes the network identified by id
func (s *Stack) DeleteNetwork(ref string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	// TODO: use concurrency.Tracer
	logrus.Debug("vclouddirector.Client.DeleteSubnet() called")
	defer logrus.Debug("vclouddirector.Client.DeleteSubnet() done")

	_, vdc, xerr := s.getOrgVdc()
	if xerr != nil {
		return xerr
	}

	nett2, err := vdc.FindVDCNetwork(ref)
	if err != nil {
		return normalizeError(err)
	}

	task, err := nett2.Delete()
	if err != nil {
		return normalizeError(err)
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		return normalizeError(err)
	}

	return nil
}

// VPL: has to disappear
// // CreateGateway creates a public Gateway for a private network
// func (s *stack) CreateGateway(req abstract.GatewayRequest, sizing *abstract.SizingRequirements) (host *abstract.IPAddress, content *userdata.Content, err error) {
//	logrus.Debug("vclouddirector.Client.CreateGateway() called")
//	defer logrus.Debug("vclouddirector.Client.CreateGateway() done")
//
//	if s == nil {
//		return nil, nil, fail.InvalidInstanceError()
//	}
//
//	if req.Networking == nil {
//		return nil, nil, fail.InvalidParameterError("req.Networking", "cannot be nil")
//	}
//	gwname := strings.Split(req.Name, ".")[0]   // req.Name may contain a FQDN...
//	if gwname == "" {
//		gwname = "gw-" + req.Networking.Name
//	}
//
//	hostReq := abstract.HostRequest{
//		ImageID:      req.ImageID,
//		KeyPair:      req.KeyPair,
//		HostName:     req.Name,
//		ResourceName: gwname,
//		TemplateID:   req.TemplateID,
//		Networks:     []*abstract.Networking{req.Networking},
//		PublicIP:     true,
//	}
//	if sizing != nil && sizing.MinDiskSize > 0 {
//		hostReq.DiskSize = sizing.MinDiskSize
//	}
//	host, userData, err := s.CreateHost(hostReq)
//	if err != nil {
//		switch err.(type) {
//		case fail.ErrInvalidRequest:
//			return nil, userData, err
//		default:
//			return nil, userData, fail.Errorf(fmt.Sprintf("Error creating gateway : %s", openstack.ProviderErrorToString(err)), err)
//		}
//	}
//
//	// Updates IPAddress Property propsv1.HostSizing
//	err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(func(clonable data.Clonable) error {
//		hostSizingV1 := clonable.(*propsv1.HostSizing)
//		hostSizingV1.Template = req.TemplateID
//		return nil
//	})
//	if err != nil {
//		return nil, userData, fail.Wrap(err, fmt.Sprintf("error creating gateway : %s", err))
//	}
//
//	return host, userData, err
// }
//
// // DeleteGateway delete the public gateway referenced by ref (id or name)
// func (s *stack) DeleteGateway(ref string) error {
//	if s == nil {
//		return fail.InvalidInstanceError()
//	}
//
//	return s.DeleteHost(ref)
// }

func (s *Stack) CreateVIP(string, string, string, []string) (*abstract.VirtualIP, fail.Error) {
	return nil, fail.NotImplementedError("CreateVIP() not implemented yet") // FIXME: Technical debt
}

func (s *Stack) AddPublicIPToVIP(ip *abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

func (s *Stack) BindHostToVIP(ip *abstract.VirtualIP, s2 string) fail.Error {
	return fail.NotImplementedError("BindHostToVIP() not implemented yet") // FIXME: Technical debt
}

func (s *Stack) UnbindHostFromVIP(ip *abstract.VirtualIP, s2 string) fail.Error {
	return fail.NotImplementedError("UnbindHostFromVIP() not implemented yet") // FIXME: Technical debt
}

func (s *Stack) DeleteVIP(ip *abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("DeleteVIP() not implemented yet") // FIXME: Technical debt
}
