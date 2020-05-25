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

package ebrc

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hostproperty"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vmware/go-vcloud-director/govcd"
	"github.com/vmware/go-vcloud-director/types/v56"
	"net"
	"strings"
)

func (s *StackEbrc) getOrgVdc() (govcd.Org, govcd.Vdc, error) {
	org, err := govcd.GetOrgByName(s.EbrcService, s.AuthOptions.ProjectName)
	if err != nil {
		return govcd.Org{}, govcd.Vdc{}, err
	}

	vdc, err := org.GetVdcByName(s.AuthOptions.ProjectID)
	if err != nil {
		return govcd.Org{}, govcd.Vdc{}, err
	}

	return org, vdc, nil
}

func (s *StackEbrc) findVAppNames() ([]string, error) {
	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return []string{}, err
	}

	var vappNames []string

	res, err := vdc.Query(map[string]string{"type": "vApp", "format": "records"})
	if err != nil {
		return vappNames, err
	}

	if res.Results != nil {
		r := res.Results
		for _, app := range r.VAppRecord {
			vappNames = append(vappNames, app.Name)
		}
	}

	return vappNames, nil
}

func (s *StackEbrc) findVmNames() ([]string, error) {
	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return []string{}, err
	}

	var vmNames []string

	res, err := vdc.Query(map[string]string{"type": "vm", "format": "records"})
	if err != nil {
		return vmNames, err
	}
	if res.Results != nil {
		r := res.Results
		for _, vm := range r.VMRecord {
			vmNames = append(vmNames, vm.Name)
		}
	}

	return vmNames, nil
}

func (s *StackEbrc) findVMByID(id string) (govcd.VM, error) {
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

func (s *StackEbrc) findVMByIDS(id string) (govcd.VM, error) {
	_, vdc, err := s.getOrgVdc()

	if err != nil {
		return govcd.VM{}, nil
	}

	vm, err := vdc.FindDefaultVMByVAppID(id)
	if err != nil {
		return govcd.VM{}, nil
	}

	return vm, nil
}

func (s *StackEbrc) findVMByName(id string) (govcd.VM, error) {
	_, vdc, err := s.getOrgVdc()

	appNames, err := s.findVAppNames()
	if err != nil {
		return govcd.VM{}, err
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
		} else {
			break
		}
	}

	return vm, nil
}

func (s *StackEbrc) findDiskByID(id string) (*govcd.Disk, error) {
	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return nil, err
	}

	res, err := vdc.Query(map[string]string{"type": "disk", "format": "records"})
	if err != nil {
		return nil, err
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

	return nil, scerr.Errorf(fmt.Sprintf("Disk with id [%s] not found", id), nil)
}

func (s *StackEbrc) findDiskByName(id string) (*govcd.Disk, error) {
	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return nil, err
	}

	res, err := vdc.Query(map[string]string{"type": "disk", "format": "records"})
	if err != nil {
		return nil, err
	}
	if res.Results != nil {
		r := res.Results
		for _, drec := range r.DiskRecord {
			if drec.Name == id {
				return vdc.FindDiskByHREF(drec.HREF)
			}
		}
	}

	return nil, scerr.Errorf(fmt.Sprintf("Disk with name [%s] not found", id), nil)
}

func (s *StackEbrc) findEdgeGatewayNames() ([]string, error) {
	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return []string{}, err
	}

	var gateways []string

	res, err := vdc.Query(map[string]string{"type": "edgeGateway", "format": "records"})
	if err != nil {
		return gateways, err
	}
	if res.Results != nil {
		r := res.Results
		for _, egr := range r.EdgeGatewayRecord {
			gateways = append(gateways, egr.Name)
		}
	}

	return gateways, nil
}

func (s *StackEbrc) getPublicIPs() (types.IPRanges, error) {
	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return types.IPRanges{}, err
	}

	names, err := s.findEdgeGatewayNames()
	if err != nil {
		return types.IPRanges{}, err
	}
	if len(names) == 0 {
		return types.IPRanges{}, scerr.Errorf(fmt.Sprintf("No edge gateway found"), nil)
	}

	eg, err := vdc.FindEdgeGateway(names[0])
	if err != nil {
		return types.IPRanges{}, err
	}

	gins := eg.EdgeGateway.Configuration.GatewayInterfaces
	for _, gif := range gins.GatewayInterface {
		if gif.SubnetParticipation.IPRanges != nil {
			return *gif.SubnetParticipation.IPRanges, nil
		}
	}

	return types.IPRanges{}, scerr.Errorf(fmt.Sprintf("No public IPs found"), nil)
}

func ipv4MaskString(m []byte) (string, error) {
	if len(m) != 4 {
		return "", fmt.Errorf("ipv4Mask: len must be 4 bytes")
	}

	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3]), nil
}

func toIPRange(cidr string) (types.IPRanges, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return types.IPRanges{}, err
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
		return types.IPRanges{}, scerr.Errorf(fmt.Sprintf("error processing network mask"), nil)
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

func getGateway(cidr string) (net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return net.IP{}, err
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
		return types.IPRanges{}, err
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
		return types.IPRanges{}, scerr.Errorf(fmt.Sprintf("error processing network mask"), nil)
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

func getLinks(org govcd.Org, typed string) ([]types.Link, error) {
	var result []types.Link

	for _, item := range org.Org.Link {
		if strings.Contains(item.Type, typed) {
			result = append(result, *item)
		}
	}

	return result, nil
}

// CreateNetwork creates a network named name
func (s *StackEbrc) CreateNetwork(req resources.NetworkRequest) (network *resources.Network, err error) {
	logrus.Debug("ebrc.Client.CreateNetwork() called")
	defer logrus.Debug("ebrc.Client.CreateNetwork() done")

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	org, vdc, err := s.getOrgVdc()
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating network"))
	}

	if utils.IsEmpty(org) || utils.IsEmpty(vdc) {
		return nil, errors.Wrap(err, fmt.Sprintf("Error recovering information"))
	}

	// Check if network is already there
	refs, err := getLinks(org, "vcloud.orgNetwork")
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error recovering network information"))
	}
	for _, ref := range refs {
		if req.Name == ref.Name {
			return nil, scerr.Errorf(fmt.Sprintf("network '%s' already exists", req.Name), nil)
		}
	}

	// Get edge gateway name
	edgeGatewayName := ""
	res, err := vdc.Query(map[string]string{"type": "edgeGateway", "format": "records"})
	if err != nil {
		return nil, err
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
			return nil, scerr.Errorf(fmt.Sprintf("unable to recover gateway: %s", err), err)
		}
	}

	// Checks if CIDR is valid...
	_, networkDesc, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("failed to create subnet '%s (%s)': %s", req.Name, req.CIDR, err.Error()), nil)
	}

	stringMask, err := ipv4MaskString(networkDesc.Mask)
	if err != nil {
		return nil, scerr.Wrap(err, "Invalid ipv4 mask")
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
		return nil, err
	}

	// Starting from here, delete network if exit with error
	defer func() {
		if err != nil {
			createdNet, derr := vdc.FindVDCNetwork(req.Name)
			if derr != nil {
				logrus.Errorf("failed to delete network during cleanup '%s' : '%v'", req.Name, derr)
			}

			cleanTask, derr := createdNet.Delete()
			if derr != nil {
				logrus.Errorf("failed to delete network during cleanup '%s' : '%v'", req.Name, derr)
			}

			derr = cleanTask.WaitTaskCompletion()
			if derr != nil {
				logrus.Errorf("failed to delete network during cleanup '%s' : '%v'", req.Name, derr)
			}
		}
	}()

	createdNetwork, err := vdc.FindVDCNetwork(req.Name)
	if err != nil {
		return nil, err
	}

	ran, err := toValidIPRange(req.CIDR)
	if err != nil {
		return nil, err
	}

	var dhcpPool []interface{}
	item := make(map[string]interface{})

	item["start_address"] = ran.IPRange[0].StartAddress
	item["end_address"] = ran.IPRange[0].EndAddress

	dhcpPool = append(dhcpPool, item)

	dhcpthing, err := edgeGateway.AddDhcpPool(createdNetwork.OrgVDCNetwork, dhcpPool)
	if err != nil {
		return nil, err
	}
	err = dhcpthing.WaitTaskCompletion()
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			var flush []interface{}
			dtask, derr := edgeGateway.DeleteDhcpPool(createdNetwork.OrgVDCNetwork, flush)
			if derr != nil {
				logrus.Errorf("failed to delete network during cleanup '%s' : '%v'", req.Name, derr)
			}
			derr = dtask.WaitTaskCompletion()
			if derr != nil {
				logrus.Errorf("failed to delete network during cleanup '%s' : '%v'", req.Name, derr)
			}
		}
	}()

	// FIXME Configure SNAT before powering on

	iprange, err := s.getPublicIPs()
	if err != nil {
		return nil, err
	}
	natTask, err := edgeGateway.AddNATMapping("SNAT", req.CIDR, iprange.IPRange[0].StartAddress)
	if err != nil {
		return nil, err
	}
	err = natTask.WaitTaskCompletion()
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			dtask, derr := edgeGateway.RemoveNATMapping("SNAT", req.CIDR, iprange.IPRange[0].StartAddress, "")
			if derr != nil {
				logrus.Errorf("failed to delete network during cleanup '%s' : '%v'", req.Name, derr)
			}
			derr = dtask.WaitTaskCompletion()
			if derr != nil {
				logrus.Errorf("failed to delete network during cleanup '%s' : '%v'", req.Name, derr)
			}
		}
	}()

	network = resources.NewNetwork()

	// FIXME Remove this, get info from recently created network
	network.ID = createdNetwork.OrgVDCNetwork.ID
	network.Name = req.Name
	network.CIDR = req.CIDR

	return network, nil
}

// GetNetwork returns the network identified by ref (id or name)
func (s *StackEbrc) GetNetwork(ref string) (*resources.Network, error) {
	logrus.Debug("ebrc.Client.GetNetwork() called")
	defer logrus.Debug("ebrc.Client.GetNetwork() done")

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	org, err := govcd.GetOrgByName(s.EbrcService, s.AuthOptions.ProjectName)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting network"))
	}

	vdc, err := org.GetVdcByName(s.AuthOptions.ProjectID)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting network"))
	}

	res, err := vdc.Query(map[string]string{"type": "orgNetwork", "format": "records"})
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting network"))
	}
	if res.Results != nil {
		for _, li := range res.Results.Link {
			if li.Name == ref {
				newnet := &resources.Network{
					ID:         li.ID,
					Name:       li.Name,
					CIDR:       "",
					GatewayID:  "",
					IPVersion:  0,
					Properties: nil,
				}
				return newnet, nil
			}
		}
	}

	return nil, resources.ResourceNotFoundError("network", ref)
}

// GetNetworkByName returns the network identified by ref (id or name)
func (s *StackEbrc) GetNetworkByName(ref string) (*resources.Network, error) {
	logrus.Debug("ebrc.Client.GetNetworkByName() called")
	defer logrus.Debug("ebrc.Client.GetNetworkByName() done")

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return nil, err
	}

	onet, err := vdc.FindVDCNetwork(ref)
	if err != nil {
		if strings.Contains(err.Error(), "can't find") {
			return nil, resources.ResourceNotFoundError("network", ref)
		} else {
			return nil, err
		}
	}

	newnet := &resources.Network{
		ID:   onet.OrgVDCNetwork.ID,
		Name: onet.OrgVDCNetwork.Name,
	}

	return newnet, nil
}

// ListNetworks lists available networks
func (s *StackEbrc) ListNetworks() ([]*resources.Network, error) {
	logrus.Debug("ebrc.Client.ListNetworks() called")
	defer logrus.Debug("ebrc.Client.ListNetworks() done")

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	org, err := govcd.GetOrgByName(s.EbrcService, s.AuthOptions.ProjectName)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error listing networks"))
	}

	refs, err := getLinks(org, "vcloud.orgNetwork")
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error listing networks"))
	}

	var nets []*resources.Network
	for _, ref := range refs {
		newnet := &resources.Network{
			ID:         ref.ID,
			Name:       ref.Name,
			CIDR:       "",
			GatewayID:  "",
			IPVersion:  0,
			Properties: nil,
		}
		nets = append(nets, newnet)
	}

	return nets, nil
}

// DeleteNetwork deletes the network identified by id
func (s *StackEbrc) DeleteNetwork(ref string) error {
	logrus.Debug("ebrc.Client.DeleteNetwork() called")
	defer logrus.Debug("ebrc.Client.DeleteNetwork() done")

	if s == nil {
		return scerr.InvalidInstanceError()
	}

	_, vdc, err := s.getOrgVdc()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error deleting network"))
	}

	nett2, err := vdc.FindVDCNetwork(ref)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error deleting network"))
	}

	task, err := nett2.Delete()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error deleting network"))
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error deleting network"))
	}

	return nil
}

// CreateGateway creates a public Gateway for a private network
func (s *StackEbrc) CreateGateway(req resources.GatewayRequest) (host *resources.Host, content *userdata.Content, err error) {
	logrus.Debug("ebrc.Client.CreateGateway() called")
	defer logrus.Debug("ebrc.Client.CreateGateway() done")

	if s == nil {
		return nil, nil, scerr.InvalidInstanceError()
	}

	if req.Network == nil {
		return nil, nil, scerr.InvalidParameterError("req.Network", "cannot be nil")
	}
	gwname := strings.Split(req.Name, ".")[0]   // req.Name may contain a FQDN...
	if gwname == "" {
		gwname = "gw-" + req.Network.Name
	}

	hostReq := resources.HostRequest{
		ImageID:      req.ImageID,
		KeyPair:      req.KeyPair,
		HostName:     req.Name,
		ResourceName: gwname,
		TemplateID:   req.TemplateID,
		Networks:     []*resources.Network{req.Network},
		PublicIP:     true,
	}
	host, userData, err := s.CreateHost(hostReq)
	if err != nil {
		switch err.(type) {
		case scerr.ErrInvalidRequest:
			return nil, userData, err
		default:
			return nil, userData, scerr.Errorf(fmt.Sprintf("Error creating gateway : %s", openstack.ProviderErrorToString(err)), err)
		}
	}

	// Updates Host Property propsv1.HostSizing
	err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(func(clonable data.Clonable) error {
		hostSizingV1 := clonable.(*propsv1.HostSizing)
		hostSizingV1.Template = req.TemplateID
		return nil
	})
	if err != nil {
		return nil, userData, scerr.Wrap(err, fmt.Sprintf("error creating gateway : %s", err))
	}

	return host, userData, err
}

// DeleteGateway delete the public gateway referenced by ref (id or name)
func (s *StackEbrc) DeleteGateway(ref string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}

	return s.DeleteHost(ref)
}
