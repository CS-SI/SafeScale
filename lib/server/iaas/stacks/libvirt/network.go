// +build libvirt

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

package local

import (
	"encoding/xml"
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"

	"github.com/libvirt/libvirt-go"
	libvirtxml "github.com/libvirt/libvirt-go-xml"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/userdata"
)

func infoFromCidr(cidr string) (string, string, string, string, fail.Error) {
	IP, IPNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", "", "", fail.Errorf(fmt.Sprintf("failed to parse cidr : %s", err.Error()), err)
	} else if IPNet.Mask[3] >= 63 {
		return "", "", "", "", fail.Errorf(fmt.Sprintf("please use a wider network range"), err)
	}

	mask := fmt.Sprintf("%d.%d.%d.%d", IPNet.Mask[0], IPNet.Mask[1], IPNet.Mask[2], IPNet.Mask[3])
	dhcpStart := fmt.Sprintf("%d.%d.%d.%d", IP[12], IP[13], IPNet.IP[2], IPNet.IP[3]+2)
	dhcpEnd := fmt.Sprintf(
		"%d.%d.%d.%d", IP[12], IP[13], IPNet.IP[2]+(255-IPNet.Mask[2]), IPNet.IP[3]+(255-IPNet.Mask[3]-1),
	)

	return IPNet.IP.String(), mask, dhcpStart, dhcpEnd, nil
}

func getNetworkFromRef(ref string, libvirtService *libvirt.Connect) (*libvirt.Network, fail.Error) {
	libvirtNetwork, err := libvirtService.LookupNetworkByUUIDString(ref)
	if err != nil {
		libvirtNetwork, err = libvirtService.LookupNetworkByName(ref)
		if err != nil {
			re := regexp.MustCompile("[0-9]+")
			errCode, _ := strconv.Atoi(re.FindString(err.Error()))
			if errCode == 43 {
				return nil, abstract.ResourceNotFoundError("network", ref)
			}
			return nil, fail.Errorf(
				fmt.Sprintf(fmt.Sprintf("failed to fetch network from ref : %s", err.Error())), err,
			)
		}
	}

	return libvirtNetwork, nil
}

func getNetworkFromLibvirtNetwork(libvirtNetwork *libvirt.Network) (*abstract.Network, fail.Error) {
	libvirtNetworkXML, err := libvirtNetwork.GetXMLDesc(0)
	if err != nil {
		return nil, fail.Errorf(
			fmt.Sprintf(fmt.Sprintf("failed get network's xml description  : %s", err.Error())), err,
		)
	}
	networkDescription := &libvirtxml.Network{}
	err = xml.Unmarshal([]byte(libvirtNetworkXML), networkDescription)
	if err != nil {
		return nil, fail.Errorf(
			fmt.Sprintf(
				fmt.Sprintf(
					"failed get Unmarshal networks's xml description  : %s", err.Error(),
				),
			), err,
		)
	}

	var ipVersion ipversion.Enum
	if networkDescription.IPv6 == "" {
		ipVersion = ipversion.IPv4
	} else {
		ipVersion = ipversion.IPv6
	}

	cidr := ""
	if ipVersion == ipversion.IPv4 {
		netmaskBloc := strings.Split(networkDescription.IPs[0].Netmask, ".")
		ipBlocstring := strings.Split(networkDescription.IPs[0].Address, ".")
		var ipBloc [4]int
		netmaskInt := 0
		for i := 0; i < 4; i++ {
			value, err := strconv.Atoi(netmaskBloc[i])
			ipBloc[i], err = strconv.Atoi(ipBlocstring[i])
			if err != nil {
				return nil, fail.Errorf(fmt.Sprintf("failed to convert x.x.x.x nemask to [0-32] netmask"), err)
			}
			nbBits := 0
			if value != 0 {
				nbBits = int(math.Log2(float64(value)) + 1)
				netmaskInt += nbBits
			}
			ipBloc[i] -= ipBloc[i] % int(math.Pow(2, float64(8-nbBits)))
		}
		cidr = fmt.Sprintf("%d.%d.%d.%d/%d", ipBloc[0], ipBloc[1], ipBloc[2], ipBloc[3], netmaskInt)
	} else {
		cidr = networkDescription.IPv6
	}

	network := abstract.NewNetwork()
	network.ID = networkDescription.UUID
	network.Name = networkDescription.Name
	network.CIDR = cidr
	network.IPVersion = ipVersion
	// network.GatewayID
	// network.Properties

	return network, nil
}

// CreateNetwork creates a network named name
func (s *Stack) CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	defer debug.NewTracer(nil, "", true).GoingIn().OnExitTrace()()

	name := req.Name
	ipVersion := req.IPVersion
	cidr := req.CIDR
	dns := req.DNSServers

	if ipVersion != ipversion.IPv4 {
		// TODO: implement IPV6 networks
		return nil, fail.NotImplementedError("only ipv4 networks are implemented")
	}
	if len(dns) != 0 {
		// TODO: implement DNS for networks
		return nil, fail.NotImplementedError("DNS not implemented yet in networks creation") // FIXME: Technical debt
	}

	libvirtNetwork, err := getNetworkFromRef(name, s.LibvirtService)
	if err != nil {
		if _, ok := err.(fail.ErrNotFound); !ok {
			return nil, err
		}
	}

	if libvirtNetwork != nil {
		return nil, fail.Errorf(fmt.Sprintf("network %s already exists", name), err)
	}

	ip, netmask, dhcpStart, dhcpEnd, err := infoFromCidr(cidr)
	if err != nil {
		return nil, err
	}

	requestXML := `
	 <network>
		 <name>` + name + `</name>
		 <ip address="` + ip + `" netmask="` + netmask + `">
			 <dhcp>
				 <range start="` + dhcpStart + `" end="` + dhcpEnd + `" />
			 </dhcp>
		 </ip>
	 </network>`

	libvirtNetwork, err = s.LibvirtService.NetworkDefineXML(requestXML)
	if err != nil {
		return nil, fail.Errorf(fmt.Sprintf("failed to create network : %s", err.Error()), err)
	}
	defer func(*libvirt.Network) {
		if err != nil {
			if err := libvirtNetwork.Undefine(); err != nil {
				fmt.Printf("failed undefining network %s : %s\n", name, err.Error())
				if err := libvirtNetwork.Destroy(); err != nil {
					fmt.Printf("failed to destroy network %s : %s\n", name, err.Error())
				}
			}
		}
	}(libvirtNetwork)

	err = libvirtNetwork.SetAutostart(true)
	if err != nil {
		return nil, fail.Errorf(fmt.Sprintf("failed to enable network autostart : %s", err.Error()), err)
	}
	err = libvirtNetwork.Create()
	if err != nil {
		return nil, fail.Errorf(fmt.Sprintf("failed to start network : %s", err.Error()), err)
	}

	network, err := getNetworkFromLibvirtNetwork(libvirtNetwork)
	if err != nil {
		return nil, fail.Errorf(
			fmt.Sprintf("failed to convert a libvirt network into a network : %s", err.Error()), err,
		)
	}

	return network, nil
}

// GetNetwork returns the network identified by ref (id or name)
func (s *Stack) GetNetwork(ref string) (*abstract.Network, fail.Error) {
	defer debug.NewTracer(nil, "", true).GoingIn().OnExitTrace()()

	libvirtNetwork, err := getNetworkFromRef(ref, s.LibvirtService)
	if err != nil {
		return nil, err
	}
	active, err := libvirtNetwork.IsActive()
	if err != nil {
		return nil, fail.Errorf(fmt.Sprintf("failed to check if the network is active : %s", err.Error()), err)
	}
	if !active {
		err = libvirtNetwork.Create()
		if err != nil {
			return nil, fail.Errorf(fmt.Sprintf("failed to start network : %s", err.Error()), err)
		}
	}

	network, err := getNetworkFromLibvirtNetwork(libvirtNetwork)
	if err != nil {
		return nil, fail.Errorf(
			fmt.Sprintf("failed to convert a libvirt network into a network : %s", err.Error()), err,
		)
	}

	return network, nil
}

// GetNetworkByName returns the network identified by ref (id or name)
func (s *Stack) GetNetworkByName(ref string) (*abstract.Network, fail.Error) {
	defer debug.NewTracer(nil, "", true).GoingIn().OnExitTrace()()
	return s.GetNetwork(ref)
}

// ListNetworks lists available networks
func (s *Stack) ListNetworks() ([]*abstract.Network, fail.Error) {
	defer debug.NewTracer(nil, "", true).GoingIn().OnExitTrace()()

	var networks []*abstract.Network

	libvirtNetworks, err := s.LibvirtService.ListAllNetworks(3)
	if err != nil {
		return nil, fail.Errorf(fmt.Sprintf(fmt.Sprintf("error listing networks : %s", err.Error())), err)
	}
	for _, libvirtNetwork := range libvirtNetworks {
		network, err := getNetworkFromLibvirtNetwork(&libvirtNetwork)
		if err != nil {
			return nil, fail.Errorf(
				fmt.Sprintf(
					fmt.Sprintf(
						"failed to get network from libvirtNetwork : %s", err.Error(),
					),
				), err,
			)
		}

		networks = append(networks, network)
	}

	return networks, nil
}

// DeleteNetwork deletes the network identified by id
func (s *Stack) DeleteNetwork(ref string) error {
	defer debug.NewTracer(nil, "", true).GoingIn().OnExitTrace()()

	libvirtNetwork, err := getNetworkFromRef(ref, s.LibvirtService)
	if err != nil {
		return err
	}

	isActive, err := libvirtNetwork.IsActive()
	if err != nil {
		return fail.Errorf(fmt.Sprintf("failed to check if the network is active : %s", err.Error()), err)
	}
	if isActive {
		err = libvirtNetwork.Destroy()
		if err != nil {
			return fail.Errorf(fmt.Sprintf("failed to destroy network : %s", err.Error()), err)
		}
	}

	err = libvirtNetwork.Undefine()
	if err != nil {
		return fail.Errorf(fmt.Sprintf("failed to undefine network : %s", err.Error()), err)
	}

	return nil
}

// CreateGateway creates a public Gateway for a private network
func (s *Stack) CreateGateway(req abstract.GatewayRequest, sizing *abstract.SizingRequirements) (*abstract.Host, *userdata.Content, fail.Error) {
	defer debug.NewTracer(nil, "", true).GoingIn().OnExitTrace()()

	network := req.Network
	templateID := req.TemplateID
	imageID := req.ImageID
	keyPair := req.KeyPair

	networkLibvirt, err := getNetworkFromRef(network.ID, s.LibvirtService)
	if err != nil {
		return nil, nil, err
	}
	gwName := strings.Split(req.Name, ".")[0] // req.Name may contain a FQDN...
	if gwName == "" {
		name, err := networkLibvirt.GetName()
		if err != nil {
			return nil, nil, fail.Errorf(fmt.Sprintf("failed to get network name : %s", err.Error()), err)
		}
		gwName = "gw-" + name
	}

	hostReq := abstract.HostRequest{
		ImageID:      imageID,
		KeyPair:      keyPair,
		HostName:     req.Name,
		ResourceName: gwName,
		TemplateID:   templateID,
		Networks:     []*abstract.Network{network},
		PublicIP:     true,
	}
	if sizing != nil && sizing.MinDiskSize > 0 {
		hostReq.DiskSize = sizing.MinDiskSize
	}
	host, userData, err := s.CreateHost(hostReq)
	if err != nil {
		return nil, nil, fail.Errorf(fmt.Sprintf("failed to create gateway host : %s", err.Error()), err)
	}

	return host, userData, nil
}

// DeleteGateway delete the public gateway referenced by ref (id or name)
func (s *Stack) DeleteGateway(ref string) error {
	defer debug.NewTracer(nil, "", true).GoingIn().OnExitTrace()()

	return s.DeleteHost(ref)
}

// CreateVIP creates a private virtual IP
// If public is set to true,
func (s *Stack) CreateVIP(networkID string, description string) (*abstract.VirtualIP, fail.Error) {
	return nil, fail.NotImplementedError("CreateVIP() not implemented yet") // FIXME: Technical debt
}

// AddPublicIPToVIP adds a public IP to VIP
func (s *Stack) AddPublicIPToVIP(vip *abstract.VirtualIP) error {
	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (s *Stack) BindHostToVIP(vip *abstract.VirtualIP, hostID string) error {
	return fail.NotImplementedError("BindHostToVIP() not implemented yet") // FIXME: Technical debt
}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (s *Stack) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) error {
	return fail.NotImplementedError("UnbindHostFromVIP() not implemented yet") // FIXME: Technical debt
}

// DeleteVIP deletes the port corresponding to the VIP
func (s *Stack) DeleteVIP(vip *abstract.VirtualIP) error {
	return fail.NotImplementedError("DeleteVIP() not implemented yet") // FIXME: Technical debt
}
