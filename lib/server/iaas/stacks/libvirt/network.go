//+build libvirt

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

package local

import (
	"encoding/xml"
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/libvirt/libvirt-go"
	libvirtxml "github.com/libvirt/libvirt-go-xml"
)

func infoFromCidr(cidr string) (string, string, string, string, error) {
	IP, IPNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to parse cidr : %s", err.Error())
	} else if IPNet.Mask[3] >= 63 {
		return "", "", "", "", fmt.Errorf("please use a wider network range")
	}

	mask := fmt.Sprintf("%d.%d.%d.%d", IPNet.Mask[0], IPNet.Mask[1], IPNet.Mask[2], IPNet.Mask[3])
	dhcpStart := fmt.Sprintf("%d.%d.%d.%d", IP[12], IP[13], IPNet.IP[2], IPNet.IP[3]+2)
	dhcpEnd := fmt.Sprintf("%d.%d.%d.%d", IP[12], IP[13], IPNet.IP[2]+(255-IPNet.Mask[2]), IPNet.IP[3]+(255-IPNet.Mask[3]-1))

	return IPNet.IP.String(), mask, dhcpStart, dhcpEnd, nil
}

func getNetworkFromRef(ref string, libvirtService *libvirt.Connect) (*libvirt.Network, error) {
	libvirtNetwork, err := libvirtService.LookupNetworkByUUIDString(ref)
	if err != nil {
		libvirtNetwork, err = libvirtService.LookupNetworkByName(ref)
		if err != nil {
			re := regexp.MustCompile("[0-9]+")
			errCode, _ := strconv.Atoi(re.FindString(err.Error()))
			if errCode == 43 {
				return nil, resources.ResourceNotFoundError("network", ref)
			}
			return nil, fmt.Errorf(fmt.Sprintf("failed to fetch network from ref : %s", err.Error()))
		}
	}

	return libvirtNetwork, nil
}

func getNetworkFromLibvirtNetwork(libvirtNetwork *libvirt.Network) (*resources.Network, error) {
	libvirtNetworkXML, err := libvirtNetwork.GetXMLDesc(0)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("failed get network's xml description  : %s", err.Error()))
	}
	networkDescription := &libvirtxml.Network{}
	err = xml.Unmarshal([]byte(libvirtNetworkXML), networkDescription)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("failed get Unmarshal networks's xml description  : %s", err.Error()))
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
				return nil, fmt.Errorf("failed to convert x.x.x.x nemask to [0-32] netmask")
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

	network := resources.NewNetwork()
	network.ID = networkDescription.UUID
	network.Name = networkDescription.Name
	network.CIDR = cidr
	network.IPVersion = ipVersion
	//network.GatewayID
	//network.Properties

	return network, nil
}

// CreateNetwork creates a network named name
func (s *Stack) CreateNetwork(req resources.NetworkRequest) (*resources.Network, error) {
	defer concurrency.NewTracer(nil, "", true).GoingIn().OnExitTrace()()

	name := req.Name
	ipVersion := req.IPVersion
	cidr := req.CIDR
	dns := req.DNSServers

	if ipVersion != ipversion.IPv4 {
		// TODO implement IPV6 networks
		return nil, scerr.NotImplementedError("only ipv4 networks are implemented")
	}
	if len(dns) != 0 {
		// TODO implement DNS for networks
		return nil, scerr.NotImplementedError("DNS not implemented yet in networks creation")
	}

	libvirtNetwork, err := getNetworkFromRef(name, s.LibvirtService)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return nil, err
		}
	}

	if libvirtNetwork != nil {
		return nil, fmt.Errorf("Network %s already exists", name)
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
		return nil, fmt.Errorf("failed to create network : %s", err.Error())
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
		return nil, fmt.Errorf("failed to enable network autostart : %s", err.Error())
	}
	err = libvirtNetwork.Create()
	if err != nil {
		return nil, fmt.Errorf("failed to start network : %s", err.Error())
	}

	network, err := getNetworkFromLibvirtNetwork(libvirtNetwork)
	if err != nil {
		return nil, fmt.Errorf("failed to convert a libvirt network into a network : %s", err.Error())
	}

	return network, nil
}

// GetNetwork returns the network identified by ref (id or name)
func (s *Stack) GetNetwork(ref string) (*resources.Network, error) {
	defer concurrency.NewTracer(nil, "", true).GoingIn().OnExitTrace()()

	libvirtNetwork, err := getNetworkFromRef(ref, s.LibvirtService)
	if err != nil {
		return nil, err
	}
	active, err := libvirtNetwork.IsActive()
	if err != nil {
		return nil, fmt.Errorf("failed to check if the network is active : %s", err.Error())
	}
	if !active {
		err = libvirtNetwork.Create()
		if err != nil {
			return nil, fmt.Errorf("failed to start network : %s", err.Error())
		}
	}

	network, err := getNetworkFromLibvirtNetwork(libvirtNetwork)
	if err != nil {
		return nil, fmt.Errorf("failed to convert a libvirt network into a network : %s", err.Error())
	}

	return network, nil
}

// GetNetworkByName returns the network identified by ref (id or name)
func (s *Stack) GetNetworkByName(ref string) (*resources.Network, error) {
	defer concurrency.NewTracer(nil, "", true).GoingIn().OnExitTrace()()
	return s.GetNetwork(ref)
}

// ListNetworks lists available networks
func (s *Stack) ListNetworks() ([]*resources.Network, error) {
	defer concurrency.NewTracer(nil, "", true).GoingIn().OnExitTrace()()

	var networks []*resources.Network

	libvirtNetworks, err := s.LibvirtService.ListAllNetworks(3)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("error listing networks : %s", err.Error()))
	}
	for _, libvirtNetwork := range libvirtNetworks {
		network, err := getNetworkFromLibvirtNetwork(&libvirtNetwork)
		if err != nil {
			return nil, fmt.Errorf(fmt.Sprintf("failed to get network from libvirtNetwork : %s", err.Error()))
		}

		networks = append(networks, network)
	}

	return networks, nil
}

// DeleteNetwork deletes the network identified by id
func (s *Stack) DeleteNetwork(ref string) error {
	defer concurrency.NewTracer(nil, "", true).GoingIn().OnExitTrace()()

	libvirtNetwork, err := getNetworkFromRef(ref, s.LibvirtService)
	if err != nil {
		return err
	}

	isActive, err := libvirtNetwork.IsActive()
	if err != nil {
		return fmt.Errorf("failed to check if the network is active : %s", err.Error())
	}
	if isActive {
		err = libvirtNetwork.Destroy()
		if err != nil {
			return fmt.Errorf("failed to destroy network : %s", err.Error())
		}
	}

	err = libvirtNetwork.Undefine()
	if err != nil {
		return fmt.Errorf("failed to undefine network : %s", err.Error())
	}

	return nil
}

// CreateGateway creates a public Gateway for a private network
func (s *Stack) CreateGateway(req resources.GatewayRequest) (*resources.Host, *userdata.Content, error) {
	defer concurrency.NewTracer(nil, "", true).GoingIn().OnExitTrace()()

	network := req.Network
	templateID := req.TemplateID
	imageID := req.ImageID
	keyPair := req.KeyPair
	gwName := req.Name

	networkLibvirt, err := getNetworkFromRef(network.ID, s.LibvirtService)
	if err != nil {
		return nil, nil, err
	}
	if gwName == "" {
		name, err := networkLibvirt.GetName()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get network name : %s", err.Error())
		}
		gwName = "gw-" + name
	}

	hostReq := resources.HostRequest{
		ImageID:      imageID,
		KeyPair:      keyPair,
		ResourceName: gwName,
		TemplateID:   templateID,
		Networks:     []*resources.Network{network},
		PublicIP:     true,
	}

	host, userData, err := s.CreateHost(hostReq)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gateway host : %s", err.Error())
	}

	return host, userData, nil
}

// DeleteGateway delete the public gateway referenced by ref (id or name)
func (s *Stack) DeleteGateway(ref string) error {
	defer concurrency.NewTracer(nil, "", true).GoingIn().OnExitTrace()()

	return s.DeleteHost(ref)
}

// CreateVIP creates a private virtual IP
// If public is set to true,
func (s *Stack) CreateVIP(networkID string, description string) (*resources.VIP, error) {
	return nil, scerr.NotImplementedError("CreateVIP() not implemented yet")
}

// AddPublicIPToVIP adds a public IP to VIP
func (s *Stack) AddPublicIPToVIP(vip *resources.VIP) error {
	return scerr.NotImplementedError("AddPublicIPToVIP() not implemented yet")
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (s *Stack) BindHostToVIP(vip *resources.VIP, host *resources.Host) error {
	return scerr.NotImplementedError("BindHostToVIP() not implemented yet")
}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (s *Stack) UnbindHostFromVIP(vip *resources.VIP, host *resources.Host) error {
	return scerr.NotImplementedError("UnbindHostFromVIP() not implemented yet")
}

// DeleteVIP deletes the port corresponding to the VIP
func (s *Stack) DeleteVIP(vip *resources.VIP) error {
	return scerr.NotImplementedError("DeleteVIP() not implemented yet")
}
