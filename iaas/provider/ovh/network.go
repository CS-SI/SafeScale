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

package ovh

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/iaas/model/enums/IPVersion"
	"github.com/CS-SI/SafeScale/iaas/stack/openstack"

	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
)

// CreateSubnet creates a sub network
//- netID ID of the parent network
//- name is the name of the sub network
//- mask is a network mask defined in CIDR notation
func (p *Ovh) CreateSubnet(name string, networkID string, cidr string, ipVersion IPVersion.Enum) (*openstack.Subnet, error) {
	// You must associate a new subnet with an existing network - to do this you
	// need its UUID. You must also provide a well-formed CIDR value.
	//addr, _, err := net.ParseCIDR(mask)
	dhcp := true
	opts := subnets.CreateOpts{
		NetworkID:      networkID,
		CIDR:           cidr,
		IPVersion:      openstack.ToGopherIPversion(ipVersion),
		Name:           name,
		EnableDHCP:     &dhcp,
		DNSNameservers: []string{"0.0.0.0"},
	}

	if !client.osclt.Cfg.UseLayer3Networking {
		noGateway := ""
		opts.GatewayIP = &noGateway
	}

	// Execute the operation and get back a subnets.Subnet struct
	subnet, err := subnets.Create(p.stack.Network, opts).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating subnet: %s", openstack.ErrorToString(err))
	}

	if p.stack.Cfg.UseLayer3Networking {
		router, err := p.CreateRouter(openstack.RouterRequest{
			Name:      subnet.ID,
			NetworkID: p.stack.ProviderNetworkID,
		})
		if err != nil {
			nerr := p.DeleteSubnet(subnet.ID)
			if nerr != nil {
				log.Warnf("Error deleting subnet: %v", nerr)
			}
			return nil, fmt.Errorf("Error creating subnet: %s", openstack.ErrorToString(err))
		}
		err = p.AddSubnetToRouter(router.ID, subnet.ID)
		if err != nil {
			nerr := p.DeleteSubnet(subnet.ID)
			if nerr != nil {
				log.Warnf("Error deleting subnet: %v", nerr)
			}
			nerr = p.DeleteRouter(router.ID)
			if nerr != nil {
				log.Warnf("Error deleting router: %v", nerr)
			}
			return nil, fmt.Errorf("Error creating subnet: %s", openstack.ErrorToString(err))
		}
	}

	return &openstack.Subnet{
		ID:        subnet.ID,
		Name:      subnet.Name,
		IPVersion: openstack.FromIntIPversion(subnet.IPVersion),
		Mask:      subnet.CIDR,
		NetworkID: subnet.NetworkID,
	}, nil
}
