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

package erbc

import (
	"fmt"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostState"
)

// The createds hosts could be connected to the network with a bridge or a nat
// CAUTION the bridged VMs needs the default route to be a macVlan interface!
// On centos the firewall bloks all ports by default so the vm will not be alble to send back useful infos
// sudo firewall-cmd --permanent --zone=public --add-port=1000-63553/tcp
// sudo firewall-cmd --reload
var bridgedVMs = false

// # Create a macvlan interface :
// # - Script creating the macvlan
// cat <<-'EOF' > ~/ssmacvlan.sh
// #!/bin/bash
// MACVLN="ssmacvlan0"
// HWLINK=$(ip -o route | grep default | awk '{{print $5}}')
// IP=$(ip address show dev $HWLINK | grep "inet " | awk '{print $2}')
// NETWORK=$(ip -o route | grep $HWLINK | grep `echo $IP|cut -d/ -f1` | awk '{print $1}')
// GATEWAY=$(ip -o route | grep default | awk '{print $3}')

// ip link add link $HWLINK $MACVLN type macvlan mode bridge
// ip address add $IP dev $MACVLN
// ip link set dev $MACVLN up

// ip route flush dev $HWLINK
// ip route flush dev $MACVLN

// ip route add $NETWORK dev $MACVLN metric 0
// ip route add default via $GATEWAY
// EOF
// chmod u+x ~/ssmacvlan.sh
// sudo mv ~/ssmacvlan.sh /sbin/

// # - Launch the scrip on each boot
// cat <<-'EOF' > ~/ssmacvlan.service
// Description=create safescale macvlan
// After=network.target

// [Service]
// ExecStart=/sbin/ssmacvlan.sh
// Restart=on-failure
// StartLimitIntervalSec=10

// [Install]
// WantedBy=multi-user.target
// EOF
// sudo mv ~/ssmacvlan.service /etc/systemd/system/
// sudo systemctl enable ssmacvlan
// sudo systemctl start ssmacvlan

//-------------IMAGES---------------------------------------------------------------------------------------------------

// ListImages lists available OS images
func (s *StackErbc) ListImages(all bool) ([]resources.Image, error) {
	panic("implement me")
}

// GetImage returns the Image referenced by id
func (s *StackErbc) GetImage(id string) (*resources.Image, error) {
	panic("implement me")
}

//-------------TEMPLATES------------------------------------------------------------------------------------------------

// ListTemplates overload OpenStackErbc ListTemplate method to filter wind and flex instance and add GPU configuration
func (s *StackErbc) ListTemplates(all bool) ([]resources.HostTemplate, error) {
	panic("implement me")
}

//GetTemplate overload OpenStackErbc GetTemplate method to add GPU configuration
func (s *StackErbc) GetTemplate(id string) (*resources.HostTemplate, error) {
	panic("implement me")
}

//-------------SSH KEYS-------------------------------------------------------------------------------------------------

// CreateKeyPair creates and import a key pair
func (s *StackErbc) CreateKeyPair(name string) (*resources.KeyPair, error) {
	panic("implement me")
}

// GetKeyPair returns the key pair identified by id
func (s *StackErbc) GetKeyPair(id string) (*resources.KeyPair, error) {
	panic("implement me")
}

// ListKeyPairs lists available key pairs
func (s *StackErbc) ListKeyPairs() ([]resources.KeyPair, error) {
	panic("implement me")
}

// DeleteKeyPair deletes the key pair identified by id
func (s *StackErbc) DeleteKeyPair(id string) error {
	panic("implement me")
}

// CreateHost creates an host satisfying request
func (s *StackErbc) CreateHost(request resources.HostRequest) (*resources.Host, error) {
	panic("implement me")
}

// GetHost returns the host identified by ref (name or id) or by a *resources.Host containing an id
func (s *StackErbc) InspectHost(hostParam interface{}) (*resources.Host, error) {
	panic("implement me")
}

// GetHostByName returns the host identified by ref (name or id)
func (s *StackErbc) GetHostByName(name string) (*resources.Host, error) {
	panic("implement me")
}

// DeleteHost deletes the host identified by id
func (s *StackErbc) DeleteHost(id string) error {
	panic("implement me")
}

// ResizeHost change the template used by an host
func (s *StackErbc) ResizeHost(id string, request resources.SizingRequirements) (*resources.Host, error) {
	return nil, fmt.Errorf("Not implemented yet")
}

// ListHosts lists available hosts
func (s *StackErbc) ListHosts() ([]*resources.Host, error) {
	panic("implement me")
}

// StopHost stops the host identified by id
func (s *StackErbc) StopHost(id string) error {
	panic("implement me")
}

// StartHost starts the host identified by id
func (s *StackErbc) StartHost(id string) error {
	panic("implement me")
}

// RebootHost reboot the host identified by id
func (s *StackErbc) RebootHost(id string) error {
	panic("implement me")
}

// GetHostState returns the host identified by id
func (s *StackErbc) GetHostState(hostParam interface{}) (HostState.Enum, error) {
	panic("implement me")
}

//-------------Provider Infos-------------------------------------------------------------------------------------------

// ListAvailabilityZones lists the usable AvailabilityZones
func (s *StackErbc) ListAvailabilityZones(all bool) (map[string]bool, error) {
	return map[string]bool{"local": true}, nil
}
