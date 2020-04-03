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

package api

import (
	"time"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
)

//go:generate mockgen -destination=../mocks/mock_stack.go -package=mocks github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api Stack

// FIXME ROBUSTNESS All functions MUST propagate context

// Stack is the interface to cloud stack
type Stack interface {
	// ListAvailabilityZones lists the usable Availability Zones
	ListAvailabilityZones() (map[string]bool, error)

	// ListRegions returns a list with the regions available
	ListRegions() ([]string, error)

	// GetImage returns the Image referenced by id
	GetImage(id string) (*abstract.Image, error)

	// GetTemplate returns the Template referenced by id
	GetTemplate(id string) (*abstract.HostTemplate, error)

	// CreateKeyPair creates and import a key pair
	CreateKeyPair(name string) (*abstract.KeyPair, error)
	// GetKeyPair returns the key pair identified by id
	GetKeyPair(id string) (*abstract.KeyPair, error)
	// ListKeyPairs lists available key pairs
	ListKeyPairs() ([]abstract.KeyPair, error)
	// DeleteKeyPair deletes the key pair identified by id
	DeleteKeyPair(id string) error

	// CreateNetwork creates a network named name
	CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, error)
	// GetNetwork returns the network identified by id
	GetNetwork(id string) (*abstract.Network, error)
	// GetNetworkByName returns the network identified by name)
	GetNetworkByName(name string) (*abstract.Network, error)
	// ListNetworks lists all networks
	ListNetworks() ([]*abstract.Network, error)
	// DeleteNetwork deletes the network identified by id
	DeleteNetwork(id string) error
	// CreateGateway creates a public Gateway for a private network
	CreateGateway(req abstract.GatewayRequest) (*abstract.HostFull, *userdata.Content, error)
	// DeleteGateway delete the public gateway of a private network
	DeleteGateway(networkID string) error

	// CreateVIP ...
	CreateVIP(string, string) (*abstract.VirtualIP, error)
	// AddPublicIPToVIP adds a public IP to VIP
	AddPublicIPToVIP(*abstract.VirtualIP) error
	// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
	BindHostToVIP(*abstract.VirtualIP, string) error
	// UnbindHostFromVIP removes the bind between the VIP and a host
	UnbindHostFromVIP(*abstract.VirtualIP, string) error
	// DeleteVIP deletes the port corresponding to the VIP
	DeleteVIP(*abstract.VirtualIP) error

	// CreateHost creates an host that fulfils the request
	CreateHost(request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, error)
	// GetHost returns the host identified by id or updates content of a *abstract.HostFull
	InspectHost(interface{}) (*abstract.HostFull, error)
	// GetHostByName returns the ID of the host identified by name
	GetHostByName(string) (*abstract.HostCore, error)
	// GetHostState returns the current state of the host identified by id
	GetHostState(interface{}) (hoststate.Enum, error)
	// ListHosts lists all hosts
	ListHosts(bool) (abstract.HostList, error)
	// DeleteHost deletes the host identified by id
	DeleteHost(id string) error
	// StopHost stops the host identified by id
	StopHost(id string) error
	// StartHost starts the host identified by id
	StartHost(id string) error
	// Reboot host
	RebootHost(id string) error
	// Resize host
	ResizeHost(id string, request abstract.HostSizingRequirements) (*abstract.HostFull, error)

	// WaitHostReady waits until host defined in hostParam is reachable by SSH
	WaitHostReady(hostParam interface{}, timeout time.Duration) error

	// CreateVolume creates a block volume
	CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, error)
	// GetVolume returns the volume identified by id
	GetVolume(id string) (*abstract.Volume, error)
	// ListVolumes list available volumes
	ListVolumes() ([]abstract.Volume, error)
	// DeleteVolume deletes the volume identified by id
	DeleteVolume(id string) error

	// CreateVolumeAttachment attaches a volume to an host
	CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, error)
	// GetVolumeAttachment returns the volume attachment identified by id
	GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, error)
	// ListVolumeAttachments lists available volume attachment
	ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, error)
	// DeleteVolumeAttachment deletes the volume attachment identified by id
	DeleteVolumeAttachment(serverID, id string) error
}

// Reserved is an interface about the methods only available to providers internally
type Reserved interface {
	ListImages() ([]abstract.Image, error)                  // lists available OS images
	ListTemplates() ([]abstract.HostTemplate, error)        // lists available host templates
	GetConfigurationOptions() stacks.ConfigurationOptions   // Returns a read-only struct containing configuration options
	GetAuthenticationOptions() stacks.AuthenticationOptions // Returns a read-only struct containing authentication options
}
