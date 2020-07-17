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
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate mockgen -destination=../mocks/mock_stack.go -package=mocks github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api Stack

// FIXME ROBUSTNESS All functions MUST propagate context

// Stack is the interface to cloud stack
type Stack interface {
	// ListAvailabilityZones lists the usable Availability Zones
	ListAvailabilityZones() (map[string]bool, fail.Error)

	// ListRegions returns a list with the regions available
	ListRegions() ([]string, fail.Error)

	// GetImage returns the Image referenced by id
	GetImage(id string) (*abstract.Image, fail.Error)

	// GetTemplate returns the Template referenced by id
	GetTemplate(id string) (*abstract.HostTemplate, fail.Error)

	// CreateKeyPair creates and import a key pair
	CreateKeyPair(name string) (*abstract.KeyPair, fail.Error)
	// GetKeyPair returns the key pair identified by id
	GetKeyPair(id string) (*abstract.KeyPair, fail.Error)
	// ListKeyPairs lists available key pairs
	ListKeyPairs() ([]abstract.KeyPair, fail.Error)
	// DeleteKeyPair deletes the key pair identified by id
	DeleteKeyPair(id string) fail.Error

	// CreateNetwork creates a network named name
	CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, fail.Error)
	// GetNetwork returns the network identified by id
	GetNetwork(id string) (*abstract.Network, fail.Error)
	// GetNetworkByName returns the network identified by name)
	GetNetworkByName(name string) (*abstract.Network, fail.Error)
	// ListNetworks lists all networks
	ListNetworks() ([]*abstract.Network, fail.Error)
	// DeleteNetwork deletes the network identified by id
	DeleteNetwork(id string) fail.Error
	// // CreateGateway creates a public Gateway for a private network
	// CreateGateway(req abstract.GatewayRequest) (*abstract.HostFull, *userdata.Content, error)
	// // DeleteGateway delete the public gateway of a private network
	// DeleteGateway(networkID string) error

	// CreateVIP ...
	CreateVIP(string, string) (*abstract.VirtualIP, fail.Error)
	// AddPublicIPToVIP adds a public IP to VIP
	AddPublicIPToVIP(*abstract.VirtualIP) fail.Error
	// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
	BindHostToVIP(*abstract.VirtualIP, string) fail.Error
	// UnbindHostFromVIP removes the bind between the VIP and a host
	UnbindHostFromVIP(*abstract.VirtualIP, string) fail.Error
	// DeleteVIP deletes the port corresponding to the VIP
	DeleteVIP(*abstract.VirtualIP) fail.Error

	// CreateHost creates an host that fulfils the request
	CreateHost(request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, fail.Error)
	// InspectHost returns the host identified by id or updates content of a *abstract.HostFull
	InspectHost(stacks.HostParameter) (*abstract.HostFull, fail.Error)
	// GetHostByName returns the ID of the host identified by name
	GetHostByName(string) (*abstract.HostCore, fail.Error)
	// GetHostState returns the current state of the host identified by id
	GetHostState(stacks.HostParameter) (hoststate.Enum, fail.Error)
	// ListHosts lists all hosts
	ListHosts(bool) (abstract.HostList, fail.Error)
	// DeleteHost deletes the host identified by id
	DeleteHost(stacks.HostParameter) fail.Error
	// StopHost stops the host identified by id
	StopHost(stacks.HostParameter) fail.Error
	// StartHost starts the host identified by id
	StartHost(stacks.HostParameter) fail.Error
	// RebootHost reboots a host
	RebootHost(stacks.HostParameter) fail.Error
	// Resize host
	ResizeHost(stacks.HostParameter, abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error)

	// WaitHostReady waits until host defined in hostParam is reachable by SSH
	WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error)

	// CreateVolume creates a block volume
	CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, fail.Error)
	// GetVolume returns the volume identified by id
	GetVolume(id string) (*abstract.Volume, fail.Error)
	// ListVolumes list available volumes
	ListVolumes() ([]abstract.Volume, fail.Error)
	// DeleteVolume deletes the volume identified by id
	DeleteVolume(id string) fail.Error

	// CreateVolumeAttachment attaches a volume to an host
	CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error)
	// GetVolumeAttachment returns the volume attachment identified by id
	GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error)
	// ListVolumeAttachments lists available volume attachment
	ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, fail.Error)
	// DeleteVolumeAttachment deletes the volume attachment identified by id
	DeleteVolumeAttachment(serverID, id string) fail.Error
}

// Reserved is an interface about the methods only available to providers internally
type Reserved interface {
	ListImages() ([]abstract.Image, fail.Error)             // lists available OS images
	ListTemplates() ([]abstract.HostTemplate, fail.Error)   // lists available host templates
	GetConfigurationOptions() stacks.ConfigurationOptions   // Returns a read-only struct containing configuration options
	GetAuthenticationOptions() stacks.AuthenticationOptions // Returns a read-only struct containing authentication options
}
