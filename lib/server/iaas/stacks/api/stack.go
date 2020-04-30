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
	ListAvailabilityZones() (map[string]bool, fail.Report)

	// ListRegions returns a list with the regions available
	ListRegions() ([]string, fail.Report)

	// GetImage returns the Image referenced by id
	GetImage(id string) (*abstract.Image, fail.Report)

	// GetTemplate returns the Template referenced by id
	GetTemplate(id string) (*abstract.HostTemplate, fail.Report)

	// CreateKeyPair creates and import a key pair
	CreateKeyPair(name string) (*abstract.KeyPair, fail.Report)
	// GetKeyPair returns the key pair identified by id
	GetKeyPair(id string) (*abstract.KeyPair, fail.Report)
	// ListKeyPairs lists available key pairs
	ListKeyPairs() ([]abstract.KeyPair, fail.Report)
	// DeleteKeyPair deletes the key pair identified by id
	DeleteKeyPair(id string) fail.Report

	// CreateNetwork creates a network named name
	CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, fail.Report)
	// GetNetwork returns the network identified by id
	GetNetwork(id string) (*abstract.Network, fail.Report)
	// GetNetworkByName returns the network identified by name)
	GetNetworkByName(name string) (*abstract.Network, fail.Report)
	// ListNetworks lists all networks
	ListNetworks() ([]*abstract.Network, fail.Report)
	// DeleteNetwork deletes the network identified by id
	DeleteNetwork(id string) fail.Report
	// // CreateGateway creates a public Gateway for a private network
	// CreateGateway(req abstract.GatewayRequest) (*abstract.HostFull, *userdata.Content, error)
	// // DeleteGateway delete the public gateway of a private network
	// DeleteGateway(networkID string) error

	// CreateVIP ...
	CreateVIP(string, string) (*abstract.VirtualIP, fail.Report)
	// AddPublicIPToVIP adds a public IP to VIP
	AddPublicIPToVIP(*abstract.VirtualIP) fail.Report
	// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
	BindHostToVIP(*abstract.VirtualIP, string) fail.Report
	// UnbindHostFromVIP removes the bind between the VIP and a host
	UnbindHostFromVIP(*abstract.VirtualIP, string) fail.Report
	// DeleteVIP deletes the port corresponding to the VIP
	DeleteVIP(*abstract.VirtualIP) fail.Report

	// CreateHost creates an host that fulfils the request
	CreateHost(request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, fail.Report)
	// GetHost returns the host identified by id or updates content of a *abstract.HostFull
	InspectHost(interface{}) (*abstract.HostFull, fail.Report)
	// GetHostByName returns the ID of the host identified by name
	GetHostByName(string) (*abstract.HostCore, fail.Report)
	// GetHostState returns the current state of the host identified by id
	GetHostState(interface{}) (hoststate.Enum, fail.Report)
	// ListHosts lists all hosts
	ListHosts(bool) (abstract.HostList, fail.Report)
	// DeleteHost deletes the host identified by id
	DeleteHost(id string) fail.Report
	// StopHost stops the host identified by id
	StopHost(id string) fail.Report
	// StartHost starts the host identified by id
	StartHost(id string) fail.Report
	// Reboot host
	RebootHost(id string) fail.Report
	// Resize host
	ResizeHost(id string, request abstract.HostSizingRequirements) (*abstract.HostFull, fail.Report)

	// WaitHostReady waits until host defined in hostParam is reachable by SSH
	WaitHostReady(hostParam interface{}, timeout time.Duration) fail.Report

	// CreateVolume creates a block volume
	CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, fail.Report)
	// GetVolume returns the volume identified by id
	GetVolume(id string) (*abstract.Volume, fail.Report)
	// ListVolumes list available volumes
	ListVolumes() ([]abstract.Volume, fail.Report)
	// DeleteVolume deletes the volume identified by id
	DeleteVolume(id string) fail.Report

	// CreateVolumeAttachment attaches a volume to an host
	CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Report)
	// GetVolumeAttachment returns the volume attachment identified by id
	GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Report)
	// ListVolumeAttachments lists available volume attachment
	ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, fail.Report)
	// DeleteVolumeAttachment deletes the volume attachment identified by id
	DeleteVolumeAttachment(serverID, id string) fail.Report
}

// Reserved is an interface about the methods only available to providers internally
type Reserved interface {
	ListImages() ([]abstract.Image, fail.Report)            // lists available OS images
	ListTemplates() ([]abstract.HostTemplate, fail.Report)  // lists available host templates
	GetConfigurationOptions() stacks.ConfigurationOptions   // Returns a read-only struct containing configuration options
	GetAuthenticationOptions() stacks.AuthenticationOptions // Returns a read-only struct containing authentication options
}
