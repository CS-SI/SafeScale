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
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propsv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
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
	GetImage(id string) (*abstracts.Image, error)

	// GetTemplate returns the Template referenced by id
	GetTemplate(id string) (*abstracts.HostTemplate, error)

	// CreateKeyPair creates and import a key pair
	CreateKeyPair(name string) (*abstracts.KeyPair, error)
	// GetKeyPair returns the key pair identified by id
	GetKeyPair(id string) (*abstracts.KeyPair, error)
	// ListKeyPairs lists available key pairs
	ListKeyPairs() ([]abstracts.KeyPair, error)
	// DeleteKeyPair deletes the key pair identified by id
	DeleteKeyPair(id string) error

	// CreateNetwork creates a network named name
	CreateNetwork(req abstracts.NetworkRequest) (*abstracts.Network, error)
	// GetNetwork returns the network identified by id
	GetNetwork(id string) (*abstracts.Network, error)
	// GetNetworkByName returns the network identified by name)
	GetNetworkByName(name string) (*abstracts.Network, error)
	// ListNetworks lists all networks
	ListNetworks() ([]*abstracts.Network, error)
	// DeleteNetwork deletes the network identified by id
	DeleteNetwork(id string) error
	// CreateGateway creates a public Gateway for a private network
	CreateGateway(req abstracts.GatewayRequest) (*abstracts.Host, *propsv2.HostSizing, *propsv1.HostNetwork, *userdata.Content, error)
	// DeleteGateway delete the public gateway of a private network
	DeleteGateway(networkID string) error

	// CreateVIP ...
	CreateVIP(string, string) (*abstracts.VIP, error)
	// AddPublicIPToVIP adds a public IP to VIP
	AddPublicIPToVIP(*abstracts.VIP) error
	// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
	BindHostToVIP(*abstracts.VIP, string) error
	// UnbindHostFromVIP removes the bind between the VIP and a host
	UnbindHostFromVIP(*abstracts.VIP, string) error
	// DeleteVIP deletes the port corresponding to the VIP
	DeleteVIP(*abstracts.VIP) error

	// CreateHost creates an host that fulfils the request
	CreateHost(request abstracts.HostRequest) (*abstracts.Host, *propsv2.HostSizing, *propsv1.HostNetwork, *propsv1.HostDescription, *userdata.Content, error)
	// GetHost returns the host identified by id or updates content of a *abstracts.Host
	InspectHost(interface{}) (*abstracts.Host, *propsv2.HostSizing, *propsv1.HostNetwork, error)
	// GetHostByName returns the ID of the host identified by name
	GetHostByName(string) (string, error)
	// GetHostState returns the current state of the host identified by id
	GetHostState(interface{}) (hoststate.Enum, error)
	// ListHosts lists all hosts
	ListHosts() ([]*abstracts.Host, error)
	// DeleteHost deletes the host identified by id
	DeleteHost(id string) error
	// StopHost stops the host identified by id
	StopHost(id string) error
	// StartHost starts the host identified by id
	StartHost(id string) error
	// Reboot host
	RebootHost(id string) error
	// Resize host
	ResizeHost(id string, request abstracts.SizingRequirements) (*abstracts.Host, error)

	// WaitHostReady waits until host defined in hostParam is reachable by SSH
	WaitHostReady(hostParam interface{}, timeout time.Duration) (*abstracts.Host, error)

	// CreateVolume creates a block volume
	CreateVolume(request abstracts.VolumeRequest) (*abstracts.Volume, error)
	// GetVolume returns the volume identified by id
	GetVolume(id string) (*abstracts.Volume, error)
	// ListVolumes list available volumes
	ListVolumes() ([]abstracts.Volume, error)
	// DeleteVolume deletes the volume identified by id
	DeleteVolume(id string) error

	// CreateVolumeAttachment attaches a volume to an host
	CreateVolumeAttachment(request abstracts.VolumeAttachmentRequest) (string, error)
	// GetVolumeAttachment returns the volume attachment identified by id
	GetVolumeAttachment(serverID, id string) (*abstracts.VolumeAttachment, error)
	// ListVolumeAttachments lists available volume attachment
	ListVolumeAttachments(serverID string) ([]abstracts.VolumeAttachment, error)
	// DeleteVolumeAttachment deletes the volume attachment identified by id
	DeleteVolumeAttachment(serverID, id string) error
}

// Reserved is an interface about the methods only available to providers internally
type Reserved interface {
	// ListImages lists available OS images
	ListImages() ([]abstracts.Image, error)

	// ListTemplates lists available host templates
	ListTemplates() ([]abstracts.HostTemplate, error)

	// Returns a read-only struct containing configuration options
	GetConfigurationOptions() stacks.ConfigurationOptions
	// Returns a read-only struct containing authentication options
	GetAuthenticationOptions() stacks.AuthenticationOptions
}
