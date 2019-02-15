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

package stacks

import (
	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/iaas/resources/enums/HostState"
)

// Stack is the interface to cloud stack
// It same interface has to be satisfied in Provider interface
type Stack interface {
	// ListAvailabilityZones lists the usable Availability Zones
	ListAvailabilityZones(bool) (map[string]bool, error)

	// ListImages lists available OS images
	ListImages() ([]resources.Image, error)
	// GetImage returns the Image referenced by id
	GetImage(id string) (*resources.Image, error)

	// GetTemplate returns the Template referenced by id
	GetTemplate(id string) (*resources.HostTemplate, error)
	// ListTemplates lists available host templates
	ListTemplates() ([]resources.HostTemplate, error)

	// CreateKeyPair creates and import a key pair
	CreateKeyPair(name string) (*resources.KeyPair, error)
	// GetKeyPair returns the key pair identified by id
	GetKeyPair(id string) (*resources.KeyPair, error)
	// ListKeyPairs lists available key pairs
	ListKeyPairs() ([]resources.KeyPair, error)
	// DeleteKeyPair deletes the key pair identified by id
	DeleteKeyPair(id string) error

	// CreateNetwork creates a network named name
	CreateNetwork(req resources.NetworkRequest) (*resources.Network, error)
	// GetNetwork returns the network identified by id
	GetNetwork(id string) (*resources.Network, error)
	// GetNetworkByName returns the network identified by name)
	GetNetworkByName(name string) (*resources.Network, error)
	// ListNetworks lists all networks
	ListNetworks() ([]*resources.Network, error)
	// DeleteNetwork deletes the network identified by id
	DeleteNetwork(id string) error
	// CreateGateway creates a public Gateway for a private network
	CreateGateway(req resources.GatewayRequest) (*resources.Host, error)
	// DeleteGateway delete the public gateway of a private network
	DeleteGateway(networkID string) error

	// CreateHost creates an host that fulfils the request
	CreateHost(request resources.HostRequest) (*resources.Host, error)
	// GetHost returns the host identified by id or updates content of a *resources.Host
	GetHost(interface{}) (*resources.Host, error)
	// GetHostByName returns the host identified by name
	GetHostByName(string) (*resources.Host, error)
	// GetHostState returns the current state of the host identified by id
	GetHostState(interface{}) (HostState.Enum, error)
	// ListHosts lists all hosts
	ListHosts() ([]*resources.Host, error)
	// DeleteHost deletes the host identified by id
	DeleteHost(id string) error
	// StopHost stops the host identified by id
	StopHost(id string) error
	// StartHost starts the host identified by id
	StartHost(id string) error
	// Reboot host
	RebootHost(id string) error
	// Resize host
	ResizeHost(id string, request resources.SizingRequirements) (*resources.Host, error)

	// CreateVolume creates a block volume
	CreateVolume(request resources.VolumeRequest) (*resources.Volume, error)
	// GetVolume returns the volume identified by id
	GetVolume(id string) (*resources.Volume, error)
	// ListVolumes list available volumes
	ListVolumes() ([]resources.Volume, error)
	// DeleteVolume deletes the volume identified by id
	DeleteVolume(id string) error

	// CreateVolumeAttachment attaches a volume to an host
	CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (string, error)
	// GetVolumeAttachment returns the volume attachment identified by id
	GetVolumeAttachment(serverID, id string) (*resources.VolumeAttachment, error)
	// ListVolumeAttachments lists available volume attachment
	ListVolumeAttachments(serverID string) ([]resources.VolumeAttachment, error)
	// DeleteVolumeAttachment deletes the volume attachment identifed by id
	DeleteVolumeAttachment(serverID, id string) error

	// Returns a read-only struct containing configuration options
	GetConfigurationOptions() ConfigurationOptions
	// Returns a read-only struct containing authentication options
	GetAuthenticationOptions() AuthenticationOptions
}
