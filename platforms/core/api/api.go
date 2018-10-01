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

package api

import (

	// "github.com/CS-SI/SafeScale/system"

	"github.com/CS-SI/SafeScale/system"
)

// Client is an interface defining an IaaS driver
type Client interface {
	Build(map[string]interface{}) (ClientAPI, error)

	// ListImages lists available OS images
	ListImages(all bool) ([]Image, error)
	// GetImage returns the Image referenced by id
	GetImage(id string) (*Image, error)

	// GetTemplate returns the Template referenced by id
	GetTemplate(id string) (*HostTemplate, error)
	// ListTemplates lists available host templates
	// Host templates are sorted using Dominant Resource Fairness Algorithm
	ListTemplates(all bool) ([]HostTemplate, error)

	// CreateKeyPair creates and import a key pair
	CreateKeyPair(name string) (*KeyPair, error)
	// GetKeyPair returns the key pair identified by id
	GetKeyPair(id string) (*KeyPair, error)
	// ListKeyPairs lists available key pairs
	ListKeyPairs() ([]KeyPair, error)
	// DeleteKeyPair deletes the key pair identified by id
	DeleteKeyPair(id string) error

	// CreateNetwork creates a network named name
	CreateNetwork(req NetworkRequest) (*Network, error)
	// GetNetwork returns the network identified by ref (id or name)
	GetNetwork(ref string) (*Network, error)
	// ListNetworks lists available networks
	ListNetworks(all bool) ([]Network, error)
	// DeleteNetwork deletes the network identified by id
	DeleteNetwork(id string) error
	// CreateGateway creates a public Gateway for a private network
	CreateGateway(req GWRequest) (*Host, error)
	// DeleteGateway delete the public gateway of a private network
	DeleteGateway(networkID string) error

	// CreateHost creates an host that fulfils the request
	CreateHost(request HostRequest) (*Host, error)
	// GetHost returns the host identified by id
	GetHost(id string) (*Host, error)
	// ListHosts lists available hosts
	ListHosts(all bool) ([]Host, error)
	// DeleteHost deletes the host identified by id
	DeleteHost(id string) error
	// StopHost stops the host identified by id
	StopHost(id string) error
	// StartHost starts the host identified by id
	StartHost(id string) error
	// GetSSHConfig creates SSHConfig from host
	GetSSHConfig(id string) (*system.SSHConfig, error)

	// CreateVolume creates a block volume
	// - name is the name of the volume
	// - size is the size of the volume in GB
	// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
	CreateVolume(request VolumeRequest) (*Volume, error)
	// GetVolume returns the volume identified by id
	GetVolume(id string) (*Volume, error)
	// ListVolumes list available volumes
	ListVolumes(all bool) ([]Volume, error)
	// DeleteVolume deletes the volume identified by id
	DeleteVolume(id string) error

	// CreateVolumeAttachment attaches a volume to an host
	//- name of the volume attachment
	//- volume to attach
	//- host on which the volume is attached
	CreateVolumeAttachment(request VolumeAttachmentRequest) (*VolumeAttachment, error)
	// GetVolumeAttachment returns the volume attachment identified by id
	GetVolumeAttachment(serverID, id string) (*VolumeAttachment, error)
	// ListVolumeAttachments lists available volume attachment
	ListVolumeAttachments(serverID string) ([]VolumeAttachment, error)
	// DeleteVolumeAttachment deletes the volume attachment identifed by id
	DeleteVolumeAttachment(serverID, id string) error

	// CreateContainer creates an object container
	CreateContainer(name string) error
	// DeleteContainer deletes an object container
	DeleteContainer(name string) error
	// ListContainers list object containers
	ListContainers() ([]string, error)
	// Getcontainer returns info of the container
	GetContainer(name string) (*ContainerInfo, error)

	// PutObject put an object into an object container
	PutObject(container string, obj Object) error
	// UpdateObjectMetadata update an object into  object container
	UpdateObjectMetadata(container string, obj Object) error
	// GetObject get  object content from an object container
	GetObject(container string, name string, ranges []Range) (*Object, error)
	// GetObjectMetadata get  object metadata from an object container
	GetObjectMetadata(container string, name string) (*Object, error)
	// ListObjects list objects of a container
	ListObjects(container string, filter ObjectFilter) ([]string, error)
	// CopyObject copies an object
	CopyObject(containerSrc, objectSrc, objectDst string) error
	// DeleteObject delete an object from a container
	DeleteObject(container, object string) error

	// GetAuthOpts returns authentification options as a Config
	GetAuthOpts() (Config, error)
	// GetCfgOpts returns configuration options as a Config
	GetCfgOpts() (Config, error)
}

// Config represents key/value configuration.
type Config interface {
	// Config gets a string configuration value and a
	// bool indicating whether the value was present or not.
	Config(name string) (interface{}, bool)
	//Get is an alias to Config()
	Get(name string) (interface{}, bool)
	//Set sets the configuration name to specified value
	Set(name string, value interface{})
	//GetString returns a string corresponding to the key, empty string if it doesn't exist
	GetString(name string) string
	//GetSliceOfStrings returns a slice of strings corresponding to the key, empty string slice if it doesn't exist
	GetSliceOfStrings(name string) []string
	//GetMapOfStrings returns a string map of strings correspondong to the key, empty map if it doesn't exist
	GetMapOfStrings(name string) map[string]string
	//GetInteger returns an integer corresponding to the key, 0 if it doesn't exist
	GetInteger(name string) int
}
