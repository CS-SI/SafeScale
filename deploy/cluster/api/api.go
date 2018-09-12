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
	"encoding/gob"

	providerapi "github.com/CS-SI/SafeScale/providers/api"

	"github.com/CS-SI/SafeScale/deploy/cluster/api/AdditionalInfo"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/ClusterState"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/Complexity"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/Flavor"

	pb "github.com/CS-SI/SafeScale/broker"
)

// Request defines what kind of Cluster is wanted
type Request struct {
	// Name is the name of the cluster wanted
	Name string
	// CIDR defines the network to create
	CIDR string
	// Complexity is the implementation wanted, can be Small, Normal or Large
	Complexity Complexity.Enum
	// Flavor tells what kind of cluster to create
	Flavor Flavor.Enum
	// NetworkID is the ID of the network to use
	NetworkID string
	// Tenant contains the name of the tenant
	Tenant string
	// KeepOnFailure is set to True to keep resources on cluster creation failure
	KeepOnFailure bool
	// NodesDef count
	NodesDef *pb.HostDefinition
}

// Cluster is an interface of methods associated to Cluster-like structs
type Cluster interface {
	// GetName returns the name of the cluster
	GetName() string
	// Start starts the cluster
	Start() error
	// Stop stops the cluster
	Stop() error
	// GetState returns the current state of the cluster
	GetState() (ClusterState.Enum, error)
	// GetNetworkID returns the ID of the network used by the cluster
	GetNetworkID() string
	// AddNode adds a node
	AddNode(bool, *pb.HostDefinition) (string, error)
	// AddNodes adds several nodes
	AddNodes(int, bool, *pb.HostDefinition) ([]string, error)
	// DeleteLastNode deletes a node
	DeleteLastNode(bool) error
	// DeleteSpecificNode deletes a node identified by its ID
	DeleteSpecificNode(string) error
	// ListMasterIDs lists the IDs of masters (if there is such masters in the flavor...)
	ListMasterIDs() []string
	// ListMasterIPs lists the IPs of masters (if there is such masters in the flavor...)
	ListMasterIPs() []string
	// FindAvailableMaster returns ID of the first master available to execute order
	FindAvailableMaster() (string, error)
	// ListNodeIDs lists IDs of the nodes in the cluster
	ListNodeIDs(bool) []string
	// ListNodeIPs lists the IPs of the nodes in the cluster
	ListNodeIPs(bool) []string
	// FindAvailableNode returns ID of the first node available to execute order
	FindAvailableNode(bool) (string, error)
	// SearchNode tells if the ID of the host passed as parameter is a node
	SearchNode(string, bool) bool
	// GetNode returns a node based on its ID
	GetNode(string) (*pb.Host, error)
	// CountNodes counts the nodes of the cluster
	CountNodes(bool) uint
	// Delete allows to destroy infrastructure of cluster
	Delete() error
	// GetConfig ...
	GetConfig() ClusterCore
	// GetAdditionalInfo returns additional info about parameter
	GetAdditionalInfo(AdditionalInfo.Enum) interface{}
	// SetAdditionalInfo sets the content of additional info
	SetAdditionalInfo(AdditionalInfo.Enum, interface{})
}

// AdditionalInfoAPI defines the interface to handle additional info
type AdditionalInfoAPI interface {
	Value() interface{}
}

// AdditionalInfoMap ...
type AdditionalInfoMap map[AdditionalInfo.Enum]interface{}

// ClusterCore contains the bare minimum information about a cluster
type ClusterCore struct {
	// Name is the name of the cluster
	Name string `json:"name"`
	// CIDR is the network CIDR wanted for the Network
	CIDR string `json:"cidr"`
	// Flavor tells what kind of cluster it is
	Flavor Flavor.Enum `json:"flavor"`
	// Mode is the mode of cluster; can be Simple, HighAvailability, HighVolume
	Complexity Complexity.Enum `json:"complexity"`
	// Keypair contains the key-pair used inside the Cluster
	Keypair *providerapi.KeyPair `json:"keypair,omitempty"`
	// State of the cluster
	State ClusterState.Enum `json:"state,omitempty"`
	// Tenant is the name of the tenant
	Tenant string `json:"tenant"`
	// NetworkID is the ID of the network to use
	NetworkID string `json:"network_id"`
	// GatewayIP is the IP of the gateway of the network
	GatewayIP string `json:"gateway_ip,omitempty"`
	// PublicNodedIDs is a slice of host IDs of the public cluster nodes
	PublicNodeIDs []string `json:"public_node_ids,omitempty"`
	// PrivateNodedIDs is a slice of host IDs of the private cluster nodes
	PrivateNodeIDs []string `json:"private_node_ids,omitempty"`
	// AdminPassword contains the password of cladm account. This password
	// is used to connect via Guacamole, but can't be used with SSH
	AdminPassword string `json:"admin_password"`
	// PublicIP is the IP address to reach the cluster (ie the public IP address of the network gateway)
	PublicIP string `json:"public_ip"`
	// NodesDef keeps the default node definition
	NodesDef *pb.HostDefinition `json:"nodes_def"`
	// Infos contains additional info about the cluster
	Infos AdditionalInfoMap `json:"infos,omitempty"`
}

// GetName returns the name of the cluster
func (c *ClusterCore) GetName() string {
	return c.Name
}

// GetNetworkID returns the ID of the Network used by the cluster
func (c *ClusterCore) GetNetworkID() string {
	return c.NetworkID
}

// GetGatewayIP returns the IP of the gateway of the network used by the cluster
func (c *ClusterCore) GetGatewayIP() string {
	return c.GatewayIP
}

// GetAdditionalInfo returns the additional info requested
func (c *ClusterCore) GetAdditionalInfo(ctx AdditionalInfo.Enum) interface{} {
	if c.Infos != nil {
		if info, ok := c.Infos[ctx]; ok {
			return info
		}
	}
	return nil
}

// SetAdditionalInfo ...
func (c *ClusterCore) SetAdditionalInfo(ctx AdditionalInfo.Enum, info interface{}) {
	if c.Infos == nil {
		c.Infos = map[AdditionalInfo.Enum]interface{}{}
	}
	c.Infos[ctx] = info
}

// CountNodes returns the number of public or private nodes in the cluster
func (c *ClusterCore) CountNodes(public bool) uint {
	if public {
		return uint(len(c.PublicNodeIDs))
	}
	return uint(len(c.PrivateNodeIDs))
}

func init() {
	gob.Register(ClusterCore{})
}
