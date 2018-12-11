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

package core

import (
	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/ClusterState"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Flavor"
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/model"
)

// Cluster contains the bare minimum information about a cluster
type Cluster struct {
	// Name is the name of the cluster
	Name string `json:"name"`
	// CIDR is the network CIDR wanted for the Network
	CIDR string `json:"cidr"`
	// Flavor tells what kind of cluster it is
	Flavor Flavor.Enum `json:"flavor"`
	// Mode is the mode of cluster; can be Simple, HighAvailability, HighVolume
	Complexity Complexity.Enum `json:"complexity"`
	// Keypair contains the key-pair used inside the Cluster
	Keypair *model.KeyPair `json:"keypair"`
	// State of the cluster
	State ClusterState.Enum `json:"state"`
	// Tenant is the name of the tenant
	Tenant string `json:"tenant"`
	// NetworkID is the ID of the network to use
	NetworkID string `json:"network_id"`
	// GatewayIP is the IP of the gateway of the network
	GatewayIP string `json:"gateway_ip,omitempty"`
	// PublicNodeIDs is a slice of IDs of the public cluster nodes
	PublicNodeIDs []string `json:"public_node_ids,omitempty"`
	// PrivateNodedIDs is a slice of IDs of the private cluster nodes
	PrivateNodeIDs []string `json:"private_node_ids,omitempty"`
	// AdminPassword contains the password of cladm account. This password
	// is used to connect via Guacamole, but can't be used with SSH
	AdminPassword string `json:"admin_password"`
	// PublicIP is the IP address to reach the cluster (ie the public IP address of the network gateway)
	PublicIP string `json:"public_ip"`
	// NodesDef keeps the default node definition
	NodesDef pb.HostDefinition `json:"nodes_def"`
	// DisabledFeatures keeps track of features normally automatically added with cluster creation,
	// but explicitely disabled; if a disabled feature is added, must be removed from this property
	DisabledFeatures map[string]struct{} `json:"disabled_features"`
	// Service contains the provider service to use
	Service *providers.Service `json:"-"`
	// Extensions contains additional info about the cluster
	Extensions *model.Extensions `json:"extensions,omitempty"`
}

// Serialize ...
func (c *Cluster) Serialize() ([]byte, error) {
	return model.SerializeToJSON(c)
}

// Deserialize reads json code and reinstanciates an Host
func (c *Cluster) Deserialize(buf []byte) error {
	err := model.DeserializeFromJSON(buf, c)
	if err != nil {
		return err
	}
	if c.Extensions == nil {
		c.Extensions = model.NewExtensions()
	}
	return nil
}

// GetName returns the name of the cluster
func (c *Cluster) GetName() string {
	return c.Name
}

// GetNetworkID returns the ID of the Network used by the cluster
func (c *Cluster) GetNetworkID() string {
	return c.NetworkID
}

// GetGatewayIP returns the IP of the gateway of the network used by the cluster
func (c *Cluster) GetGatewayIP() string {
	return c.GatewayIP
}

// CountNodes returns the number of public or private nodes in the cluster
func (c *Cluster) CountNodes(public bool) uint {
	if public {
		return uint(len(c.PublicNodeIDs))
	}
	return uint(len(c.PrivateNodeIDs))
}
