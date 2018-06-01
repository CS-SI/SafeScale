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
	providerapi "github.com/CS-SI/SafeScale/providers/api"

	"github.com/CS-SI/SafeScale/perform/cluster/api/ClusterState"
	"github.com/CS-SI/SafeScale/perform/cluster/api/Complexity"
	"github.com/CS-SI/SafeScale/perform/cluster/api/Flavor"
	"github.com/CS-SI/SafeScale/perform/cluster/api/NodeType"

	pb "github.com/CS-SI/SafeScale/broker"
)

//Request defines what kind of Cluster is wanted
type Request struct {
	//Name is the name of the cluster wanted
	Name string
	//CIDR defines the network to create
	CIDR string
	//Mode is the implementation wanted, can be Simple, HighAvailability or HighVolume
	Complexity Complexity.Enum
	//Flavor tells what kind of cluster to create
	Flavor Flavor.Enum
	//NetworkID is the ID of the network to use
	NetworkID string
	//Tenant contains the name of the tenant
	Tenant string
}

//ClusterAPI is an interface of methods associated to Cluster-like structs
type ClusterAPI interface {
	//Start starts the cluster
	Start() error
	//Stop stops the cluster
	Stop() error
	//GetState returns the current state of the cluster
	GetState() (ClusterState.Enum, error)
	//GetNetworkID returns the ID of the network used by the cluster
	GetNetworkID() string

	//AddNode adds a node
	AddNode(NodeType.Enum, *pb.VMDefinition) (*pb.VM, error)
	//DeleteNode deletes a node
	DeleteNode(string) error
	//ListNodes lists the nodes in the cluster
	ListNodes() ([]*pb.VM, error)
	//getNode returns a node based on its ID
	GetNode(string) (*pb.VM, error)

	//Delete allows to destroy infrastructure of cluster
	Delete() error

	//GetDefinition
	GetDefinition() Cluster
	//UpdateMetadata
	//UpdateMetadata() error
	//RemoveMetadata
	//RemoveMetadata() error
}

//Cluster contains the bare minimum information about a cluster
type Cluster struct {
	//Name is the name of the cluster
	Name string
	//CIDR is the network CIDR wanted for the Network
	CIDR string
	//Flavor tells what kind of cluster it is
	Flavor Flavor.Enum
	//Mode is the mode of cluster; can be Simple, HighAvailability, HighVolume
	Complexity Complexity.Enum
	//Keypair contains the key-pair used inside the Cluster
	Keypair *providerapi.KeyPair
	//State
	State ClusterState.Enum
	//Tenant is the name of the tenant
	Tenant string
	//NetworkID is the ID of the network to use
	NetworkID string
}

/*
//MarshalBinary helps gob.Encode to serialize Cluster struct
func (c *Cluster) MarshalBinary() ([]byte, error) {
	// A simple encoding: plain text.
	var b bytes.Buffer
	fmt.Fprintln(&b, c.Name, c.CIDR, c.Flavor, c.Complexity, c.Keypair, c.State, c.Tenant, c.NetworkID)
	return b.Bytes(), nil
}

// UnmarshalBinary helps gob.Decode to unserialize Cluster struct
func (c *Cluster) UnmarshalBinary(data []byte) error {
	// A simple encoding: plain text.
	b := bytes.NewBuffer(data)
	_, err := fmt.Fscanln(b, &c.Name, &c.CIDR, &c.Flavor, &c.Complexity, &c.Keypair, &c.State, &c.Tenant, &c.NetworkID)
	return err
}
*/

//GetNetworkID returns the ID of the Network used by the cluster
func (c *Cluster) GetNetworkID() string {
	return c.NetworkID
}
