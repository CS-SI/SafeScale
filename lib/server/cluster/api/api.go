/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	pb "github.com/CS-SI/SafeScale/lib"
	propsv2 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v2"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/ClusterState"
	"github.com/CS-SI/SafeScale/lib/server/cluster/identity"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

//go:generate mockgen -destination=../mocks/mock_cluster.go -package=mocks github.com/CS-SI/SafeScale/lib/server/cluster/api Cluster

// NodeList contains a list of string indexed by node Numerical ID.
type NodeList map[uint]string

// KeysAndValues returns a slice with keys and a slice with values from map[uint]string
func (nl NodeList) KeysAndValues() ([]uint, []string) {
	length := len(nl)
	if length <= 0 {
		return []uint{}, []string{}
	}

	keys := make([]uint, 0, length)
	values := make([]string, 0, length)
	for k, v := range nl {
		keys = append(keys, k)
		values = append(values, v)
	}
	return keys, values
}

// Keys returns a slice with keys from map[uint]string
func (nl NodeList) Keys() []uint {
	length := len(nl)
	if length <= 0 {
		return []uint{}
	}

	keys := make([]uint, 0, length)
	for k := range nl {
		keys = append(keys, k)
	}
	return keys
}

// Values returns a slice with values from map[uint]string
func (nl NodeList) Values() []string {
	length := len(nl)
	if length <= 0 {
		return []string{}
	}

	values := make([]string, 0, length)
	for _, v := range nl {
		values = append(values, v)
	}
	return values
}

// Cluster is an interface of methods associated to Cluster-like structs
type Cluster interface {
	// GetService ...
	GetService(task concurrency.Task) iaas.Service
	// GetIdentity returns the identity of the cluster (name, flavor, complexity)
	GetIdentity(task concurrency.Task) identity.Identity
	// GetNetworkConfig returns network configuration of the cluster
	GetNetworkConfig(concurrency.Task) (propsv2.Network, error)
	// GetProperties returns the extension of the cluster
	GetProperties(concurrency.Task) *serialize.JSONProperties

	// Start starts the cluster
	Start(concurrency.Task) error
	// Stop stops the cluster
	Stop(concurrency.Task) error
	// GetState returns the current state of the cluster
	GetState(concurrency.Task) (ClusterState.Enum, error)
	// AddNode adds a node
	AddNode(concurrency.Task, *pb.HostDefinition) (string, error)
	// AddNodes adds several nodes
	AddNodes(concurrency.Task, int, *pb.HostDefinition) ([]string, error)
	// DeleteLastNode deletes a node
	DeleteLastNode(concurrency.Task, string) error
	// DeleteSpecificNode deletes a node identified by its ID
	DeleteSpecificNode(concurrency.Task, string, string) error
	// ListMasters lists the masters (if there is such masters in the flavor...)
	ListMasters(concurrency.Task) ([]*propsv2.Node, error)
	// ListMasterNames lists the names of masters (if there is such masters in the flavor...) (map key is the NumericalID of the host)
	ListMasterNames(concurrency.Task) (NodeList, error)
	// ListMasterIDs lists the IDs of masters (if there is such masters in the flavor...) (map key is the NumericalID of the host)
	ListMasterIDs(concurrency.Task) (NodeList, error)
	// ListMasterIPs lists the IPs of masters (if there is such masters in the flavor...) (map key is the NumericalID of the host)
	ListMasterIPs(concurrency.Task) (NodeList, error)
	// FindAvailableMaster returns a propsv2.Node corresponding to first master available to execute order (map key is the NumericalID of the host)
	FindAvailableMaster(concurrency.Task) (*propsv2.Node, error)
	// ListNodes lists Nodes in the cluster
	ListNodes(concurrency.Task) ([]*propsv2.Node, error)
	// ListNodeNames lists IDs of the nodes in the cluster (map key is the NumericalID of the host)
	ListNodeNames(concurrency.Task) (NodeList, error)
	// ListNodeIDs lists IDs of the nodes in the cluster (map key is the NumericalID of the host)
	ListNodeIDs(concurrency.Task) (NodeList, error)
	// ListNodeIPs lists the IPs of the nodes in the cluster (map key is the NumericalID of the host)
	ListNodeIPs(concurrency.Task) (NodeList, error)
	// FindAvailableNode returns a propsv2.Node corresponding to first node available to execute order
	FindAvailableNode(concurrency.Task) (*propsv2.Node, error)
	// SearchNode tells if the ID of the host passed as parameter is a node
	SearchNode(concurrency.Task, string) bool
	// GetNode returns a node based on its ID
	GetNode(concurrency.Task, string) (*pb.Host, error)
	// CountNodes counts the nodes of the cluster
	CountNodes(concurrency.Task) (uint, error)

	// Delete allows to destroy infrastructure of cluster
	Delete(concurrency.Task) error
}
