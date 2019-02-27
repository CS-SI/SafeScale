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
	pb "github.com/CS-SI/SafeScale/safescale"
	clusterpropsv1 "github.com/CS-SI/SafeScale/safescale/server/cluster/controller/properties/v1"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/ClusterState"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/identity"
	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/utils/serialize"
)

//go:generate mockgen -destination=../mocks/mock_cluster.go -package=mocks github.com/CS-SI/SafeScale/safescale/server/cluster/api Cluster

// Cluster is an interface of methods associated to Cluster-like structs
type Cluster interface {
	// GetService ...
	GetService() *iaas.Service
	// GetIdentity returns the identity of the cluster (name, flavor, complexity)
	GetIdentity() identity.Identity
	// GetNetworkConfig returns network configuration of the cluster
	GetNetworkConfig() clusterpropsv1.Network
	// GetProperties returns the extension of the cluster
	GetProperties() *serialize.JSONProperties

	// Start starts the cluster
	Start() error
	// Stop stops the cluster
	Stop() error
	// GetState returns the current state of the cluster
	GetState() (ClusterState.Enum, error)
	// AddNode adds a node
	AddNode(bool, *resources.HostDefinition) (string, error)
	// AddNodes adds several nodes
	AddNodes(int, bool, *resources.HostDefinition) ([]string, error)
	// DeleteLastNode deletes a node
	DeleteLastNode(bool, string) error
	// DeleteSpecificNode deletes a node identified by its ID
	DeleteSpecificNode(string, string) error
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
}
