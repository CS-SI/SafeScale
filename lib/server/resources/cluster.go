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

package resources

import (
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterstate"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

// Cluster is the interface of all cluster object instances
type Cluster interface {
	Metadata
	Targetable

	Create(task concurrency.Task, req abstracts.ClusterRequest) error // Create creates a new cluster and save its metadata
	Identity(task concurrency.Task) (abstracts.ClusterIdentity, error)
	Flavor(task concurrency.Task) (clusterflavor.Enum, error)                                                      // Flavor returns the flavor of the cluster
	Complexity(task concurrency.Task) (clustercomplexity.Enum, error)                                              // Complexity returns the complexity of the cluster
	AdminPassword(task concurrency.Task) (string, error)                                                           // AdminPassword returns the password of the cluster admin account
	KeyPair(task concurrency.Task) (abstracts.KeyPair, error)                                                      // KeyPair returns the key pair used in the cluster
	NetworkConfig(task concurrency.Task) (*propertiesv1.ClusterNetwork, error)                                     // NetworkConfig returns network configuration of the cluster
	Start(task concurrency.Task) error                                                                             // Start starts the cluster
	Stop(task concurrency.Task) error                                                                              // Stop stops the cluster
	State(task concurrency.Task) (clusterstate.Enum, error)                                                        // State returns the current state of the cluster
	AddNode(task concurrency.Task, def *abstracts.HostDefinition) (*propertiesv2.ClusterNode, error)               // AddNode adds a node
	AddNodes(task concurrency.Task, count int, def *abstracts.HostDefinition) ([]*propertiesv2.ClusterNode, error) // AddNodes adds several nodes
	DeleteLastNode(task concurrency.Task) (*propertiesv2.ClusterNode, error)                                       // DeleteLastNode deletes the last added node and returns its name
	DeleteSpecificNode(task concurrency.Task, hostID string, selectedMasterID string) error                        // DeleteSpecificNode deletes a node identified by its ID
	ListMasters(task concurrency.Task) (data.IndexedListOfStrings, error)                                          // ListMasters lists the node instances corresponding to masters (if there is such masters in the flavor...)
	ListMasterNames(task concurrency.Task) (data.IndexedListOfStrings, error)                                      // ListMasterNames lists the names of the master nodes in the Cluster
	ListMasterIDs(task concurrency.Task) (data.IndexedListOfStrings, error)                                        // ListMasterIDs lists the IDs of masters (if there is such masters in the flavor...)
	ListMasterIPs(task concurrency.Task) (data.IndexedListOfStrings, error)                                        // ListMasterIPs lists the IPs of masters (if there is such masters in the flavor...)
	FindAvailableMaster(task concurrency.Task) (*propertiesv2.ClusterNode, error)                                  // FindAvailableMaster returns ID of the first master available to execute order
	ListNodes(task concurrency.Task) ([]*propertiesv2.ClusterNode, error)                                          // ListNodes lists node instances corresponding to the nodes in the cluster
	ListNodeNames(task concurrency.Task) (data.IndexedListOfStrings, error)                                        // ListNodeNames lists the names of the nodes in the Cluster
	ListNodeIDs(task concurrency.Task) (data.IndexedListOfStrings, error)                                          // ListNodeIDs lists IDs of the nodes in the cluster
	ListNodeIPs(task concurrency.Task) (data.IndexedListOfStrings, error)                                          // ListNodeIPs lists the IPs of the nodes in the cluster
	FindAvailableNode(task concurrency.Task) (*propertiesv2.ClusterNode, error)                                    // FindAvailableNode returns node instance of the first node available to execute order
	LookupNode(task concurrency.Task, ref string) (bool, error)                                                    // LookupNode tells if the ID of the host passed as parameter is a node
	CountNodes(task concurrency.Task) (uint, error)                                                                // CountNodes counts the nodes of the cluster
	AddFeature(task concurrency.Task, name string, vars data.Map) (InstallResults, error)                          // Installs feature on cluster
}
