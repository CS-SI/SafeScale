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
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterstate"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

type IndexedListOfClusterNodes map[uint]Host

// Cluster is the interface of all cluster object instances
type Cluster interface {
	Metadata
	Targetable
	data.NullValue

	Create(task concurrency.Task, req abstract.ClusterRequest) error // Create creates a new cluster and save its metadata
	GetIdentity(task concurrency.Task) (abstract.ClusterIdentity, error)
	GetFlavor(task concurrency.Task) (clusterflavor.Enum, error)                                                   // Flavor returns the flavor of the cluster
	GetComplexity(task concurrency.Task) (clustercomplexity.Enum, error)                                           // Complexity returns the complexity of the cluster
	GetAdminPassword(task concurrency.Task) (string, error)                                                        // AdminPassword returns the password of the cluster admin account
	GetKeyPair(task concurrency.Task) (abstract.KeyPair, error)                                                    // KeyPair returns the key pair used in the cluster
	GetNetworkConfig(task concurrency.Task) (*propertiesv2.ClusterNetwork, error)                                  // NetworkConfig returns network configuration of the cluster
	SafeGetIdentity(task concurrency.Task) abstract.ClusterIdentity                                                // returns the identity of the cluster, without error handling
	SafeGetFlavor(task concurrency.Task) clusterflavor.Enum                                                        // returns the flavor of the cluster
	SafeGetComplexity(task concurrency.Task) clustercomplexity.Enum                                                // returns the complexity of the cluster
	SafeGetAdminPassword(task concurrency.Task) string                                                             // returns the password of the cluster admin account
	SafeGetKeyPair(task concurrency.Task) abstract.KeyPair                                                         // returns the key pair used in the cluster
	SafeGetNetworkConfig(task concurrency.Task) *propertiesv2.ClusterNetwork                                       // returns network configuration of the cluster
	Start(task concurrency.Task) error                                                                             // starts the cluster
	Stop(task concurrency.Task) error                                                                              // stops the cluster
	State(task concurrency.Task) (clusterstate.Enum, error)                                                        // returns the current state of the cluster
	AddNode(task concurrency.Task, def *abstract.HostSizingRequirements, image string) (Host, error)               // adds a node
	AddNodes(task concurrency.Task, count int, def *abstract.HostSizingRequirements, image string) ([]Host, error) // adds several nodes
	DeleteLastNode(task concurrency.Task) (*propertiesv2.ClusterNode, error)                                       // deletes the last added node and returns its name
	DeleteSpecificNode(task concurrency.Task, hostID string, selectedMasterID string) error                        // deletes a node identified by its ID
	ListMasters(task concurrency.Task) (IndexedListOfClusterNodes, error)                                          // lists the node instances corresponding to masters (if there is such masters in the flavor...)
	ListMasterNames(task concurrency.Task) (data.IndexedListOfStrings, error)                                      // lists the names of the master nodes in the Cluster
	ListMasterIDs(task concurrency.Task) (data.IndexedListOfStrings, error)                                        // lists the IDs of masters (if there is such masters in the flavor...)
	ListMasterIPs(task concurrency.Task) (data.IndexedListOfStrings, error)                                        // lists the IPs of masters (if there is such masters in the flavor...)
	FindAvailableMaster(task concurrency.Task) (Host, error)                                                       // returns ID of the first master available to execute order
	ListNodes(task concurrency.Task) (IndexedListOfClusterNodes, error)                                            // lists node instances corresponding to the nodes in the cluster
	ListNodeNames(task concurrency.Task) (data.IndexedListOfStrings, error)                                        // lists the names of the nodes in the Cluster
	ListNodeIDs(task concurrency.Task) (data.IndexedListOfStrings, error)                                          // lists the IDs of the nodes in the cluster
	ListNodeIPs(task concurrency.Task) (data.IndexedListOfStrings, error)                                          // lists the IPs of the nodes in the cluster
	FindAvailableNode(task concurrency.Task) (Host, error)                                                         // returns node instance of the first node available to execute order
	LookupNode(task concurrency.Task, ref string) (bool, error)                                                    // tells if the ID of the host passed as parameter is a node
	CountNodes(task concurrency.Task) (uint, error)                                                                // counts the nodes of the cluster
	CheckFeature(task concurrency.Task, name string, vars data.Map, settings FeatureSettings) (Results, error)     // checks feature on cluster
	AddFeature(task concurrency.Task, name string, vars data.Map, settings FeatureSettings) (Results, error)       // adds feature on cluster
	RemoveFeature(task concurrency.Task, name string, vars data.Map, settings FeatureSettings) (Results, error)    // removes feature from cluster
	ListInstalledFeatures(task concurrency.Task) ([]Feature, error)                                                // returns the list of installed features
}
