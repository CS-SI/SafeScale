/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterstate"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

type IndexedListOfClusterNodes map[uint]Host

// Cluster is the interface of all cluster object instances
type Cluster interface {
	Metadata
	Targetable
	data.NullValue

	Browse(task concurrency.Task, callback func(*abstract.ClusterIdentity) fail.Error) fail.Error // ...
	Create(task concurrency.Task, req abstract.ClusterRequest) fail.Error                         // Create creates a new cluster and save its metadata
	GetIdentity(task concurrency.Task) (abstract.ClusterIdentity, fail.Error)
	GetFlavor(task concurrency.Task) (clusterflavor.Enum, fail.Error)                                                // Flavor returns the flavor of the cluster
	GetComplexity(task concurrency.Task) (clustercomplexity.Enum, fail.Error)                                        // Complexity returns the complexity of the cluster
	GetAdminPassword(task concurrency.Task) (string, fail.Error)                                                     // AdminPassword returns the password of the cluster admin account
	GetKeyPair(task concurrency.Task) (abstract.KeyPair, fail.Error)                                                 // KeyPair returns the key pair used in the cluster
	GetNetworkConfig(task concurrency.Task) (*propertiesv2.ClusterNetwork, fail.Error)                               // NetworkConfig returns network configuration of the cluster
	GetState(task concurrency.Task) (clusterstate.Enum, fail.Error)                                                  // returns the current state of the cluster
	Start(task concurrency.Task) fail.Error                                                                          // starts the cluster
	Stop(task concurrency.Task) fail.Error                                                                           // stops the cluster
	AddNode(task concurrency.Task, def abstract.HostSizingRequirements) (Host, fail.Error)                           // adds a node
	AddNodes(task concurrency.Task, count uint, def abstract.HostSizingRequirements) ([]Host, fail.Error)            // adds several nodes
	DeleteLastNode(task concurrency.Task) (*propertiesv2.ClusterNode, fail.Error)                                    // deletes the last added node and returns its name
	DeleteSpecificNode(task concurrency.Task, hostID string, selectedMasterID string) fail.Error                     // deletes a node identified by its ID
	ListMasters(task concurrency.Task) (IndexedListOfClusterNodes, fail.Error)                                       // lists the node instances corresponding to masters (if there is such masters in the flavor...)
	ListMasterNames(task concurrency.Task) (data.IndexedListOfStrings, fail.Error)                                   // lists the names of the master nodes in the Cluster
	ListMasterIDs(task concurrency.Task) (data.IndexedListOfStrings, fail.Error)                                     // lists the IDs of masters (if there is such masters in the flavor...)
	ListMasterIPs(task concurrency.Task) (data.IndexedListOfStrings, fail.Error)                                     // lists the IPs of masters (if there is such masters in the flavor...)
	FindAvailableMaster(task concurrency.Task) (Host, fail.Error)                                                    // returns ID of the first master available to execute order
	ListNodes(task concurrency.Task) (IndexedListOfClusterNodes, fail.Error)                                         // lists node instances corresponding to the nodes in the cluster
	ListNodeNames(task concurrency.Task) (data.IndexedListOfStrings, fail.Error)                                     // lists the names of the nodes in the Cluster
	ListNodeIDs(task concurrency.Task) (data.IndexedListOfStrings, fail.Error)                                       // lists the IDs of the nodes in the cluster
	ListNodeIPs(task concurrency.Task) (data.IndexedListOfStrings, fail.Error)                                       // lists the IPs of the nodes in the cluster
	FindAvailableNode(task concurrency.Task) (Host, fail.Error)                                                      // returns node instance of the first node available to execute order
	LookupNode(task concurrency.Task, ref string) (bool, fail.Error)                                                 // tells if the ID of the host passed as parameter is a node
	CountNodes(task concurrency.Task) (uint, fail.Error)                                                             // counts the nodes of the cluster
	CheckFeature(task concurrency.Task, name string, vars data.Map, settings FeatureSettings) (Results, fail.Error)  // checks feature on cluster
	AddFeature(task concurrency.Task, name string, vars data.Map, settings FeatureSettings) (Results, fail.Error)    // adds feature on cluster
	RemoveFeature(task concurrency.Task, name string, vars data.Map, settings FeatureSettings) (Results, fail.Error) // removes feature from cluster
	ListInstalledFeatures(task concurrency.Task) ([]Feature, fail.Error)                                             // returns the list of installed features
	ToProtocol(concurrency.Task) (*protocol.ClusterResponse, fail.Error)
}
