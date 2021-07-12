/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"context"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterstate"
	propertiesv3 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v3"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// IndexedListOfClusterNodes ...
type IndexedListOfClusterNodes map[uint]*propertiesv3.ClusterNode

// Cluster is the interface of all cluster object instances
type Cluster interface {
	Metadata
	Targetable
	observer.Observable
	cache.Cacheable

	AddFeature(ctx context.Context, name string, vars data.Map, settings FeatureSettings) (Results, fail.Error)             // adds feature on cluster
	AddNode(ctx context.Context, def abstract.HostSizingRequirements, keepOnFailure bool) (Host, fail.Error)                // adds a node
	AddNodes(ctx context.Context, count uint, def abstract.HostSizingRequirements, keepOnFailure bool) ([]Host, fail.Error) // adds several nodes
	Browse(ctx context.Context, callback func(*abstract.ClusterIdentity) fail.Error) fail.Error                             // browse in metadata clusters and execute a callback on each entry
	CheckFeature(ctx context.Context, name string, vars data.Map, settings FeatureSettings) (Results, fail.Error)           // checks feature on cluster
	CountNodes(ctx context.Context) (uint, fail.Error)                                                                      // counts the nodes of the cluster
	Create(ctx context.Context, req abstract.ClusterRequest) fail.Error                                                     // creates a new cluster and save its metadata
	DeleteLastNode(ctx context.Context) (*propertiesv3.ClusterNode, fail.Error)                                             // deletes the last added node and returns its name
	DeleteSpecificNode(ctx context.Context, hostID string, selectedMasterID string) fail.Error                              // deletes a node identified by its ID
	Delete(ctx context.Context, force bool) fail.Error                                                                      // deletes the cluster (Delete is not used to not collision with metadata)
	FindAvailableMaster(ctx context.Context) (Host, fail.Error)                                                             // returns ID of the first master available to execute order
	FindAvailableNode(ctx context.Context) (Host, fail.Error)                                                               // returns node instance of the first node available to execute order
	GetIdentity() (abstract.ClusterIdentity, fail.Error)                                                                    // returns Cluster Identity
	GetFlavor() (clusterflavor.Enum, fail.Error)                                                                            // returns the flavor of the cluster
	GetComplexity() (clustercomplexity.Enum, fail.Error)                                                                    // returns the complexity of the cluster
	GetAdminPassword() (string, fail.Error)                                                                                 // returns the password of the cluster admin account
	GetKeyPair() (abstract.KeyPair, fail.Error)                                                                             // returns the key pair used in the cluster
	GetNetworkConfig() (*propertiesv3.ClusterNetwork, fail.Error)                                                           // returns network configuration of the cluster
	GetState() (clusterstate.Enum, fail.Error)                                                                              // returns the current state of the cluster
	IsFeatureInstalled(ctx context.Context, name string) (found bool, xerr fail.Error)                                      // tells if a feature is installed in Cluster using only metadata
	ListInstalledFeatures(ctx context.Context) ([]Feature, fail.Error)                                                      // returns the list of installed features
	ListMasters(ctx context.Context) (IndexedListOfClusterNodes, fail.Error)                                                // lists the node instances corresponding to masters (if there is such masters in the flavor...)
	ListMasterIDs(ctx context.Context) (data.IndexedListOfStrings, fail.Error)                                              // lists the IDs of masters (if there is such masters in the flavor...)
	ListMasterIPs(ctx context.Context) (data.IndexedListOfStrings, fail.Error)                                              // lists the IPs of masters (if there is such masters in the flavor...)
	ListMasterNames(ctx context.Context) (data.IndexedListOfStrings, fail.Error)                                            // lists the names of the master nodes in the Cluster
	ListNodes(ctx context.Context) (IndexedListOfClusterNodes, fail.Error)                                                  // lists node instances corresponding to the nodes in the cluster
	ListNodeIDs(ctx context.Context) (data.IndexedListOfStrings, fail.Error)                                                // lists the IDs of the nodes in the cluster
	ListNodeIPs(ctx context.Context) (data.IndexedListOfStrings, fail.Error)                                                // lists the IPs of the nodes in the cluster
	ListNodeNames(ctx context.Context) (data.IndexedListOfStrings, fail.Error)                                              // lists the names of the nodes in the Cluster
	LookupNode(ctx context.Context, ref string) (bool, fail.Error)                                                          // tells if the ID of the host passed as parameter is a node
	RemoveFeature(ctx context.Context, name string, vars data.Map, settings FeatureSettings) (Results, fail.Error)          // removes feature from cluster
	Shrink(ctx context.Context, count uint) ([]*propertiesv3.ClusterNode, fail.Error)                                       // reduce the size of the cluster of 'count' nodes (the last created)
	Start(ctx context.Context) fail.Error                                                                                   // starts the cluster
	Stop(ctx context.Context) fail.Error                                                                                    // stops the cluster
	ToProtocol() (*protocol.ClusterResponse, fail.Error)
}
