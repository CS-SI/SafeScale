/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -o mocks/mock_cluster.go -i github.com/CS-SI/SafeScale/v22/lib/backend/resources.Cluster

// IndexedListOfClusterNodes ...
type IndexedListOfClusterNodes map[uint]*propertiesv3.ClusterNode

// Cluster is the interface of all cluster object instances
type Cluster interface {
	Metadata
	Targetable
	Consistent

	GetName() string
	AddFeature(ctx context.Context, name string, vars data.Map, settings FeatureSettings) (Results, fail.Error)                                               // adds feature on cluster
	AddNodes(ctx context.Context, name string, count uint, def abstract.HostSizingRequirements, parameters data.Map, keepOnFailure bool) ([]Host, fail.Error) // adds several nodes
	Browse(ctx context.Context, callback func(*abstract.ClusterIdentity) fail.Error) fail.Error                                                               // browse in metadata clusters and execute a callback on each entry
	CheckFeature(ctx context.Context, name string, vars data.Map, settings FeatureSettings) (Results, fail.Error)                                             // checks feature on cluster
	Create(ctx context.Context, req abstract.ClusterRequest) fail.Error                                                                                       // creates a new cluster and save its metadata
	DeleteSpecificNode(ctx context.Context, hostID string, selectedMasterID string) fail.Error                                                                // deletes a node identified by its ID
	Delete(ctx context.Context, force bool) fail.Error                                                                                                        // deletes the cluster (Delete is not used to not collision with metadata)
	FindAvailableMaster(ctx context.Context) (Host, fail.Error)                                                                                               // returns ID of the first master available to execute order
	GetIdentity(ctx context.Context) (abstract.ClusterIdentity, fail.Error)                                                                                   // returns Cluster Identity
	GetFlavor(ctx context.Context) (clusterflavor.Enum, fail.Error)                                                                                           // returns the flavor of the cluster
	GetComplexity(ctx context.Context) (clustercomplexity.Enum, fail.Error)                                                                                   // returns the complexity of the cluster
	GetAdminPassword(ctx context.Context) (string, fail.Error)                                                                                                // returns the password of the cluster admin account
	GetKeyPair(ctx context.Context) (*abstract.KeyPair, fail.Error)                                                                                           // returns the key pair used in the cluster
	GetNetworkConfig(ctx context.Context) (*propertiesv3.ClusterNetwork, fail.Error)                                                                          // returns network configuration of the cluster
	GetState(ctx context.Context) (clusterstate.Enum, fail.Error)                                                                                             // returns the current state of the cluster
	IsFeatureInstalled(ctx context.Context, name string) (found bool, ferr fail.Error)                                                                        // tells if a feature is installed in Cluster using only metadata
	ListEligibleFeatures(ctx context.Context) ([]Feature, fail.Error)                                                                                         // returns the list of eligible features for the Cluster
	ListInstalledFeatures(ctx context.Context) ([]Feature, fail.Error)                                                                                        // returns the list of installed features on the Cluster
	ListMasters(ctx context.Context) (IndexedListOfClusterNodes, fail.Error)                                                                                  // lists the node instances corresponding to masters (if there is such masters in the flavor...)
	ListNodes(ctx context.Context) (IndexedListOfClusterNodes, fail.Error)                                                                                    // lists node instances corresponding to the nodes in the cluster
	RemoveFeature(ctx context.Context, name string, vars data.Map, settings FeatureSettings) (Results, fail.Error)                                            // removes feature from cluster
	Shrink(ctx context.Context, name string, count uint) ([]*propertiesv3.ClusterNode, fail.Error)                                                            // reduce the size of the cluster of 'count' nodes (the last created)
	Start(ctx context.Context) fail.Error                                                                                                                     // starts the cluster
	Stop(ctx context.Context) fail.Error                                                                                                                      // stops the cluster
	ToProtocol(ctx context.Context) (*protocol.ClusterResponse, fail.Error)
}
