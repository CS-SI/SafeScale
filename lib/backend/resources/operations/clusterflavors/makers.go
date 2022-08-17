/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package clusterflavors

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Makers ...
type Makers struct {
	MinimumRequiredServers func(clusterIdentity abstract.ClusterIdentity) (uint, uint, uint, fail.Error) // returns masterCount, privateNodeCount, publicNodeCount
	DefaultGatewaySizing   func(c resources.Cluster) abstract.HostSizingRequirements                     // sizing of gateway(s)
	DefaultMasterSizing    func(c resources.Cluster) abstract.HostSizingRequirements                     // default sizing of master(s)
	DefaultNodeSizing      func(c resources.Cluster) abstract.HostSizingRequirements                     // default sizing of node(s)
	DefaultImage           func(c resources.Cluster) string                                              // default image of server(s)
	// GetNodeInstallationScript func(c resources.Cluster, nodeType clusternodetype.Enum) (string, map[string]interface{})
	// GetGlobalSystemRequirements func(c resources.Cluster) (string, fail.Error)
	ConfigureGateway       func(c resources.Cluster) fail.Error
	CreateMaster           func(c resources.Cluster, index uint) fail.Error
	ConfigureMaster        func(c resources.Cluster, index uint, host resources.Host) fail.Error
	UnconfigureMaster      func(c resources.Cluster, host resources.Host) fail.Error
	CreateNode             func(c resources.Cluster, index uint, host resources.Host) fail.Error
	ConfigureNode          func(c resources.Cluster, index uint, host resources.Host) fail.Error
	UnconfigureNode        func(c resources.Cluster, host resources.Host, selectedMaster resources.Host) fail.Error
	ConfigureCluster       func(ctx context.Context, c resources.Cluster, params data.Map) fail.Error
	UnconfigureCluster     func(c resources.Cluster) fail.Error
	JoinMasterToCluster    func(c resources.Cluster, host resources.Host) fail.Error
	JoinNodeToCluster      func(c resources.Cluster, host resources.Host) fail.Error
	LeaveMasterFromCluster func(c resources.Cluster, host resources.Host) fail.Error
	LeaveNodeFromCluster   func(ctx context.Context, c resources.Cluster, host resources.Host, selectedMaster resources.Host) fail.Error
	GetState               func(c resources.Cluster) (clusterstate.Enum, fail.Error)
}
