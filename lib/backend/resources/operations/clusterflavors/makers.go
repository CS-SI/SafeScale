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
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Makers ...
type Makers struct {
	MinimumRequiredServers func(ctx context.Context, clusterIdentity abstract.ClusterIdentity) (uint, uint, uint, fail.Error) // returns masterCount, privateNodeCount, publicNodeCount
	DefaultGatewaySizing   func(ctx context.Context, c resources.Cluster) abstract.HostSizingRequirements                     // sizing of gateway(s)
	DefaultMasterSizing    func(ctx context.Context, c resources.Cluster) abstract.HostSizingRequirements                     // default sizing of master(s)
	DefaultNodeSizing      func(ctx context.Context, c resources.Cluster) abstract.HostSizingRequirements                     // default sizing of node(s)
	DefaultImage           func(ctx context.Context, c resources.Cluster) string                                              // default image of server(s)
	ConfigureNode          func(ctx context.Context, c resources.Cluster, host resources.Host) fail.Error
	UnconfigureNode        func(ctx context.Context, c resources.Cluster, host resources.Host, selectedMaster resources.Host) fail.Error
	ConfigureCluster       func(ctx context.Context, c resources.Cluster, params data.Map) fail.Error
	UnconfigureCluster     func(ctx context.Context, c resources.Cluster) fail.Error
	JoinMasterToCluster    func(ctx context.Context, c resources.Cluster, host resources.Host) fail.Error
	JoinNodeToCluster      func(ctx context.Context, c resources.Cluster, host resources.Host) fail.Error
	LeaveMasterFromCluster func(ctx context.Context, c resources.Cluster, host resources.Host) fail.Error
	LeaveNodeFromCluster   func(ctx context.Context, c resources.Cluster, host resources.Host, selectedMaster resources.Host) fail.Error
}
