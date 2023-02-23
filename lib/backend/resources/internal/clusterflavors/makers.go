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

package clusterflavors

import (
	"context"
	"time"

	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	rscapi "github.com/CS-SI/SafeScale/v22/lib/backend/resources/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
)

type ClusterTarget interface {
	Service() (iaasapi.Service, fail.Error)
	GetName() string
	AddFeature(context.Context, string, data.Map[string, any], ...options.Option) (rscapi.Results, fail.Error)
}

type HostTarget interface {
	GetName() string
	Run(context.Context, string, outputs.Enum, time.Duration, time.Duration) (int, string, string, fail.Error)
	Service() (iaasapi.Service, fail.Error)
}

// Makers ...
type Makers struct {
	MinimumRequiredServers func(clusterIdentity *abstract.Cluster) (mas uint, pri uint, pub uint, ferr fail.Error) // returns masterCount, privateNodeCount, publicNodeCount
	DefaultGatewaySizing   func(c ClusterTarget) abstract.HostSizingRequirements                                   // sizing of gateway(s)
	DefaultMasterSizing    func(c ClusterTarget) abstract.HostSizingRequirements                                   // default sizing of master(s)
	DefaultNodeSizing      func(c ClusterTarget) abstract.HostSizingRequirements                                   // default sizing of node(s)
	DefaultImage           func(c ClusterTarget) string                                                            // default image of server(s)
	// GetNodeInstallationScript func(c resources.Cluster, nodeType clusternodetype.Enum) (string, map[string]interface{})
	// GetGlobalSystemRequirements func(c resources.Cluster) (string, fail.Error)
	ConfigureGateway       func(c ClusterTarget) fail.Error
	CreateMaster           func(c ClusterTarget) fail.Error
	ConfigureMaster        func(c ClusterTarget, host HostTarget) fail.Error
	UnconfigureMaster      func(c ClusterTarget, host HostTarget) fail.Error
	CreateNode             func(c ClusterTarget, host HostTarget) fail.Error
	ConfigureNode          func(c ClusterTarget, host HostTarget) fail.Error
	UnconfigureNode        func(c ClusterTarget, host HostTarget, selectedMaster HostTarget) fail.Error
	ConfigureCluster       func(ctx context.Context, c ClusterTarget, params data.Map[string, any]) fail.Error
	UnconfigureCluster     func(c ClusterTarget) fail.Error
	JoinMasterToCluster    func(c ClusterTarget, host HostTarget) fail.Error
	JoinNodeToCluster      func(c ClusterTarget, host HostTarget) fail.Error
	LeaveMasterFromCluster func(c ClusterTarget, host HostTarget) fail.Error
	LeaveNodeFromCluster   func(ctx context.Context, c ClusterTarget, host HostTarget, selectedMaster HostTarget) fail.Error
	GetState               func(c ClusterTarget) (clusterstate.Enum, fail.Error)
}
