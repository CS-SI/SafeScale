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

package flavors

import (
	rice "github.com/GeertJohan/go.rice"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Makers ...
type Makers struct {
	MinimumRequiredServers      func(task concurrency.Task, c resources.Cluster) (uint, uint, uint, fail.Error)  // returns masterCount, privateNodeCount, publicNodeCount
	DefaultGatewaySizing        func(task concurrency.Task, c resources.Cluster) abstract.HostSizingRequirements // sizing of Gateway(s)
	DefaultMasterSizing         func(task concurrency.Task, c resources.Cluster) abstract.HostSizingRequirements // default sizing of master(s)
	DefaultNodeSizing           func(task concurrency.Task, c resources.Cluster) abstract.HostSizingRequirements // default sizing of node(s)
	DefaultImage                func(task concurrency.Task, c resources.Cluster) string                          // default image of server(s)
	GetNodeInstallationScript   func(task concurrency.Task, c resources.Cluster, nodeType clusternodetype.Enum) (string, data.Map)
	GetGlobalSystemRequirements func(task concurrency.Task, c resources.Cluster) (string, fail.Error)
	GetTemplateBox              func() (*rice.Box, fail.Error)
	ConfigureGateway            func(task concurrency.Task, c resources.Cluster) fail.Error
	CreateMaster                func(task concurrency.Task, c resources.Cluster, index uint) fail.Error
	ConfigureMaster             func(task concurrency.Task, c resources.Cluster, index uint, host resources.Host) fail.Error
	UnconfigureMaster           func(task concurrency.Task, c resources.Cluster, host resources.Host) fail.Error
	CreateNode                  func(task concurrency.Task, c resources.Cluster, index uint, host resources.Host) fail.Error
	ConfigureNode               func(task concurrency.Task, c resources.Cluster, index uint, host resources.Host) fail.Error
	UnconfigureNode             func(task concurrency.Task, c resources.Cluster, host resources.Host, selectedMaster resources.Host) fail.Error
	ConfigureCluster            func(task concurrency.Task, c resources.Cluster) fail.Error
	UnconfigureCluster          func(task concurrency.Task, c resources.Cluster) fail.Error
	JoinMasterToCluster         func(task concurrency.Task, c resources.Cluster, host resources.Host) fail.Error
	JoinNodeToCluster           func(task concurrency.Task, c resources.Cluster, host resources.Host) fail.Error
	LeaveMasterFromCluster      func(task concurrency.Task, c resources.Cluster, host resources.Host) fail.Error
	LeaveNodeFromCluster        func(task concurrency.Task, c resources.Cluster, host resources.Host, selectedMaster resources.Host) fail.Error
	GetState                    func(task concurrency.Task, c resources.Cluster) (clusterstate.Enum, fail.Error)
}
