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

package boh

/*
 * Implements a cluster of hosts without cluster management environment
 */

import (
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	flavors "github.com/CS-SI/SafeScale/lib/server/resources/operations/clusterflavors"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

var (
	// // funcMap defines the custome functions to be used in templates
	// funcMap = txttmpl.FuncMap{
	// 	// The name "inc" is what the function will be called in the template text.
	// 	"inc": func(i int) int {
	// 		return i + 1
	// 	},
	// }

	// Makers returns a configured Makers to construct a BOH Cluster
	Makers = flavors.Makers{
		MinimumRequiredServers: minimumRequiredServers,
		DefaultGatewaySizing:   gatewaySizing,
		DefaultMasterSizing:    nodeSizing,
		DefaultNodeSizing:      nodeSizing,
		DefaultImage:           defaultImage,
		// GetNodeInstallationScript:   makers.GetNodeInstallationScript,
		// GetGlobalSystemRequirements: flavors.GetGlobalSystemRequirements,
	}
)

func minimumRequiredServers(task concurrency.Task, c resources.Cluster) (uint, uint, uint, fail.Error) {
	var (
		privateNodeCount uint
		masterNodeCount  uint
	)
	complexity, xerr := c.GetComplexity(task)
	if xerr != nil {
		return 0, 0, 0, xerr
	}
	switch complexity {
	case clustercomplexity.Small:
		privateNodeCount = 1
		masterNodeCount = 1
	case clustercomplexity.Normal:
		privateNodeCount = 3
		masterNodeCount = 2
	case clustercomplexity.Large:
		privateNodeCount = 7
		masterNodeCount = 3
	}
	return masterNodeCount, privateNodeCount, 0, nil
}

func gatewaySizing(task concurrency.Task, _ resources.Cluster) abstract.HostSizingRequirements {
	return abstract.HostSizingRequirements{
		MinCores:    2,
		MaxCores:    4,
		MinRAMSize:  7.0,
		MaxRAMSize:  16.0,
		MinDiskSize: 50,
		MinGPU:      -1,
	}
}

func nodeSizing(task concurrency.Task, _ resources.Cluster) abstract.HostSizingRequirements {
	return abstract.HostSizingRequirements{
		MinCores:    2,
		MaxCores:    4,
		MinRAMSize:  15.0,
		MaxRAMSize:  32.0,
		MinDiskSize: 80,
		MinGPU:      -1,
	}
}

func defaultImage(task concurrency.Task, _ resources.Cluster) string {
	return "Ubuntu 18.04"
}

// VPL: eventually this part will be removed (some things have to be included in node_install_requirements
// func getNodeInstallationScript(task concurrency.Task, _ resources.Cluster, nodeType clusternodetype.Enum) (string, data.Map) {
// 	data := data.Map{}
// 	script := ""
//
// 	switch nodeType {
// 	case clusternodetype.Master:
// 		script = "boh_install_master.sh"
// 	case clusternodetype.getGateway, clusternodetype.Node:
// 		script = "boh_install_node.sh"
// 	}
// 	return script, data
// }
// ENDVPL
