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

package boh

/*
 * Implements a cluster of hosts without cluster management environment
 */

import (
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/clusterflavors"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

var (
	// Makers returns a configured Makers to construct a BOH Cluster
	Makers = clusterflavors.Makers{
		MinimumRequiredServers: minimumRequiredServers,
		DefaultGatewaySizing:   gatewaySizing,
		DefaultMasterSizing:    nodeSizing,
		DefaultNodeSizing:      nodeSizing,
		DefaultImage:           defaultImage,
		// GetNodeInstallationScript:   makers.GetNodeInstallationScript,
		// GetGlobalSystemRequirements: flavors.GetGlobalSystemRequirements,
	}
)

func minimumRequiredServers(clusterIdentity abstract.ClusterIdentity) (uint, uint, uint, fail.Error) {
	var (
		privateNodeCount uint
		masterNodeCount  uint
	)

	switch clusterIdentity.Complexity {
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

func gatewaySizing(_ resources.Cluster) abstract.HostSizingRequirements {
	return abstract.HostSizingRequirements{
		MinCores:    2,
		MaxCores:    4,
		MinRAMSize:  7.0,
		MaxRAMSize:  16.0,
		MinDiskSize: 50,
		MinGPU:      -1,
	}
}

func nodeSizing(_ resources.Cluster) abstract.HostSizingRequirements {
	return abstract.HostSizingRequirements{
		MinCores:    2,
		MaxCores:    4,
		MinRAMSize:  15.0,
		MaxRAMSize:  32.0,
		MinDiskSize: 80,
		MinGPU:      -1,
	}
}

func defaultImage(_ resources.Cluster) string {
	return "Ubuntu 20.04"
}
