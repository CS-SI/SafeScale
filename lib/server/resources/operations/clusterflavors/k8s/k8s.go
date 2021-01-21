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

package k8s

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	flavors "github.com/CS-SI/SafeScale/lib/server/resources/operations/clusterflavors"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

var (

	// Makers initializes a control.Makers struct to construct a BOH Cluster
	Makers = flavors.Makers{
		MinimumRequiredServers: minimumRequiredServers,
		DefaultGatewaySizing:   gatewaySizing,
		DefaultMasterSizing:    nodeSizing,
		DefaultNodeSizing:      nodeSizing,
		DefaultImage:           defaultImage,
		// GetGlobalSystemRequirements: flavors.GetGlobalSystemRequirements,
		// GetNodeInstallationScript: getNodeInstallationScript,
		ConfigureCluster: configureCluster,
	}
)

func minimumRequiredServers(task concurrency.Task, c resources.Cluster) (uint, uint, uint, fail.Error) {
	complexity, xerr := c.GetComplexity(task)
	if xerr != nil {
		return 0, 0, 0, xerr
	}
	var masterCount uint
	var privateNodeCount uint
	var publicNodeCount uint

	switch complexity {
	case clustercomplexity.Small:
		masterCount = 1
		privateNodeCount = 1
	case clustercomplexity.Normal:
		masterCount = 3
		privateNodeCount = 3
	case clustercomplexity.Large:
		masterCount = 5
		privateNodeCount = 6
	}
	return masterCount, privateNodeCount, publicNodeCount, nil
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
		MinCores:    4,
		MaxCores:    8,
		MinRAMSize:  15.0,
		MaxRAMSize:  32.0,
		MinDiskSize: 80,
		MinGPU:      -1,
	}
}

func defaultImage(task concurrency.Task, _ resources.Cluster) string {
	return "Ubuntu 18.04"
}

func configureCluster(task concurrency.Task, c resources.Cluster) fail.Error {
	clusterName := c.GetName()
	logrus.Println(fmt.Sprintf("[cluster %s] adding feature 'kubernetes'...", clusterName))

	// feat, err := featurefactory.New(task, c.GetService(), "kubernetes")
	// if err != nil {
	// 	return fmt.Errorf("failed to prepare feature 'kubernetes': %s : %s", fmt.Sprintf("[cluster %s] failed to instantiate feature 'kubernetes': %v", clusterName, err), err.Error()
	// }
	// results, err := feat.Add(c, data.Map{}, resources.FeatureSettings{})
	results, xerr := c.AddFeature(task, "kubernetes", data.Map{}, resources.FeatureSettings{})
	if xerr != nil {
		return fail.Wrap(xerr, "[cluster %s] failed to add feature 'kubernetes'", clusterName)
	}
	if !results.Successful() {
		xerr = fail.NewError(fmt.Errorf(results.AllErrorMessages()), nil, "failed to add feature 'kubernetes' to cluster '%s'", clusterName)
		logrus.Errorf("[cluster %s] failed to add feature 'kubernetes': %s", clusterName, xerr.Error())
		return xerr
	}
	logrus.Infof("[cluster %s] feature 'kubernetes' addition successful.", clusterName)
	return nil
}

//
// // VPL: eventually this part will be removed (some things have to be included in node_install_requirements
// func getNodeInstallationScript(task concurrency.Task, _ resources.Cluster, nodeType clusternodetype.Enum) (string, data.Map) {
// 	script := ""
// 	data := data.Map{}
//
// 	switch nodeType {
// 	case clusternodetype.Gateway:
// 	case clusternodetype.Master:
// 		script = "k8s_install_master.sh"
// 	case clusternodetype.Node:
// 		script = "k8s_install_node.sh"
// 	}
// 	return script, data
// }

// ENDVPL
