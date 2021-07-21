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
	"golang.org/x/net/context"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/clusterflavors"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

var (

	// Makers initializes a control.Makers struct to construct a BOH Cluster
	Makers = clusterflavors.Makers{
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

func minimumRequiredServers(clusterIdentity abstract.ClusterIdentity) (uint, uint, uint, fail.Error) {
	var masterCount uint
	var privateNodeCount uint
	var publicNodeCount uint

	switch clusterIdentity.Complexity {
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
		MinCores:    4,
		MaxCores:    8,
		MinRAMSize:  15.0,
		MaxRAMSize:  32.0,
		MinDiskSize: 80,
		MinGPU:      -1,
	}
}

func defaultImage(_ resources.Cluster) string {
	return "Ubuntu 20.04"
}

func configureCluster(ctx context.Context, c resources.Cluster) fail.Error {
	clusterName := c.GetName()
	logrus.Println(fmt.Sprintf("[cluster %s] adding feature 'kubernetes'...", clusterName))

	results, xerr := c.AddFeature(ctx, "kubernetes", data.Map{}, resources.FeatureSettings{})
	if xerr != nil {
		return fail.Wrap(xerr, "[cluster %s] failed to add feature 'kubernetes'", clusterName)
	}

	if !results.Successful() {
		xerr = fail.NewError(fmt.Errorf(results.AllErrorMessages()), nil, "failed to add feature 'kubernetes' to cluster '%s'", clusterName)
		logrus.Errorf("[cluster %s] failed to add feature 'kubernetes': %s", clusterName, xerr.Error())
		return xerr
	}

	results, xerr = c.AddFeature(ctx, "helm3", data.Map{}, resources.FeatureSettings{})
	if xerr != nil {
		return fail.Wrap(xerr, "[cluster %s] failed to add feature 'helm3'", clusterName)
	}

	if !results.Successful() {
		xerr = fail.NewError(fmt.Errorf(results.AllErrorMessages()), nil, "failed to add feature 'helm3' to cluster '%s'", clusterName)
		logrus.Errorf("[cluster %s] failed to add feature 'helm3': %s", clusterName, xerr.Error())
		return xerr
	}

	logrus.Infof("[cluster %s] feature 'kubernetes' addition successful.", clusterName)

	return nil
}
