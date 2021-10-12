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
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/clusterflavors"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/consts"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
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
		ConfigureCluster:     configureCluster,
		LeaveNodeFromCluster: leaveNodeFromCluster,
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
	return consts.DEFAULTOS
}

func configureCluster(ctx context.Context, c resources.Cluster) fail.Error {
	clusterName := c.GetName()
	logrus.Println(fmt.Sprintf("[cluster %s] adding feature 'kubernetes'...", clusterName))

	results, xerr := c.AddFeature(ctx, "kubernetes", map[string]interface{}{}, resources.FeatureSettings{})
	if xerr != nil {
		return fail.Wrap(xerr, "[cluster %s] failed to add feature 'kubernetes'", clusterName)
	}

	if !results.Successful() {
		xerr = fail.NewError(fmt.Errorf(results.AllErrorMessages()), nil, "failed to add feature 'kubernetes' to cluster '%s'", clusterName)
		logrus.Errorf("[cluster %s] failed to add feature 'kubernetes': %s", clusterName, xerr.Error())
		return xerr
	}

	results, xerr = c.AddFeature(ctx, "helm3", map[string]interface{}{}, resources.FeatureSettings{})
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

// This function is called to remove a node from a Cluster
func leaveNodeFromCluster(ctx context.Context, clusterInstance resources.Cluster, node resources.Host, selectedMaster resources.Host) (xerr fail.Error) {
	if clusterInstance == nil {
		return fail.InvalidParameterCannotBeNilError("clusterInstance")
	}
	if node == nil {
		return fail.InvalidParameterCannotBeNilError("node")
	}

	if selectedMaster == nil {
		selectedMaster, xerr = clusterInstance.FindAvailableMaster(ctx)
		if xerr != nil {
			return xerr
		}

		defer selectedMaster.Released()
	}

	// Drain pods from node
	cmd := fmt.Sprintf("sudo -u cladm -i kubectl drain %s --ignore-daemonsets --delete-emptydir-data", node.GetName())
	retcode, stdout, stderr, xerr := selectedMaster.Run(ctx, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if xerr != nil {
		return fail.Wrap(xerr, "failed to execute pod drain from node '%s'", node.GetName())
	}
	switch retcode {
	case 0:
		break
	case 1:
		if strings.Contains(stderr, "(NotFound)") {
			break
		}
		fallthrough
	default:
		xerr := fail.ExecutionError(nil, "failed to drain pods from node '%s'", node.GetName())
		_ = xerr.Annotate("retcode", retcode)
		_ = xerr.Annotate("stdout", stdout)
		_ = xerr.Annotate("stderr", stderr)
		return xerr
	}

	// delete node from Kubernetes
	cmd = fmt.Sprintf("sudo -u cladm -i kubectl delete node %s", node.GetName())
	retcode, stdout, stderr, xerr = selectedMaster.Run(ctx, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if xerr != nil {
		return fail.Wrap(xerr, "failed to execute node deletion '%s' from cluster '%s'", node.GetName(), clusterInstance.GetName())
	}
	switch retcode {
	case 0:
		break
	case 1:
		if strings.Contains(stderr, "(NotFound)") {
			break
		}
		fallthrough
	default:
		xerr := fail.ExecutionError(nil, "failed to delete node '%s' from cluster '%s'", node.GetName(), clusterInstance.GetName())
		_ = xerr.Annotate("retcode", retcode)
		_ = xerr.Annotate("stdout", stdout)
		_ = xerr.Annotate("stderr", stderr)
		return xerr
	}

	// Finally, reset kubernetes configuration of node
	retcode, stdout, stderr, xerr = node.Run(ctx, "sudo kubeadm reset -f", outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if xerr != nil {
		return fail.Wrap(xerr, "failed to execute reset of kubernetes configuration on Host '%s'", node.GetName())
	}
	if retcode != 0 {
		xerr := fail.ExecutionError(nil, "failed to reset kubernetes configuration on Host '%s'", node.GetName())
		_ = xerr.Annotate("retcode", retcode)
		_ = xerr.Annotate("stdout", stdout)
		_ = xerr.Annotate("stderr", stderr)
		return xerr
	}

	return nil
}
