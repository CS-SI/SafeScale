//go:build debug
// +build debug

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

package k8s

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/clusterflavors"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/consts"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

var (

	// Makers initializes a control.Makers struct to construct a BOH Cluster
	Makers = clusterflavors.Makers{
		MinimumRequiredServers: minimumRequiredServers,
		DefaultGatewaySizing:   gatewaySizing,
		DefaultMasterSizing:    nodeSizing,
		DefaultNodeSizing:      nodeSizing,
		DefaultImage:           defaultImage,
		ConfigureCluster:       configureCluster,
		LeaveNodeFromCluster:   leaveNodeFromCluster,
	}
)

func minimumRequiredServers(ctx context.Context, clusterIdentity abstract.ClusterIdentity) (uint, uint, uint, fail.Error) {
	var masterCount uint
	var privateNodeCount uint
	var publicNodeCount uint

	switch clusterIdentity.Complexity {
	case clustercomplexity.Small:
		masterCount = 1
		privateNodeCount = 1
	case clustercomplexity.Normal:
		masterCount = 3
		privateNodeCount = 6
	case clustercomplexity.Large:
		masterCount = 5
		privateNodeCount = 20
	}
	return masterCount, privateNodeCount, publicNodeCount, nil
}

func gatewaySizing(ctx context.Context, _ resources.Cluster) abstract.HostSizingRequirements {
	return abstract.HostSizingRequirements{
		MinCores:    2,
		MaxCores:    4,
		MinRAMSize:  7.0,
		MaxRAMSize:  16.0,
		MinDiskSize: 50,
		MinGPU:      -1,
	}
}

func nodeSizing(ctx context.Context, _ resources.Cluster) abstract.HostSizingRequirements {
	return abstract.HostSizingRequirements{
		MinCores:    4,
		MaxCores:    8,
		MinRAMSize:  15.0,
		MaxRAMSize:  32.0,
		MinDiskSize: 80,
		MinGPU:      -1,
	}
}

func defaultImage(ctx context.Context, _ resources.Cluster) string {
	return consts.DEFAULTOS
}

func kubernetesIsRunning(ctx context.Context, c resources.Cluster, params data.Map) fail.Error {
	if c == nil {
		return fail.InvalidParameterCannotBeNilError("clusterInstance")
	}

	sm, xerr := c.FindAvailableMaster(ctx)
	if xerr != nil {
		return xerr
	}

	// sudo -u cladm kubectl get nodes | tail -n +2 | wc -l
	cmd := fmt.Sprintf("sudo -u cladm kubectl get nodes | tail -n +2 | wc -l")
	timings, xerr := c.Service().Timings()
	if xerr != nil {
		return xerr
	}

	retcode, stdout, stderr, xerr := sm.Run(ctx, cmd, outputs.COLLECT, timings.ConnectionTimeout(), timings.ExecutionTimeout())
	if xerr != nil {
		return fail.Wrap(xerr, "failed to get number of nodes '%s'", c.GetName())
	}
	switch retcode {
	case 0:
		break
	default:
		xerr := fail.ExecutionError(nil, "failed to get number of nodes '%s'", c.GetName())
		xerr.Annotate("retcode", retcode)
		xerr.Annotate("stdout", stdout)
		xerr.Annotate("stderr", stderr)
		return xerr
	}
	first := stdout

	// sudo -u cladm kubectl get nodes | tail -n +2 | wc -l
	cmd = fmt.Sprintf("sudo -u cladm kubectl get nodes | tail -n +2 | grep Ready | wc -l")
	timings, xerr = c.Service().Timings()
	if xerr != nil {
		return xerr
	}

	retcode, stdout, stderr, xerr = sm.Run(ctx, cmd, outputs.COLLECT, timings.ConnectionTimeout(), timings.ExecutionTimeout())
	if xerr != nil {
		return fail.Wrap(xerr, "failed to get number of nodes '%s'", c.GetName())
	}
	switch retcode {
	case 0:
		break
	default:
		xerr := fail.ExecutionError(nil, "failed to get number of nodes '%s'", c.GetName())
		xerr.Annotate("retcode", retcode)
		xerr.Annotate("stdout", stdout)
		xerr.Annotate("stderr", stderr)
		return xerr
	}
	second := stdout

	if first != second {
		return fail.NewError("not all k8s nodes are Ready")
	}

	lm, xerr := c.ListMasters(ctx)
	if xerr != nil {
		return xerr
	}

	ln, xerr := c.ListNodes(ctx)
	if xerr != nil {
		return xerr
	}

	numMachines := len(lm) + len(ln)

	bar := strings.Trim(first, "\n")
	bar = strings.Trim(bar, " ")
	running, err := strconv.Atoi(bar)
	if err != nil {
		return fail.ConvertError(err)
	}

	if running <= numMachines {
		return fail.NewError("not all k8s nodes are Ready")
	}

	return nil
}

func configureCluster(ctx context.Context, c resources.Cluster, params data.Map, b bool) fail.Error {
	clusterName := c.GetName()
	logrus.Println(fmt.Sprintf("[cluster %s] adding feature 'kubernetes'...", clusterName))

	results, xerr := c.AddFeature(ctx, "kubernetes", params, resources.FeatureSettings{
		AddUnconditionally: b,
	})
	if xerr != nil {
		return fail.Wrap(xerr, "[cluster %s] failed to add feature 'kubernetes'", clusterName)
	}

	if !results.Successful() {
		xerr = fail.NewError(fmt.Errorf(results.AllErrorMessages()), nil, "failed to add feature 'kubernetes' to cluster '%s'", clusterName)
		logrus.WithContext(ctx).Errorf("[cluster %s] failed to add feature 'kubernetes': %s", clusterName, xerr.Error())
		return xerr
	}

	results, xerr = c.AddFeature(ctx, "helm3", params, resources.FeatureSettings{
		AddUnconditionally: b,
	})
	if xerr != nil {
		return fail.Wrap(xerr, "[cluster %s] failed to add feature 'helm3'", clusterName)
	}

	if !results.Successful() {
		xerr = fail.NewError(fmt.Errorf(results.AllErrorMessages()), nil, "failed to add feature 'helm3' to cluster '%s'", clusterName)
		logrus.WithContext(ctx).Errorf("[cluster %s] failed to add feature 'helm3': %s", clusterName, xerr.Error())
		return xerr
	}

	xerr = kubernetesIsRunning(ctx, c, params)
	if xerr != nil {
		return fail.Wrap(xerr, "[cluster %s] failed to verify all nodes are running", clusterName)
	}

	logrus.WithContext(ctx).Infof("[cluster %s] feature 'kubernetes' addition successful.", clusterName)

	return nil
}

// This function is called to remove a node from a Cluster
func leaveNodeFromCluster(
	ctx context.Context, clusterInstance resources.Cluster, node resources.Host, selectedMaster resources.Host,
) (ferr fail.Error) {
	if clusterInstance == nil {
		return fail.InvalidParameterCannotBeNilError("clusterInstance")
	}
	if node == nil {
		return fail.InvalidParameterCannotBeNilError("node")
	}

	if selectedMaster == nil {
		var xerr fail.Error
		selectedMaster, xerr = clusterInstance.FindAvailableMaster(ctx)
		if xerr != nil {
			return xerr
		}
	}

	// Drain pods from node
	// cmd := fmt.Sprintf("sudo -u cladm -i kubectl drain %s --ignore-daemonsets --delete-emptydir-data", node.GetName())
	cmd := fmt.Sprintf("sudo -u cladm -i kubectl drain %s --ignore-daemonsets", node.GetName())
	timings, xerr := clusterInstance.Service().Timings()
	if xerr != nil {
		return xerr
	}
	retcode, stdout, stderr, xerr := selectedMaster.Run(ctx, cmd, outputs.COLLECT, timings.ConnectionTimeout(), timings.ExecutionTimeout())
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
		xerr.Annotate("retcode", retcode)
		xerr.Annotate("stdout", stdout)
		xerr.Annotate("stderr", stderr)
		return xerr
	}

	// delete node from Kubernetes
	cmd = fmt.Sprintf("sudo -u cladm -i kubectl delete node %s", node.GetName())
	retcode, stdout, stderr, xerr = selectedMaster.Run(ctx, cmd, outputs.COLLECT, timings.ConnectionTimeout(), timings.ExecutionTimeout())
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
		xerr.Annotate("retcode", retcode)
		xerr.Annotate("stdout", stdout)
		xerr.Annotate("stderr", stderr)
		return xerr
	}

	// Finally, reset kubernetes configuration of node
	retcode, stdout, stderr, xerr = node.Run(ctx, "sudo kubeadm reset -f", outputs.COLLECT, timings.ConnectionTimeout(), timings.ExecutionTimeout())
	if xerr != nil {
		return fail.Wrap(xerr, "failed to execute reset of kubernetes configuration on Host '%s'", node.GetName())
	}
	switch retcode {
	case 0:
		break
	case 1:
		if strings.Contains(stderr, "command not found") {
			break
		}
		fallthrough
	default:
		xerr := fail.ExecutionError(nil, "failed to reset kubernetes configuration on Host '%s'", node.GetName())
		xerr.Annotate("retcode", retcode)
		xerr.Annotate("stdout", stdout)
		xerr.Annotate("stderr", stderr)
		return xerr
	}

	return nil
}
