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

package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	flavors "github.com/CS-SI/SafeScale/lib/server/resources/operations/clusterflavors"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/clusterflavors/boh"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/clusterflavors/k8s"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	propertiesv3 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v3"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/template"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	clusterKind = "cluster"
	// Path is the path to use to reach Cluster Definitions/Metadata
	clustersFolderName = "clusters"
)

// Cluster is the implementation of resources.Cluster interface
type cluster struct {
	*core

	lock                sync.RWMutex
	installMethods      map[uint8]installmethod.Enum
	lastStateCollection time.Time
	makers              flavors.Makers
}

func nullCluster() *cluster {
	return &cluster{core: nullCore()}
}

// NewCluster ...
func NewCluster(svc iaas.Service) (_ resources.Cluster, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if svc == nil {
		return nullCluster(), fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, xerr := newCore(svc, "cluster", clustersFolderName, &abstract.ClusterIdentity{})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nullCluster(), xerr
	}

	instance := &cluster{
		core: coreInstance,
	}
	return instance, nil
}

// LoadCluster ...
func LoadCluster(svc iaas.Service, name string) (rc resources.Cluster, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if svc == nil {
		return nullCluster(), fail.InvalidParameterCannotBeNilError("svc")
	}
	if name = strings.TrimSpace(name); name == "" {
		return nullCluster(), fail.InvalidParameterError("name", "cannot be empty string")
	}

	clusterCache, xerr := svc.GetCache(clusterKind)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nullCluster(), xerr
	}

	options := []data.ImmutableKeyValue{
		data.NewImmutableKeyValue("onMiss", func() (cache.Cacheable, fail.Error) {
			rc, innerXErr := NewCluster(svc)
			if innerXErr != nil {
				return nil, innerXErr
			}
			// TODO: core.ReadByID() does not check communication failure, side effect of limitations of Stow (waiting for stow replacement by rclone)
			if innerXErr = rc.Read(name); innerXErr != nil {
				return nil, innerXErr
			}

			// deal with legacy
			xerr = rc.(*cluster).updateClusterNodesPropertyIfNeeded()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nullCluster(), xerr
			}

			xerr = rc.(*cluster).updateClusterNetworkPropertyIfNeeded()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nullCluster(), xerr
			}

			xerr = rc.(*cluster).updateClusterDefaultsPropertyIfNeeded()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nullCluster(), xerr
			}

			rc.(*cluster).updateCachedInformation()

			return rc, nil
		}),
	}
	cacheEntry, xerr := clusterCache.Get(name, options...)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// rewrite NotFoundError, user does not bother about metadata stuff
			return nullCluster(), fail.NotFoundError("failed to find Cluster '%s'", name)
		default:
			return nullCluster(), xerr
		}
	}

	if rc = cacheEntry.Content().(resources.Cluster); rc == nil {
		return nullCluster(), fail.InconsistentError("nil value found in Cluster cache for key '%s'", name)
	}
	_ = cacheEntry.LockContent()

	return rc, nil
}

// updateClusterNodesPropertyIfNeeded upgrades current Nodes property to last Nodes property (currently NodesV2)
func (instance *cluster) updateClusterNodesPropertyIfNeeded() fail.Error {
	xerr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		if props.Lookup(clusterproperty.NodesV3) {
			return nil
		}

		if props.Lookup(clusterproperty.NodesV2) {
			var (
				nodesV2 *propertiesv2.ClusterNodes
				ok      bool
			)
			innerXErr := props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
				nodesV2, ok = clonable.(*propertiesv2.ClusterNodes)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
				nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
				if !ok {
					return fail.InconsistentError("'*propertiesv3.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				for _, i := range nodesV2.Masters {
					nodesV3.GlobalLastIndex++

					node := &propertiesv3.ClusterNode{
						ID:          i.ID,
						NumericalID: nodesV3.GlobalLastIndex,
						Name:        i.Name,
						PrivateIP:   i.PrivateIP,
						PublicIP:    i.PublicIP,
					}
					nodesV3.Masters = append(nodesV3.Masters, nodesV3.GlobalLastIndex)
					nodesV3.ByNumericalID[nodesV3.GlobalLastIndex] = node
				}
				for _, i := range nodesV2.PrivateNodes {
					nodesV3.GlobalLastIndex++

					node := &propertiesv3.ClusterNode{
						ID:          i.ID,
						NumericalID: nodesV3.GlobalLastIndex,
						Name:        i.Name,
						PrivateIP:   i.PrivateIP,
						PublicIP:    i.PublicIP,
					}
					nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, nodesV3.GlobalLastIndex)
					nodesV3.ByNumericalID[nodesV3.GlobalLastIndex] = node
				}
				nodesV3.MasterLastIndex = nodesV2.MasterLastIndex
				nodesV3.PrivateLastIndex = nodesV2.PrivateLastIndex
				return nil
			})
		}

		if props.Lookup(clusterproperty.NodesV1) {
			var (
				nodesV1 *propertiesv1.ClusterNodes
				ok      bool
			)

			innerXErr := props.Inspect(clusterproperty.NodesV1, func(clonable data.Clonable) fail.Error {
				nodesV1, ok = clonable.(*propertiesv1.ClusterNodes)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
				nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
				if !ok {
					return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				for _, i := range nodesV1.Masters {
					nodesV3.GlobalLastIndex++

					node := &propertiesv3.ClusterNode{
						ID:          i.ID,
						NumericalID: nodesV3.GlobalLastIndex,
						Name:        i.Name,
						PrivateIP:   i.PrivateIP,
						PublicIP:    i.PublicIP,
					}
					nodesV3.Masters = append(nodesV3.Masters, node.NumericalID)
					nodesV3.ByNumericalID[node.NumericalID] = node
				}
				for _, i := range nodesV1.PrivateNodes {
					nodesV3.GlobalLastIndex++

					node := &propertiesv3.ClusterNode{
						ID:          i.ID,
						NumericalID: nodesV3.GlobalLastIndex,
						Name:        i.Name,
						PrivateIP:   i.PrivateIP,
						PublicIP:    i.PublicIP,
					}
					nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, node.NumericalID)
					nodesV3.ByNumericalID[node.NumericalID] = node
				}
				nodesV3.MasterLastIndex = nodesV1.MasterLastIndex
				nodesV3.PrivateLastIndex = nodesV1.PrivateLastIndex
				return nil
			})
		}

		// Returning explicitly this error tells Alter not to try to commit changes, there are none
		return fail.AlteredNothingError()
	})
	xerr = debug.InjectPlannedFail(xerr)
	return xerr
}

// updateClusterNetworkPropertyIfNeeded creates a clusterproperty.NetworkV3 property if previous versions are found
func (instance *cluster) updateClusterNetworkPropertyIfNeeded() fail.Error {
	xerr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		if props.Lookup(clusterproperty.NetworkV3) {
			return fail.AlteredNothingError()
		}

		var (
			config *propertiesv3.ClusterNetwork
			update bool
		)

		if props.Lookup(clusterproperty.NetworkV2) {
			// Having a clusterproperty.NetworkV2, need to update instance with clusterproperty.NetworkV3
			innerXErr = props.Inspect(clusterproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				// In v2, NetworkID actually contains the subnet ID; we do not need ID of the Network owning the Subnet in
				// the property, meaning that Network would have to be deleted also on cluster deletion because Network
				// AND Subnet were created forcibly at cluster creation.
				config = &propertiesv3.ClusterNetwork{
					NetworkID:          "",
					SubnetID:           networkV2.NetworkID,
					CIDR:               networkV2.CIDR,
					GatewayID:          networkV2.GatewayID,
					GatewayIP:          networkV2.GatewayIP,
					SecondaryGatewayID: networkV2.SecondaryGatewayID,
					SecondaryGatewayIP: networkV2.SecondaryGatewayIP,
					PrimaryPublicIP:    networkV2.PrimaryPublicIP,
					SecondaryPublicIP:  networkV2.SecondaryPublicIP,
					DefaultRouteIP:     networkV2.DefaultRouteIP,
					EndpointIP:         networkV2.EndpointIP,
					Domain:             networkV2.Domain,
				}
				update = true
				return nil
			})
		} else {
			// Having a clusterproperty.NetworkV1, need to update instance with clusterproperty.NetworkV3
			innerXErr = props.Inspect(clusterproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
				networkV1, ok := clonable.(*propertiesv1.ClusterNetwork)
				if !ok {
					return fail.InconsistentError()
				}

				config = &propertiesv3.ClusterNetwork{
					SubnetID:       networkV1.NetworkID,
					CIDR:           networkV1.CIDR,
					GatewayID:      networkV1.GatewayID,
					GatewayIP:      networkV1.GatewayIP,
					DefaultRouteIP: networkV1.GatewayIP,
					EndpointIP:     networkV1.PublicIP,
				}
				update = true
				return nil
			})
		}
		if innerXErr != nil {
			return innerXErr
		}

		if update {
			return props.Alter(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
				networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
				if !ok {
					return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				networkV3.Replace(config)
				return nil
			})
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) { //nolint
		case *fail.ErrAlteredNothing:
			xerr = nil
		}
	}
	return xerr
}

// updateClusterDefaultsPropertyIfNeeded ...
func (instance *cluster) updateClusterDefaultsPropertyIfNeeded() fail.Error {
	xerr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		if props.Lookup(clusterproperty.DefaultsV2) {
			return fail.AlteredNothingError()
		}

		// If property.DefaultsV2 is not found but there is a property.DefaultsV1, converts it to DefaultsV2
		return props.Inspect(clusterproperty.DefaultsV1, func(clonable data.Clonable) fail.Error {
			defaultsV1, ok := clonable.(*propertiesv1.ClusterDefaults)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return props.Alter(clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
				defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				convertDefaultsV1ToDefaultsV2(defaultsV1, defaultsV2)
				return nil
			})
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAlteredNothing:
			xerr = nil
		default:
		}
	}
	return xerr
}

// updateCachedInformation updates information cached in the instance
func (instance *cluster) updateCachedInformation() {
	instance.installMethods = map[uint8]installmethod.Enum{}
	var index uint8
	flavor, err := instance.unsafeGetFlavor()
	if err == nil && flavor == clusterflavor.K8S {
		index++
		instance.installMethods[index] = installmethod.Helm
	}
	index++
	instance.installMethods[index] = installmethod.Bash
	index++
	instance.installMethods[index] = installmethod.None
}

// convertDefaultsV1ToDefaultsV2 converts propertiesv1.ClusterDefaults to propertiesv2.ClusterDefaults
func convertDefaultsV1ToDefaultsV2(defaultsV1 *propertiesv1.ClusterDefaults, defaultsV2 *propertiesv2.ClusterDefaults) {
	defaultsV2.Image = defaultsV1.Image
	defaultsV2.GatewaySizing = propertiesv1.HostSizingRequirements{
		MinCores:    defaultsV1.GatewaySizing.Cores,
		MinCPUFreq:  defaultsV1.GatewaySizing.CPUFreq,
		MinGPU:      defaultsV1.GatewaySizing.GPUNumber,
		MinRAMSize:  defaultsV1.GatewaySizing.RAMSize,
		MinDiskSize: defaultsV1.GatewaySizing.DiskSize,
		Replaceable: defaultsV1.GatewaySizing.Replaceable,
	}
	defaultsV2.MasterSizing = propertiesv1.HostSizingRequirements{
		MinCores:    defaultsV1.MasterSizing.Cores,
		MinCPUFreq:  defaultsV1.MasterSizing.CPUFreq,
		MinGPU:      defaultsV1.MasterSizing.GPUNumber,
		MinRAMSize:  defaultsV1.MasterSizing.RAMSize,
		MinDiskSize: defaultsV1.MasterSizing.DiskSize,
		Replaceable: defaultsV1.MasterSizing.Replaceable,
	}
	defaultsV2.NodeSizing = propertiesv1.HostSizingRequirements{
		MinCores:    defaultsV1.NodeSizing.Cores,
		MinCPUFreq:  defaultsV1.NodeSizing.CPUFreq,
		MinGPU:      defaultsV1.NodeSizing.GPUNumber,
		MinRAMSize:  defaultsV1.NodeSizing.RAMSize,
		MinDiskSize: defaultsV1.NodeSizing.DiskSize,
		Replaceable: defaultsV1.NodeSizing.Replaceable,
	}
}

// isNull tells if the instance should be considered as a null value
func (instance *cluster) isNull() bool {
	return instance == nil || instance.core.isNull()
}

// carry ...
func (instance *cluster) carry(clonable data.Clonable) (xerr fail.Error) {
	identifiable, ok := clonable.(data.Identifiable)
	if !ok {
		return fail.InvalidParameterError("clonable", "must also satisfy interface 'data.Identifiable'")
	}

	kindCache, xerr := instance.GetService().GetCache(instance.core.kind)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = kindCache.ReserveEntry(identifiable.GetID())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer func() {
		if xerr != nil {
			if derr := kindCache.FreeEntry(identifiable.GetID()); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free %s cache entry for key '%s'", instance.core.kind, identifiable.GetID()))
			}

		}
	}()

	// Note: do not validate parameters, this call will do it
	xerr = instance.core.carry(clonable)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	cacheEntry, xerr := kindCache.CommitEntry(identifiable.GetID(), instance)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	cacheEntry.LockContent()
	instance.updateCachedInformation()

	return nil
}

// Create creates the necessary infrastructure of the Cluster
func (instance *cluster) Create(ctx context.Context, req abstract.ClusterRequest) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	crashPlan := ""
	if crashPlanCandidate := os.Getenv("SAFESCALE_PLANNED_CRASHES"); crashPlanCandidate != "" {
		if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
			logrus.Warnf("Reloading crashplan: %s", crashPlanCandidate)
		}
		crashPlan = crashPlanCandidate
	}
	_ = errcontrol.CrashSetup(crashPlan)

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()
	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting creation of infrastructure of cluster '%s'...", req.Name),
		fmt.Sprintf("Ending creation of infrastructure of cluster '%s'", req.Name),
	)()

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	// Check if cluster exists in metadata; if yes, error
	existing, xerr := LoadCluster(instance.GetService(), req.Name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// good, continue
		default:
			return xerr
		}
	} else {
		existing.Released()
		return fail.DuplicateError("a cluster named '%s' already exist", req.Name)
	}

	// Create first metadata of Cluster after initialization
	xerr = instance.firstLight(req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Starting from here, delete metadata if exiting with error
	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			logrus.Debugf("Cleaning up on %s, deleting metadata of Cluster '%s'...", actionFromError(xerr), req.Name)
			if derr := instance.core.delete(); derr != nil {
				logrus.Errorf("cleaning up on %s, failed to delete metadata of Cluster '%s'", actionFromError(xerr), req.Name)
				_ = xerr.AddConsequence(derr)
			} else {
				logrus.Debugf("Cleaning up on %s, successfully deleted metadata of Cluster '%s'", actionFromError(xerr), req.Name)
			}
		}
	}()

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Obtain number of nodes to create
	_, privateNodeCount, _, xerr := instance.determineRequiredNodes()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if req.InitialNodeCount == 0 {
		req.InitialNodeCount = privateNodeCount
	}
	if req.InitialNodeCount > 0 && req.InitialNodeCount < privateNodeCount {
		logrus.Warnf("[cluster %s] cannot create less than required minimum of workers by the Flavor (%d requested, minimum being %d for flavor '%s')", req.Name, req.InitialNodeCount, privateNodeCount, req.Flavor.String())
		req.InitialNodeCount = privateNodeCount
	}

	// Define the sizing requirements for cluster hosts
	gatewaysDef, mastersDef, nodesDef, xerr := instance.determineSizingRequirements(req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Create the Network and Subnet
	rn, rs, xerr := instance.createNetworkingResources(ctx, req, gatewaysDef)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			// Disable abort signal during the clean up
			defer task.DisarmAbortSignal()()

			logrus.Debugf("Cleaning up on failure, deleting Subnet '%s'...", rs.GetName())
			if derr := rs.Delete(context.Background()); derr != nil {
				logrus.Errorf("Cleaning up on %s, failed to delete Subnet '%s'", actionFromError(xerr), rs.GetName())
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Subnet", actionFromError(xerr)))
			} else {
				logrus.Debugf("Cleaning up on %s, successfully deleted Subnet '%s'", actionFromError(xerr), rs.GetName())
				if req.NetworkID == "" {
					logrus.Debugf("Cleaning up on %s, deleting Network '%s'...", actionFromError(xerr), rn.GetName())
					if derr := rn.Delete(context.Background()); derr != nil {
						logrus.Errorf("cleaning up on %s, failed to delete Network '%s'", actionFromError(xerr), rn.GetName())
						_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Network", actionFromError(xerr)))
					} else {
						logrus.Debugf("Cleaning up on %s, successfully deleted Network '%s'", actionFromError(xerr), rn.GetName())
					}
				}
			}
		}
	}()

	// Creates and configures hosts
	xerr = instance.createHostResources(ctx, rs, *mastersDef, *nodesDef, req.InitialNodeCount, req.KeepOnFailure)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Starting from here, exiting with error deletes hosts if req.keepOnFailure is false
	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			// Disable abort signal during the clean up
			defer task.DisarmAbortSignal()()

			tg, tgerr := concurrency.NewTaskGroup(task)
			if tgerr != nil {
				_ = xerr.AddConsequence(tgerr)
			} else {
				logrus.Debugf("Cleaning up on failure, deleting Hosts...")
				var list map[uint]*propertiesv3.ClusterNode
				derr := instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
					return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
						nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
						if !ok {
							return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						list = nodesV3.ByNumericalID
						return nil
					})
				})
				if derr != nil {
					_ = xerr.AddConsequence(derr)
				} else {
					for _, v := range list {
						if _, derr = tg.StartInSubtask(instance.taskDeleteNodeOnFailure, taskDeleteNodeOnFailureParameters{node: v}); derr != nil {
							_ = xerr.AddConsequence(derr)
						}
					}
				}

				if _, _, tgerr = tg.WaitGroupFor(temporal.GetLongOperationTimeout()); tgerr != nil {
					_ = xerr.AddConsequence(tgerr)
				}
			}
		}
	}()

	// configure cluster as a whole
	xerr = instance.configureCluster(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Sets nominal state of the new cluster in metadata
	xerr = instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Nominal
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	return xerr
}

// firstLight contains the code leading to cluster first metadata written
func (instance *cluster) firstLight(req abstract.ClusterRequest) fail.Error {
	if req.Name = strings.TrimSpace(req.Name); req.Name == "" {
		return fail.InvalidParameterError("req.Name", "cannot be empty string")
	}

	// Initializes instance
	ci := abstract.NewClusterIdentity()
	ci.Name = req.Name
	ci.Flavor = req.Flavor
	ci.Complexity = req.Complexity

	xerr := instance.carry(ci)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		aci, ok := clonable.(*abstract.ClusterIdentity)
		if !ok {
			return fail.InconsistentError("'*abstract.ClusterIdentity' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		innerXErr := props.Alter(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			// VPL: For now, always disable addition of feature proxycache
			featuresV1.Disabled["proxycache"] = struct{}{}
			// ENDVPL
			for k := range req.DisabledDefaultFeatures {
				featuresV1.Disabled[k] = struct{}{}
			}
			return nil
		})
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to disable feature 'proxycache'")
		}

		// Sets initial state of the new cluster and create metadata
		innerXErr = props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Creating
			return nil
		})
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to set initial state of cluster")
		}

		// sets default sizing from req
		innerXErr = props.Alter(clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
			defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.Defaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			defaultsV2.GatewaySizing = *converters.HostSizingRequirementsFromAbstractToPropertyV1(req.GatewaysDef)
			defaultsV2.MasterSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV1(req.MastersDef)
			defaultsV2.NodeSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV1(req.NodesDef)
			defaultsV2.Image = req.NodesDef.Image
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// FUTURE: sets the cluster composition (when we will be able to manage cluster spread on several tenants...)
		innerXErr = props.Alter(clusterproperty.CompositeV1, func(clonable data.Clonable) fail.Error {
			compositeV1, ok := clonable.(*propertiesv1.ClusterComposite)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterComposite' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			compositeV1.Tenants = []string{req.Tenant}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Create a KeyPair for the user cladm
		kpName := "cluster_" + req.Name + "_cladm_key"
		kp, innerXErr := abstract.NewKeyPair(kpName)
		if innerXErr != nil {
			return innerXErr
		}
		aci.Keypair = kp

		// Generate needed password for account cladm
		cladmPassword, innerErr := utils.GeneratePassword(16)
		if innerErr != nil {
			return fail.ConvertError(innerErr)
		}
		aci.AdminPassword = cladmPassword

		// Links maker based on Flavor
		return instance.bootstrap(aci.Flavor)
	})
	xerr = debug.InjectPlannedFail(xerr)
	return xerr
}

// determineSizingRequirements calculates the sizings needed for the hosts of the cluster
func (instance *cluster) determineSizingRequirements(req abstract.ClusterRequest) (
	_ *abstract.HostSizingRequirements, _ *abstract.HostSizingRequirements, _ *abstract.HostSizingRequirements, xerr fail.Error,
) {

	var (
		gatewaysDefault *abstract.HostSizingRequirements
		mastersDefault  *abstract.HostSizingRequirements
		nodesDefault    *abstract.HostSizingRequirements
		imageID         string
	)

	// Determine default image
	imageID = req.NodesDef.Image
	if imageID == "" && instance.makers.DefaultImage != nil {
		imageID = instance.makers.DefaultImage(instance)
	}
	if imageID == "" {
		if cfg, xerr := instance.GetService().GetConfigurationOptions(); xerr == nil {
			if anon, ok := cfg.Get("DefaultImage"); ok {
				imageID = anon.(string)
			}
		}
	}
	if imageID == "" {
		imageID = "Ubuntu 18.04"
	}

	// Determine getGateway sizing
	if instance.makers.DefaultGatewaySizing != nil {
		gatewaysDefault = complementSizingRequirements(nil, instance.makers.DefaultGatewaySizing(instance))
	} else {
		gatewaysDefault = &abstract.HostSizingRequirements{
			MinCores:    2,
			MaxCores:    4,
			MinRAMSize:  7.0,
			MaxRAMSize:  16.0,
			MinDiskSize: 50,
			MinGPU:      -1,
		}
	}

	emptySizing := abstract.HostSizingRequirements{
		MinGPU: -1,
	}

	gatewaysDef := complementSizingRequirements(&req.GatewaysDef, *gatewaysDefault)
	gatewaysDef.Image = imageID

	if !req.GatewaysDef.Equals(emptySizing) {
		if lower, err := req.GatewaysDef.LowerThan(gatewaysDefault); err == nil && lower {
			if !req.Force {
				return nil, nil, nil, fail.NewError("requested gateway sizing less than recommended")
			}
		}
	}

	svc := instance.GetService()
	tmpl, xerr := svc.FindTemplateBySizing(*gatewaysDef)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, nil, xerr
	}
	gatewaysDef.Template = tmpl.Name

	// Determine master sizing
	if instance.makers.DefaultMasterSizing != nil {
		mastersDefault = complementSizingRequirements(nil, instance.makers.DefaultMasterSizing(instance))
	} else {
		mastersDefault = &abstract.HostSizingRequirements{
			MinCores:    4,
			MaxCores:    8,
			MinRAMSize:  15.0,
			MaxRAMSize:  32.0,
			MinDiskSize: 100,
			MinGPU:      -1,
		}
	}
	mastersDef := complementSizingRequirements(&req.MastersDef, *mastersDefault)
	mastersDef.Image = imageID

	if !req.MastersDef.Equals(emptySizing) {
		if lower, err := req.MastersDef.LowerThan(mastersDefault); err == nil && lower {
			if !req.Force {
				return nil, nil, nil, fail.NewError("requested master sizing less than recommended")
			}
		}
	}

	if mastersDef.Equals(*gatewaysDef) {
		mastersDef.Template = gatewaysDef.Template
	} else {
		tmpl, xerr = svc.FindTemplateBySizing(*mastersDef)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, nil, nil, xerr
		}
		mastersDef.Template = tmpl.Name
	}

	// Determine node sizing
	if instance.makers.DefaultNodeSizing != nil {
		nodesDefault = complementSizingRequirements(nil, instance.makers.DefaultNodeSizing(instance))
	} else {
		nodesDefault = &abstract.HostSizingRequirements{
			MinCores:    4,
			MaxCores:    8,
			MinRAMSize:  15.0,
			MaxRAMSize:  32.0,
			MinDiskSize: 100,
			MinGPU:      -1,
		}
	}
	nodesDef := complementSizingRequirements(&req.NodesDef, *nodesDefault)
	nodesDef.Image = imageID

	if !req.NodesDef.Equals(emptySizing) {
		if lower, err := req.NodesDef.LowerThan(nodesDefault); err == nil && lower {
			if !req.Force {
				return nil, nil, nil, fail.NewError("requested node sizing less than recommended")
			}
		}
	}

	if nodesDef.Equals(*gatewaysDef) { //nolint
		nodesDef.Template = gatewaysDef.Template
	} else if nodesDef.Equals(*mastersDef) {
		nodesDef.Template = mastersDef.Template
	} else {
		tmpl, xerr = svc.FindTemplateBySizing(*nodesDef)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, nil, nil, xerr
		}
		nodesDef.Template = tmpl.Name
	}

	// Updates property
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
			defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			defaultsV2.GatewaySizing = *converters.HostSizingRequirementsFromAbstractToPropertyV1(*gatewaysDef)
			defaultsV2.MasterSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV1(*mastersDef)
			defaultsV2.NodeSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV1(*nodesDef)
			defaultsV2.Image = imageID
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, nil, xerr
	}

	return gatewaysDef, mastersDef, nodesDef, nil
}

// createNetworkingResources creates the network and subnet for the cluster
func (instance *cluster) createNetworkingResources(ctx context.Context, req abstract.ClusterRequest, gatewaysDef *abstract.HostSizingRequirements) (_ resources.Network, _ resources.Subnet, xerr fail.Error) {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	if task.Aborted() {
		return nil, nil, fail.AbortedError(nil, "aborted")
	}

	// Determine if getGateway Failover must be set
	caps := instance.GetService().GetCapabilities()
	gwFailoverDisabled := req.Complexity == clustercomplexity.Small || !caps.PrivateVirtualIP
	for k := range req.DisabledDefaultFeatures {
		if k == "gateway-failover" {
			gwFailoverDisabled = true
			break
		}
	}

	req.Name = strings.ToLower(strings.TrimSpace(req.Name))

	// Creates Network
	var rn resources.Network
	if req.NetworkID != "" {
		rn, xerr = LoadNetwork(instance.GetService(), req.NetworkID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, nil, fail.Wrap(xerr, "failed to use network %s to contain cluster Subnet", req.NetworkID)
		}
	} else {
		logrus.Debugf("[cluster %s] creating Network '%s'", req.Name, req.Name)
		networkReq := abstract.NetworkRequest{
			Name:          req.Name,
			CIDR:          req.CIDR,
			KeepOnFailure: req.KeepOnFailure,
		}

		rn, xerr = NewNetwork(instance.GetService())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, nil, fail.Wrap(xerr, "failed to instanciate new Network")
		}

		xerr = rn.Create(ctx, networkReq)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, nil, fail.Wrap(xerr, "failed to create Network '%s'", req.Name)
		}

		defer func() {
			if xerr != nil && !req.KeepOnFailure {
				// Using context.Background() here disables abort
				if derr := rn.Delete(context.Background()); derr != nil {
					_ = xerr.AddConsequence(derr)
				}
			}
		}()
	}
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			networkV3.NetworkID = rn.GetID()
			networkV3.CreatedNetwork = req.NetworkID == "" // empty NetworkID means that the Network would have to be deleted when the cluster will
			networkV3.CIDR = req.CIDR
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	if task.Aborted() {
		return nil, nil, fail.AbortedError(nil, "aborted")
	}

	// Creates Subnet
	logrus.Debugf("[cluster %s] creating Subnet '%s'", req.Name, req.Name)
	subnetReq := abstract.SubnetRequest{
		Name:          req.Name,
		NetworkID:     rn.GetID(),
		CIDR:          req.CIDR,
		HA:            !gwFailoverDisabled,
		Image:         gatewaysDef.Image,
		KeepOnFailure: false, // We consider subnet and its gateways as a whole; if any error occurs during the creation of the whole, do keep nothing
	}

	rs, xerr := NewSubnet(instance.GetService())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	xerr = rs.Create(ctx, subnetReq, "", gatewaysDef)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrInvalidRequest:
			// Some cloud providers do not allow to create a Subnet with the same CIDR than the Network; try with a sub-CIDR once
			logrus.Warnf("Cloud Provider does not allow to use the same CIDR than the Network one, trying a subset of CIDR...")
			_, ipNet, err := net.ParseCIDR(subnetReq.CIDR)
			err = debug.InjectPlannedError(err)
			if err != nil {
				_ = xerr.AddConsequence(fail.Wrap(err, "failed to compute subset of CIDR '%s'", req.CIDR))
				return nil, nil, xerr
			}

			if subIPNet, subXErr := netutils.FirstIncludedSubnet(*ipNet, 1); subXErr == nil {
				subnetReq.CIDR = subIPNet.String()
			} else {
				_ = xerr.AddConsequence(fail.Wrap(subXErr, "failed to compute subset of CIDR '%s'", req.CIDR))
				return nil, nil, xerr
			}
			if subXErr := rs.Create(ctx, subnetReq, "", gatewaysDef); subXErr != nil {
				return nil, nil, fail.Wrap(subXErr, "failed to create Subnet '%s' (with CIDR %s) in Network '%s' (with CIDR %s)", subnetReq.Name, subnetReq.CIDR, rn.GetName(), req.CIDR)
			}
			logrus.Infof("CIDR '%s' used successfully for Subnet, there will be less available private IP Addresses than expected.", subnetReq.CIDR)
			xerr = nil
		default:
			return nil, nil, fail.Wrap(xerr, "failed to create Subnet '%s' in Network '%s'", req.Name, rn.GetName())
		}
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			if derr := rs.Delete(context.Background()); derr != nil {
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	if task.Aborted() {
		return nil, nil, fail.AbortedError(nil, "aborted")
	}

	// Updates again cluster metadata, propertiesv3.ClusterNetwork, with subnet infos
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			primaryGateway, innerXErr := rs.InspectGateway(true)
			if innerXErr != nil {
				return innerXErr
			}

			var secondaryGateway resources.Host
			if !gwFailoverDisabled {
				secondaryGateway, innerXErr = rs.InspectGateway(false)
				if innerXErr != nil {
					return innerXErr
				}
			}
			networkV3.SubnetID = rs.GetID()
			networkV3.GatewayID = primaryGateway.GetID()
			if networkV3.GatewayIP, innerXErr = primaryGateway.GetPrivateIP(); innerXErr != nil {
				return innerXErr
			}
			if networkV3.DefaultRouteIP, innerXErr = rs.GetDefaultRouteIP(); innerXErr != nil {
				return innerXErr
			}
			if networkV3.EndpointIP, innerXErr = rs.GetEndpointIP(); innerXErr != nil {
				return innerXErr
			}
			if networkV3.PrimaryPublicIP, innerXErr = primaryGateway.GetPublicIP(); innerXErr != nil {
				return innerXErr
			}
			if !gwFailoverDisabled {
				networkV3.SecondaryGatewayID = secondaryGateway.GetID()
				if networkV3.SecondaryGatewayIP, innerXErr = secondaryGateway.GetPrivateIP(); innerXErr != nil {
					return innerXErr
				}
				if networkV3.SecondaryPublicIP, innerXErr = secondaryGateway.GetPublicIP(); innerXErr != nil {
					return innerXErr
				}
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	logrus.Debugf("[cluster %s] Subnet '%s' in Network '%s' creation successful.", req.Name, rn.GetName(), req.Name)
	return rn, rs, nil
}

func onFailureAbortTask(task concurrency.Task, inErr *fail.Error) {
	if inErr != nil && *inErr != nil {
		st, xerr := task.GetStatus()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			_ = (*inErr).AddConsequence(xerr)
			return
		}

		if st != concurrency.DONE {
			xerr = task.Abort()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				_ = (*inErr).AddConsequence(xerr)
				return
			}
			_, xerr = task.Wait()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				_ = (*inErr).AddConsequence(xerr)
			}
		}
	}
}

// createHostResources creates and configures hosts for the cluster
func (instance *cluster) createHostResources(
	ctx context.Context,
	subnet resources.Subnet,
	mastersDef abstract.HostSizingRequirements,
	nodesDef abstract.HostSizingRequirements,
	initialNodeCount uint,
	keepOnFailure bool,
) (xerr fail.Error) {

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	var (
		primaryGateway, secondaryGateway             resources.Host
		primaryGatewayStatus, secondaryGatewayStatus fail.Error
		mastersStatus, privateNodesStatus            fail.Error
		primaryGatewayTask, secondaryGatewayTask     concurrency.Task
		primaryGatewayConfigTask                     concurrency.Task
		secondaryGatewayConfigTask                   concurrency.Task
	)

	primaryGateway, xerr = subnet.InspectGateway(true)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	haveSecondaryGateway := true
	secondaryGateway, xerr = subnet.InspectGateway(false)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// It's a valid state not to have a secondary gateway, so continue
			haveSecondaryGateway = false
		default:
			return xerr
		}
	}

	_, xerr = primaryGateway.WaitSSHReady(ctx, temporal.GetExecutionTimeout())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "wait for remote ssh service to be ready")
	}

	if haveSecondaryGateway {
		_, xerr = secondaryGateway.WaitSSHReady(ctx, temporal.GetExecutionTimeout())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to wait for remote ssh service to become ready")
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	masterCount, _, _, xerr := instance.determineRequiredNodes()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Step 1: starts gateway installation plus masters creation plus nodes creation
	primaryGatewayTask, xerr = task.StartInSubtask(instance.taskInstallGateway, taskInstallGatewayParameters{primaryGateway})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer onFailureAbortTask(primaryGatewayTask, &xerr)

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	if haveSecondaryGateway {
		secondaryGatewayTask, xerr = task.StartInSubtask(instance.taskInstallGateway, taskInstallGatewayParameters{secondaryGateway})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
		defer onFailureAbortTask(secondaryGatewayTask, &xerr)
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	mastersTask, xerr := task.StartInSubtask(instance.taskCreateMasters, taskCreateMastersParameters{
		count:         masterCount,
		mastersDef:    mastersDef,
		keepOnFailure: keepOnFailure,
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer onFailureAbortTask(mastersTask, &xerr)

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	privateNodesTask, xerr := task.StartInSubtask(instance.taskCreateNodes, taskCreateNodesParameters{
		count:         initialNodeCount,
		public:        false,
		nodesDef:      nodesDef,
		keepOnFailure: keepOnFailure,
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	defer onFailureAbortTask(privateNodesTask, &xerr)

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Step 2: awaits gateway installation end and masters installation end
	if _, primaryGatewayStatus = primaryGatewayTask.Wait(); primaryGatewayStatus != nil {
		return primaryGatewayStatus
	}
	if haveSecondaryGateway && secondaryGatewayTask != nil {
		if _, secondaryGatewayStatus = secondaryGatewayTask.Wait(); secondaryGatewayStatus != nil {
			return secondaryGatewayStatus
		}
	}

	// Starting from here, delete masters if exiting with error and req.keepOnFailure is not true
	defer func() {
		if xerr != nil && !keepOnFailure {
			// Disable abort signal during the clean up
			defer task.DisarmAbortSignal()()

			list, merr := instance.unsafeListMasters()
			if merr != nil {
				_ = xerr.AddConsequence(merr)
			} else {
				tg, tgerr := concurrency.NewTaskGroup(task)
				if tgerr != nil {
					_ = xerr.AddConsequence(tgerr)
				} else {
					for _, v := range list {
						if _, derr := tg.StartInSubtask(instance.taskDeleteNodeOnFailure, taskDeleteNodeOnFailureParameters{node: v}); derr != nil {
							_ = xerr.AddConsequence(derr)
						}
					}
					if _, _, derr := tg.WaitGroupFor(temporal.GetLongOperationTimeout()); derr != nil {
						_ = xerr.AddConsequence(derr)
					}
				}
			}
		}
	}()

	if _, mastersStatus = mastersTask.Wait(); mastersStatus != nil {
		return mastersStatus
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Step 3: start gateway configuration (needs MasterIPs so masters must be installed first)
	// Configure gateway(s) and waits for the result
	primaryGatewayConfigTask, xerr = task.StartInSubtask(instance.taskConfigureGateway, taskConfigureGatewayParameters{Host: primaryGateway})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer onFailureAbortTask(primaryGatewayConfigTask, &xerr)

	if haveSecondaryGateway {
		secondaryGatewayConfigTask, xerr = task.StartInSubtask(instance.taskConfigureGateway, taskConfigureGatewayParameters{Host: secondaryGateway})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
		defer onFailureAbortTask(secondaryGatewayConfigTask, &xerr)
	}

	if _, primaryGatewayStatus = primaryGatewayConfigTask.Wait(); primaryGatewayStatus != nil {
		return primaryGatewayStatus
	}

	if haveSecondaryGateway && secondaryGatewayConfigTask != nil {
		if _, secondaryGatewayStatus = secondaryGatewayConfigTask.Wait(); secondaryGatewayStatus != nil {
			return secondaryGatewayStatus
		}
	}

	// Step 4: configure masters (if masters created successfully and gateways configured successfully)
	if _, mastersStatus = task.RunInSubtask(instance.taskConfigureMasters, nil); mastersStatus != nil {
		return mastersStatus
	}

	// Starting from here, if exiting with error, delete nodes
	defer func() {
		if xerr != nil && !keepOnFailure {
			// Disable abort signal during the clean up
			defer task.DisarmAbortSignal()()

			list, merr := instance.unsafeListNodes()
			if merr != nil {
				_ = xerr.AddConsequence(merr)
			} else {
				tg, tgerr := concurrency.NewTaskGroup(task)
				if tgerr != nil {
					_ = xerr.AddConsequence(tgerr)
				} else {
					for _, v := range list {
						if _, derr := tg.StartInSubtask(instance.taskDeleteNodeOnFailure, taskDeleteNodeOnFailureParameters{node: v}); derr != nil {
							_ = xerr.AddConsequence(derr)
						}
					}
					if _, _, derr := tg.WaitGroupFor(temporal.GetLongOperationTimeout()); derr != nil {
						_ = xerr.AddConsequence(derr)
					}
				}
			}
		}
	}()

	// Step 5: awaits nodes creation
	if _, privateNodesStatus = privateNodesTask.Wait(); privateNodesStatus != nil {
		return privateNodesStatus
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Step 6: Starts nodes configuration, if all masters and nodes have been created and gateway has been configured with success
	if _, privateNodesStatus = task.RunInSubtask(instance.taskConfigureNodes, nil); privateNodesStatus != nil {
		return privateNodesStatus
	}

	return nil
}

// complementSizingRequirements complements req with default values if needed
func complementSizingRequirements(req *abstract.HostSizingRequirements, def abstract.HostSizingRequirements) *abstract.HostSizingRequirements {
	var finalDef abstract.HostSizingRequirements
	if req == nil {
		finalDef = def
	} else {
		finalDef = *req

		if def.MinCores > 0 && finalDef.MinCores == 0 {
			finalDef.MinCores = def.MinCores
		}
		if def.MaxCores > 0 && finalDef.MaxCores == 0 {
			finalDef.MaxCores = def.MaxCores
		}
		if def.MinRAMSize > 0.0 && finalDef.MinRAMSize == 0.0 {
			finalDef.MinRAMSize = def.MinRAMSize
		}
		if def.MaxRAMSize > 0.0 && finalDef.MaxRAMSize == 0.0 {
			finalDef.MaxRAMSize = def.MaxRAMSize
		}
		if def.MinDiskSize > 0 && finalDef.MinDiskSize == 0 {
			finalDef.MinDiskSize = def.MinDiskSize
		}
		if finalDef.MinGPU <= 0 && def.MinGPU > 0 {
			finalDef.MinGPU = def.MinGPU
		}
		if finalDef.MinCPUFreq == 0 && def.MinCPUFreq > 0 {
			finalDef.MinCPUFreq = def.MinCPUFreq
		}
		if finalDef.MinCores <= 0 {
			finalDef.MinCores = 2
		}
		if finalDef.MaxCores <= 0 {
			finalDef.MaxCores = 4
		}
		if finalDef.MinRAMSize <= 0.0 {
			finalDef.MinRAMSize = 7.0
		}
		if finalDef.MaxRAMSize <= 0.0 {
			finalDef.MaxRAMSize = 16.0
		}
		if finalDef.MinDiskSize <= 0 {
			finalDef.MinDiskSize = 50
		}
	}

	return &finalDef
}

// Serialize converts cluster data to JSON
func (instance *cluster) Serialize() (_ []byte, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return []byte{}, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	r, err := json.Marshal(instance) // nolint
	return r, fail.ConvertError(err)
}

// Deserialize reads json code and reinstantiates cluster
func (instance *cluster) Deserialize(buf []byte) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}

	if len(buf) == 0 {
		return fail.InvalidParameterError("buf", "cannot be empty []byte")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	err := json.Unmarshal(buf, instance) // nolint
	return fail.ConvertError(err)
}

// bootstrap (re)connects controller with the appropriate Makers
func (instance *cluster) bootstrap(flavor clusterflavor.Enum) (xerr fail.Error) {
	switch flavor {
	case clusterflavor.BOH:
		instance.makers = boh.Makers
	case clusterflavor.K8S:
		instance.makers = k8s.Makers
	default:
		return fail.NotImplementedError("unknown cluster Flavor '%d'", flavor)
	}
	return nil
}

// Browse walks through cluster folder and executes a callback for each entry
// FIXME: adds a cluster status check to prevent operations on removed clusters
func (instance *cluster) Browse(ctx context.Context, callback func(*abstract.ClusterIdentity) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: Browse is intended to be callable from null value, so do not validate instance
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	return instance.core.BrowseFolder(func(buf []byte) fail.Error {
		aci := abstract.NewClusterIdentity()
		xerr := aci.Deserialize(buf)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		return callback(aci)
	})
}

// GetIdentity returns the identity of the cluster
func (instance *cluster) GetIdentity() (clusterIdentity abstract.ClusterIdentity, xerr fail.Error) {
	if instance.isNull() {
		return abstract.ClusterIdentity{}, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.unsafeGetIdentity()
}

// GetFlavor returns the flavor of the cluster
func (instance *cluster) GetFlavor() (flavor clusterflavor.Enum, xerr fail.Error) {
	if instance.isNull() {
		return 0, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.unsafeGetFlavor()
}

// GetComplexity returns the complexity of the cluster
func (instance *cluster) GetComplexity() (_ clustercomplexity.Enum, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return 0, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	return instance.unsafeGetComplexity()
}

// GetAdminPassword returns the password of the cluster admin account
// satisfies interface cluster.Controller
func (instance *cluster) GetAdminPassword() (adminPassword string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return "", fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	aci, xerr := instance.GetIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}
	return aci.AdminPassword, nil
}

// GetKeyPair returns the key pair used in the cluster
func (instance *cluster) GetKeyPair() (keyPair abstract.KeyPair, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	nullAKP := abstract.KeyPair{}
	if instance.isNull() {
		return nullAKP, fail.InvalidInstanceError()
	}

	aci, xerr := instance.GetIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nullAKP, xerr
	}

	return *(aci.Keypair), nil
}

// GetNetworkConfig returns subnet configuration of the cluster
func (instance *cluster) GetNetworkConfig() (config *propertiesv3.ClusterNetwork, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	nullConfig := &propertiesv3.ClusterNetwork{}
	if instance.isNull() {
		return nullConfig, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	xerr = instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			// config = networkV3.Clone().(*propertiesv3.ClusterNetwork)
			config = networkV3
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nullConfig, xerr
	}

	return config, nil
}

// Start starts the cluster
func (instance *cluster) Start(ctx context.Context) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	// If the cluster is in state Stopping or Stopped, do nothing
	var prevState clusterstate.Enum
	prevState, xerr = instance.unsafeGetState()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	switch prevState {
	case clusterstate.Removed:
		return fail.NotAvailableError("cluster is being removed")
	case clusterstate.Stopping:
		return nil
	case clusterstate.Starting:
		// If the cluster is in state Starting, wait for it to finish its start procedure
		xerr = retry.WhileUnsuccessfulDelay5Seconds(
			func() error {
				state, innerErr := instance.unsafeGetState()
				if innerErr != nil {
					return innerErr
				}

				if state == clusterstate.Nominal || state == clusterstate.Degraded {
					return nil
				}

				return fail.NewError("current state of cluster is '%s'", state.String())
			},
			5*time.Minute, // FIXME: hardcoded timeout
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if _, ok := xerr.(*retry.ErrTimeout); ok {
				xerr = fail.Wrap(xerr, "timeout waiting cluster to become started")
			}
			return xerr
		}
		return nil
	case clusterstate.Stopped:
		// continue
	default:
		return fail.NotAvailableError("failed to start cluster because of it's current state: %s", prevState.String())
	}

	// First mark cluster to be in state Starting
	xerr = instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			stateV1.State = clusterstate.Starting
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	var (
		nodes                         []string
		masters                       []string
		gatewayID, secondaryGatewayID string
	)

	// Then start it and mark it as STARTED on success
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		innerXErr := props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			masters = make([]string, 0, len(nodesV3.Masters))
			for _, v := range nodesV3.Masters {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if node, found := nodesV3.ByNumericalID[v]; found {
					masters = append(masters, node.ID)
				}
			}
			nodes = make([]string, 0, len(nodesV3.PrivateNodes))
			for _, v := range nodesV3.PrivateNodes {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if node, found := nodesV3.ByNumericalID[v]; found {
					nodes = append(nodes, node.ID)
				}
			}

			return nil
		})
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to get list of hosts")
		}

		innerXErr = props.Inspect(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			gatewayID = networkV3.GatewayID
			secondaryGatewayID = networkV3.SecondaryGatewayID
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Mark cluster as state Starting
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			stateV1.State = clusterstate.Starting
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Start gateway(s)
	taskGroup, xerr := concurrency.NewTaskGroup(task)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	_, xerr = taskGroup.Start(instance.taskStartHost, gatewayID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if secondaryGatewayID != "" {
		_, xerr = taskGroup.Start(instance.taskStartHost, secondaryGatewayID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	// Start masters
	for _, n := range masters {
		_, xerr = taskGroup.Start(instance.taskStartHost, n)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}
	// Start nodes
	for _, n := range nodes {
		_, xerr = taskGroup.Start(instance.taskStartHost, n)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}
	_, xerr = taskGroup.WaitGroup()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Nominal
			return nil
		})
	})
}

// Stop stops the cluster
func (instance *cluster) Stop(ctx context.Context) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	// If the cluster is stopped, do nothing
	var prevState clusterstate.Enum
	prevState, xerr = instance.unsafeGetState()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	switch prevState {
	case clusterstate.Removed:
		return fail.NotAvailableError("cluster is being removed")
	case clusterstate.Stopped:
		return nil
	case clusterstate.Stopping:
		xerr = retry.WhileUnsuccessfulDelay5Seconds(
			func() error {
				state, innerErr := instance.unsafeGetState()
				if innerErr != nil {
					return innerErr
				}

				if state == clusterstate.Removed {
					return retry.StopRetryError(fail.NotAvailableError("cluster is being removed"))
				}

				if state != clusterstate.Stopped {
					return fail.NotAvailableError("current state of cluster is '%s'", state.String())
				}

				return nil
			},
			5*time.Minute, // FIXME: hardcoded timeout
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrTimeout:
				xerr = fail.Wrap(xerr, "timeout waiting cluster transitioning from state Stopping to Stopped")
			case *retry.ErrStopRetry:
				xerr = fail.ConvertError(xerr.Cause())
			}
		}
		return xerr
	case clusterstate.Nominal, clusterstate.Degraded:
		// continue
	default:
		// If the cluster is not in state Nominal or Degraded, can't stop
		return fail.NotAvailableError("failed to stop cluster because of it's current state: %s", prevState.String())
	}

	// First mark cluster to be in state Stopping
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			stateV1.State = clusterstate.Stopping
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Then stop it and mark it as STOPPED on success
	return instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		var (
			nodes                         []string
			masters                       []string
			gatewayID, secondaryGatewayID string
		)
		innerXErr := props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			masters = make([]string, 0, len(nodesV3.Masters))
			for _, v := range nodesV3.Masters {
				if node, found := nodesV3.ByNumericalID[v]; found {
					masters = append(masters, node.ID)
				}
			}
			nodes = make([]string, 0, len(nodesV3.PrivateNodes))
			for _, v := range nodesV3.PrivateNodes {
				if node, found := nodesV3.ByNumericalID[v]; found {
					nodes = append(nodes, node.ID)
				}
			}
			return nil
		})
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to get list of hosts")
		}

		innerXErr = props.Inspect(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			gatewayID = networkV3.GatewayID
			secondaryGatewayID = networkV3.SecondaryGatewayID
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Stop nodes
		taskGroup, innerXErr := concurrency.NewTaskGroup(task)
		if innerXErr != nil {
			return innerXErr
		}

		for _, n := range nodes {
			if _, innerXErr = taskGroup.Start(instance.taskStopHost, n); innerXErr != nil {
				return innerXErr
			}
		}
		// Stop masters
		for _, n := range masters {
			if _, innerXErr = taskGroup.Start(instance.taskStopHost, n); innerXErr != nil {
				return innerXErr
			}
		}
		// Stop gateway(s)
		if _, innerXErr = taskGroup.Start(instance.taskStopHost, gatewayID); innerXErr != nil {
			return innerXErr
		}
		if secondaryGatewayID != "" {
			if _, innerXErr = taskGroup.Start(instance.taskStopHost, secondaryGatewayID); innerXErr != nil {
				return innerXErr
			}
		}

		if _, innerXErr = taskGroup.WaitGroup(); innerXErr != nil {
			return innerXErr
		}

		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Stopped
			return nil
		})
	})
}

// GetState returns the current state of the Cluster
// Uses the "maker" ForceGetState
func (instance *cluster) GetState() (state clusterstate.Enum, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	state = clusterstate.Unknown
	if instance.isNull() {
		return state, fail.InvalidInstanceError()
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeGetState()
}

// AddNode adds a node
func (instance *cluster) AddNode(ctx context.Context, def abstract.HostSizingRequirements) (_ resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nullHost(), fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nullHost(), fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nullHost(), fail.AbortedError(nil, "aborted")
	}

	nodes, xerr := instance.AddNodes(ctx, 1, def)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nullHost(), xerr
	}

	return nodes[0], nil
}

// AddNodes adds several nodes
func (instance *cluster) AddNodes(ctx context.Context, count uint, def abstract.HostSizingRequirements) (_ []resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if count == 0 {
		return nil, fail.InvalidParameterError("count", "must be an int > 0")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%d)", count)
	defer tracer.Entering().Exiting()

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	var (
		hostImage             string
		nodeDefaultDefinition *propertiesv1.HostSizingRequirements
	)
	xerr = instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
			defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			nodeDefaultDefinition = &defaultsV2.NodeSizing
			hostImage = defaultsV2.Image
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	nodeDef := complementHostDefinition(def, *nodeDefaultDefinition)
	if nodeDef.Image == "" {
		nodeDef.Image = hostImage
	}

	var (
		nodeTypeStr string
		errors      []string
		hosts       []resources.Host
	)

	timeout := temporal.GetExecutionTimeout() + time.Duration(count)*time.Minute

	var subtasks []concurrency.Task
	for i := uint(0); i < count; i++ {
		if task.Aborted() {
			return nil, fail.AbortedError(nil, "aborted")
		}

		subtask, xerr := task.StartInSubtask(instance.taskCreateNode, taskCreateNodeParameters{
			index:         i + 1,
			nodeDef:       nodeDef,
			timeout:       timeout,
			keepOnFailure: false,
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		subtasks = append(subtasks, subtask)
	}
	for _, s := range subtasks {
		res, err := s.Wait()
		err = debug.InjectPlannedFail(err)
		if err != nil {
			errors = append(errors, err.Error())
		} else {
			hosts = append(hosts, res.(resources.Host))
		}
	}

	// Starting from here, delete nodes if exiting with error
	newHosts := hosts
	defer func() {
		if xerr != nil && len(newHosts) > 0 {
			logrus.Debugf("Cleaning up on failure, deleting Nodes...")
			if derr := instance.deleteHosts(task, newHosts); derr != nil {
				logrus.Errorf("Cleaning up on failure, failed to delete Nodes")
				_ = xerr.AddConsequence(derr)
			} else {
				logrus.Debugf("Cleaning up on failure, successfully deleted Nodes")
			}
		}
	}()

	if len(errors) > 0 {
		xerr = fail.NewError("errors occurred on %s node%s addition: %s", nodeTypeStr, strprocess.Plural(uint(len(errors))), strings.Join(errors, "\n"))
		return nil, xerr
	}

	// Now configure new nodes
	xerr = instance.configureNodesFromList(task, hosts)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// At last join nodes to cluster
	xerr = instance.joinNodesFromList(ctx, hosts)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return hosts, nil
}

// complementHostDefinition complements req with default values if needed
func complementHostDefinition(req abstract.HostSizingRequirements, def propertiesv1.HostSizingRequirements) abstract.HostSizingRequirements {
	if def.MinCores > 0 && req.MinCores == 0 {
		req.MinCores = def.MinCores
	}
	if def.MaxCores > 0 && req.MaxCores == 0 {
		req.MaxCores = def.MaxCores
	}
	if def.MinRAMSize > 0.0 && req.MinRAMSize == 0.0 {
		req.MinRAMSize = def.MinRAMSize
	}
	if def.MaxRAMSize > 0.0 && req.MaxRAMSize == 0.0 {
		req.MaxRAMSize = def.MaxRAMSize
	}
	if def.MinDiskSize > 0 && req.MinDiskSize == 0 {
		req.MinDiskSize = def.MinDiskSize
	}
	if req.MinGPU <= 0 && def.MinGPU > 0 {
		req.MinGPU = def.MinGPU
	}
	if req.MinCPUFreq == 0 && def.MinCPUFreq > 0 {
		req.MinCPUFreq = def.MinCPUFreq
	}
	if req.MinCores <= 0 {
		req.MinCores = 2
	}
	if req.MaxCores <= 0 {
		req.MaxCores = 4
	}
	if req.MinRAMSize <= 0.0 {
		req.MinRAMSize = 7.0
	}
	if req.MaxRAMSize <= 0.0 {
		req.MaxRAMSize = 16.0
	}
	if req.MinDiskSize <= 0 {
		req.MinDiskSize = 50
	}

	return req
}

// DeleteLastNode deletes the last added node and returns its name
func (instance *cluster) DeleteLastNode(ctx context.Context) (node *propertiesv3.ClusterNode, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Removed reference of the node from cluster
	xerr = instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			numericalID := nodesV3.PrivateNodes[len(nodesV3.PrivateNodes)-1]
			if node, ok = nodesV3.ByNumericalID[numericalID]; !ok {
				return fail.InconsistentError("the last recorded node in metadata points to missing Host")
			}

			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	if node == nil {
		return nil, fail.NotFoundError("failed to find last node")
	}

	selectedMaster, xerr := instance.unsafeFindAvailableMaster(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	xerr = instance.deleteNode(ctx, node, selectedMaster.(*host))
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return node, nil
}

// DeleteSpecificNode deletes a node identified by its ID
func (instance *cluster) DeleteSpecificNode(ctx context.Context, hostID string, selectedMasterID string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if hostID = strings.TrimSpace(hostID); hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(hostID=%s)", hostID).Entering()
	defer tracer.Exiting()

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	var selectedMaster resources.Host
	if selectedMasterID != "" {
		selectedMaster, xerr = LoadHost(instance.GetService(), selectedMasterID)
	} else {
		selectedMaster, xerr = instance.unsafeFindAvailableMaster(ctx)
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	var node *propertiesv3.ClusterNode
	xerr = instance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			numericalID, ok := nodesV3.PrivateNodeByID[hostID]
			if !ok {
				return fail.NotFoundError("failed to find a node identified by %s", hostID)
			}

			node, ok = nodesV3.ByNumericalID[numericalID]
			if !ok {
				return fail.NotFoundError("failed to find a node identified by %s", hostID)
			}

			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return instance.deleteNode(ctx, node, selectedMaster.(*host))
}

// ListMasters lists the node instances corresponding to masters (if there is such masters in the flavor...)
func (instance *cluster) ListMasters(ctx context.Context) (list resources.IndexedListOfClusterNodes, xerr fail.Error) {
	emptyList := resources.IndexedListOfClusterNodes{}
	if instance.isNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	return instance.unsafeListMasters()
}

// ListMasterNames lists the names of the master nodes in the Cluster
func (instance *cluster) ListMasterNames(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	if instance.isNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			list = make(data.IndexedListOfStrings, len(nodesV3.Masters))
			for _, v := range nodesV3.Masters {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if node, found := nodesV3.ByNumericalID[v]; found {
					list[node.NumericalID] = node.Name
				}
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	return list, nil
}

// ListMasterIDs lists the IDs of masters (if there is such masters in the flavor...)
func (instance *cluster) ListMasterIDs(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	if instance.isNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeListMasterIDs(ctx)
}

func (instance *cluster) unsafeListMasterIDs(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	emptyList := data.IndexedListOfStrings{}
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			list = make(data.IndexedListOfStrings, len(nodesV3.Masters))
			for _, v := range nodesV3.Masters {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if node, found := nodesV3.ByNumericalID[v]; found {
					list[node.NumericalID] = node.ID
				}
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	return list, nil
}

// ListMasterIPs lists the IPs of masters (if there is such masters in the flavor...)
func (instance *cluster) ListMasterIPs(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	if instance.isNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeListMasterIPs()
}

// FindAvailableMaster returns ID of the first master available to execute order
// satisfies interface cluster.cluster.Controller
func (instance *cluster) FindAvailableMaster(ctx context.Context) (master resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	master = nil
	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return instance.unsafeFindAvailableMaster(ctx)
}

// ListNodes lists node instances corresponding to the nodes in the cluster
// satisfies interface cluster.Controller
func (instance *cluster) ListNodes(ctx context.Context) (list resources.IndexedListOfClusterNodes, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := resources.IndexedListOfClusterNodes{}
	if instance.isNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return instance.unsafeListNodes()
}

// beingRemoved tells if the cluster is currently marked as Removed (meaning a removal operation is running)
func (instance *cluster) beingRemoved() fail.Error {
	state, xerr := instance.unsafeGetState()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if state == clusterstate.Removed {
		return fail.NotAvailableError("cluster is being removed")
	}

	return nil
}

// ListNodeNames lists the names of the nodes in the Cluster
func (instance *cluster) ListNodeNames(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	if instance.isNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			list = make(data.IndexedListOfStrings, len(nodesV3.PrivateNodes))
			for _, v := range nodesV3.PrivateNodes {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if node, found := nodesV3.ByNumericalID[v]; found {
					list[node.NumericalID] = node.Name
				}
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	return list, nil
}

// ListNodeIDs lists IDs of the nodes in the cluster
func (instance *cluster) ListNodeIDs(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	if instance.isNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeListNodeIDs(ctx)
}

// ListNodeIPs lists the IPs of the nodes in the cluster
func (instance *cluster) ListNodeIPs(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	if instance.isNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return instance.unsafeListNodeIPs()
}

// FindAvailableNode returns node instance of the first node available to execute order
func (instance *cluster) FindAvailableNode(ctx context.Context) (node resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeFindAvailableNode(ctx)
}

// LookupNode tells if the ID of the master passed as parameter is a node
func (instance *cluster) LookupNode(ctx context.Context, ref string) (found bool, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return false, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return false, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if ref == "" {
		return false, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

	if task.Aborted() {
		return false, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

	var host resources.Host
	host, xerr = LoadHost(instance.GetService(), ref)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

	found = false
	xerr = instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			_, found = nodesV3.PrivateNodeByID[host.GetID()]
			return nil
		})
	})
	return found, xerr
}

// CountNodes counts the nodes of the cluster
func (instance *cluster) CountNodes(ctx context.Context) (count uint, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return 0, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return 0, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	if task.Aborted() {
		return 0, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	xerr = instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			count = uint(len(nodesV3.PrivateNodes))
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return count, nil
}

// GetNodeByID returns a node based on its ID
func (instance *cluster) GetNodeByID(ctx context.Context, hostID string) (host resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostID == "" {
		return nil, fail.InvalidParameterError("hostID", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%s)", hostID)
	defer tracer.Entering().Exiting()

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	found := false
	xerr = instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			_, found = nodesV3.PrivateNodeByID[hostID]
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	if !found {
		return nil, fail.NotFoundError("failed to find node %s in Cluster '%s'", hostID, instance.GetName())
	}

	return LoadHost(instance.GetService(), hostID)
}

// deleteMaster deletes the master specified by its ID
func (instance *cluster) deleteMaster(ctx context.Context, host resources.Host) fail.Error {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	var master *propertiesv3.ClusterNode
	xerr = instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			// Removes master from cluster properties
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			numericalID, found := nodesV3.MasterByID[host.GetID()]
			if !found {
				return abstract.ResourceNotFoundError("master", host.GetName())
			}

			master = nodesV3.ByNumericalID[numericalID]
			delete(nodesV3.ByNumericalID, numericalID)
			delete(nodesV3.MasterByName, host.GetName())
			delete(nodesV3.MasterByID, host.GetID())
			if found, indexInSlice := containsClusterNode(nodesV3.Masters, numericalID); found {
				length := len(nodesV3.Masters)
				if indexInSlice < length-1 {
					nodesV3.Masters = append(nodesV3.Masters[:indexInSlice], nodesV3.Masters[indexInSlice+1:]...)
				} else {
					nodesV3.Masters = nodesV3.Masters[:indexInSlice]
				}
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Starting from here, restore master in cluster properties if exiting with error
	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			derr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
					nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
					if !ok {
						return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					nodesV3.Masters = append(nodesV3.Masters, master.NumericalID)
					nodesV3.MasterByName[master.Name] = master.NumericalID
					nodesV3.MasterByID[master.ID] = master.NumericalID
					nodesV3.ByNumericalID[master.NumericalID] = master
					return nil
				})
			})
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to restore master '%s' in cluster metadata", actionFromError(xerr), master.Name))
			}
		}
	}()

	// Finally delete host
	xerr = host.Delete(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// master seems already deleted, so consider it as a success
			logrus.Tracef("master not found, deletion considered as a success")
		default:
			return xerr
		}
	}
	return nil
}

// deleteNode deletes a node identified by its ID
func (instance *cluster) deleteNode(ctx context.Context, node *propertiesv3.ClusterNode, master *host) (xerr fail.Error) {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	nodeRef := node.ID
	if nodeRef == "" {
		nodeRef = node.Name
	}

	// Identify the node to delete and remove it preventive from metadata
	xerr = instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			delete(nodesV3.ByNumericalID, node.NumericalID)

			if found, indexInSlice := containsClusterNode(nodesV3.PrivateNodes, node.NumericalID); found {
				length := len(nodesV3.PrivateNodes)
				if indexInSlice < length-1 {
					nodesV3.PrivateNodes = append(nodesV3.PrivateNodes[:indexInSlice], nodesV3.PrivateNodes[indexInSlice+1:]...)
				} else {
					nodesV3.PrivateNodes = nodesV3.PrivateNodes[:indexInSlice]
				}
			}
			delete(nodesV3.PrivateNodeByID, node.ID)
			delete(nodesV3.PrivateNodeByName, node.Name)
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Starting from here, restore node in cluster metadata if exiting with error
	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			derr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
					nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
					if !ok {
						return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, node.NumericalID)
					if node.Name != "" {
						nodesV3.PrivateNodeByName[node.Name] = node.NumericalID
					}
					if node.ID != "" {
						nodesV3.PrivateNodeByID[node.ID] = node.NumericalID
					}
					nodesV3.ByNumericalID[node.NumericalID] = node
					return nil
				})
			})
			if derr != nil {
				logrus.Errorf("failed to restore node ownership in cluster")
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to restore node ownership in cluster metadata", actionFromError(xerr)))
			}
		}
	}()

	// Deletes node
	return instance.Alter(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		hostInstance, xerr := LoadHost(instance.GetService(), nodeRef)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		// Leave node from cluster, if master is not null
		if !master.isNull() {
			if innerXErr := instance.leaveNodesFromList([]resources.Host{hostInstance}, master); innerXErr != nil {
				return innerXErr
			}
			if instance.makers.UnconfigureNode != nil {
				if innerXErr := instance.makers.UnconfigureNode(instance, hostInstance, master); innerXErr != nil {
					return innerXErr
				}
			}
		}

		// Finally delete host
		if innerXErr := hostInstance.Delete(ctx); innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				// host seems already deleted, so it's a success
			default:
				return innerXErr
			}
		}
		return nil
	})
}

// Delete deletes the cluster
func (instance *cluster) Delete(ctx context.Context, force bool) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	if !force {
		xerr = instance.beingRemoved()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.delete(ctx)
}

// delete does the work to delete cluster
func (instance *cluster) delete(ctx context.Context) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	var cleaningErrors []error

	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			derr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
					stateV1, ok := clonable.(*propertiesv1.ClusterState)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					stateV1.State = clusterstate.Degraded
					return nil
				})
			})
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to set cluster state to DEGRADED", actionFromError(xerr)))
			}
		}
	}()

	var (
		all            map[uint]*propertiesv3.ClusterNode
		nodes, masters []uint
	)
	// Mark the cluster as Removed and get nodes from properties
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		// Updates cluster state to mark cluster as Removing
		innerXErr := props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			stateV1.State = clusterstate.Removed
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			nodes = nodesV3.PrivateNodes
			masters = nodesV3.Masters
			all = nodesV3.ByNumericalID
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Note: we are not using a TaskGroup here because we need to filter ErrNotFound for each Host (a missing Host is considered a successful deletion)
	// TaskGroup, as currently designed, does not allow that
	masterCount, nodeCount := len(masters), len(nodes)
	//	subtasks := make([]concurrency.Task, 0, masterCount+nodeCount)
	tg, xerr := concurrency.NewTaskGroupWithParent(task)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	options := []data.ImmutableKeyValue{
		data.NewImmutableKeyValue("normalizeError", func(err error) error {
			err = debug.InjectPlannedError(err)
			if err != nil {
				switch err.(type) {
				case *fail.ErrNotFound:
					return nil
				default:
				}
			}
			return err
		}),
	}

	if nodeCount > 0 {
		for _, v := range nodes {
			if task.Aborted() {
				return fail.AbortedError(nil, "aborted")
			}

			if n, ok := all[v]; ok {
				// subtask, xerr := task.StartInSubtask(instance.taskDeleteNode, taskDeleteNodeParameters{node: n})
				_, xerr = tg.Start(instance.taskDeleteNode, taskDeleteNodeParameters{node: n}, options...)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					cleaningErrors = append(cleaningErrors, fail.Wrap(xerr, "failed to start deletion of Host '%s'", n.Name))
					break
				}
				// subtasks = append(subtasks, subtask)
			}
		}
	}
	if masterCount > 0 {
		for _, v := range masters {
			if task.Aborted() {
				return fail.AbortedError(nil, "aborted")
			}

			if n, ok := all[v]; ok {
				// subtask, xerr := task.StartInSubtask(instance.taskDeleteMaster, taskDeleteNodeParameters{node: n})
				_, xerr := tg.Start(instance.taskDeleteMaster, taskDeleteNodeParameters{node: n}, options...)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					cleaningErrors = append(cleaningErrors, fail.Wrap(xerr, "failed to start deletion of Host '%s'", n.Name))
					break
				}
				// subtasks = append(subtasks, subtask)
			}
		}
	}
	_, xerr = tg.WaitGroup()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		cleaningErrors = append(cleaningErrors, xerr)
	}

	if len(cleaningErrors) > 0 {
		return fail.Wrap(fail.NewErrorList(cleaningErrors), "failed to delete Hosts")
	}

	// From here, make sure there is nothing in nodesV3.ByNumericalID; if there is something, delete all the remaining
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			all = nodesV3.ByNumericalID
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	allCount := len(all)
	tg, xerr = concurrency.NewTaskGroupWithParent(task)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if allCount > 0 {
		for _, v := range all {
			if task.Aborted() {
				return fail.AbortedError(nil, "aborted")
			}

			_, xerr = task.StartInSubtask(instance.taskDeleteNode, taskDeleteNodeParameters{node: v})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				cleaningErrors = append(cleaningErrors, fail.Wrap(xerr, "failed to start deletion of Host '%s'", v.Name))
				break
			}
		}
	}

	_, xerr = tg.WaitGroup()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		cleaningErrors = append(cleaningErrors, xerr)
	}
	if len(cleaningErrors) > 0 {
		return fail.Wrap(fail.NewErrorList(cleaningErrors), "failed to delete Hosts")
	}

	// --- Deletes the Network, Subnet and gateway ---
	rn, deleteNetwork, rs, xerr := instance.extractNetworkingInfo(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	if rs != nil {
		subnetName := rs.GetName()
		logrus.Debugf("Cluster Deleting Subnet '%s'", subnetName)
		xerr = retry.WhileUnsuccessfulDelay5SecondsTimeout(
			func() error {
				if innerXErr := rs.Delete(ctx); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotAvailable:
						return retry.StopRetryError(innerXErr)
					case *fail.ErrNotFound:
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			temporal.GetHostTimeout(),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrTimeout:
				xerr = fail.ConvertError(xerr.Cause())
			case *fail.ErrAborted:
				xerr = fail.ConvertError(xerr.Cause())
			}
		}
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// Subnet not found, consider as a successful deletion and continue
			default:
				return fail.Wrap(xerr, "failed to delete Subnet '%s'", subnetName)
			}
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	if rn != nil && deleteNetwork {
		networkName := rn.GetName()
		logrus.Debugf("Deleting Network '%s'...", networkName)
		xerr = retry.WhileUnsuccessfulDelay5SecondsTimeout(
			func() error {
				if innerXErr := rn.Delete(ctx); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound:
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			temporal.GetHostTimeout(),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrTimeout:
				xerr = fail.ConvertError(xerr.Cause())
			case *fail.ErrAborted:
				xerr = fail.ConvertError(xerr.Cause())
			}
		}
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// network not found, consider as a successful deletion and continue
			default:
				logrus.Errorf("Failed to delete Network '%s'", networkName)
				return fail.Wrap(xerr, "failed to delete Network '%s'", networkName)
			}
		}
		logrus.Infof("Network '%s' successfully deleted.", networkName)
	}

	// --- Delete metadata ---
	return instance.core.delete()
}

// extractNetworkingInfo returns the ID of the network from properties, taking care of ascending compatibility
func (instance *cluster) extractNetworkingInfo(ctx context.Context) (network resources.Network, deleteNetwork bool, subnet resources.Subnet, xerr fail.Error) {
	network, subnet = nil, nil
	deleteNetwork = false
	xerr = instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		return props.Inspect(clusterproperty.NetworkV3, func(clonable data.Clonable) (innerXErr fail.Error) {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if networkV3.SubnetID != "" {
				if subnet, innerXErr = LoadSubnet( /*ctx,*/ instance.GetService(), networkV3.NetworkID, networkV3.SubnetID); innerXErr != nil {
					return innerXErr
				}
			}

			if networkV3.NetworkID != "" {
				network, innerXErr = LoadNetwork(instance.GetService(), networkV3.NetworkID)
				if innerXErr != nil {
					return innerXErr
				}
				deleteNetwork = networkV3.CreatedNetwork
			}
			if networkV3.SubnetID != "" {
				subnet, innerXErr = LoadSubnet(instance.GetService(), networkV3.NetworkID, networkV3.SubnetID)
				if innerXErr != nil {
					return innerXErr
				}
				if network == nil {
					network, innerXErr = subnet.InspectNetwork()
					if innerXErr != nil {
						return innerXErr
					}
				}
				deleteNetwork = networkV3.CreatedNetwork
			}

			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nullNetwork(), deleteNetwork, nullSubnet(), xerr
	}

	return network, deleteNetwork, subnet, nil
}

func containsClusterNode(list []uint, numericalID uint) (bool, int) {
	var idx int
	found := false
	for i, v := range list {
		if v == numericalID {
			found = true
			idx = i
			break
		}
	}
	return found, idx
}

// configureCluster ...
// params contains a data.Map with primary and secondary getGateway hosts
func (instance *cluster) configureCluster(ctx context.Context) (xerr fail.Error) {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	logrus.Infof("[cluster %s] configuring cluster...", instance.GetName())
	defer func() {
		if xerr == nil {
			logrus.Infof("[cluster %s] configuration successful.", instance.GetName())
		} else {
			logrus.Errorf("[cluster %s] configuration failed: %s", instance.GetName(), xerr.Error())
		}
	}()

	// Install reverseproxy feature on cluster (gateways)
	xerr = instance.installReverseProxy(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Install remotedesktop feature on cluster (all masters)
	xerr = instance.installRemoteDesktop(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// configure what has to be done cluster-wide
	if instance.makers.ConfigureCluster != nil {
		return instance.makers.ConfigureCluster(ctx, instance)
	}

	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

func (instance *cluster) determineRequiredNodes() (uint, uint, uint, fail.Error) {
	if instance.makers.MinimumRequiredServers != nil {
		g, m, n, xerr := instance.makers.MinimumRequiredServers(func() abstract.ClusterIdentity { out, _ := instance.unsafeGetIdentity(); return out }())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return 0, 0, 0, xerr
		}

		return g, m, n, nil
	}
	return 0, 0, 0, nil
}

// realizeTemplate generates a file from box template with variables updated
func realizeTemplate(box *rice.Box, tmplName string, data map[string]interface{}, fileName string) (string, string, fail.Error) {
	if box == nil {
		return "", "", fail.InvalidParameterError("box", "cannot be nil!")
	}

	tmplString, err := box.String(tmplName)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", "", fail.Wrap(err, "failed to load template")
	}

	tmplCmd, err := template.Parse(fileName, tmplString)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", "", fail.Wrap(err, "failed to parse template")
	}

	dataBuffer := bytes.NewBufferString("")
	err = tmplCmd.Execute(dataBuffer, data)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", "", fail.Wrap(err, "failed to execute  template")
	}

	cmd := dataBuffer.String()
	remotePath := utils.TempFolder + "/" + fileName

	return cmd, remotePath, nil
}

// configureNodesFromList configures nodes from a list
func (instance *cluster) configureNodesFromList(task concurrency.Task, hosts []resources.Host) (xerr fail.Error) {
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	var (
		hostID string
		errs   []error
	)

	var subtasks []concurrency.Task
	length := len(hosts)
	for i := 0; i < length; i++ {
		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		subtask, err := task.StartInSubtask(instance.taskConfigureNode, taskConfigureNodeParameters{
			Index: uint(i + 1),
			Host:  hosts[i],
		})
		err = debug.InjectPlannedFail(err)
		if err != nil {
			xerr = err
			break
		}
		subtasks = append(subtasks, subtask)
	}
	// Deals with the metadata read failure
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		errs = append(errs, fail.Wrap(xerr, "failed to get metadata of Host '%s'", hostID))
	}

	for _, s := range subtasks {
		_, state := s.Wait()
		if state != nil {
			errs = append(errs, state)
		}
	}
	if len(errs) > 0 {
		return fail.NewErrorList(errs)
	}
	return nil
}

// joinNodesFromList makes nodes from a list join the cluster
func (instance *cluster) joinNodesFromList(ctx context.Context, hosts []resources.Host) fail.Error {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	if instance.makers.JoinNodeToCluster == nil {
		// configure what has to be done cluster-wide
		if instance.makers.ConfigureCluster != nil {
			return instance.makers.ConfigureCluster(ctx, instance)
		}
	}

	logrus.Debugf("Joining nodes to cluster...")

	// Joins to cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	if instance.makers.JoinMasterToCluster != nil {
		for _, host := range hosts {
			xerr = instance.makers.JoinNodeToCluster(instance, host)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}

	return nil
}

// leaveNodesFromList makes nodes from a list leave the cluster
func (instance *cluster) leaveNodesFromList(hosts []resources.Host, master resources.Host) (xerr fail.Error) {
	logrus.Debugf("Instructing nodes to leave cluster...")

	// Unjoins from cluster are done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, rh := range hosts {
		if instance.makers.LeaveNodeFromCluster != nil {
			xerr = instance.makers.LeaveNodeFromCluster(instance, rh, master)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}

	return nil
}

// BuildHostname builds a unique hostname in the Cluster
func (instance *cluster) buildHostname(core string, nodeType clusternodetype.Enum) (_ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	var index int
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			switch nodeType {
			case clusternodetype.Node:
				nodesV3.PrivateLastIndex++
				index = nodesV3.PrivateLastIndex
			case clusternodetype.Master:
				nodesV3.MasterLastIndex++
				index = nodesV3.MasterLastIndex
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}
	return instance.GetName() + "-" + core + "-" + strconv.Itoa(index), nil
}

func (instance *cluster) deleteHosts(task concurrency.Task, hosts []resources.Host) fail.Error {
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tg, xerr := concurrency.NewTaskGroupWithParent(task)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	errors := make([]error, 0, len(hosts)+1)
	for _, h := range hosts {
		_, xerr = tg.StartInSubtask(instance.taskDeleteHostOnFailure, taskDeleteHostOnFailureParameters{host: h.(*host)})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			errors = append(errors, xerr)
		}
	}
	_, xerr = tg.WaitGroup()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		errors = append(errors, xerr)
	}
	return fail.NewErrorList(errors)
}

// ToProtocol converts instance to protocol.ClusterResponse message
func (instance *cluster) ToProtocol() (_ *protocol.ClusterResponse, xerr fail.Error) {
	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.ClusterResponse{}
	xerr = instance.Inspect(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		ci, ok := clonable.(*abstract.ClusterIdentity)
		if !ok {
			return fail.InconsistentError("'*abstract.ClusterIdentity' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		out.Identity = converters.ClusterIdentityFromAbstractToProtocol(*ci)

		innerXErr := props.Inspect(clusterproperty.ControlPlaneV1, func(clonable data.Clonable) fail.Error {
			controlplaneV1, ok := clonable.(*propertiesv1.ClusterControlplane)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterControlplane' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			out.Controlplane = converters.ClusterControlplaneFromPropertyToProtocol(*controlplaneV1)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = props.Inspect(clusterproperty.CompositeV1, func(clonable data.Clonable) fail.Error {
			compositeV1, ok := clonable.(*propertiesv1.ClusterComposite)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterComposite' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			out.Composite = converters.ClusterCompositeFromPropertyToProtocol(*compositeV1)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = props.Inspect(clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
			defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			out.Defaults = converters.ClusterDefaultsFromPropertyToProtocol(*defaultsV2)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = props.Inspect(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			out.Network = converters.ClusterNetworkFromPropertyToProtocol(*networkV3)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			convertClusterNodes := func(in []uint) []*protocol.Host {
				list := make([]*protocol.Host, 0, len(in))
				for _, v := range in {
					if node, found := nodesV3.ByNumericalID[v]; found {
						ph := &protocol.Host{
							Name:      node.Name,
							Id:        node.ID,
							PublicIp:  node.PublicIP,
							PrivateIp: node.PrivateIP,
						}
						list = append(list, ph)
					}
				}
				return list
			}

			out.Nodes = convertClusterNodes(nodesV3.PrivateNodes)
			out.Masters = convertClusterNodes(nodesV3.Masters)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			out.InstalledFeatures, out.DisabledFeatures = converters.ClusterFeaturesFromPropertyToProtocol(*featuresV1)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		return props.Inspect(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			out.State = protocol.ClusterState(stateV1.State)
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	return out, nil
}

func (instance *cluster) Shrink(ctx context.Context, count uint) (_ []*propertiesv3.ClusterNode, xerr fail.Error) {
	emptySlice := make([]*propertiesv3.ClusterNode, 0)
	if instance.isNull() {
		return emptySlice, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptySlice, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if count == 0 {
		return emptySlice, fail.InvalidParameterError("count", "cannot be 0")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptySlice, xerr
	}

	if task.Aborted() {
		return emptySlice, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptySlice, xerr
	}

	tg, xerr := concurrency.NewTaskGroup(task)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptySlice, xerr
	}

	var (
		removedNodes []*propertiesv3.ClusterNode
		errors       []error
		toRemove     []uint
	)
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) (innerXErr fail.Error) {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			length := uint(len(nodesV3.PrivateNodes))
			if length < count {
				return fail.InvalidRequestError("cannot shrink by %d node%s, only %d node%s available", count, strprocess.Plural(count), length, strprocess.Plural(length))
			}

			first := length - count
			toRemove = nodesV3.PrivateNodes[first:]
			nodesV3.PrivateNodes = nodesV3.PrivateNodes[:first-1]
			for _, v := range toRemove {
				if node, ok := nodesV3.ByNumericalID[v]; ok {
					removedNodes = append(removedNodes, node)
					delete(nodesV3.ByNumericalID, v)
					delete(nodesV3.PrivateNodeByID, node.ID)
					delete(nodesV3.PrivateNodeByName, node.Name)
				}
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptySlice, nil
	}

	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			derr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) (innerXErr fail.Error) {
					nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
					if !ok {
						return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, toRemove...)
					for _, v := range removedNodes {
						nodesV3.ByNumericalID[v.NumericalID] = v
						nodesV3.PrivateNodeByName[v.Name] = v.NumericalID
						nodesV3.PrivateNodeByID[v.ID] = v.NumericalID
					}
					return nil
				})
			})
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to restore cluster nodes metadata", actionFromError(xerr)))
			}
		}
	}()

	for _, v := range removedNodes {
		_, xerr = tg.Start(instance.taskDeleteNode, taskDeleteNodeParameters{node: v, master: nil})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			errors = append(errors, xerr)
		}
	}
	_, xerr = tg.Wait()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		errors = append(errors, xerr)
	}
	if len(errors) > 0 {
		return emptySlice, fail.NewErrorList(errors)
	}

	return removedNodes, nil
}

// IsFeatureInstalled tells if a Feature identified by name is installed on Cluster, using only metadata
func (instance *cluster) IsFeatureInstalled(ctx context.Context, name string) (found bool, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	found = false
	if instance.isNull() {
		return false, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return false, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if name = strings.TrimSpace(name); name == "" {
		return false, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

	if task.Aborted() {
		return false, fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

	return found, instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("`propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			_, found = featuresV1.Installed[name]
			return nil
		})
	})
}
