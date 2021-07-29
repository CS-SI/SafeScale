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
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	clusterflavors2 "github.com/CS-SI/SafeScale/lib/server/resources/operations/clusterflavors"
	boh2 "github.com/CS-SI/SafeScale/lib/server/resources/operations/clusterflavors/boh"
	k8s2 "github.com/CS-SI/SafeScale/lib/server/resources/operations/clusterflavors/k8s"
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
type Cluster struct {
	*MetadataCore

	lock                sync.RWMutex
	installMethods      sync.Map // map[uint8]installmethod.Enum
	lastStateCollection time.Time
	makers              clusterflavors2.Makers
}

// VPL: not used
// // ClusterNullValue returns a *Cluster representing a null value
// func ClusterNullValue() *Cluster {
// 	return &Cluster{MetadataCore: NullCore()}
// }

// NewCluster ...
func NewCluster(svc iaas.Service) (_ resources.Cluster, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, xerr := NewCore(svc, clusterKind, clustersFolderName, &abstract.ClusterIdentity{})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &Cluster{
		MetadataCore: coreInstance,
	}
	return instance, nil
}

// LoadCluster ...
func LoadCluster(svc iaas.Service, name string) (rc resources.Cluster, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	clusterCache, xerr := svc.GetCache(clusterKind)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	options := []data.ImmutableKeyValue{
		data.NewImmutableKeyValue("onMiss", func() (cache.Cacheable, fail.Error) {
			rc, innerXErr := NewCluster(svc)
			if innerXErr != nil {
				return nil, innerXErr
			}

			// TODO: core.Read() does not check communication failure, side effect of limitations of Stow (waiting for stow replacement)
			if innerXErr = rc.Read(name); innerXErr != nil {
				return nil, innerXErr
			}

			// VPL: disabled silent metadata upgrade; will be implemented in a global one-pass migration
			// // deal with legacy
			// xerr = rc.(*cluster).updateClusterNodesPropertyIfNeeded()
			// xerr = debug.InjectPlannedFail(xerr)
			// if xerr != nil {
			// 	return nullCluster(), xerr
			// }
			//
			// xerr = rc.(*cluster).updateClusterNetworkPropertyIfNeeded()
			// xerr = debug.InjectPlannedFail(xerr)
			// if xerr != nil {
			// 	return nullCluster(), xerr
			// }
			//
			// xerr = rc.(*cluster).updateClusterDefaultsPropertyIfNeeded()
			// xerr = debug.InjectPlannedFail(xerr)
			// if xerr != nil {
			// 	return nullCluster(), xerr
			// }

			rc.(*Cluster).updateCachedInformation()

			return rc, nil
		}),
	}
	cacheEntry, xerr := clusterCache.Get(name, options...)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// rewrite NotFoundError, user does not bother about metadata stuff
			return nil, fail.NotFoundError("failed to find Cluster '%s'", name)
		default:
			return nil, xerr
		}
	}

	if rc = cacheEntry.Content().(resources.Cluster); rc == nil {
		return nil, fail.InconsistentError("nil value found in Cluster cache for key '%s'", name)
	}
	_ = cacheEntry.LockContent()

	return rc, nil
}

// VPL: disabled silent metadata upgrade; will be implemented in a global one-pass migration
// // updateClusterNodesPropertyIfNeeded upgrades current Nodes property to last Nodes property (currently NodesV2)
// func (instance *cluster) updateClusterNodesPropertyIfNeeded() fail.Error {
// 	if instance.isNull() {
// 		return fail.InvalidInstanceError()
// 	}
// 	xerr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
// 		if props.Lookup(clusterproperty.NodesV3) {
// 			return nil
// 		}
//
// 		if props.Lookup(clusterproperty.NodesV2) {
// 			var (
// 				nodesV2 *propertiesv2.ClusterNodes
// 				ok      bool
// 			)
// 			innerXErr := props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
// 				nodesV2, ok = clonable.(*propertiesv2.ClusterNodes)
// 				if !ok {
// 					return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
// 				}
// 				return nil
// 			})
// 			if innerXErr != nil {
// 				return innerXErr
// 			}
//
// 			return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
// 				nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
// 				if !ok {
// 					return fail.InconsistentError("'*propertiesv3.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
// 				}
//
// 				for _, i := range nodesV2.Masters {
// 					nodesV3.GlobalLastIndex++
//
// 					node := &propertiesv3.ClusterNode{
// 						ID:          i.ID,
// 						NumericalID: nodesV3.GlobalLastIndex,
// 						Name:        i.Name,
// 						PrivateIP:   i.PrivateIP,
// 						PublicIP:    i.PublicIP,
// 					}
// 					nodesV3.Masters = append(nodesV3.Masters, nodesV3.GlobalLastIndex)
// 					nodesV3.ByNumericalID[nodesV3.GlobalLastIndex] = node
// 				}
// 				for _, i := range nodesV2.PrivateNodes {
// 					nodesV3.GlobalLastIndex++
//
// 					node := &propertiesv3.ClusterNode{
// 						ID:          i.ID,
// 						NumericalID: nodesV3.GlobalLastIndex,
// 						Name:        i.Name,
// 						PrivateIP:   i.PrivateIP,
// 						PublicIP:    i.PublicIP,
// 					}
// 					nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, nodesV3.GlobalLastIndex)
// 					nodesV3.ByNumericalID[nodesV3.GlobalLastIndex] = node
// 				}
// 				nodesV3.MasterLastIndex = nodesV2.MasterLastIndex
// 				nodesV3.PrivateLastIndex = nodesV2.PrivateLastIndex
// 				return nil
// 			})
// 		}
//
// 		if props.Lookup(clusterproperty.NodesV1) {
// 			var (
// 				nodesV1 *propertiesv1.ClusterNodes
// 				ok      bool
// 			)
//
// 			innerXErr := props.Inspect(clusterproperty.NodesV1, func(clonable data.Clonable) fail.Error {
// 				nodesV1, ok = clonable.(*propertiesv1.ClusterNodes)
// 				if !ok {
// 					return fail.InconsistentError("'*propertiesv1.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
// 				}
// 				return nil
// 			})
// 			if innerXErr != nil {
// 				return innerXErr
// 			}
//
// 			return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
// 				nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
// 				if !ok {
// 					return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
// 				}
//
// 				for _, i := range nodesV1.Masters {
// 					nodesV3.GlobalLastIndex++
//
// 					node := &propertiesv3.ClusterNode{
// 						ID:          i.ID,
// 						NumericalID: nodesV3.GlobalLastIndex,
// 						Name:        i.Name,
// 						PrivateIP:   i.PrivateIP,
// 						PublicIP:    i.PublicIP,
// 					}
// 					nodesV3.Masters = append(nodesV3.Masters, node.NumericalID)
// 					nodesV3.ByNumericalID[node.NumericalID] = node
// 				}
// 				for _, i := range nodesV1.PrivateNodes {
// 					nodesV3.GlobalLastIndex++
//
// 					node := &propertiesv3.ClusterNode{
// 						ID:          i.ID,
// 						NumericalID: nodesV3.GlobalLastIndex,
// 						Name:        i.Name,
// 						PrivateIP:   i.PrivateIP,
// 						PublicIP:    i.PublicIP,
// 					}
// 					nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, node.NumericalID)
// 					nodesV3.ByNumericalID[node.NumericalID] = node
// 				}
// 				nodesV3.MasterLastIndex = nodesV1.MasterLastIndex
// 				nodesV3.PrivateLastIndex = nodesV1.PrivateLastIndex
// 				return nil
// 			})
// 		}
//
// 		// Returning explicitly this error tells Alter not to try to commit changes, there are none
// 		return fail.AlteredNothingError()
// 	})
// 	xerr = debug.InjectPlannedFail(xerr)
// 	return xerr
// }
//
// // updateClusterNetworkPropertyIfNeeded creates a clusterproperty.NetworkV3 property if previous versions are found
// func (instance *cluster) updateClusterNetworkPropertyIfNeeded() fail.Error {
// 	if instance.isNull() {
// 		return fail.InvalidInstanceError()
// 	}
// 	xerr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
// 		if props.Lookup(clusterproperty.NetworkV3) {
// 			return fail.AlteredNothingError()
// 		}
//
// 		var (
// 			config *propertiesv3.ClusterNetwork
// 			update bool
// 		)
//
// 		if props.Lookup(clusterproperty.NetworkV2) {
// 			// Having a clusterproperty.NetworkV2, need to update instance with clusterproperty.NetworkV3
// 			innerXErr = props.Inspect(clusterproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
// 				networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
// 				if !ok {
// 					return fail.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
// 				}
//
// 				// In v2, NetworkID actually contains the subnet ID; we do not need ID of the Network owning the Subnet in
// 				// the property, meaning that Network would have to be deleted also on cluster deletion because Network
// 				// AND Subnet were created forcibly at cluster creation.
// 				config = &propertiesv3.ClusterNetwork{
// 					NetworkID:          "",
// 					SubnetID:           networkV2.NetworkID,
// 					CIDR:               networkV2.CIDR,
// 					GatewayID:          networkV2.GatewayID,
// 					GatewayIP:          networkV2.GatewayIP,
// 					SecondaryGatewayID: networkV2.SecondaryGatewayID,
// 					SecondaryGatewayIP: networkV2.SecondaryGatewayIP,
// 					PrimaryPublicIP:    networkV2.PrimaryPublicIP,
// 					SecondaryPublicIP:  networkV2.SecondaryPublicIP,
// 					DefaultRouteIP:     networkV2.DefaultRouteIP,
// 					EndpointIP:         networkV2.EndpointIP,
// 					Domain:             networkV2.Domain,
// 				}
// 				update = true
// 				return nil
// 			})
// 		} else {
// 			// Having a clusterproperty.NetworkV1, need to update instance with clusterproperty.NetworkV3
// 			innerXErr = props.Inspect(clusterproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
// 				networkV1, ok := clonable.(*propertiesv1.ClusterNetwork)
// 				if !ok {
// 					return fail.InconsistentError()
// 				}
//
// 				config = &propertiesv3.ClusterNetwork{
// 					SubnetID:       networkV1.NetworkID,
// 					CIDR:           networkV1.CIDR,
// 					GatewayID:      networkV1.GatewayID,
// 					GatewayIP:      networkV1.GatewayIP,
// 					DefaultRouteIP: networkV1.GatewayIP,
// 					EndpointIP:     networkV1.PublicIP,
// 				}
// 				update = true
// 				return nil
// 			})
// 		}
// 		if innerXErr != nil {
// 			return innerXErr
// 		}
//
// 		if update {
// 			return props.Alter(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
// 				networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
// 				if !ok {
// 					return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
// 				}
// 				networkV3.Replace(config)
// 				return nil
// 			})
// 		}
// 		return nil
// 	})
// 	xerr = debug.InjectPlannedFail(xerr)
// 	if xerr != nil {
// 		switch xerr.(type) { //nolint
// 		case *fail.ErrAlteredNothing:
// 			xerr = nil
// 		}
// 	}
// 	return xerr
// }
//
// // updateClusterDefaultsPropertyIfNeeded ...
// func (instance *cluster) updateClusterDefaultsPropertyIfNeeded() fail.Error {
// 	if instance.isNull() {
// 		return fail.InvalidInstanceError()
// 	}
// 	xerr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
// 		if props.Lookup(clusterproperty.DefaultsV2) {
// 			return fail.AlteredNothingError()
// 		}
//
// 		// If property.DefaultsV2 is not found but there is a property.DefaultsV1, converts it to DefaultsV2
// 		return props.Inspect(clusterproperty.DefaultsV1, func(clonable data.Clonable) fail.Error {
// 			defaultsV1, ok := clonable.(*propertiesv1.ClusterDefaults)
// 			if !ok {
// 				return fail.InconsistentError("'*propertiesv1.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
// 			}
// 			return props.Alter(clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
// 				defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
// 				if !ok {
// 					return fail.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
// 				}
//
// 				convertDefaultsV1ToDefaultsV2(defaultsV1, defaultsV2)
// 				return nil
// 			})
// 		})
// 	})
// 	xerr = debug.InjectPlannedFail(xerr)
// 	if xerr != nil {
// 		switch xerr.(type) {
// 		case *fail.ErrAlteredNothing:
// 			xerr = nil
// 		default:
// 		}
// 	}
// 	return xerr
// }

// updateCachedInformation updates information cached in the instance
func (instance *Cluster) updateCachedInformation() {
	var index uint8
	flavor, err := instance.UnsafeGetFlavor()
	if err == nil && flavor == clusterflavor.K8S {
		index++
		instance.installMethods.Store(index, installmethod.Helm)
	}

	index++
	instance.installMethods.Store(index, installmethod.Bash)
	index++
	instance.installMethods.Store(index, installmethod.None)
}

// VPL: not used
// // convertDefaultsV1ToDefaultsV2 converts propertiesv1.ClusterDefaults to propertiesv2.ClusterDefaults
// func convertClusterDefaultsV1ToDefaultsV2(defaultsV1 *propertiesv1.ClusterDefaults, defaultsV2 *propertiesv2.ClusterDefaults) {
// 	defaultsV2.Image = defaultsV1.Image
// 	defaultsV2.GatewaySizing = propertiesv2.HostSizingRequirements{
// 		MinCores:    defaultsV1.GatewaySizing.Cores,
// 		MinCPUFreq:  defaultsV1.GatewaySizing.CPUFreq,
// 		MinGPU:      defaultsV1.GatewaySizing.GPUNumber,
// 		MinRAMSize:  defaultsV1.GatewaySizing.RAMSize,
// 		MinDiskSize: defaultsV1.GatewaySizing.DiskSize,
// 		Replaceable: defaultsV1.GatewaySizing.Replaceable,
// 	}
// 	defaultsV2.MasterSizing = propertiesv2.HostSizingRequirements{
// 		MinCores:    defaultsV1.MasterSizing.Cores,
// 		MinCPUFreq:  defaultsV1.MasterSizing.CPUFreq,
// 		MinGPU:      defaultsV1.MasterSizing.GPUNumber,
// 		MinRAMSize:  defaultsV1.MasterSizing.RAMSize,
// 		MinDiskSize: defaultsV1.MasterSizing.DiskSize,
// 		Replaceable: defaultsV1.MasterSizing.Replaceable,
// 	}
// 	defaultsV2.NodeSizing = propertiesv2.HostSizingRequirements{
// 		MinCores:    defaultsV1.NodeSizing.Cores,
// 		MinCPUFreq:  defaultsV1.NodeSizing.CPUFreq,
// 		MinGPU:      defaultsV1.NodeSizing.GPUNumber,
// 		MinRAMSize:  defaultsV1.NodeSizing.RAMSize,
// 		MinDiskSize: defaultsV1.NodeSizing.DiskSize,
// 		Replaceable: defaultsV1.NodeSizing.Replaceable,
// 	}
// }

// IsNull tells if the instance should be considered as a null value
func (instance *Cluster) IsNull() bool {
	return instance == nil || instance.MetadataCore == nil || instance.MetadataCore.IsNull()
}

// carry ...
func (instance *Cluster) carry(clonable data.Clonable) (xerr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !instance.IsNull() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}
	identifiable, ok := clonable.(data.Identifiable)
	if !ok {
		return fail.InvalidParameterError("clonable", "must also satisfy interface 'data.Identifiable'")
	}

	kindCache, xerr := instance.GetService().GetCache(instance.MetadataCore.GetKind())
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
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free %s cache entry for key '%s'", instance.MetadataCore.GetKind(), identifiable.GetID()))
			}

		}
	}()

	// Note: do not validate parameters, this call will do it
	xerr = instance.MetadataCore.Carry(clonable)
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
func (instance *Cluster) Create(ctx context.Context, req abstract.ClusterRequest) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !instance.IsNull() {
		clusterName := instance.GetName()
		if clusterName != "" {
			return fail.NotAvailableError("already carrying Cluster '%s'", clusterName)
		}
		return fail.InvalidInstanceContentError("instance", "is not null value")
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()
	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting creation of infrastructure of Cluster '%s'...", req.Name),
		fmt.Sprintf("Ending creation of infrastructure of Cluster '%s'", req.Name),
	)()

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	_, xerr = task.Run(instance.taskCreateCluster, req)
	if xerr != nil {
		return xerr
	}
	return nil
}

// Serialize converts Cluster data to JSON
func (instance *Cluster) Serialize() (_ []byte, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return []byte{}, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	r, err := json.Marshal(instance) // nolint
	return r, fail.ConvertError(err)
}

// Deserialize reads json code and reinstantiates Cluster
func (instance *Cluster) Deserialize(buf []byte) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
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
func (instance *Cluster) bootstrap(flavor clusterflavor.Enum) (xerr fail.Error) {
	switch flavor {
	case clusterflavor.BOH:
		instance.makers = boh2.Makers
	case clusterflavor.K8S:
		instance.makers = k8s2.Makers
	default:
		return fail.NotImplementedError("unknown Cluster Flavor '%d'", flavor)
	}
	return nil
}

// Browse walks through Cluster MetadataFolder and executes a callback for each entry
// FIXME: adds a Cluster status check to prevent operations on removed clusters
func (instance *Cluster) Browse(ctx context.Context, callback func(*abstract.ClusterIdentity) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: Browse is intended to be callable from null value, so do not validate instance with .IsNull()
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	return instance.MetadataCore.BrowseFolder(func(buf []byte) fail.Error {
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

// GetIdentity returns the identity of the Cluster
func (instance *Cluster) GetIdentity() (clusterIdentity abstract.ClusterIdentity, xerr fail.Error) {
	if instance == nil || instance.IsNull() {
		return abstract.ClusterIdentity{}, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.unsafeGetIdentity()
}

// GetFlavor returns the flavor of the Cluster
func (instance *Cluster) GetFlavor() (flavor clusterflavor.Enum, xerr fail.Error) {
	if instance == nil || instance.IsNull() {
		return 0, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.UnsafeGetFlavor()
}

// GetComplexity returns the complexity of the Cluster
func (instance *Cluster) GetComplexity() (_ clustercomplexity.Enum, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return 0, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	return instance.unsafeGetComplexity()
}

// GetAdminPassword returns the password of the Cluster admin account
// satisfies interface Cluster.Controller
func (instance *Cluster) GetAdminPassword() (adminPassword string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
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

// GetKeyPair returns the key pair used in the Cluster
func (instance *Cluster) GetKeyPair() (keyPair abstract.KeyPair, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	nullAKP := abstract.KeyPair{}
	if instance == nil || instance.IsNull() {
		return nullAKP, fail.InvalidInstanceError()
	}

	aci, xerr := instance.GetIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nullAKP, xerr
	}

	return *(aci.Keypair), nil
}

// GetNetworkConfig returns subnet configuration of the Cluster
func (instance *Cluster) GetNetworkConfig() (config *propertiesv3.ClusterNetwork, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	nullConfig := &propertiesv3.ClusterNetwork{}
	if instance == nil || instance.IsNull() {
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

// Start starts the Cluster
func (instance *Cluster) Start(ctx context.Context) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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

	// If the Cluster is in state Stopping or Stopped, do nothing
	var prevState clusterstate.Enum
	prevState, xerr = instance.unsafeGetState()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	switch prevState {
	case clusterstate.Removed:
		return fail.NotAvailableError("Cluster is being removed")
	case clusterstate.Stopping:
		return nil
	case clusterstate.Starting:
		// If the Cluster is in state Starting, wait for it to finish its start procedure
		xerr = retry.WhileUnsuccessfulDelay5Seconds(
			func() error {
				state, innerErr := instance.unsafeGetState()
				if innerErr != nil {
					return innerErr
				}

				if state == clusterstate.Nominal || state == clusterstate.Degraded {
					return nil
				}

				return fail.NewError("current state of Cluster is '%s'", state.String())
			},
			5*time.Minute, // FIXME: hardcoded timeout
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if _, ok := xerr.(*retry.ErrTimeout); ok {
				xerr = fail.Wrap(xerr, "timeout waiting Cluster to become started")
			}
			return xerr
		}
		return nil
	case clusterstate.Stopped:
		// continue
	default:
		return fail.NotAvailableError("failed to start Cluster because of it's current state: %s", prevState.String())
	}

	// First mark Cluster to be in state Starting
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

		// Mark Cluster as state Starting
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
	taskGroup, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
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

// Stop stops the Cluster
func (instance *Cluster) Stop(ctx context.Context) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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

	// If the Cluster is stopped, do nothing
	var prevState clusterstate.Enum
	prevState, xerr = instance.unsafeGetState()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	switch prevState {
	case clusterstate.Removed:
		return fail.NotAvailableError("Cluster is being removed")
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
					return retry.StopRetryError(fail.NotAvailableError("Cluster is being removed"))
				}

				if state != clusterstate.Stopped {
					return fail.NotAvailableError("current state of Cluster is '%s'", state.String())
				}

				return nil
			},
			5*time.Minute, // FIXME: hardcoded timeout
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrTimeout:
				xerr = fail.Wrap(xerr, "timeout waiting Cluster transitioning from state Stopping to Stopped")
			case *retry.ErrStopRetry:
				xerr = fail.ConvertError(xerr.Cause())
			}
		}
		return xerr
	case clusterstate.Nominal, clusterstate.Degraded:
		// continue
	default:
		// If the Cluster is not in state Nominal or Degraded, can't stop
		return fail.NotAvailableError("failed to stop Cluster because of it's current state: %s", prevState.String())
	}

	// First mark Cluster to be in state Stopping
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
		taskGroup, innerXErr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
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
func (instance *Cluster) GetState() (state clusterstate.Enum, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	state = clusterstate.Unknown
	if instance == nil || instance.IsNull() {
		return state, fail.InvalidInstanceError()
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.unsafeGetState()
}

// AddNode adds a node
func (instance *Cluster) AddNode(ctx context.Context, def abstract.HostSizingRequirements, keepOnFailure bool) (_ resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return HostNullValue(), fail.InvalidInstanceError()
	}
	if ctx == nil {
		return HostNullValue(), fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return HostNullValue(), xerr
	}

	if task.Aborted() {
		return HostNullValue(), fail.AbortedError(nil, "aborted")
	}

	nodes, xerr := instance.AddNodes(ctx, 1, def, keepOnFailure)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return HostNullValue(), xerr
	}

	return nodes[0], nil
}

// AddNodes adds several nodes
func (instance *Cluster) AddNodes(ctx context.Context, count uint, def abstract.HostSizingRequirements, keepOnFailure bool) (_ []resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
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
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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
		nodeDefaultDefinition *propertiesv2.HostSizingRequirements
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

	svc := instance.GetService()
	_, nodeDef.Image, xerr = determineImageID(svc, hostImage)
	if xerr != nil {
		return nil, xerr
	}

	var (
		errors []string
		nodes  []*propertiesv3.ClusterNode
	)

	timeout := temporal.GetExecutionTimeout() + time.Duration(count)*time.Minute

	tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/%d", count)))
	if xerr != nil {
		return nil, xerr
	}

	for i := uint(1); i <= count; i++ {
		_, xerr := tg.Start(instance.taskCreateNode, taskCreateNodeParameters{
			index:         i,
			nodeDef:       nodeDef,
			timeout:       timeout,
			keepOnFailure: keepOnFailure,
		}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%d/create", i)))
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
	}

	res, xerr := tg.WaitGroup()
	if res != nil {
		for _, v := range res {
			if item, ok := v.(*propertiesv3.ClusterNode); ok {
				nodes = append(nodes, item)
			}
		}
	}

	// Starting from here, if exiting with error, delete created nodes if allowed (cf. keepOnFailure)
	defer func() {
		if xerr != nil && !keepOnFailure && len(nodes) > 0 {
			// Note: using context.Background() disable cancellation mecanism for a workload that needs to go to the end
			tg, derr := concurrency.NewTaskGroupWithContext(context.Background())
			if derr != nil {
				_ = xerr.AddConsequence(derr)
			}
			derr = tg.SetID("/onfailure")
			if derr != nil {
				_ = xerr.AddConsequence(derr)
			}

			for _, v := range nodes {
				_, derr = tg.Start(instance.taskDeleteNodeOnFailure, taskDeleteNodeOnFailureParameters{node: v})
				if derr != nil {
					_ = xerr.AddConsequence(derr)
				}
			}
			_, derr = tg.WaitGroup()
			if derr != nil {
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.NewErrorWithCause(xerr, "errors occurred on node%s addition", strprocess.Plural(uint(len(errors))))
	}

	// configure what has to be done Cluster-wide
	if instance.makers.ConfigureCluster != nil {
		xerr = instance.makers.ConfigureCluster(ctx, instance)
		if xerr != nil {
			return nil, xerr
		}
	}

	// Now configure new nodes
	xerr = instance.configureNodesFromList(task, nodes)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// At last join nodes to Cluster
	xerr = instance.joinNodesFromList(ctx, nodes)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	hosts := make([]resources.Host, 0, len(nodes))
	for _, v := range nodes {
		hostInstance, xerr := LoadHost(instance.GetService(), v.ID)
		if xerr != nil {
			return nil, xerr
		}
		hosts = append(hosts, hostInstance)
	}
	return hosts, nil
}

// complementHostDefinition complements req with default values if needed
func complementHostDefinition(req abstract.HostSizingRequirements, def propertiesv2.HostSizingRequirements) abstract.HostSizingRequirements {
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
func (instance *Cluster) DeleteLastNode(ctx context.Context) (node *propertiesv3.ClusterNode, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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

	// Removed reference of the node from Cluster
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

	selectedMaster, xerr := instance.UnsafeFindAvailableMaster(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	xerr = instance.deleteNode(ctx, node, selectedMaster.(*Host))
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return node, nil
}

// DeleteSpecificNode deletes a node identified by its ID
func (instance *Cluster) DeleteSpecificNode(ctx context.Context, hostID string, selectedMasterID string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
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
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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
		selectedMaster, xerr = instance.UnsafeFindAvailableMaster(ctx)
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

	return instance.deleteNode(ctx, node, selectedMaster.(*Host))
}

// ListMasters lists the node instances corresponding to masters (if there is such masters in the flavor...)
func (instance *Cluster) ListMasters(ctx context.Context) (list resources.IndexedListOfClusterNodes, xerr fail.Error) {
	emptyList := resources.IndexedListOfClusterNodes{}
	if instance == nil || instance.IsNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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

	return instance.UnsafeListMasters()
}

// ListMasterNames lists the names of the master nodes in the Cluster
func (instance *Cluster) ListMasterNames(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	if instance == nil || instance.IsNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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
func (instance *Cluster) ListMasterIDs(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	if instance == nil || instance.IsNull() {
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

func (instance *Cluster) unsafeListMasterIDs(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	emptyList := data.IndexedListOfStrings{}
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return emptyList, xerr
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
func (instance *Cluster) ListMasterIPs(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	if instance == nil || instance.IsNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.UnsafeListMasterIPs()
}

// FindAvailableMaster returns ID of the first master available to execute order
// satisfies interface Cluster.Cluster.Controller
func (instance *Cluster) FindAvailableMaster(ctx context.Context) (master resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	master = nil
	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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

	return instance.UnsafeFindAvailableMaster(ctx)
}

// ListNodes lists node instances corresponding to the nodes in the Cluster
// satisfies interface Cluster.Controller
func (instance *Cluster) ListNodes(ctx context.Context) (list resources.IndexedListOfClusterNodes, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := resources.IndexedListOfClusterNodes{}
	if instance == nil || instance.IsNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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

// beingRemoved tells if the Cluster is currently marked as Removed (meaning a removal operation is running)
func (instance *Cluster) beingRemoved() fail.Error {
	state, xerr := instance.unsafeGetState()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if state == clusterstate.Removed {
		return fail.NotAvailableError("Cluster is being removed")
	}

	return nil
}

// ListNodeNames lists the names of the nodes in the Cluster
func (instance *Cluster) ListNodeNames(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	if instance == nil || instance.IsNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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

// ListNodeIDs lists IDs of the nodes in the Cluster
func (instance *Cluster) ListNodeIDs(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	if instance == nil || instance.IsNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.UnsafeListNodeIDs(ctx)
}

// ListNodeIPs lists the IPs of the nodes in the Cluster
func (instance *Cluster) ListNodeIPs(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	if instance == nil || instance.IsNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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
func (instance *Cluster) FindAvailableNode(ctx context.Context) (node resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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

	return instance.UnsafeFindAvailableNode(ctx)
}

// LookupNode tells if the ID of the master passed as parameter is a node
func (instance *Cluster) LookupNode(ctx context.Context, ref string) (found bool, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
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
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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

	var hostInstance resources.Host
	hostInstance, xerr = LoadHost(instance.GetService(), ref)
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

			_, found = nodesV3.PrivateNodeByID[hostInstance.GetID()]
			return nil
		})
	})
	return found, xerr
}

// CountNodes counts the nodes of the Cluster
func (instance *Cluster) CountNodes(ctx context.Context) (count uint, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return 0, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return 0, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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
func (instance *Cluster) GetNodeByID(ctx context.Context, hostID string) (hostInstance resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
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
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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
func (instance *Cluster) deleteMaster(ctx context.Context, host resources.Host) fail.Error {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}

	var master *propertiesv3.ClusterNode
	xerr = instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			// Removes master from Cluster properties
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

	// Starting from here, restore master in Cluster properties if exiting with error
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
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to restore master '%s' in Cluster metadata", ActionFromError(xerr), master.Name))
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
			logrus.Tracef("master not found, deletion considered successful")
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}
	return nil
}

// deleteNode deletes a node
func (instance *Cluster) deleteNode(ctx context.Context, node *propertiesv3.ClusterNode, master *Host) (xerr fail.Error) {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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

	// Identify the node to delete and remove it preventively from metadata
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

	// Starting from here, restore node in Cluster metadata if exiting with error
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
				logrus.Errorf("failed to restore node ownership in Cluster")
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to restore node ownership in Cluster metadata", ActionFromError(xerr)))
			}
		}
	}()

	// Deletes node
	hostInstance, xerr := LoadHost(instance.GetService(), nodeRef, HostLightOption)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// Host already deleted, consider as a success, continue
		default:
			return xerr
		}
	} else {
		// host still exists, leave it from Cluster, if master is not null
		if master != nil && !master.IsNull() {
			xerr = instance.leaveNodesFromList([]resources.Host{hostInstance}, master)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			if instance.makers.UnconfigureNode != nil {
				xerr = instance.makers.UnconfigureNode(instance, hostInstance, master)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}
			}
		}

		// Finally delete host
		xerr = hostInstance.Delete(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// Host seems already deleted, so it's a success
			default:
				return xerr
			}
		}
	}

	return nil
}

// Delete deletes the Cluster
func (instance *Cluster) Delete(ctx context.Context, force bool) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
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

// delete does the work to delete Cluster
func (instance *Cluster) delete(ctx context.Context) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	var cleaningErrors []error

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}

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
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to set Cluster state to DEGRADED", ActionFromError(xerr)))
			}
		}
	}()

	var (
		all            map[uint]*propertiesv3.ClusterNode
		nodes, masters []uint
	)
	// Mark the Cluster as Removed and get nodes from properties
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		// Updates Cluster state to mark Cluster as Removing
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

	masterCount, nodeCount := len(masters), len(nodes)
	if masterCount+nodeCount > 0 {
		tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		options := []data.ImmutableKeyValue{
			concurrency.InheritParentIDOption,
			data.NewImmutableKeyValue("normalize_error", func(err error) error {
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

		for _, v := range nodes {
			if n, ok := all[v]; ok {
				completedOptions := append(options, concurrency.AmendID(fmt.Sprintf("/node/%s/delete", n.Name)))
				_, xerr = tg.Start(instance.taskDeleteNode, taskDeleteNodeParameters{node: n}, completedOptions...)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					cleaningErrors = append(cleaningErrors, fail.Wrap(xerr, "failed to start deletion of Host '%s'", n.Name))
					break
				}
			}
		}

		for _, v := range masters {
			if n, ok := all[v]; ok {
				completedOptions := append(options, concurrency.AmendID(fmt.Sprintf("/master/%s/delete", n.Name)))
				_, xerr := tg.Start(instance.taskDeleteMaster, taskDeleteNodeParameters{node: n}, completedOptions...)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					cleaningErrors = append(cleaningErrors, fail.Wrap(xerr, "failed to start deletion of Host '%s'", n.Name))
					break
				}
			}
		}

		_, xerr = tg.WaitGroup()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			cleaningErrors = append(cleaningErrors, xerr)
		}
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
	if allCount > 0 {
		tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		for _, v := range all {
			_, xerr = tg.Start(instance.taskDeleteNode, taskDeleteNodeParameters{node: v}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/node/%s/delete", v.Name)))
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				cleaningErrors = append(cleaningErrors, fail.Wrap(xerr, "failed to start deletion of Host '%s'", v.Name))
				break
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
	}

	// --- Deletes the Network, Subnet and gateway ---
	networkInstance, deleteNetwork, subnetInstance, xerr := instance.extractNetworkingInfo()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// missing Network and Subnet is considered as a successful deletion, continue
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	if subnetInstance != nil && !subnetInstance.IsNull() {
		subnetName := subnetInstance.GetName()
		logrus.Debugf("Cluster Deleting Subnet '%s'", subnetName)
		xerr = retry.WhileUnsuccessfulDelay5SecondsTimeout(
			func() error {
				if innerXErr := subnetInstance.Delete(ctx); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotAvailable, *fail.ErrNotFound:
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
			case *fail.ErrTimeout, *fail.ErrAborted:
				xerr = fail.ConvertError(xerr.Cause())
			default:
			}
		}
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// Subnet not found, considered as a successful deletion and continue
				debug.IgnoreError(xerr)
			default:
				return fail.Wrap(xerr, "failed to delete Subnet '%s'", subnetName)
			}
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	if networkInstance != nil && !networkInstance.IsNull() && deleteNetwork {
		networkName := networkInstance.GetName()
		logrus.Debugf("Deleting Network '%s'...", networkName)
		xerr = retry.WhileUnsuccessfulDelay5SecondsTimeout(
			func() error {
				if innerXErr := networkInstance.Delete(ctx); innerXErr != nil {
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
				// network not found, considered as a successful deletion and continue
				debug.IgnoreError(xerr)
			default:
				logrus.Errorf("Failed to delete Network '%s'", networkName)
				return fail.Wrap(xerr, "failed to delete Network '%s'", networkName)
			}
		}
		logrus.Infof("Network '%s' successfully deleted.", networkName)
	}

	// --- Delete metadata ---
	return instance.MetadataCore.Delete()
}

// extractNetworkingInfo returns the ID of the network from properties, taking care of ascending compatibility
func (instance *Cluster) extractNetworkingInfo() (networkInstance resources.Network, deleteNetwork bool, subnetInstance resources.Subnet, xerr fail.Error) {
	networkInstance, subnetInstance = nil, nil
	deleteNetwork = false
	xerr = instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		return props.Inspect(clusterproperty.NetworkV3, func(clonable data.Clonable) (innerXErr fail.Error) {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if networkV3.SubnetID != "" {
				if subnetInstance, innerXErr = LoadSubnet(instance.GetService(), networkV3.NetworkID, networkV3.SubnetID); innerXErr != nil {
					return innerXErr
				}
			}

			if networkV3.NetworkID != "" {
				networkInstance, innerXErr = LoadNetwork(instance.GetService(), networkV3.NetworkID)
				if innerXErr != nil {
					return innerXErr
				}
				deleteNetwork = networkV3.CreatedNetwork
			}
			if networkV3.SubnetID != "" {
				subnetInstance, innerXErr = LoadSubnet(instance.GetService(), networkV3.NetworkID, networkV3.SubnetID)
				if innerXErr != nil {
					return innerXErr
				}
				if networkInstance == nil {
					networkInstance, innerXErr = subnetInstance.InspectNetwork()
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
		return nil, deleteNetwork, NullSubnet(), xerr
	}

	return networkInstance, deleteNetwork, subnetInstance, nil
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
func (instance *Cluster) configureCluster(ctx context.Context) (xerr fail.Error) {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	logrus.Infof("[Cluster %s] configuring Cluster...", instance.GetName())
	defer func() {
		if xerr == nil {
			logrus.Infof("[Cluster %s] configuration successful.", instance.GetName())
		} else {
			logrus.Errorf("[Cluster %s] configuration failed: %s", instance.GetName(), xerr.Error())
		}
	}()

	// Install reverseproxy feature on Cluster (gateways)
	xerr = instance.installReverseProxy(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Install remotedesktop feature on Cluster (all masters)
	xerr = instance.installRemoteDesktop(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// configure what has to be done Cluster-wide
	if instance.makers.ConfigureCluster != nil {
		return instance.makers.ConfigureCluster(ctx, instance)
	}

	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

func (instance *Cluster) determineRequiredNodes() (uint, uint, uint, fail.Error) {
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
func (instance *Cluster) configureNodesFromList(task concurrency.Task, nodes []*propertiesv3.ClusterNode) (xerr fail.Error) {
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	length := len(nodes)
	if length > 0 {
		tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
		if xerr != nil {
			return xerr
		}

		for i := 0; i < length; i++ {
			_, ierr := tg.Start(instance.taskConfigureNode, taskConfigureNodeParameters{
				Index: uint(i + 1),
				Node:  nodes[i],
			}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s/configure", nodes[i].Name)))
			ierr = debug.InjectPlannedFail(ierr)
			if ierr != nil {
				_ = tg.Abort()
				break
			}
		}
		_, xerr = tg.WaitGroup()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	return nil
}

// joinNodesFromList makes nodes from a list join the Cluster
func (instance *Cluster) joinNodesFromList(ctx context.Context, nodes []*propertiesv3.ClusterNode) fail.Error {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	if instance.makers.JoinNodeToCluster == nil {
		// configure what has to be done Cluster-wide
		if instance.makers.ConfigureCluster != nil {
			return instance.makers.ConfigureCluster(ctx, instance)
		}
	}

	logrus.Debugf("Joining nodes to Cluster...")

	// Joins to Cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the Cluster Flavor)
	if instance.makers.JoinMasterToCluster != nil {
		for _, v := range nodes {
			hostInstance, xerr := LoadHost(instance.GetService(), v.ID)
			if xerr != nil {
				return xerr
			}

			xerr = instance.makers.JoinNodeToCluster(instance, hostInstance)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}

	return nil
}

// leaveNodesFromList makes nodes from a list leave the Cluster
func (instance *Cluster) leaveNodesFromList(hosts []resources.Host, master resources.Host) (xerr fail.Error) {
	logrus.Debugf("Instructing nodes to leave Cluster...")

	// Unjoins from Cluster are done sequentially, experience shows too many join at the same time
	// may fail (depending of the Cluster Flavor)
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
func (instance *Cluster) buildHostname(core string, nodeType clusternodetype.Enum) (_ string, xerr fail.Error) {
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

func (instance *Cluster) deleteHosts(task concurrency.Task, hosts []resources.Host) fail.Error {
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	errors := make([]error, 0, len(hosts)+1)
	for _, h := range hosts {
		_, xerr = tg.Start(instance.taskDeleteHostOnFailure, taskDeleteHostOnFailureParameters{host: h.(*Host)}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s/delete", h.GetName())))
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
func (instance *Cluster) ToProtocol() (_ *protocol.ClusterResponse, xerr fail.Error) {
	if instance == nil || instance.IsNull() {
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

func (instance *Cluster) Shrink(ctx context.Context, count uint) (_ []*propertiesv3.ClusterNode, xerr fail.Error) {
	emptySlice := make([]*propertiesv3.ClusterNode, 0)
	if instance == nil || instance.IsNull() {
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
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to restore Cluster nodes metadata", ActionFromError(xerr)))
			}
		}
	}()

	if len(removedNodes) > 0 {
		tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/shrink/%d", len(removedNodes))))
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return emptySlice, xerr
		}

		for _, v := range removedNodes {
			_, xerr = tg.Start(instance.taskDeleteNode, taskDeleteNodeParameters{node: v, master: nil}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/node/%s/delete", v.Name)))
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
	}
	if len(errors) > 0 {
		return emptySlice, fail.NewErrorList(errors)
	}

	return removedNodes, nil
}

// IsFeatureInstalled tells if a Feature identified by name is installed on Cluster, using only metadata
func (instance *Cluster) IsFeatureInstalled(ctx context.Context, name string) (found bool, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	found = false
	if instance == nil || instance.IsNull() {
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
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
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
