/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"embed"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations/clusterflavors"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations/clusterflavors/boh"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations/clusterflavors/k8s"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v2"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/template"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

const (
	clusterKind        = "cluster"
	clustersFolderName = "clusters" // path to use to reach Cluster Definitions/Metadata

)

// Cluster is the implementation of resources.Cluster interface
type Cluster struct {
	*MetadataCore

	localCache struct {
		sync.RWMutex
		installMethods      sync.Map
		lastStateCollection time.Time
		makers              clusterflavors.Makers
	}

	randomDelayTask concurrency.Task
	randomDelayCh   <-chan int
}

// NewCluster is the constructor of resources.Cluster struct
func NewCluster(ctx context.Context, svc iaas.Service) (_ *Cluster, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

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
	xerr = instance.startRandomDelayGenerator(ctx, 0, 2000)
	if xerr != nil {
		return nil, xerr
	}

	xerr = instance.updateCachedInformation()
	if xerr != nil {
		return nil, xerr
	}

	return instance, nil
}

// StartRandomDelayGenerator starts a Task to generate random delays, read from instance.randomDelayCh
func (instance *Cluster) startRandomDelayGenerator(ctx context.Context, min, max int) fail.Error {
	chint := make(chan int)
	mrand.Seed(time.Now().UnixNano())

	var xerr fail.Error
	instance.randomDelayTask, xerr = concurrency.NewTaskWithContext(ctx)
	if xerr != nil {
		return xerr
	}

	_, xerr = instance.randomDelayTask.Start(func(t concurrency.Task, _ concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
		if min == max {
			for !t.Aborted() {
				chint <- min
			}
		} else {
			value := max - min
			for !t.Aborted() {
				chint <- mrand.Intn(value) + min // nolint
			}
		}

		close(chint)
		return nil, nil
	}, nil)
	if xerr != nil {
		return xerr
	}

	instance.randomDelayCh = chint
	return nil
}

// LoadCluster loads cluster information from metadata
func LoadCluster(ctx context.Context, svc iaas.Service, name string, options ...data.ImmutableKeyValue) (_ resources.Cluster, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	cacheMissLoader := func() (data.Identifiable, fail.Error) { return onClusterCacheMiss(ctx, svc, name) }
	anon, xerr := cacheMissLoader()
	if xerr != nil {
		return nil, xerr
	}

	var (
		clusterInstance *Cluster
		ok              bool
	)
	if clusterInstance, ok = anon.(*Cluster); !ok {
		return nil, fail.InconsistentError("value found in Cluster cache for key '%s' is not a Cluster", name)
	}
	if clusterInstance == nil {
		return nil, fail.InconsistentError("nil value found in Cluster cache for key '%s'", name)
	}

	if clusterInstance.randomDelayCh == nil {
		xerr = clusterInstance.startRandomDelayGenerator(ctx, 0, 2000)
		if xerr != nil {
			return nil, xerr
		}
	}

	return clusterInstance, nil
}

// onClusterCacheMiss is called when cluster cache does not contain an instance of cluster 'name'
func onClusterCacheMiss(ctx context.Context, svc iaas.Service, name string) (data.Identifiable, fail.Error) {
	clusterInstance, xerr := NewCluster(ctx, svc)
	if xerr != nil {
		return nil, xerr
	}

	if xerr = clusterInstance.Read(name); xerr != nil {
		return nil, xerr
	}

	flavor, xerr := clusterInstance.GetFlavor()
	if xerr != nil {
		return nil, xerr
	}

	xerr = clusterInstance.bootstrap(flavor)
	if xerr != nil {
		return nil, xerr
	}

	xerr = clusterInstance.updateCachedInformation()
	if xerr != nil {
		return nil, xerr
	}
	return clusterInstance, nil
}

// updateCachedInformation updates information cached in the instance
func (instance *Cluster) updateCachedInformation() fail.Error {
	instance.localCache.Lock()
	defer instance.localCache.Unlock()

	var index uint8
	flavor, err := instance.unsafeGetFlavor()
	if err != nil {
		return err
	}
	if flavor == clusterflavor.K8S {
		index++
		instance.localCache.installMethods.Store(index, installmethod.Helm)
	}

	index++
	instance.localCache.installMethods.Store(index, installmethod.Bash)
	index++
	instance.localCache.installMethods.Store(index, installmethod.None)
	return nil
}

// IsNull tells if the instance should be considered as a null value
func (instance *Cluster) IsNull() bool {
	return instance == nil || instance.MetadataCore == nil || valid.IsNil(instance.MetadataCore)
}

// Released tells cache handler the instance is no more used, giving a chance to free this instance from cache
func (instance *Cluster) Released() error {
	if instance.randomDelayTask != nil {
		// Stops task generating random delays
		if err := instance.randomDelayTask.Abort(); err != nil {
			logrus.Debugf("there was a problem stopping random delay generator: %v", err)
		}
	}

	return instance.MetadataCore.Released()
}

// carry ...
func (instance *Cluster) carry(ctx context.Context, clonable data.Clonable) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) {
		if instance.MetadataCore.IsTaken() {
			return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
		}
	}

	// Note: do not validate parameters, this call will do it
	xerr := instance.MetadataCore.Carry(clonable)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Create creates the necessary infrastructure of the Cluster
func (instance *Cluster) Create(ctx context.Context, req abstract.ClusterRequest) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance.MetadataCore) {
		if instance.MetadataCore.IsTaken() {
			return fail.InconsistentError("already carrying information")
		}
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
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

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	_, xerr = task.Run(instance.taskCreateCluster, req)
	if xerr != nil {
		return xerr
	}
	xerr = instance.unsafeUpdateClusterInventory(task.Context())
	if xerr != nil {
		return xerr
	}

	return nil
}

func (instance *Cluster) Sdump() (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	dumped, _ := instance.MetadataCore.Sdump()
	return dumped, nil
}

// Deserialize reads json code and recreates Cluster metadata
func (instance *Cluster) Deserialize(buf []byte) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	if len(buf) == 0 {
		return fail.InvalidParameterError("buf", "cannot be empty []byte")
	}

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	err := json.Unmarshal(buf, instance) // nolint
	return fail.ConvertError(err)
}

// bootstrap (re)connects controller with the appropriate Makers
func (instance *Cluster) bootstrap(flavor clusterflavor.Enum) (ferr fail.Error) {
	instance.localCache.Lock()
	defer instance.localCache.Unlock()

	switch flavor {
	case clusterflavor.BOH:
		instance.localCache.makers = boh.Makers
	case clusterflavor.K8S:
		instance.localCache.makers = k8s.Makers
	default:
		return fail.NotImplementedError("unknown Cluster Flavor '%d'", flavor)
	}
	return nil
}

// Browse walks through Cluster MetadataFolder and executes a callback for each entry
// FIXME: adds a Cluster status check to prevent operations on removed clusters
func (instance *Cluster) Browse(ctx context.Context, callback func(*abstract.ClusterIdentity) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// Note: Do not test with Isnull here, as Browse may be used from null value
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
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	return instance.MetadataCore.BrowseFolder(
		func(buf []byte) fail.Error {
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
		},
	)
}

// GetIdentity returns the identity of the Cluster
func (instance *Cluster) GetIdentity() (clusterIdentity abstract.ClusterIdentity, ferr fail.Error) {
	if valid.IsNil(instance) {
		return abstract.ClusterIdentity{}, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	return instance.unsafeGetIdentity()
}

// GetFlavor returns the flavor of the Cluster
func (instance *Cluster) GetFlavor() (flavor clusterflavor.Enum, ferr fail.Error) {
	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	return instance.unsafeGetFlavor()
}

// GetComplexity returns the complexity of the Cluster
func (instance *Cluster) GetComplexity() (_ clustercomplexity.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	return instance.unsafeGetComplexity()
}

// GetAdminPassword returns the password of the Cluster admin account
// satisfies interface Cluster.Controller
func (instance *Cluster) GetAdminPassword() (adminPassword string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
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
func (instance *Cluster) GetKeyPair() (keyPair *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	aci, xerr := instance.GetIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return aci.Keypair, nil
}

// GetNetworkConfig returns subnet configuration of the Cluster
func (instance *Cluster) GetNetworkConfig() (config *propertiesv3.ClusterNetwork, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	xerr := instance.Inspect(
		func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Inspect(
				clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
					networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
					if !ok {
						return fail.InconsistentError(
							"'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String(),
						)
					}
					// config = networkV3.Clone().(*propertiesv3.ClusterNetwork)
					config = networkV3
					return nil
				},
			)
		},
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return config, nil
}

// Start starts the Cluster
func (instance *Cluster) Start(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
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

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	// make sure no other parallel actions interferes
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

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
		xerr = retry.WhileUnsuccessful(
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
			timings.NormalDelay(),
			timings.ExecutionTimeout(),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrStopRetry:
				return fail.Wrap(fail.Cause(xerr), "stopping retries")
			case *retry.ErrTimeout:
				return fail.Wrap(fail.Cause(xerr), "timeout")
			default:
				return xerr
			}
		}
		return nil
	case clusterstate.Stopped, clusterstate.Degraded:
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

	// Then start it and mark it as NOMINAL on success
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
				return fail.InconsistentError(
					"'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String(),
				)
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

	var problems []error

	// Start gateway(s)
	taskGroup, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	_, xerr = taskGroup.Start(instance.taskStartHost, gatewayID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		problems = append(problems, xerr)
		abErr := taskGroup.AbortWithCause(xerr)
		if abErr != nil {
			logrus.Warnf("problem aborting taskgroup: %v", abErr)
		}
	}

	if secondaryGatewayID != "" {
		_, xerr = taskGroup.Start(instance.taskStartHost, secondaryGatewayID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			problems = append(problems, xerr)
			abErr := taskGroup.AbortWithCause(xerr)
			if abErr != nil {
				logrus.Warnf("problem aborting taskgroup: %v", abErr)
			}
		}
	}

	// Start masters
	for _, n := range masters {
		n := n
		_, xerr = taskGroup.Start(instance.taskStartHost, n)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			problems = append(problems, xerr)
			abErr := taskGroup.AbortWithCause(xerr)
			if abErr != nil {
				logrus.Warnf("problem aborting taskgroup: %v", abErr)
			}
			break
		}
	}

	// Start nodes
	for _, n := range nodes {
		n := n
		_, xerr = taskGroup.Start(instance.taskStartHost, n)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			problems = append(problems, xerr)
			abErr := taskGroup.AbortWithCause(xerr)
			if abErr != nil {
				logrus.Warnf("problem aborting taskgroup: %v", abErr)
			}
			break
		}
	}

	_, xerr = taskGroup.WaitGroup()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		if len(problems) > 0 {
			_ = xerr.AddConsequence(fail.NewErrorList(problems))
		}
		return xerr
	}

	if len(problems) > 0 {
		// Mark Cluster as state Degraded
		outerr := fail.NewErrorList(problems)
		xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
				stateV1, ok := clonable.(*propertiesv1.ClusterState)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				stateV1.State = clusterstate.Degraded
				return nil
			})
		})
		if xerr != nil {
			_ = outerr.AddConsequence(xerr)
		}
		return outerr
	}

	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError(
					"'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String(),
				)
			}
			stateV1.State = clusterstate.Nominal
			return nil
		})
	})
}

// Stop stops the Cluster
func (instance *Cluster) Stop(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
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

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	// make sure no other parallel actions interferes
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

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
		xerr = retry.WhileUnsuccessful(
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
			timings.NormalDelay(),
			timings.ExecutionTimeout(),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrTimeout:
				return fail.Wrap(xerr.Cause(), "timeout")
			case *retry.ErrStopRetry:
				return fail.Wrap(xerr.Cause(), "stopping retries")
			default:
				return xerr
			}
		}
		return nil
	case clusterstate.Nominal, clusterstate.Degraded, clusterstate.Starting:
		// continue
	default:
		// If the Cluster is not in state Nominal, Starting or Degraded, forbid to stop
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
				return fail.InconsistentError(
					"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
				)
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

		// If there's a problem starting things don't return, note the problem, break if needed, then abort and wait.
		var problems []error

		for _, n := range nodes {
			n := n
			if _, innerXErr = taskGroup.Start(instance.taskStopHost, n); innerXErr != nil {
				problems = append(problems, innerXErr)
				abErr := taskGroup.AbortWithCause(innerXErr)
				if abErr != nil {
					logrus.Warnf("problem aborting taskgroup: %v", abErr)
				}
				break
			}
		}
		// Stop masters
		for _, n := range masters {
			n := n
			if _, innerXErr = taskGroup.Start(instance.taskStopHost, n); innerXErr != nil {
				problems = append(problems, innerXErr)
				abErr := taskGroup.AbortWithCause(innerXErr)
				if abErr != nil {
					logrus.Warnf("problem aborting taskgroup: %v", abErr)
				}
				break
			}
		}
		// Stop gateway(s)
		if _, innerXErr = taskGroup.Start(instance.taskStopHost, gatewayID); innerXErr != nil {
			problems = append(problems, innerXErr)
			abErr := taskGroup.AbortWithCause(innerXErr)
			if abErr != nil {
				logrus.Warnf("problem aborting taskgroup: %v", abErr)
			}
		}

		if secondaryGatewayID != "" {
			if _, innerXErr = taskGroup.Start(instance.taskStopHost, secondaryGatewayID); innerXErr != nil {
				problems = append(problems, innerXErr)
				abErr := taskGroup.AbortWithCause(innerXErr)
				if abErr != nil {
					logrus.Warnf("problem aborting taskgroup: %v", abErr)
				}
			}
		}

		if _, innerXErr = taskGroup.WaitGroup(); innerXErr != nil {
			if len(problems) > 0 {
				_ = innerXErr.AddConsequence(fail.NewErrorList(problems))
			}
			return innerXErr
		}
		if len(problems) > 0 {
			return fail.NewErrorList(problems)
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
func (instance *Cluster) GetState() (state clusterstate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	state = clusterstate.Unknown
	if instance == nil || valid.IsNil(instance) {
		return state, fail.InvalidInstanceError()
	}

	// make sure no other parallel actions interferes
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	return instance.unsafeGetState()
}

// AddNodes adds several nodes
func (instance *Cluster) AddNodes(ctx context.Context, count uint, def abstract.HostSizingRequirements, parameters data.Map, keepOnFailure bool) (_ []resources.Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if count == 0 {
		return nil, fail.InvalidParameterError("count", "must be an int > 0")
	}
	if parameters == nil {
		parameters = data.Map{}
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
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

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
		if props.Lookup(clusterproperty.DefaultsV3) {
			return props.Inspect(clusterproperty.DefaultsV3, func(clonable data.Clonable) fail.Error {
				defaultsV3, ok := clonable.(*propertiesv3.ClusterDefaults)
				if !ok {
					return fail.InconsistentError("'*propertiesv3.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				nodeDefaultDefinition = &defaultsV3.NodeSizing
				hostImage = defaultsV3.Image

				// merge FeatureParameters in parameters, the latter keeping precedence over the former
				for k, v := range ExtractFeatureParameters(defaultsV3.FeatureParameters) {
					if _, ok := parameters[k]; !ok {
						parameters[k] = v
					}
				}

				return nil
			})
		}

		// Cluster may have been created before ClusterDefaultV3, so still support this context
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

	svc := instance.Service()
	_, nodeDef.Image, xerr = determineImageID(svc, hostImage)
	if xerr != nil {
		return nil, xerr
	}

	var (
		errors []string
		nodes  []*propertiesv3.ClusterNode
	)

	timings, xerr := svc.Timings()
	if xerr != nil {
		return nil, xerr
	}

	timeout := 2 * timings.HostCreationTimeout() // More than enough

	tg, xerr := concurrency.NewTaskGroupWithParent(
		task, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/%d", count)),
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	for i := uint(1); i <= count; i++ {
		captured := i
		params := taskCreateNodeParameters{
			nodeDef:       nodeDef,
			timeout:       timeout,
			keepOnFailure: keepOnFailure,
			index:         captured,
		}
		_, xerr := tg.Start(instance.taskCreateNode, params, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%d/create", captured)))
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			abErr := tg.AbortWithCause(xerr)
			if abErr != nil {
				logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
			}
			break
		}
	}

	// Starting from here, if exiting with error, delete created nodes if allowed (cf. keepOnFailure)
	defer func() {
		if ferr != nil && !keepOnFailure && len(nodes) > 0 {
			// Note: using context.Background() disable cancellation mechanism for a workload that needs to go to the end
			dtg, derr := concurrency.NewTaskGroupWithContext(context.Background())
			if derr != nil {
				_ = ferr.AddConsequence(derr)
			}
			derr = dtg.SetID("/onfailure")
			if derr != nil {
				_ = ferr.AddConsequence(derr)
			}

			for _, v := range nodes {
				v := v
				_, derr = dtg.Start(
					instance.taskDeleteNode, taskDeleteNodeParameters{node: v},
				)
				if derr != nil {
					abErr := dtg.AbortWithCause(derr)
					if abErr != nil {
						logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
					}
					break
				}
			}
			_, derr = dtg.WaitGroup()
			derr = debug.InjectPlannedFail(derr)
			if derr != nil {
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

	_, res, xerr := tg.WaitGroupFor(3 * timings.HostCreationTimeout())
	xerr = debug.InjectPlannedFail(xerr)
	if len(res) > 0 {
		for _, v := range res {
			if item, ok := v.(*propertiesv3.ClusterNode); ok {
				nodes = append(nodes, item)
			}
		}
	}
	if xerr != nil {
		return nil, fail.NewErrorWithCause(xerr, "errors occurred on node%s addition", strprocess.Plural(uint(len(errors))))
	}

	// configure what has to be done Cluster-wide
	instance.localCache.RLock()
	makers := instance.localCache.makers
	instance.localCache.RUnlock() // nolint
	if makers.ConfigureCluster != nil {
		xerr = makers.ConfigureCluster(task.Context(), instance, parameters)
		if xerr != nil {
			return nil, xerr
		}
	}

	// Now configure new nodes
	xerr = instance.configureNodesFromList(task, nodes, parameters)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// At last join nodes to Cluster
	xerr = instance.joinNodesFromList(task.Context(), nodes)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	hosts := make([]resources.Host, 0, len(nodes))
	for _, v := range nodes {
		hostInstance, xerr := LoadHost(task.Context(), svc, v.ID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		hosts = append(hosts, hostInstance)
	}

	xerr = instance.unsafeUpdateClusterInventory(task.Context())
	if xerr != nil {
		return nil, xerr
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

// DeleteSpecificNode deletes a node identified by its ID
func (instance *Cluster) DeleteSpecificNode(ctx context.Context, hostID string, selectedMasterID string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if hostID = strings.TrimSpace(hostID); hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
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
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	var selectedMaster resources.Host
	if selectedMasterID != "" {
		selectedMaster, xerr = LoadHost(task.Context(), instance.Service(), selectedMasterID)
	} else {
		selectedMaster, xerr = instance.unsafeFindAvailableMaster(task.Context())
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
				return fail.InconsistentError(
					"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
				)
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

	xerr = instance.deleteNode(task.Context(), node, selectedMaster.(*Host))
	if xerr != nil {
		return xerr
	}

	return nil
}

// ListMasters lists the node instances corresponding to masters (if there is such masters in the flavor...)
func (instance *Cluster) ListMasters(ctx context.Context) (list resources.IndexedListOfClusterNodes, ferr fail.Error) {
	emptyList := resources.IndexedListOfClusterNodes{}
	if instance == nil || valid.IsNil(instance) {
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
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	return instance.unsafeListMasters()
}

// ListMasterNames lists the names of the master nodes in the Cluster
func (instance *Cluster) ListMasterNames(ctx context.Context) (list data.IndexedListOfStrings, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := data.IndexedListOfStrings{}
	if instance == nil || valid.IsNil(instance) {
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
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

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
func (instance *Cluster) ListMasterIDs(ctx context.Context) (list data.IndexedListOfStrings, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := data.IndexedListOfStrings{}
	if instance == nil || valid.IsNil(instance) {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	// make sure no other parallel actions interferes
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	return instance.unsafeListMasterIDs(ctx)
}

// ListMasterIPs lists the IPs of masters (if there is such masters in the flavor...)
func (instance *Cluster) ListMasterIPs(ctx context.Context) (list data.IndexedListOfStrings, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := data.IndexedListOfStrings{}
	if instance == nil || valid.IsNil(instance) {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	return instance.unsafeListMasterIPs()
}

// FindAvailableMaster returns ID of the first master available to execute order
// satisfies interface Cluster.Cluster.Controller
func (instance *Cluster) FindAvailableMaster(ctx context.Context) (master resources.Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	master = nil
	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
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
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return instance.unsafeFindAvailableMaster(task.Context())
}

// ListNodes lists node instances corresponding to the nodes in the Cluster
// satisfies interface Cluster.Controller
func (instance *Cluster) ListNodes(ctx context.Context) (list resources.IndexedListOfClusterNodes, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := resources.IndexedListOfClusterNodes{}
	if instance == nil || valid.IsNil(instance) {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

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
func (instance *Cluster) ListNodeNames(ctx context.Context) (list data.IndexedListOfStrings, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := data.IndexedListOfStrings{}
	if instance == nil || valid.IsNil(instance) {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

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
func (instance *Cluster) ListNodeIDs(ctx context.Context) (list data.IndexedListOfStrings, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := data.IndexedListOfStrings{}
	if instance == nil || valid.IsNil(instance) {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	return instance.unsafeListNodeIDs(task.Context())
}

// ListNodeIPs lists the IPs of the nodes in the Cluster
func (instance *Cluster) ListNodeIPs(ctx context.Context) (list data.IndexedListOfStrings, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := data.IndexedListOfStrings{}
	if instance == nil || valid.IsNil(instance) {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return instance.unsafeListNodeIPs()
}

// FindAvailableNode returns node instance of the first node available to execute order
func (instance *Cluster) FindAvailableNode(ctx context.Context) (node resources.Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
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
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	return instance.unsafeFindAvailableNode(task.Context())
}

// LookupNode tells if the ID of the master passed as parameter is a node
func (instance *Cluster) LookupNode(ctx context.Context, ref string) (found bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return false, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if ref == "" {
		return false, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

	if task.Aborted() {
		return false, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

	var hostInstance resources.Host
	hostInstance, xerr = LoadHost(ctx, instance.Service(), ref)
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
func (instance *Cluster) CountNodes(ctx context.Context) (count uint, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return 0, fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	if task.Aborted() {
		return 0, fail.AbortedError(nil, "aborted")
	}

	// make sure no other parallel actions interferes
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

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
func (instance *Cluster) GetNodeByID(ctx context.Context, hostID string) (hostInstance resources.Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostID == "" {
		return nil, fail.InvalidParameterError("hostID", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
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
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

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

	return LoadHost(task.Context(), instance.Service(), hostID)
}

// deleteMaster deletes the master specified by its ID
func (instance *Cluster) deleteMaster(ctx context.Context, host resources.Host) (ferr fail.Error) {
	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	if instance == nil || valid.IsNil(instance) {
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
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
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
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to restore master '%s' in Cluster metadata", ActionFromError(ferr), master.Name))
			}
		}
	}()

	// Finally delete host
	xerr = host.Delete(task.Context())
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
func (instance *Cluster) deleteNode(ctx context.Context, node *propertiesv3.ClusterNode, master *Host) (ferr fail.Error) {
	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
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
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
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
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to restore node ownership in Cluster metadata", ActionFromError(ferr)))
			}
		}
	}()

	// Deletes node
	hostInstance, xerr := LoadHost(task.Context(), instance.Service(), nodeRef)
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
		if master != nil && !valid.IsNil(master) {
			xerr = instance.leaveNodesFromList(task.Context(), []resources.Host{hostInstance}, master)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			instance.localCache.RLock()
			makers := instance.localCache.makers
			instance.localCache.RUnlock() // nolint
			if makers.UnconfigureNode != nil {
				xerr = makers.UnconfigureNode(instance, hostInstance, master)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}
			}
		}

		// Finally delete host
		xerr = hostInstance.Delete(task.Context())
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
func (instance *Cluster) Delete(ctx context.Context, force bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	if !force {
		xerr := instance.beingRemoved()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	return instance.delete(ctx)
}

// delete does the work to delete Cluster
func (instance *Cluster) delete(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	var cleaningErrors []error

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := instance.Alter(
				func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
					return props.Alter(
						clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
							stateV1, ok := clonable.(*propertiesv1.ClusterState)
							if !ok {
								return fail.InconsistentError(
									"'*propertiesv1.ClusterState' expected, '%s' provided",
									reflect.TypeOf(clonable).String(),
								)
							}

							stateV1.State = clusterstate.Degraded
							return nil
						},
					)
				},
			)
			if derr != nil {
				_ = ferr.AddConsequence(
					fail.Wrap(
						derr, "cleaning up on %s, failed to set Cluster state to DEGRADED", ActionFromError(ferr),
					),
				)
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
		innerXErr := props.Alter(
			clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
				stateV1, ok := clonable.(*propertiesv1.ClusterState)
				if !ok {
					return fail.InconsistentError(
						"'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String(),
					)
				}

				stateV1.State = clusterstate.Removed
				return nil
			},
		)
		if innerXErr != nil {
			return innerXErr
		}

		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError(
					"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
				)
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

		foundSomething := false
		for _, v := range nodes {
			if n, ok := all[v]; ok {
				foundSomething = true

				var completedOptions []data.ImmutableKeyValue
				copy(completedOptions, options)

				completedOptions = append(completedOptions, concurrency.AmendID(fmt.Sprintf("/node/%s/delete", n.Name)))
				_, xerr = tg.Start(
					instance.taskDeleteNode, taskDeleteNodeParameters{node: n},
					completedOptions...,
				)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					abErr := tg.AbortWithCause(xerr)
					if abErr != nil {
						logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
					}
					cleaningErrors = append(
						cleaningErrors, fail.Wrap(xerr, "failed to start deletion of Host '%s'", n.Name),
					)
					break
				}
			}
		}

		for _, v := range masters {
			if n, ok := all[v]; ok {
				foundSomething = true

				var completedOptions []data.ImmutableKeyValue
				copy(completedOptions, options)

				completedOptions = append(completedOptions, concurrency.AmendID(fmt.Sprintf("/master/%s/delete", n.Name)))
				_, xerr := tg.Start(
					instance.taskDeleteMaster, taskDeleteNodeParameters{node: n},
					completedOptions...,
				)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					cleaningErrors = append(
						cleaningErrors, fail.Wrap(xerr, "failed to start deletion of Host '%s'", n.Name),
					)
					abErr := tg.AbortWithCause(xerr)
					if abErr != nil {
						logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
					}
					break
				}
			}
		}

		if foundSomething {
			_, xerr = tg.WaitGroup()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				cleaningErrors = append(cleaningErrors, xerr)
			}
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
				return fail.InconsistentError(
					"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
				)
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
			_, xerr = tg.Start(
				instance.taskDeleteNode, taskDeleteNodeParameters{node: v},
				concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/node/%s/delete", v.Name)),
			)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				cleaningErrors = append(
					cleaningErrors, fail.Wrap(xerr, "failed to start deletion of Host '%s'", v.Name),
				)
				abErr := tg.AbortWithCause(xerr)
				if abErr != nil {
					logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
				}
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
	networkInstance, deleteNetwork, subnetInstance, xerr := instance.extractNetworkingInfo(task.Context())
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

	svc := instance.Service()
	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	if subnetInstance != nil && !valid.IsNil(subnetInstance) {
		subnetName := subnetInstance.GetName()
		logrus.Debugf("Cluster Deleting Subnet '%s'", subnetName)
		xerr = retry.WhileUnsuccessfulWithHardTimeout(
			func() error {
				innerXErr := subnetInstance.Delete(task.Context())
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotAvailable, *fail.ErrNotFound:
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			timings.NormalDelay(),
			timings.HostOperationTimeout(),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				debug.IgnoreError(xerr)
			case *fail.ErrTimeout, *fail.ErrAborted:
				nerr := fail.ConvertError(fail.Cause(xerr))
				switch nerr.(type) {
				case *fail.ErrNotFound:
					// Subnet not found, considered as a successful deletion and continue
					debug.IgnoreError(nerr)
				default:
					return fail.Wrap(nerr, "failed to delete Subnet '%s'", subnetName)
				}
			default:
				return fail.Wrap(xerr, "failed to delete Subnet '%s'", subnetName)
			}
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	if networkInstance != nil && !valid.IsNil(networkInstance) && deleteNetwork {
		networkName := networkInstance.GetName()
		logrus.Debugf("Deleting Network '%s'...", networkName)
		xerr = retry.WhileUnsuccessfulWithHardTimeout(
			func() error {
				innerXErr := networkInstance.Delete(task.Context())
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound, *fail.ErrInvalidRequest:
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			timings.NormalDelay(),
			timings.HostOperationTimeout(),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// network not found, considered as a successful deletion and continue
				debug.IgnoreError(xerr)
			case *retry.ErrStopRetry:
				return fail.Wrap(xerr.Cause(), "stopping retries")
			case *retry.ErrTimeout:
				return fail.Wrap(xerr.Cause(), "timeout")
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
func (instance *Cluster) extractNetworkingInfo(ctx context.Context) (networkInstance resources.Network, deleteNetwork bool, subnetInstance resources.Subnet, ferr fail.Error) {
	networkInstance, subnetInstance = nil, nil
	deleteNetwork = false

	xerr := instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var inErr fail.Error
			if networkV3.SubnetID != "" {
				if subnetInstance, inErr = LoadSubnet(ctx, instance.Service(), networkV3.NetworkID, networkV3.SubnetID); inErr != nil {
					return inErr
				}
			}

			if networkV3.NetworkID != "" {
				networkInstance, inErr = LoadNetwork(ctx, instance.Service(), networkV3.NetworkID)
				if inErr != nil {
					return inErr
				}
				deleteNetwork = networkV3.CreatedNetwork
			}
			if networkV3.SubnetID != "" {
				subnetInstance, inErr = LoadSubnet(ctx, instance.Service(), networkV3.NetworkID, networkV3.SubnetID)
				if inErr != nil {
					return inErr
				}
				if networkInstance == nil {
					networkInstance, inErr = subnetInstance.InspectNetwork(ctx)
					if inErr != nil {
						return inErr
					}
				}
				deleteNetwork = networkV3.CreatedNetwork
			}

			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, deleteNetwork, nil, xerr
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
func (instance *Cluster) configureCluster(ctx context.Context, req abstract.ClusterRequest) (ferr fail.Error) {
	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
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
		if ferr != nil {
			logrus.Errorf("[Cluster %s] configuration failed: %s", instance.GetName(), ferr.Error())
		} else {
			logrus.Infof("[Cluster %s] configuration successful.", instance.GetName())
		}
	}()

	// Install reverse-proxy feature on Cluster (gateways)
	parameters := ExtractFeatureParameters(req.FeatureParameters)
	xerr = instance.installReverseProxy(task.Context(), parameters)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Install remote-desktop feature on Cluster (all masters)
	xerr = instance.installRemoteDesktop(task.Context(), parameters)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		// Break execution flow only if the Feature cannot be run (file transfer, Host unreachable, ...), not if it ran but has failed
		if annotation, found := xerr.Annotation("ran_but_failed"); !found || !annotation.(bool) {
			return xerr
		}
	}

	// Install ansible feature on Cluster (all masters)
	xerr = instance.installAnsible(task.Context(), parameters)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// configure what has to be done Cluster-wide
	instance.localCache.RLock()
	makers := instance.localCache.makers
	instance.localCache.RUnlock() // nolint
	if makers.ConfigureCluster != nil {
		return makers.ConfigureCluster(task.Context(), instance, parameters)
	}

	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

func (instance *Cluster) determineRequiredNodes() (uint, uint, uint, fail.Error) {
	instance.localCache.RLock()
	makers := instance.localCache.makers
	instance.localCache.RUnlock() // nolint
	if makers.MinimumRequiredServers != nil {
		g, m, n, xerr := makers.MinimumRequiredServers(func() abstract.ClusterIdentity { out, _ := instance.unsafeGetIdentity(); return out }())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return 0, 0, 0, xerr
		}

		return g, m, n, nil
	}
	return 0, 0, 0, nil
}

// realizeTemplate generates a file from box template with variables updated
func realizeTemplate(tmplName string, adata map[string]interface{}, fileName string) (string, string, fail.Error) {
	tmplString, err := clusterFlavorScripts.ReadFile(tmplName)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", "", fail.Wrap(err, "failed to load template")
	}

	tmplCmd, err := template.Parse(fileName, string(tmplString))
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", "", fail.Wrap(err, "failed to parse template")
	}

	dataBuffer := bytes.NewBufferString("")
	err = tmplCmd.Option("missingkey=error").Execute(dataBuffer, adata)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", "", fail.Wrap(err, "failed to execute  template")
	}

	cmd := dataBuffer.String()
	remotePath := utils.TempFolder + "/" + fileName

	return cmd, remotePath, nil
}

//go:embed scripts/*
var ansibleScripts embed.FS

// Regenerate ansible inventory
func (instance *Cluster) unsafeUpdateClusterInventory(ctx context.Context) fail.Error {
	logrus.Infof("[Cluster %s] Update ansible inventory", instance.GetName())

	// Check incoming parameters
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	// Collect data
	featureAnsibleInventoryInstalled := false
	var masters []resources.Host
	var params = map[string]interface{}{
		"ClusterName":          "",
		"ClusterAdminUsername": "cladm",
		"ClusterAdminPassword": "",
		"PrimaryGatewayName":   fmt.Sprintf("gw-%s", instance.GetName()),
		"PrimaryGatewayIP":     "",
		"PrimaryGatewayPort":   "22",
		"SecondaryGatewayName": fmt.Sprintf("gw2-%s", instance.GetName()),
		"SecondaryGatewayIP":   "",
		"SecondaryGatewayPort": "22",
		"ClusterMasters":       resources.IndexedListOfClusterNodes{},
		"ClusterNodes":         resources.IndexedListOfClusterNodes{},
	}

	xerr := instance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		// Check if feature ansible is installed
		innerXErr := props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("`propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, featureAnsibleInventoryInstalled = featuresV1.Installed["ansible-for-cluster"]
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}
		if !featureAnsibleInventoryInstalled {
			return nil
		}

		// Collect get network config
		var networkCfg *propertiesv3.ClusterNetwork
		innerXErr = props.Inspect(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if networkV3 == nil {
				return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", "nil")
			}
			networkCfg = networkV3
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Collect template data, list masters hosts
		aci, ok := clonable.(*abstract.ClusterIdentity)
		if !ok {
			return fail.InconsistentError("'*abstract.ClusterIdentity' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if aci == nil {
			return fail.InconsistentError("'*abstract.ClusterIdentity' expected, '%s' provided", "nil")
		}
		if reflect.TypeOf(aci.Name).Kind() != reflect.String && aci.Name == "" {
			return fail.InconsistentError("Cluster name must be a not empty string")
		}

		params["Clustername"] = aci.Name
		params["ClusterAdminUsername"] = "cladm"
		params["ClusterAdminPassword"] = aci.AdminPassword
		params["PrimaryGatewayIP"] = networkCfg.GatewayIP
		if networkCfg.SecondaryGatewayIP != "" {
			params["SecondaryGatewayIP"] = networkCfg.SecondaryGatewayIP
		}

		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if nodesV3 == nil {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", "nil")
			}

			// Template params: gateways
			rh, err := LoadHost(ctx, instance.Service(), networkCfg.GatewayID)
			if err != nil {
				return fail.InconsistentError("Fail to load primary gateway '%s'", networkCfg.GatewayID)
			}
			err = rh.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
				ahc, ok := clonable.(*abstract.HostCore)
				if !ok {
					return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				if ahc == nil {
					return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", "nil")
				}
				params["PrimaryGatewayPort"] = strconv.Itoa(int(ahc.SSHPort))
				if ahc.Name != "" {
					params["PrimaryGatewayName"] = ahc.Name
				}
				return nil
			})
			if err != nil {
				return fail.InconsistentError("Fail to load primary gateway '%s'", networkCfg.GatewayID)
			}

			if networkCfg.SecondaryGatewayIP != "" {
				rh, err = LoadHost(ctx, instance.Service(), networkCfg.SecondaryGatewayID)
				if err != nil {
					return fail.InconsistentError("Fail to load secondary gateway '%s'", networkCfg.SecondaryGatewayID)
				}
				err = rh.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
					ahc, ok := clonable.(*abstract.HostCore)
					if !ok {
						return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					if ahc == nil {
						return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", "nil")
					}
					params["SecondaryGatewayPort"] = strconv.Itoa(int(ahc.SSHPort))
					if ahc.Name != "" {
						params["SecondaryGatewayName"] = ahc.Name
					}
					return nil
				})
				if err != nil {
					return fail.InconsistentError("Fail to load secondary gateway '%s'", networkCfg.SecondaryGatewayID)
				}
			}

			// Template params: masters
			nodes := make(resources.IndexedListOfClusterNodes, len(nodesV3.Masters))
			for _, v := range nodesV3.Masters {
				if node, found := nodesV3.ByNumericalID[v]; found {
					nodes[node.NumericalID] = node
					master, err := LoadHost(ctx, instance.Service(), node.ID)
					if err != nil {
						return fail.InconsistentError("Fail to load master '%s'", node.ID)
					}
					masters = append(masters, master)
				}
			}
			params["ClusterMasters"] = nodes

			// Template params: nodes
			nodes = make(resources.IndexedListOfClusterNodes, len(nodesV3.PrivateNodes))
			for _, v := range nodesV3.PrivateNodes {
				if node, found := nodesV3.ByNumericalID[v]; found {
					nodes[node.NumericalID] = node
				}
			}
			params["ClusterNodes"] = nodes
			return nil

		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	prerr := fmt.Sprintf("[Cluster %s] Update ansible inventory: ", instance.GetName())

	// Feature ansible found ?
	if !featureAnsibleInventoryInstalled {
		logrus.Infof("%snothing to update (feature not installed)", prerr)
		return nil
	}
	// Has at least one master ?
	if len(masters) == 0 {
		logrus.Infof("%s nothing to update (no masters in cluster)", prerr)
		return nil
	}

	tmplString, err := ansibleScripts.ReadFile("scripts/ansible_inventory.py")
	if err != nil {
		return fail.Wrap(err, "%s failed to load template 'ansible_inventory.py'", prerr)
	}

	// --------- Build ansible inventory --------------
	fileName := fmt.Sprintf("cluster-inventory-%s.py", params["Clustername"])
	tmplCmd, err := template.Parse(fileName, string(tmplString))
	if err != nil {
		return fail.Wrap(err, "%s failed to parse template 'ansible_inventory.py'", prerr)
	}

	dataBuffer := bytes.NewBufferString("")
	ferr := tmplCmd.Execute(dataBuffer, params)
	if ferr != nil {
		return fail.Wrap(ferr, "%s failed to execute template 'ansible_inventory.py'", prerr)
	}

	// --------- Upload file for each master and test it (parallelized) --------------
	tg, xerr := concurrency.NewTaskGroup()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	xerr = tg.SetID(fileName)
	if xerr != nil {
		return xerr
	}

	var errors []error
	for master := range masters {
		logrus.Infof("%s Update master %s", prerr, masters[master].GetName())

		_, xerr = tg.Start(
			instance.taskUpdateClusterInventoryMaster,
			taskUpdateClusterInventoryMasterParameters{
				ctx:           ctx,
				master:        masters[master],
				inventoryData: dataBuffer.String(),
			},
			concurrency.InheritParentIDOption,
			concurrency.AmendID(fmt.Sprintf("/cluster/%s/master/%s/update_inventory", instance.GetName(), masters[master].GetName())),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			errors = append(errors, xerr)
			abErr := tg.AbortWithCause(xerr)
			if abErr != nil {
				logrus.Warnf("%s there was an error trying to abort TaskGroup: %s", prerr, spew.Sdump(abErr))
			}
			break
		}
	}

	var tgr concurrency.TaskGroupResult
	tgr, xerr = tg.WaitGroup()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		if withTimeout(xerr) {
			logrus.Warnf("%s Timeouts ansible update inventory", prerr)
		}
	}
	if len(errors) != 0 {
		return fail.NewError("%s failed to update inventory: %s", prerr, fail.NewErrorList(errors))
	}
	logrus.Debugf("%s update inventory successful: %v", prerr, tgr)

	return nil

}

// configureNodesFromList configures nodes from a list
func (instance *Cluster) configureNodesFromList(task concurrency.Task, nodes []*propertiesv3.ClusterNode, parameters data.Map) (ferr fail.Error) {
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	length := len(nodes)
	if length > 0 {
		tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		for i := 0; i < length; i++ {
			captured := i
			_, ierr := tg.Start(
				instance.taskConfigureNode, taskConfigureNodeParameters{
					index:     uint(captured + 1),
					node:      nodes[captured],
					variables: parameters,
				}, concurrency.InheritParentIDOption,
				concurrency.AmendID(fmt.Sprintf("/host/%s/configure", nodes[captured].Name)),
			)
			ierr = debug.InjectPlannedFail(ierr)
			if ierr != nil {
				abErr := tg.AbortWithCause(ierr)
				if abErr != nil {
					logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
				}
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
	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	logrus.Debugf("Joining nodes to Cluster...")

	// Joins to Cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending on the Cluster Flavor)
	instance.localCache.RLock()
	makers := instance.localCache.makers
	instance.localCache.RUnlock() // nolint
	if makers.JoinNodeToCluster != nil {
		for _, v := range nodes {
			hostInstance, xerr := LoadHost(task.Context(), instance.Service(), v.ID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			xerr = makers.JoinNodeToCluster(instance, hostInstance)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}

	return nil
}

// leaveNodesFromList makes nodes from a list leave the Cluster
func (instance *Cluster) leaveNodesFromList(ctx context.Context, hosts []resources.Host, selectedMaster resources.Host) (ferr fail.Error) {
	logrus.Debugf("Instructing nodes to leave Cluster...")

	// Un-joins from Cluster are done sequentially, experience shows too many (un)join at the same time
	// may fail (depending on the Cluster Flavor)
	instance.localCache.RLock()
	makers := instance.localCache.makers
	instance.localCache.RUnlock() // nolint
	if makers.LeaveNodeFromCluster != nil {
		var xerr fail.Error
		for _, node := range hosts {
			xerr = makers.LeaveNodeFromCluster(ctx, instance, node, selectedMaster)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}

	return nil
}

// BuildHostname builds a unique hostname in the Cluster
func (instance *Cluster) buildHostname(core string, nodeType clusternodetype.Enum) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var index int
	xerr := instance.Alter(
		func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(
				clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
					nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
					if !ok {
						return fail.InconsistentError(
							"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
						)
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
				},
			)
		},
	)
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
		_, xerr = tg.Start(
			instance.taskDeleteHostOnFailure, taskDeleteHostOnFailureParameters{host: h.(*Host)},
			concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s/delete", h.GetName())),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			errors = append(errors, xerr)
			abErr := tg.AbortWithCause(xerr)
			if abErr != nil {
				logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
			}
			break
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
func (instance *Cluster) ToProtocol() (_ *protocol.ClusterResponse, ferr fail.Error) {
	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// make sure no other parallel actions interferes
	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	xerr := instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.ClusterResponse{}
	xerr = instance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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

		if props.Lookup(clusterproperty.DefaultsV3) {
			innerXErr = props.Inspect(clusterproperty.DefaultsV3, func(clonable data.Clonable) fail.Error {
				defaultsV3, ok := clonable.(*propertiesv3.ClusterDefaults)
				if !ok {
					return fail.InconsistentError("'*propertiesv3.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				out.Defaults = converters.ClusterDefaultsFromPropertyV3ToProtocol(*defaultsV3)
				return nil
			})
		} else {
			innerXErr = props.Inspect(clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
				defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				out.Defaults = converters.ClusterDefaultsFromPropertyV2ToProtocol(*defaultsV2)
				return nil
			})
		}
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

		innerXErr = props.Inspect(
			clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
				featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				out.InstalledFeatures, out.DisabledFeatures = converters.ClusterFeaturesFromPropertyToProtocol(*featuresV1)
				return nil
			},
		)
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

// Shrink reduces cluster size by 'count' nodes
func (instance *Cluster) Shrink(ctx context.Context, count uint) (_ []*propertiesv3.ClusterNode, ferr fail.Error) {
	emptySlice := make([]*propertiesv3.ClusterNode, 0)
	if instance == nil || valid.IsNil(instance) {
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
	// instance.lock.Lock()
	// defer instance.lock.Unlock()

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
	xerr = instance.Alter(
		func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(
				clusterproperty.NodesV3, func(clonable data.Clonable) (innerXErr fail.Error) {
					nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
					if !ok {
						return fail.InconsistentError(
							"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
						)
					}

					length := uint(len(nodesV3.PrivateNodes))
					if length < count {
						return fail.InvalidRequestError(
							"cannot shrink by %d node%s, only %d node%s available", count, strprocess.Plural(count),
							length, strprocess.Plural(length),
						)
					}

					first := length - count
					toRemove = nodesV3.PrivateNodes[first:]
					nodesV3.PrivateNodes = nodesV3.PrivateNodes[:first]
					for _, v := range toRemove {
						if node, ok := nodesV3.ByNumericalID[v]; ok {
							removedNodes = append(removedNodes, node)
							delete(nodesV3.ByNumericalID, v)
							delete(nodesV3.PrivateNodeByID, node.ID)
							delete(nodesV3.PrivateNodeByName, node.Name)
						}
					}
					return nil
				},
			)
		},
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptySlice, nil
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := instance.Alter(
				func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
					return props.Alter(
						clusterproperty.NodesV3, func(clonable data.Clonable) (innerXErr fail.Error) {
							nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
							if !ok {
								return fail.InconsistentError(
									"'*propertiesv3.ClusterNodes' expected, '%s' provided",
									reflect.TypeOf(clonable).String(),
								)
							}

							nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, toRemove...)
							for _, v := range removedNodes {
								nodesV3.ByNumericalID[v.NumericalID] = v
								nodesV3.PrivateNodeByName[v.Name] = v.NumericalID
								nodesV3.PrivateNodeByID[v.ID] = v.NumericalID
							}
							return nil
						},
					)
				},
			)
			if derr != nil {
				_ = ferr.AddConsequence(
					fail.Wrap(
						derr, "cleaning up on %s, failed to restore Cluster nodes metadata", ActionFromError(ferr),
					),
				)
			}
		}
	}()

	if len(removedNodes) > 0 {
		tg, xerr := concurrency.NewTaskGroupWithParent(
			task, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/shrink/%d", len(removedNodes))),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return emptySlice, xerr
		}

		selectedMaster, xerr := instance.unsafeFindAvailableMaster(task.Context())
		if xerr != nil {
			return emptySlice, xerr
		}

		for _, v := range removedNodes {
			_, xerr = tg.Start(
				instance.taskDeleteNode,
				taskDeleteNodeParameters{node: v, master: selectedMaster.(*Host)},
				concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/node/%s/delete", v.Name)),
			)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				errors = append(errors, xerr)
				abErr := tg.AbortWithCause(xerr)
				if abErr != nil {
					logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
				}
				break
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
	xerr = instance.unsafeUpdateClusterInventory(task.Context())
	if xerr != nil {
		return emptySlice, xerr
	}

	return removedNodes, nil
}

// IsFeatureInstalled tells if a Feature identified by name is installed on Cluster, using only metadata
func (instance *Cluster) IsFeatureInstalled(ctx context.Context, name string) (found bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	found = false
	if instance == nil || valid.IsNil(instance) {
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

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

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
