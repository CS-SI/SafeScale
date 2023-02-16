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

package resources

import (
	"bytes"
	"context"
	"fmt"
	"math"
	mrand "math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	rscapi "github.com/CS-SI/SafeScale/v22/lib/backend/resources/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/consts"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/callstack"
	"github.com/eko/gocache/v2/store"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/converters"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/internal/clusterflavors"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/internal/clusterflavors/boh"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/internal/clusterflavors/k8s"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/template"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	clusterKind        = "cluster"
	clustersFolderName = "clusters" // path to use to reach Cluster Definitions/Metadata
)

// Cluster is the implementation of resources.Cluster interface
type Cluster struct {
	*metadata.Core[*abstract.Cluster]

	localCache struct {
		installMethods sync.Map
		makers         clusterflavors.Makers
	}

	machines map[string]*Host

	randomDelayTask func()
	randomDelayCh   <-chan int
}

var _ metadata.Metadata[*abstract.Cluster] = (*Cluster)(nil)

// NewCluster is the constructor of resources.Cluster struct
func NewCluster(ctx context.Context) (_ *Cluster, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	coreInstance, xerr := metadata.NewCore(ctx, metadata.MethodObjectStorage, clusterKind, clustersFolderName, abstract.NewEmptyCluster())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &Cluster{
		Core:     coreInstance,
		machines: make(map[string]*Host),
	}
	xerr = instance.startRandomDelayGenerator(ctx, 0, 2000)
	if xerr != nil {
		return nil, xerr
	}

	return instance, nil
}

// newEmptyCluster ...
func newBulkCluster() (*Cluster, fail.Error) {
	protected, err := abstract.NewCluster()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	core, err := metadata.NewEmptyCore(abstract.ClusterKind, protected)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	instance := &Cluster{Core: core}
	return instance, nil
}

// Exists checks if the resource actually exists in provider side (not in stow metadata)
func (instance *Cluster) Exists(ctx context.Context) (_ bool, ferr fail.Error) {
	// FIXME: Requires iteration of quite a few members...
	if instance == nil || instance.Core == nil {
		return false, fail.InvalidInstanceError()
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return false, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	// begin by inspecting all hosts...
	ci, xerr := clusterTrx.getIdentity(ctx)
	if xerr != nil {
		return false, xerr
	}

	gws, xerr := clusterTrx.getGatewayIDs(ctx)
	if xerr != nil {
		return false, xerr
	}

	hostInstance, xerr := LoadHost(ctx, fmt.Sprintf("gw-%s", ci.Name))
	if xerr != nil {
		return false, xerr
	}

	exists, xerr := hostInstance.Exists(ctx)
	if xerr != nil {
		return false, xerr
	}

	if !exists {
		return false, abstract.ResourceNotFoundError("host", fmt.Sprintf("gw-%s", ci.Name))
	}

	if len(gws) == 2 {
		rh, xerr := LoadHost(ctx, fmt.Sprintf("gw2-%s", ci.Name))
		if xerr != nil {
			return false, xerr
		}

		exists, xerr := rh.Exists(ctx)
		if xerr != nil {
			return false, xerr
		}

		if !exists {
			return false, abstract.ResourceNotFoundError("host", fmt.Sprintf("gw2-%s", ci.Name))
		}
	}

	mids, xerr := trxListMasters(ctx, clusterTrx)
	if xerr != nil {
		return false, xerr
	}

	for _, mid := range mids {
		hostInstance, xerr := LoadHost(ctx, mid.Name)
		if xerr != nil {
			return false, xerr
		}

		exists, xerr := hostInstance.Exists(ctx)
		if xerr != nil {
			return false, xerr
		}

		if !exists {
			return false, abstract.ResourceNotFoundError("host", mid.Name)
		}
	}

	nids, xerr := instance.trxListNodes(ctx, clusterTrx)
	if xerr != nil {
		return false, xerr
	}

	for _, nid := range nids {
		hostInstance, xerr := LoadHost(ctx, nid.Name)
		if xerr != nil {
			return false, xerr
		}

		exists, xerr := hostInstance.Exists(ctx)
		if xerr != nil {
			return false, xerr
		}

		if !exists {
			return false, abstract.ResourceNotFoundError("host", nid.Name)
		}
	}

	return true, nil
}

// StartRandomDelayGenerator starts a Task to generate random delays, read from instance.randomDelayCh
func (instance *Cluster) startRandomDelayGenerator(ctx context.Context, min, max int) fail.Error {
	chint := make(chan int)
	mrand.Seed(time.Now().UnixNano())

	instance.randomDelayTask = func() {
		defer close(chint)
		if min == max {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					chint <- min
				}
			}
		} else {
			value := max - min
			for {
				select {
				case <-ctx.Done():
					return
				default:
					chint <- mrand.Intn(value) + min // nolint
				}
			}
		}
	}
	go instance.randomDelayTask()

	instance.randomDelayCh = chint
	return nil
}

// LoadCluster loads cluster information from metadata
func LoadCluster(inctx context.Context, name string) (_ *Cluster, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	myjob, xerr := jobapi.FromContext(inctx)
	if xerr != nil {
		return nil, xerr
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type localresult struct {
		rTr  *Cluster
		rErr fail.Error
	}

	chRes := make(chan localresult)
	go func() {
		defer close(chRes)

		ga, gerr := func() (_ *Cluster, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// trick to avoid collisions
			var kt *Cluster
			refcache := fmt.Sprintf("%T/%s", kt, name)

			cache, xerr := myjob.Service().Cache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			var (
				clusterInstance *Cluster
				inCache         bool
				err             error
			)
			if cache != nil {
				entry, err := cache.Get(ctx, refcache)
				if err == nil {
					clusterInstance, err = lang.Cast[*Cluster](entry)
					if err != nil {
						return nil, fail.Wrap(err)
					}

					inCache = true

					// -- reload from metadata storage
					xerr := clusterInstance.Core.Reload(ctx)
					if xerr != nil {
						return nil, xerr
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}
			if clusterInstance == nil {
				anon, xerr := onClusterCacheMiss(ctx, name)
				if xerr != nil {
					return nil, xerr
				}

				clusterInstance, err = lang.Cast[*Cluster](anon)
				if err != nil {
					return nil, fail.Wrap(err)
				}
			}

			if clusterInstance.randomDelayCh == nil {
				xerr = clusterInstance.startRandomDelayGenerator(ctx, 0, 2000)
				if xerr != nil {
					return nil, xerr
				}
			}

			if cache != nil && !inCache {
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, clusterInstance.GetName()), clusterInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.Wrap(err)
				}

				time.Sleep(10 * time.Millisecond) // consolidate cache.Set
				entry, xerr := cache.Get(ctx, name)
				if xerr == nil {
					_, err := lang.Cast[*Cluster](entry)
					if err != nil {
						logrus.WithContext(ctx).Warnf("wrong type of *Cluster")
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}

			if myjob.Service().Capabilities().UseTerraformer {
				clusterTrx, xerr := newClusterTransaction(ctx, clusterInstance)
				if xerr != nil {
					return nil, xerr
				}
				defer clusterTrx.TerminateFromError(ctx, &ferr)

				xerr = inspectClusterMetadataAbstract(ctx, clusterTrx, func(ac *abstract.Cluster) fail.Error {
					_, innerXErr := myjob.Scope().RegisterAbstractIfNeeded(ac)
					return innerXErr
				})
				if xerr != nil {
					return nil, xerr
				}
			}

			return clusterInstance, nil
		}()
		chRes <- localresult{ga, gerr}
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}
}

// onClusterCacheMiss is called when cluster cache does not contain an instance of cluster 'name'
func onClusterCacheMiss(inctx context.Context, name string) (_ data.Identifiable, ferr fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	clusterInstance, xerr := NewCluster(ctx)
	if xerr != nil {
		return nil, xerr
	}

	xerr = clusterInstance.Read(ctx, name)
	if xerr != nil {
		return nil, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, clusterInstance)
	if xerr != nil {
		return nil, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	flavor, xerr := trxGetFlavor(ctx, clusterTrx)
	if xerr != nil {
		return nil, xerr
	}

	xerr = clusterInstance.bootstrap(flavor)
	if xerr != nil {
		return nil, xerr
	}

	xerr = clusterInstance.updateCachedInformation(ctx, clusterTrx)
	if xerr != nil {
		return nil, xerr
	}

	return clusterInstance, nil
}

// updateCachedInformation updates information cached in the instance
func (instance *Cluster) updateCachedInformation(inctx context.Context, clusterTrx clusterTransaction) fail.Error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		i := 0
		instance.localCache.installMethods.Range(func(key, value interface{}) bool {
			i++
			return true
		})

		if i != 0 { // if there is something in here, quit
			chRes <- result{nil}
			return
		}

		var index uint8
		flavor, err := trxGetFlavor(ctx, clusterTrx)
		if err != nil {
			chRes <- result{err}
			return
		}
		if flavor == clusterflavor.K8S {
			index++
			instance.localCache.installMethods.Store(index, installmethod.Helm)
		}

		// this is wrong, localCache.installMethods should have installmethod.Bash and installmethod.None upon creation, not added later
		index++
		instance.localCache.installMethods.Store(index, installmethod.Bash)
		index++
		instance.localCache.installMethods.Store(index, installmethod.None)
		chRes <- result{nil}
	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// IsNull tells if the instance should be considered as a null value
func (instance *Cluster) IsNull() bool {
	return instance == nil || valid.IsNil(instance.Core)
}

func (instance *Cluster) Clone() (clonable.Clonable, error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}

	newInstance, xerr := newBulkCluster()
	if xerr != nil {
		return nil, xerr
	}

	return newInstance, newInstance.Replace(instance)
}

func (instance *Cluster) Replace(in clonable.Clonable) error {
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*Cluster](in)
	if err != nil {
		return err
	}

	err = instance.Core.Replace(src.Core)
	if err != nil {
		return err
	}

	src.localCache.installMethods.Range(func(k, v interface{}) bool {
		instance.localCache.installMethods.Store(k, v)
		return true
	})
	instance.localCache.makers = src.localCache.makers

	instance.machines = make(map[string]*Host, len(src.machines))
	for k, v := range src.machines {
		instance.machines[k] = v
	}

	return nil
}

// Carry ...
func (instance *Cluster) Carry(inctx context.Context, ac *abstract.Cluster) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) && instance.IsTaken() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	// Note: do not validate parameters, this call will do it
	xerr := instance.Core.Carry(ctx, ac)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Create creates the necessary infrastructure of the Cluster
func (instance *Cluster) Create(inctx context.Context, req abstract.ClusterRequest) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if !valid.IsNil(instance.Core) && instance.IsTaken() {
				return fail.InconsistentError("already carrying information")
			}
			if ctx == nil {
				return fail.InvalidParameterCannotBeNilError("ctx")
			}

			xerr := instance.createCluster(ctx, req)
			if xerr != nil {
				return xerr
			}

			logrus.WithContext(ctx).Tracef("Cluster creation finished")

			return nil
		}()
		chRes <- result{gerr}
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// Deserialize reads json code and recreates Cluster metadata
func (instance *Cluster) Deserialize(_ context.Context, buf []byte) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	if len(buf) == 0 {
		return fail.InvalidParameterError("buf", "cannot be empty []byte")
	}

	err := json.Unmarshal(buf, instance) // nolint
	return fail.Wrap(err)
}

// bootstrap (re)connects controller with the appropriate Makers
func (instance *Cluster) bootstrap(flavor clusterflavor.Enum) (ferr fail.Error) {
	switch flavor {
	case clusterflavor.BOH:
		instance.localCache.makers = boh.Makers
	case clusterflavor.K8S:
		instance.localCache.makers = k8s.Makers
	default:
		return fail.InvalidParameterError("unknown Cluster Flavor '%d'", flavor)
	}
	return nil
}

// Browse walks through Cluster MetadataFolder and executes a callback for each entry
// FIXME: adds a Cluster status check to prevent operations on removed clusters
func (instance *Cluster) Browse(inctx context.Context, callback func(*abstract.Cluster) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	return instance.BrowseFolder(ctx, func(buf []byte) fail.Error {
		aci, _ := abstract.NewCluster()
		xerr := aci.Deserialize(buf)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		return callback(aci)
	})
}

// GetIdentity returns the identity of the Cluster
func (instance *Cluster) GetIdentity(ctx context.Context) (clusterIdentity abstract.Cluster, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return abstract.Cluster{}, fail.InvalidInstanceError()
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return abstract.Cluster{}, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.getIdentity(ctx)
}

// GetFlavor returns the flavor of the Cluster
func (instance *Cluster) GetFlavor(ctx context.Context) (flavor clusterflavor.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return 0, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	return trxGetFlavor(ctx, trx)
}

// GetComplexity returns the complexity of the Cluster
func (instance *Cluster) GetComplexity(ctx context.Context) (_ clustercomplexity.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return 0, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	return trxGetComplexity(ctx, trx)
}

// GetAdminPassword returns the password of the Cluster admin account
// satisfies interface Cluster.Controller
func (instance *Cluster) GetAdminPassword(ctx context.Context) (adminPassword string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	aci, xerr := instance.GetIdentity(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}
	return aci.AdminPassword, nil
}

// GetKeyPair returns the key pair used in the Cluster
func (instance *Cluster) GetKeyPair(ctx context.Context) (keyPair *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	aci, xerr := instance.GetIdentity(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return aci.Keypair, nil
}

// GetNetworkConfig returns subnet configuration of the Cluster
func (instance *Cluster) GetNetworkConfig(ctx context.Context) (config *propertiesv3.ClusterNetwork, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = inspectClusterMetadataProperty(ctx, trx, clusterproperty.NetworkV3, func(networkV3 *propertiesv3.ClusterNetwork) fail.Error {
		config = networkV3
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if config == nil {
		return nil, fail.InconsistentError("config should NOT be nil")
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

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	// If the Cluster is in state Stopping or Stopped, do nothing
	var prevState clusterstate.Enum
	prevState, xerr = instance.trxGetState(ctx, trx)
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
				select {
				case <-ctx.Done():
					return retry.StopRetryError(ctx.Err())
				default:
				}

				state, innerErr := instance.trxGetState(ctx, trx)
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
		return fail.NotAvailableError("failed to start Cluster because of its current state: %s", prevState.String())
	}

	// First mark Cluster to be in state Starting
	xerr = alterClusterMetadataProperty(ctx, trx, clusterproperty.StateV1, func(stateV1 *propertiesv1.ClusterState) fail.Error {
		stateV1.State = clusterstate.Starting
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Commit now to save changing status of Cluster
	xerr = trx.Commit(ctx)
	if xerr != nil {
		return fail.Wrap(xerr)
	}

	var (
		nodes                         []string
		masters                       []string
		gatewayID, secondaryGatewayID string
	)

	// Then start it and mark it as NOMINAL on success
	xerr = alterClusterMetadataProperties(ctx, trx, func(props *serialize.JSONProperties) fail.Error {
		innerXErr := props.Inspect(clusterproperty.NodesV3, func(p clonable.Clonable) fail.Error {
			nodesV3, err := lang.Cast[*propertiesv3.ClusterNodes](p)
			if err != nil {
				return fail.Wrap(err)
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

		innerXErr = props.Inspect(clusterproperty.NetworkV3, func(p clonable.Clonable) fail.Error {
			networkV3, err := lang.Cast[*propertiesv3.ClusterNetwork](p)
			if err != nil {
				return fail.Wrap(err)
			}

			gatewayID = networkV3.GatewayID
			secondaryGatewayID = networkV3.SecondaryGatewayID
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Mark Cluster as state Starting
		return props.Alter(clusterproperty.StateV1, func(p clonable.Clonable) fail.Error {
			stateV1, err := lang.Cast[*propertiesv1.ClusterState](p)
			if err != nil {
				return fail.Wrap(err)
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
	runGroup := new(errgroup.Group)
	runGroup.Go(func() error {
		_, err := instance.taskStartHost(ctx, gatewayID)
		return err
	})

	if secondaryGatewayID != "" {
		runGroup.Go(func() error {
			_, err := instance.taskStartHost(ctx, secondaryGatewayID)
			return err
		})
	}

	// Start masters
	for _, n := range masters {
		n := n
		runGroup.Go(func() error {
			_, err := instance.taskStartHost(ctx, n)
			return err
		})
	}

	// Start nodes
	for _, n := range nodes {
		n := n
		runGroup.Go(func() error {
			_, err := instance.taskStartHost(ctx, n)
			return err
		})
	}

	xerr = fail.Wrap(runGroup.Wait())
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
		xerr = alterClusterMetadataProperty(ctx, trx, clusterproperty.StateV1, func(stateV1 *propertiesv1.ClusterState) fail.Error {
			stateV1.State = clusterstate.Degraded
			return nil
		})
		if xerr != nil {
			_ = outerr.AddConsequence(xerr)
		}
		return outerr
	}

	return metadata.AlterProperty[*abstract.Cluster, *propertiesv1.ClusterState](ctx, trx, clusterproperty.StateV1, func(stateV1 *propertiesv1.ClusterState) fail.Error {
		stateV1.State = clusterstate.Nominal
		return nil
	})
}

// Stop stops the Cluster
func (instance *Cluster) Stop(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	trx, err := newClusterTransaction(ctx, instance)
	if err != nil {
		return fail.Wrap(err)
	}
	defer trx.TerminateFromError(ctx, &ferr)

	// If the Cluster is stopped, do nothing
	var prevState clusterstate.Enum
	prevState, xerr = instance.trxGetState(ctx, trx)
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
				select {
				case <-ctx.Done():
					return retry.StopRetryError(ctx.Err())
				default:
				}

				state, innerErr := instance.trxGetState(ctx, trx)
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
		return fail.NotAvailableError("failed to stop Cluster because of its current state: %s", prevState.String())
	}

	// First mark Cluster to be in state Stopping
	xerr = alterClusterMetadataProperty(ctx, trx, clusterproperty.StateV1, func(stateV1 *propertiesv1.ClusterState) fail.Error {
		stateV1.State = clusterstate.Stopping
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Change cluster state in metadata as soon as possible
	xerr = trx.Commit(ctx)
	if xerr != nil {
		return xerr
	}

	// Then stop it and mark it as STOPPED on success
	return alterClusterMetadata(ctx, trx, func(_ *abstract.Cluster, props *serialize.JSONProperties) fail.Error {
		var (
			nodes                         []string
			masters                       []string
			gatewayID, secondaryGatewayID string
		)
		innerXErr := props.Inspect(clusterproperty.NodesV3, func(p clonable.Clonable) fail.Error {
			nodesV3, innerErr := lang.Cast[*propertiesv3.ClusterNodes](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
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

		innerXErr = props.Inspect(clusterproperty.NetworkV3, func(p clonable.Clonable) fail.Error {
			networkV3, innerErr := lang.Cast[*propertiesv3.ClusterNetwork](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			gatewayID = networkV3.GatewayID
			secondaryGatewayID = networkV3.SecondaryGatewayID
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Stop nodes
		egStopHosts := new(errgroup.Group)

		for _, n := range nodes {
			n := n
			egStopHosts.Go(func() error {
				_, err := instance.taskStopHost(ctx, n)
				return err
			})
		}
		// Stop masters
		for _, n := range masters {
			n := n
			egStopHosts.Go(func() error {
				_, err := instance.taskStopHost(ctx, n)
				return err
			})
		}
		// Stop gateway(s)
		egStopHosts.Go(func() error {
			_, err := instance.taskStopHost(ctx, gatewayID)
			return err
		})

		if secondaryGatewayID != "" {
			egStopHosts.Go(func() error {
				_, err := instance.taskStopHost(ctx, secondaryGatewayID)
				return err
			})
		}

		innerXErr = fail.Wrap(egStopHosts.Wait())
		if innerXErr != nil {
			return innerXErr
		}

		return props.Alter(clusterproperty.StateV1, func(p clonable.Clonable) fail.Error {
			stateV1, innerErr := lang.Cast[*propertiesv1.ClusterState](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			stateV1.State = clusterstate.Stopped
			return nil
		})
	})
}

// GetState returns the current state of the Cluster
// Uses the "maker" ForceGetState
func (instance *Cluster) GetState(ctx context.Context) (state clusterstate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	state = clusterstate.Unknown
	if valid.IsNil(instance) {
		return state, fail.InvalidInstanceError()
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return state, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	return instance.trxGetState(ctx, trx)
}

// AddNodes adds several nodes
func (instance *Cluster) AddNodes(ctx context.Context, count uint, def abstract.HostSizingRequirements, parameters data.Map[string, any], keepOnFailure bool) (_ []*Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if count == 0 {
		return nil, fail.InvalidParameterError("count", "must be an int > 0")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%d)", count)
	defer tracer.Entering().Exiting()

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, clusterTrx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	var (
		hostImage             string
		nodeDefaultDefinition *propertiesv2.HostSizingRequirements
	)
	xerr = inspectClusterMetadata(ctx, clusterTrx, func(_ *abstract.Cluster, props *serialize.JSONProperties) fail.Error {
		if props.Lookup(clusterproperty.DefaultsV3) {
			return props.Inspect(clusterproperty.DefaultsV3, func(p clonable.Clonable) fail.Error {
				defaultsV3, innerErr := lang.Cast[*propertiesv3.ClusterDefaults](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
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

		// Cluster may have been created before ClusterDefaultV3, so still support this property
		return props.Inspect(clusterproperty.DefaultsV2, func(p clonable.Clonable) fail.Error {
			defaultsV2, innerErr := lang.Cast[*propertiesv2.ClusterDefaults](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
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

	nodeDef := complementHostDefinition(def, *nodeDefaultDefinition)
	if def.Image != "" {
		hostImage = def.Image
	}

	svc := instance.Service()
	_, nodeDef.Image, xerr = determineImageID(ctx, svc, hostImage)
	if xerr != nil {
		return nil, xerr
	}

	var (
		nodes []*propertiesv3.ClusterNode
	)

	timings, xerr := svc.Timings()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	timeout := time.Duration(count) * timings.HostCreationTimeout() // More than enough
	winSize := 8
	cfg, xerr := svc.ConfigurationOptions()
	if xerr == nil {
		winSize = cfg.ConcurrentMachineCreationLimit
	}

	// for OVH, we have to ignore the errors and keep trying until we have 'count'
	nodesChan := make(chan StdResult, count)
	err := runWindow(ctx, clusterTrx, count, uint(math.Min(float64(count), float64(winSize))), timeout, nodesChan, instance.taskCreateNode, taskCreateNodeParameters{
		nodeDef:       nodeDef,
		timeout:       timings.HostCreationTimeout(),
		keepOnFailure: keepOnFailure,
	})
	if err != nil {
		close(nodesChan)
		return nil, fail.Wrap(err)
	}

	close(nodesChan)
	for v := range nodesChan {
		if v.Err != nil {
			continue
		}
		if v.ToBeDeleted {
			_, xerr = instance.trxDeleteNodeWithCtx(cleanupContextFrom(ctx), clusterTrx, v.Content.(*propertiesv3.ClusterNode), nil)
			debug.IgnoreErrorWithContext(ctx, xerr)
			continue
		}
		nodes = append(nodes, v.Content.(*propertiesv3.ClusterNode))
	}

	// Starting from here, if exiting with error, Delete created nodes if allowed (cf. keepOnFailure)
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && !keepOnFailure && len(nodes) > 0 {
			egDeletion := new(errgroup.Group)

			for _, v := range nodes {
				v := v
				egDeletion.Go(func() error {
					_, err := instance.trxDeleteNodeWithCtx(cleanupContextFrom(ctx), clusterTrx, v, nil)
					return err
				})
			}
			derr := fail.Wrap(egDeletion.Wait())
			derr = debug.InjectPlannedFail(derr)
			if derr != nil {
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

	// configure what has to be done Cluster-wide
	makers := instance.localCache.makers
	if makers.ConfigureCluster != nil {
		xerr = makers.ConfigureCluster(ctx, instance, parameters)
		if xerr != nil {
			return nil, xerr
		}
	}
	incrementExpVar("cluster.cache.hit")

	// Now configure new nodes
	xerr = instance.trxConfigureNodesFromList(ctx, clusterTrx, nodes, parameters)
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

	hosts := make([]*Host, 0, len(nodes))
	for _, v := range nodes {
		hostInstance, xerr := LoadHost(ctx, v.ID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		hosts = append(hosts, hostInstance)
	}

	xerr = instance.updateClusterInventory(ctx, clusterTrx)
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

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if hostID = strings.TrimSpace(hostID); hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(hostID=%s)", hostID).Entering()
	defer tracer.Exiting()

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	var selectedMaster *Host
	if selectedMasterID != "" {
		selectedMaster, xerr = LoadHost(ctx, selectedMasterID)
	} else {
		selectedMaster, xerr = instance.trxFindAvailableMaster(ctx, trx)
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	var node *propertiesv3.ClusterNode
	xerr = inspectClusterMetadataProperty(ctx, trx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return instance.trxDeleteNode(cleanupContextFrom(ctx), trx, node, selectedMaster)
}

// ListMasters lists the node instances corresponding to masters (if there is such masters in the flavor...)
func (instance *Cluster) ListMasters(ctx context.Context) (list rscapi.IndexedListOfClusterNodes, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := rscapi.IndexedListOfClusterNodes{}
	if valid.IsNil(instance) {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	return trxListMasters(ctx, trx)
}

// ListMasterNames lists the names of the master nodes in the Cluster
func (instance *Cluster) ListMasterNames(ctx context.Context) (list data.IndexedListOfStrings, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := data.IndexedListOfStrings{}
	if valid.IsNil(instance) {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	xerr = inspectClusterMetadataProperty(ctx, trx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
		list = make(data.IndexedListOfStrings, len(nodesV3.Masters))
		for _, v := range nodesV3.Masters {
			if node, found := nodesV3.ByNumericalID[v]; found {
				list[node.NumericalID] = node.Name
			}
		}
		return nil
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
	if valid.IsNil(instance) {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	return instance.trxListMasterIDs(ctx, trx)
}

// ListMasterIPs lists the IPs of masters (if there is such masters in the flavor...)
func (instance *Cluster) ListMasterIPs(ctx context.Context) (list data.IndexedListOfStrings, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := data.IndexedListOfStrings{}
	if valid.IsNil(instance) {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	return instance.trxListMasterIPs(ctx, trx)
}

// FindAvailableMaster returns ID of the first master available to execute order
// satisfies interface Cluster.Cluster.Controller
func (instance *Cluster) FindAvailableMaster(ctx context.Context) (master *Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return instance.trxFindAvailableMaster(ctx, trx)
}

// ListNodes lists node instances corresponding to the nodes in the Cluster
// satisfies interface Cluster.Controller
func (instance *Cluster) ListNodes(ctx context.Context) (list rscapi.IndexedListOfClusterNodes, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := rscapi.IndexedListOfClusterNodes{}
	if valid.IsNil(instance) {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return instance.trxListNodes(ctx, trx)
}

// trxBeingRemoved tells if the Cluster is currently marked as Removed (meaning a removal operation is running)
func (instance *Cluster) trxBeingRemoved(ctx context.Context, clusterTrx clusterTransaction) fail.Error {
	state, xerr := instance.trxGetState(ctx, clusterTrx)
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
	if valid.IsNil(instance) {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	xerr = inspectClusterMetadataProperty(ctx, trx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
		list = make(data.IndexedListOfStrings, len(nodesV3.PrivateNodes))
		for _, v := range nodesV3.PrivateNodes {
			if node, found := nodesV3.ByNumericalID[v]; found {
				list[node.NumericalID] = node.Name
			}
		}
		return nil
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
	if valid.IsNil(instance) {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	return instance.trxListNodeIDs(ctx, trx)
}

// ListNodeIPs lists the IPs of the nodes in the Cluster
func (instance *Cluster) ListNodeIPs(ctx context.Context) (list data.IndexedListOfStrings, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := data.IndexedListOfStrings{}
	if valid.IsNil(instance) {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	return instance.trxListNodeIPs(ctx, trx)
}

// FindAvailableNode returns node instance of the first node available to execute order
func (instance *Cluster) FindAvailableNode(ctx context.Context) (node *Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return instance.trxFindAvailableNode(ctx, trx)
}

// LookupNode tells if the ID of the master passed as parameter is a node
func (instance *Cluster) LookupNode(ctx context.Context, ref string) (found bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return false, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if ref == "" {
		return false, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return false, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

	hostInstance, xerr := LoadHost(ctx, ref)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

	found = false
	xerr = inspectClusterMetadataProperty(ctx, trx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
		hid, innerErr := hostInstance.GetID()
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		_, found = nodesV3.PrivateNodeByID[hid]
		return nil
	})
	return found, xerr
}

// CountNodes counts the nodes of the Cluster
func (instance *Cluster) CountNodes(ctx context.Context) (count uint, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return 0, fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return 0, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	xerr = inspectClusterMetadataProperty(ctx, trx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
		count = uint(len(nodesV3.PrivateNodes))
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return count, nil
}

// GetNodeByID returns a node based on its ID
func (instance *Cluster) GetNodeByID(ctx context.Context, hostID string) (_ *Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostID == "" {
		return nil, fail.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%s)", hostID)
	defer tracer.Entering().Exiting()

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	found := false
	xerr = inspectClusterMetadataProperty(ctx, trx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
		_, found = nodesV3.PrivateNodeByID[hostID]
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	if !found {
		return nil, fail.NotFoundError("failed to find node %s in Cluster '%s'", hostID, instance.GetName())
	}

	return LoadHost(ctx, hostID)
}

// deleteMaster deletes the master specified by its ID
func (instance *Cluster) deleteMaster(ctx context.Context, clusterTrx clusterTransaction, host string) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if valid.IsNil(host) {
		return fail.InvalidParameterCannotBeNilError("host")
	}

	// FIXME: Bad idea, the first thing to go must be the resource, then the metadata; if not we can have zombie instances without metadata (it happened)
	// which means that the code doing the "restore" never worked

	// Removes master from Cluster properties
	xerr := alterClusterMetadataProperty(cleanupContextFrom(ctx), clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
		hid := host
		numericalID, found := nodesV3.MasterByID[hid]
		if !found {
			return abstract.ResourceNotFoundError("master", host)
		}

		delete(nodesV3.ByNumericalID, numericalID)
		delete(nodesV3.MasterByID, hid)
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	lh, xerr := LoadHost(ctx, host)
	if xerr != nil {
		return xerr
	}

	xerr = lh.Delete(ctx)
	if xerr != nil {
		return xerr
	}

	return nil
}

// trxDeleteNode deletes a node
func (instance *Cluster) trxDeleteNode(inctx context.Context, clusterTrx clusterTransaction, node *propertiesv3.ClusterNode, master *Host) (_ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
			defer tracer.Exiting()

			nodeRef := node.ID
			if nodeRef == "" {
				nodeRef = node.Name
			}

			// Identify the node to Delete and remove it preventively from metadata
			xerr := alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
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
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{xerr}, xerr
			}

			// VPL: trx.Rollback should take care of not saving metadata on failure, so this code becomes useless
			// // Starting from here, restore node in Cluster metadata if exiting with error
			// defer func() {
			// 	ferr = debug.InjectPlannedFail(ferr)
			// 	if ferr != nil {
			// 		derr := alterClusterMetadataProperty(jobapi.NewContextPropagatingJob(inctx), trx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
			// 			nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, node.NumericalID)
			// 			if node.Name != "" {
			// 				nodesV3.PrivateNodeByName[node.Name] = node.NumericalID
			// 			}
			// 			if node.ID != "" {
			// 				nodesV3.PrivateNodeByID[node.ID] = node.NumericalID
			// 			}
			// 			nodesV3.ByNumericalID[node.NumericalID] = node
			// 			return nil
			// 		})
			// 		if derr != nil {
			// 			logrus.WithContext(context.Background()).Errorf("failed to restore node ownership in Cluster")
			// 			_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to restore node ownership in Cluster metadata", ActionFromError(ferr)))
			// 		}
			// 	}
			// }()

			// Deletes node
			hostInstance, xerr := LoadHost(ctx, nodeRef)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// Host already deleted, consider as a success, continue
					return result{nil}, nil // nolint
				default:
					return result{xerr}, xerr
				}
			}

			// host still exists, leave it from Cluster, if master is not null
			if master != nil && !valid.IsNil(master) {
				xerr = instance.leaveNodesFromList(ctx, []*Host{hostInstance}, master)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return result{xerr}, xerr
				}

				makers := instance.localCache.makers
				incrementExpVar("cluster.cache.hit")
				if makers.UnconfigureNode != nil {
					xerr = makers.UnconfigureNode(instance, hostInstance, master)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						return result{xerr}, xerr
					}
				}
			}

			hid, _ := hostInstance.GetID()

			// Finally Delete host
			xerr = hostInstance.Delete(cleanupContextFrom(ctx))
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// Host seems already deleted, so it's a success
				default:
					return result{xerr}, xerr
				}
			}

			delete(instance.machines, hid)
			return result{nil}, nil // nolint
		}() // nolint
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		<-chRes // wait for defer cleanup
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for defer cleanup
		return fail.Wrap(inctx.Err())
	}
}

// Delete deletes the Cluster
func (instance *Cluster) Delete(ctx context.Context, force bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	if !force {
		xerr := instance.trxBeingRemoved(ctx, trx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	return instance.trxDelete(ctx, trx)
}

// trxDelete does the work to Delete Cluster
func (instance *Cluster) trxDelete(inctx context.Context, clusterTrx clusterTransaction) (_ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type localresult struct {
		rErr fail.Error
	}
	chRes := make(chan localresult)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ localresult, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			var cleaningErrors []error

			if valid.IsNil(instance) {
				xerr := fail.InvalidInstanceError()
				return localresult{xerr}, xerr
			}

			// Special treatment for cluster state, it must be updated, so we need to first rollback changes then alter state followed by a commit
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil {
					derr := clusterTrx.Rollback(ctx)
					if derr != nil {
						_ = ferr.AddConsequence(derr)
					}

					ctx := jobapi.NewContextPropagatingJob(inctx)
					derr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.StateV1, func(stateV1 *propertiesv1.ClusterState) fail.Error {
						stateV1.State = clusterstate.Degraded
						return nil
					})
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to set Cluster state to DEGRADED", ActionFromError(ferr)))
					} else {
						derr = clusterTrx.Commit(ctx)
						if derr != nil {
							_ = ferr.AddConsequence(derr)
						}
					}
				}
			}()

			var (
				all            map[uint]*propertiesv3.ClusterNode
				nodes, masters []uint
			)
			// Mark the Cluster as Removed and get nodes from properties
			xerr := alterClusterMetadataProperties(ctx, clusterTrx, func(props *serialize.JSONProperties) fail.Error {
				// Updates Cluster state to mark Cluster as Removing
				innerXErr := props.Alter(clusterproperty.StateV1, func(p clonable.Clonable) fail.Error {
					stateV1, innerErr := lang.Cast[*propertiesv1.ClusterState](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					stateV1.State = clusterstate.Removed
					return nil
				})
				if innerXErr != nil {
					return innerXErr
				}

				return props.Inspect(clusterproperty.NodesV3, func(p clonable.Clonable) fail.Error {
					nodesV3, innerErr := lang.Cast[*propertiesv3.ClusterNodes](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					nodes = nodesV3.PrivateNodes
					masters = nodesV3.Masters
					all = nodesV3.ByNumericalID
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return localresult{xerr}, xerr
			}

			xerr = clusterTrx.Commit(ctx)
			if xerr != nil {
				return localresult{xerr}, xerr
			}

			masterCount, nodeCount := len(masters), len(nodes)
			if masterCount+nodeCount > 0 {
				egKill := new(errgroup.Group)

				foundSomething := false
				for _, v := range nodes {
					v := v
					if n, ok := all[v]; ok {
						foundSomething = true

						egKill.Go(func() error {
							_, err := instance.trxDeleteNodeWithCtx(cleanupContextFrom(ctx), clusterTrx, n, nil)
							return err
						})
					}
				}

				for _, v := range masters {
					v := v
					if n, ok := all[v]; ok {
						foundSomething = true

						egKill.Go(func() error {
							_, err := instance.trxDeleteMaster(cleanupContextFrom(ctx), clusterTrx, n)
							return err
						})
					}
				}

				if foundSomething {
					xerr = fail.Wrap(egKill.Wait())
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						cleaningErrors = append(cleaningErrors, xerr)
					}
				}
			}
			if len(cleaningErrors) > 0 {
				xerr = fail.Wrap(fail.NewErrorList(cleaningErrors), "failed to Delete Hosts")
				return localresult{xerr}, xerr
			}

			// From here, make sure there is nothing in nodesV3.ByNumericalID; if there is something, Delete all the remaining
			xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
				all = nodesV3.ByNumericalID
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return localresult{xerr}, xerr
			}

			allCount := len(all)
			if allCount > 0 {
				egKill := new(errgroup.Group)

				for _, v := range all {
					v := v
					egKill.Go(func() error {
						_, err := instance.trxDeleteNodeWithCtx(cleanupContextFrom(ctx), clusterTrx, v, nil)
						return err
					})
				}

				xerr = fail.Wrap(egKill.Wait())
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					cleaningErrors = append(cleaningErrors, xerr)
				}
				if len(cleaningErrors) > 0 {
					xerr = fail.Wrap(fail.NewErrorList(cleaningErrors), "failed to Delete Hosts")
					return localresult{xerr}, xerr
				}
			}

			// --- Deletes the Network, Subnet and gateway ---
			networkInstance, deleteNetwork, subnetInstance, xerr := instance.trxExtractNetworkingInfo(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// missing Network and Subnet is considered as a successful deletion, continue
					debug.IgnoreErrorWithContext(ctx, xerr)
				default:
					return localresult{xerr}, xerr
				}
			}

			svc := instance.Service()
			timings, xerr := svc.Timings()
			if xerr != nil {
				return localresult{xerr}, xerr
			}

			if subnetInstance != nil && !valid.IsNil(subnetInstance) {
				subnetName := subnetInstance.GetName()
				logrus.WithContext(ctx).Debugf("Cluster Deleting Subnet '%s'", subnetName)
				xerr = retry.WhileUnsuccessfulWithHardTimeout(
					func() error {
						select {
						case <-ctx.Done():
							return retry.StopRetryError(ctx.Err())
						default:
						}

						innerXErr := subnetInstance.Delete(cleanupContextFrom(ctx))
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
						debug.IgnoreErrorWithContext(ctx, xerr)
					case *fail.ErrTimeout, *fail.ErrAborted:
						nerr := fail.Wrap(fail.Cause(xerr))
						switch nerr.(type) {
						case *fail.ErrNotFound:
							// Subnet not found, considered as a successful deletion and continue
							debug.IgnoreErrorWithContext(ctx, nerr)
						default:
							xerr = fail.Wrap(nerr, "failed to Delete Subnet '%s'", subnetName)
							return localresult{xerr}, xerr
						}
					default:
						xerr = fail.Wrap(xerr, "failed to Delete Subnet '%s'", subnetName)
						return localresult{xerr}, xerr
					}
				}
			}

			if networkInstance != nil && !valid.IsNil(networkInstance) && deleteNetwork {
				networkName := networkInstance.GetName()
				logrus.WithContext(ctx).Debugf("Deleting Network '%s'...", networkName)
				xerr = retry.WhileUnsuccessfulWithHardTimeout(
					func() error {
						select {
						case <-ctx.Done():
							return retry.StopRetryError(ctx.Err())
						default:
						}

						innerXErr := networkInstance.Delete(cleanupContextFrom(ctx))
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
						debug.IgnoreErrorWithContext(ctx, xerr)
					case *retry.ErrStopRetry:
						xerr = fail.Wrap(xerr.Cause(), "stopping retries")
						return localresult{xerr}, xerr
					case *retry.ErrTimeout:
						xerr = fail.Wrap(xerr.Cause(), "timeout")
						return localresult{xerr}, xerr
					default:
						xerr = fail.Wrap(xerr, "failed to Delete Network '%s'", networkName)
						logrus.WithContext(ctx).Errorf(xerr.Error())
						return localresult{xerr}, xerr
					}
				}
				logrus.WithContext(ctx).Infof("Network '%s' successfully deleted.", networkName)
			}

			// Need to explicitly terminate cluster transaction to be able to Delete metadata (dead-lock otherwise)
			clusterTrx.SilentTerminate(ctx)

			// --- Delete metadata ---
			xerr = instance.Core.Delete(cleanupContextFrom(ctx))
			if xerr != nil {
				return localresult{xerr}, xerr
			}

			return localresult{nil}, nil // nolint
		}() // nolint
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		<-chRes // wait for defer cleanup
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for defer cleanup
		return fail.Wrap(inctx.Err())
	}
}

// trxExtractNetworkingInfo returns the ID of the network from properties, taking care of ascending compatibility
func (instance *Cluster) trxExtractNetworkingInfo(ctx context.Context, clusterTrx clusterTransaction) (networkInstance *Network, deleteNetwork bool, subnetInstance *Subnet, ferr fail.Error) {
	networkInstance, subnetInstance = nil, nil
	deleteNetwork = false

	xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NetworkV3, func(networkV3 *propertiesv3.ClusterNetwork) (innerXErr fail.Error) {
		if networkV3.SubnetID != "" {
			if subnetInstance, innerXErr = LoadSubnet(ctx, networkV3.NetworkID, networkV3.SubnetID); innerXErr != nil {
				return innerXErr
			}
		}

		if networkV3.NetworkID != "" {
			networkInstance, innerXErr = LoadNetwork(ctx, networkV3.NetworkID)
			if innerXErr != nil {
				return innerXErr
			}
			deleteNetwork = networkV3.CreatedNetwork
		}
		if networkV3.SubnetID != "" {
			subnetInstance, innerXErr = LoadSubnet(ctx, networkV3.NetworkID, networkV3.SubnetID)
			if innerXErr != nil {
				return innerXErr
			}
			if networkInstance == nil {
				networkInstance, innerXErr = subnetInstance.InspectNetwork(ctx)
				if innerXErr != nil {
					return innerXErr
				}
			}
			deleteNetwork = networkV3.CreatedNetwork
		}

		return nil
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
func (instance *Cluster) configureCluster(inctx context.Context, clusterTrx clusterTransaction, req abstract.ClusterRequest) (ferr fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	logrus.WithContext(ctx).Infof("[Cluster %s] configuring Cluster...", instance.GetName())
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			logrus.WithContext(ctx).Errorf("[Cluster %s] configuration failed: %s", instance.GetName(), ferr.Error())
		} else {
			logrus.WithContext(ctx).Infof("[Cluster %s] configuration successful.", instance.GetName())
		}
	}()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		// FIXME: OPP This should use instance.AddFeature instead

		// Install reverse-proxy feature on Cluster (gateways)
		parameters := ExtractFeatureParameters(req.FeatureParameters)
		xerr := instance.installReverseProxy(ctx, clusterTrx, parameters)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		// Install remote-desktop feature on Cluster (all masters)
		xerr = instance.installRemoteDesktop(ctx, clusterTrx, parameters)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			// Break execution flow only if the Feature cannot be run (file transfer, Host unreachable, ...), not if it ran but has failed
			if annotation, found := xerr.Annotation("ran_but_failed"); !found || !annotation.(bool) {
				chRes <- result{xerr}
				return
			}
		}

		// Install ansible feature on Cluster (all masters)
		xerr = instance.installAnsible(ctx, clusterTrx, parameters)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		// configure what has to be done Cluster-wide
		makers := instance.localCache.makers
		incrementExpVar("cluster.cache.hit")
		if makers.ConfigureCluster != nil {
			chRes <- result{makers.ConfigureCluster(ctx, instance, parameters)}
			return
		}

		chRes <- result{nil}
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// determineRequiredNodes ...
func (instance *Cluster) determineRequiredNodes(ctx context.Context, clusterTrx clusterTransaction) (uint, uint, uint, fail.Error) {
	makers := instance.localCache.makers
	if makers.MinimumRequiredServers != nil {
		g, m, n, xerr := makers.MinimumRequiredServers(func() abstract.Cluster { out, _ := clusterTrx.getIdentity(ctx); return out }())
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

// joinNodesFromList makes nodes from a list join the Cluster
func (instance *Cluster) joinNodesFromList(ctx context.Context, nodes []*propertiesv3.ClusterNode) fail.Error {
	logrus.WithContext(ctx).Debugf("Joining nodes to Cluster...")

	// Joins to Cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending on the Cluster Flavor)
	makers := instance.localCache.makers
	if makers.JoinNodeToCluster != nil {
		for _, v := range nodes {
			hostInstance, xerr := LoadHost(ctx, v.ID)
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
func (instance *Cluster) leaveNodesFromList(ctx context.Context, hosts []*Host, selectedMaster *Host) (ferr fail.Error) {
	if selectedMaster == nil {
		return fail.InvalidParameterCannotBeNilError("selectedMaster")
	}

	logrus.WithContext(ctx).Debugf("Instructing nodes to leave Cluster...")

	// Un-joins from Cluster are done sequentially, experience shows too many (un)join at the same time
	// may fail (depending on the Cluster Flavor)
	makers := instance.localCache.makers
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
func (instance *Cluster) trxBuildHostname(ctx context.Context, clusterTrx clusterTransaction, core string, nodeType clusternodetype.Enum) (_ string, _ fail.Error) {
	var index int
	xerr := alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(p clonable.Clonable) fail.Error {
		nodesV3, innerErr := lang.Cast[*propertiesv3.ClusterNodes](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}
	return instance.GetName() + "-" + core + "-" + strconv.Itoa(index), nil
}

// ToProtocol converts instance to protocol.ClusterResponse message
func (instance *Cluster) ToProtocol(ctx context.Context) (_ *protocol.ClusterResponse, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.ClusterResponse{}
	xerr = inspectClusterMetadata(ctx, trx, func(aci *abstract.Cluster, props *serialize.JSONProperties) fail.Error {
		out.Identity = converters.ClusterFromAbstractToProtocol(*aci)

		innerXErr := props.Inspect(clusterproperty.ControlPlaneV1, func(p clonable.Clonable) fail.Error {
			controlplaneV1, innerErr := lang.Cast[*propertiesv1.ClusterControlplane](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			out.Controlplane = converters.ClusterControlplaneFromPropertyToProtocol(*controlplaneV1)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = props.Inspect(clusterproperty.CompositeV1, func(p clonable.Clonable) fail.Error {
			compositeV1, innerErr := lang.Cast[*propertiesv1.ClusterComposite](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			out.Composite = converters.ClusterCompositeFromPropertyToProtocol(*compositeV1)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		if props.Lookup(clusterproperty.DefaultsV3) {
			innerXErr = props.Inspect(clusterproperty.DefaultsV3, func(p clonable.Clonable) fail.Error {
				defaultsV3, innerErr := lang.Cast[*propertiesv3.ClusterDefaults](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				out.Defaults = converters.ClusterDefaultsFromPropertyV3ToProtocol(*defaultsV3)
				return nil
			})
		} else {
			innerXErr = props.Inspect(clusterproperty.DefaultsV2, func(p clonable.Clonable) fail.Error {
				defaultsV2, innerErr := lang.Cast[*propertiesv2.ClusterDefaults](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				out.Defaults = converters.ClusterDefaultsFromPropertyV2ToProtocol(*defaultsV2)
				return nil
			})
		}
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = props.Inspect(clusterproperty.NetworkV3, func(p clonable.Clonable) fail.Error {
			networkV3, innerErr := lang.Cast[*propertiesv3.ClusterNetwork](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			out.Network = converters.ClusterNetworkFromPropertyToProtocol(*networkV3)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = props.Inspect(clusterproperty.NodesV3, func(p clonable.Clonable) fail.Error {
			nodesV3, innerErr := lang.Cast[*propertiesv3.ClusterNodes](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
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

		innerXErr = props.Inspect(clusterproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
			featuresV1, innerErr := lang.Cast[*propertiesv1.ClusterFeatures](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			out.InstalledFeatures, out.DisabledFeatures = converters.ClusterFeaturesFromPropertyToProtocol(*featuresV1)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		return props.Inspect(clusterproperty.StateV1, func(p clonable.Clonable) fail.Error {
			stateV1, innerErr := lang.Cast[*propertiesv1.ClusterState](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
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
	defer fail.OnPanic(&ferr)

	emptySlice := make([]*propertiesv3.ClusterNode, 0)
	if valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptySlice, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if count == 0 {
		return emptySlice, fail.InvalidParameterError("count", "cannot be 0")
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = instance.trxBeingRemoved(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptySlice, xerr
	}

	var (
		removedNodes []*propertiesv3.ClusterNode
		errors       []error
		toRemove     []uint
	)

	xerr = alterClusterMetadataProperty(ctx, trx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) (innerXErr fail.Error) {
		length := uint(len(nodesV3.PrivateNodes))
		if length < count {
			return fail.InvalidRequestError("cannot shrink by %d node%s, only %d node%s available", count, strprocess.Plural(count), length, strprocess.Plural(length))
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
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		derr := trx.Rollback(ctx)
		if derr != nil {
			_ = xerr.AddConsequence(derr)
		}
		return emptySlice, xerr
	}

	xerr = trx.Commit(ctx)
	if xerr != nil {
		return emptySlice, xerr
	}

	// VPL: trx.Rollback should have done the job
	// defer func() {
	// 	ferr = debug.InjectPlannedFail(ferr)
	// 	if ferr != nil {
	// 		// derr := instance.Alter(jobapi.NewContextPropagatingJob(ctx), func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
	// 		derr := trx.AlterProperty(cleanupContextFrom(ctx), clusterproperty.NodesV3, func(p clonable.Clonable) fail.Error {
	// 			nodesV3, err := lang.Cast[*propertiesv3.ClusterNodes](p)
	// 			if err != nil {
	// 				return fail.Wrap(err)
	// 			}
	//
	// 			nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, toRemove...)
	// 			for _, v := range removedNodes {
	// 				nodesV3.ByNumericalID[v.NumericalID] = v
	// 				nodesV3.PrivateNodeByName[v.Name] = v.NumericalID
	// 				nodesV3.PrivateNodeByID[v.ID] = v.NumericalID
	// 			}
	// 			return nil
	// 		})
	// 		if derr != nil {
	// 			_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to restore Cluster nodes metadata", ActionFromError(ferr)))
	// 		}
	// 	}
	// }()

	if len(removedNodes) > 0 {
		tg := new(errgroup.Group)

		selectedMaster, xerr := instance.trxFindAvailableMaster(ctx, trx)
		if xerr != nil {
			return emptySlice, xerr
		}

		for _, v := range removedNodes {
			v := v
			tg.Go(func() error {
				_, err := instance.trxDeleteNodeWithCtx(cleanupContextFrom(ctx), trx, v, selectedMaster)
				return err
			})
		}
		xerr = fail.Wrap(tg.Wait())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			errors = append(errors, xerr)
		}
	}
	if len(errors) > 0 {
		return emptySlice, fail.NewErrorList(errors)
	}
	xerr = instance.updateClusterInventory(ctx, trx)
	if xerr != nil {
		return emptySlice, xerr
	}

	return removedNodes, nil
}

// IsFeatureInstalled tells if a Feature identified by name is installed on Cluster, using only metadata
func (instance *Cluster) IsFeatureInstalled(inctx context.Context, name string) (_ bool, gerr fail.Error) {
	defer fail.OnPanic(&gerr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  bool
		rErr fail.Error
	}

	chRes := make(chan result)

	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			found := false
			if valid.IsNil(instance) {
				ar := result{false, fail.InvalidInstanceError()}
				return ar, ar.rErr
			}
			if ctx == nil {
				ar := result{false, fail.InvalidParameterCannotBeNilError("ctx")}
				return ar, ar.rErr
			}
			if name = strings.TrimSpace(name); name == "" {
				ar := result{false, fail.InvalidParameterCannotBeEmptyStringError("name")}
				return ar, ar.rErr
			}

			trx, xerr := newClusterTransaction(ctx, instance)
			if xerr != nil {
				ar := result{false, xerr}
				return ar, ar.rErr
			}
			defer trx.TerminateFromError(ctx, &ferr)

			xerr = instance.trxBeingRemoved(ctx, trx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{false, xerr}
				return ar, ar.rErr
			}

			xerr = inspectClusterMetadataProperty(ctx, trx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
				_, found = featuresV1.Installed[name]
				return nil
			})

			ar := result{found, xerr}
			return ar, ar.rErr
		}() // nolint
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes
		return false, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return false, fail.Wrap(inctx.Err())
	}
}

// determineSizingRequirements calculates the sizings needed for the hosts of the Cluster
func (instance *Cluster) determineSizingRequirements(inctx context.Context, clusterTrx clusterTransaction, req abstract.ClusterRequest) (
	_ *abstract.HostSizingRequirements, _ *abstract.HostSizingRequirements, _ *abstract.HostSizingRequirements, xerr fail.Error,
) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		aa   *abstract.HostSizingRequirements
		ab   *abstract.HostSizingRequirements
		ac   *abstract.HostSizingRequirements
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			var (
				gatewaysDefault     *abstract.HostSizingRequirements
				mastersDefault      *abstract.HostSizingRequirements
				nodesDefault        *abstract.HostSizingRequirements
				imageQuery, imageID string
			)

			// Determine default image
			imageQuery = req.NodesDef.Image
			if imageQuery == "" {
				cfg, xerr := instance.Service().ConfigurationOptions()
				if xerr != nil {
					xerr := fail.Wrap(xerr, "failed to get configuration options")
					return result{nil, nil, nil, xerr}, xerr
				}
				imageQuery = cfg.DefaultImage
			}
			makers := instance.localCache.makers
			if imageQuery == "" && makers.DefaultImage != nil {
				imageQuery = makers.DefaultImage(instance)
			}
			if imageQuery == "" {
				imageQuery = consts.DEFAULTOS
			}
			svc := instance.Service()
			_, imageID, xerr = determineImageID(ctx, svc, imageQuery)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, nil, nil, xerr}, xerr
			}

			// Determine getGateway sizing
			if makers.DefaultGatewaySizing != nil {
				gatewaysDefault = complementSizingRequirements(nil, makers.DefaultGatewaySizing(instance))
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
						xerr := fail.NewError("requested gateway sizing less than recommended")
						return result{nil, nil, nil, xerr}, xerr
					}
				}
			}

			tmpl, xerr := svc.FindTemplateBySizing(ctx, *gatewaysDef)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, nil, nil, xerr}, xerr
			}

			gatewaysDef.Template = tmpl.ID

			// Determine master sizing
			if makers.DefaultMasterSizing != nil {
				mastersDefault = complementSizingRequirements(nil, makers.DefaultMasterSizing(instance))
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
						xerr := fail.NewError("requested master sizing less than recommended")
						return result{nil, nil, nil, xerr}, xerr
					}
				}
			}

			tmpl, xerr = svc.FindTemplateBySizing(ctx, *mastersDef)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, nil, nil, xerr}, xerr
			}

			mastersDef.Template = tmpl.ID

			// Determine node sizing
			if makers.DefaultNodeSizing != nil {
				nodesDefault = complementSizingRequirements(nil, makers.DefaultNodeSizing(instance))
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
						xerr := fail.NewError("requested node sizing less than recommended")
						return result{nil, nil, nil, xerr}, xerr
					}
				}
			}

			tmpl, xerr = svc.FindTemplateBySizing(ctx, *nodesDef)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, nil, nil, xerr}, xerr
			}
			nodesDef.Template = tmpl.ID

			// Updates property
			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.DefaultsV2, func(defaultsV2 *propertiesv2.ClusterDefaults) fail.Error { //nolint
				defaultsV2.GatewaySizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*gatewaysDef)
				defaultsV2.MasterSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*mastersDef)
				defaultsV2.NodeSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*nodesDef)
				defaultsV2.Image = imageQuery
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{nil, nil, nil, xerr}, xerr
			}

			return result{gatewaysDef, mastersDef, nodesDef, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.aa, res.ab, res.ac, res.rErr
	case <-ctx.Done():
		return nil, nil, nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, nil, nil, fail.Wrap(inctx.Err())
	}
}
