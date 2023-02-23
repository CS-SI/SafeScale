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
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	rscapi "github.com/CS-SI/SafeScale/v22/lib/backend/resources/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/internal/clusterflavors"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/eko/gocache/v2/store"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/converters"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
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
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	clusterKind        = "cluster"
	clustersFolderName = "clusters" // path to use to reach Cluster Definitions/Metadata
)

// Cluster is the implementation of resources.Cluster interface
type Cluster struct {
	*metadata.Core[*abstract.Cluster]
}

var _ metadata.Metadata[*abstract.Cluster] = (*Cluster)(nil)

type extraInAbstract struct {
	InstallMethods sync.Map              `json:"-"`
	Makers         clusterflavors.Makers `json:"-"`
	RandomDelayCh  <-chan int            `json:"-"`
}

func newExtraInAbstract() *extraInAbstract {
	return &extraInAbstract{}
}

func (lia *extraInAbstract) IsNull() bool {
	return lia == nil
}

// Clone creates a copy of instance
// satisfies interface clonable.Clonable
func (lia *extraInAbstract) Clone() (clonable.Clonable, error) {
	if lia == nil {
		return nil, fail.InvalidInstanceError()
	}

	newLia := newExtraInAbstract()
	return newLia, newLia.Replace(lia)
}

// Replace replaces the content of the instance with the content of the parameter
// satisfies interface clonable.Clonable
func (lia *extraInAbstract) Replace(in clonable.Clonable) error {
	if lia == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*extraInAbstract](in)
	if err != nil {
		return err
	}

	lia.Makers = src.Makers
	lia.InstallMethods = sync.Map{}
	src.InstallMethods.Range(func(key any, value any) bool {
		lia.InstallMethods.Store(key, value)
		return true
	})
	lia.RandomDelayCh = src.RandomDelayCh
	return nil
}

// NewCluster is the constructor of resources.Cluster struct
func NewCluster(ctx context.Context) (_ *Cluster, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	emptyCluster := abstract.NewEmptyCluster()
	emptyCluster.Local = newExtraInAbstract()

	coreInstance, xerr := metadata.NewCore(ctx, metadata.MethodObjectStorage, clusterKind, clustersFolderName, emptyCluster)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &Cluster{
		Core: coreInstance,
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
	ci, xerr := clusterTrx.getAbstract(ctx)
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

	mids, xerr := clusterTrx.ListMasters(ctx)
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

	nids, xerr := clusterTrx.ListNodes(ctx)
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

	svc, xerr := myjob.Service()
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

			cache, xerr := svc.Cache(ctx)
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

			clusterTrx, xerr := newClusterTransaction(ctx, clusterInstance)
			if xerr != nil {
				return nil, xerr
			}
			defer clusterTrx.TerminateFromError(ctx, &ferr)

			var newAbstract bool
			xerr = inspectClusterMetadataAbstract(ctx, clusterTrx, func(ac *abstract.Cluster) (innerXErr fail.Error) {
				newAbstract, innerXErr = myjob.Scope().RegisterAbstractIfNeeded(ac)
				return innerXErr
			})
			if xerr != nil {
				return nil, xerr
			}

			if newAbstract {
				xerr = clusterTrx.startRandomDelayGenerator(ctx, 0, 2000)
			}
			if xerr != nil {
				return nil, xerr
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

	var (
		flavor          clusterflavor.Enum
		clusterInstance *Cluster
		xerr            fail.Error
	)

	clusterInstance, xerr = NewCluster(ctx)
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

	flavor, xerr = clusterTrx.GetFlavor(ctx)
	if xerr != nil {
		return nil, xerr
	}

	xerr = clusterTrx.Bootstrap(ctx, flavor)
	if xerr != nil {
		return nil, xerr
	}

	return clusterInstance, nil
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

	return nil
}

// Carry ...
func (instance *Cluster) Carry(inctx context.Context, ac *abstract.Cluster) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
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

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.startRandomDelayGenerator(ctx, 0, 2000)
}

// Create creates the necessary infrastructure of the Cluster
func (instance *Cluster) Create(inctx context.Context, req abstract.ClusterRequest) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}
	if !valid.IsNil(instance.Core) && instance.IsTaken() {
		return fail.InconsistentError("already carrying information")
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
func (instance *Cluster) GetIdentity(ctx context.Context) (clusterIdentity *abstract.Cluster, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.getAbstract(ctx)
}

// GetFlavor returns the flavor of the Cluster
func (instance *Cluster) GetFlavor(ctx context.Context) (flavor clusterflavor.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return 0, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.GetFlavor(ctx)
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

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.NetworkConfig(ctx)
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

	svc, xerr := instance.Service()
	if xerr != nil {
		return xerr
	}

	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	// If the Cluster is in state Stopping or Stopped, do nothing
	var prevState clusterstate.Enum
	prevState, xerr = clusterTrx.getState(ctx)
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

				state, innerErr := clusterTrx.getState(ctx)
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
	xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.StateV1, func(stateV1 *propertiesv1.ClusterState) fail.Error {
		stateV1.State = clusterstate.Starting
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Commit now to save changing status of Cluster
	xerr = clusterTrx.Commit(ctx)
	if xerr != nil {
		return fail.Wrap(xerr)
	}

	var (
		nodes                         []string
		masters                       []string
		gatewayID, secondaryGatewayID string
	)

	// Then start it and mark it as NOMINAL on success
	xerr = alterClusterMetadataProperties(ctx, clusterTrx, func(props *serialize.JSONProperties) fail.Error {
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
		return clusterTrx.StartHost(ctx, gatewayID)
	})

	if secondaryGatewayID != "" {
		runGroup.Go(func() error {
			return clusterTrx.StartHost(ctx, secondaryGatewayID)
		})
	}

	// Start masters
	for _, n := range masters {
		n := n
		runGroup.Go(func() error {
			return clusterTrx.StartHost(ctx, n)
		})
	}

	// Start nodes
	for _, n := range nodes {
		n := n
		runGroup.Go(func() error {
			return clusterTrx.StartHost(ctx, n)
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
		xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.StateV1, func(stateV1 *propertiesv1.ClusterState) fail.Error {
			stateV1.State = clusterstate.Degraded
			return nil
		})
		if xerr != nil {
			_ = outerr.AddConsequence(xerr)
		}
		return outerr
	}

	return metadata.AlterProperty[*abstract.Cluster, *propertiesv1.ClusterState](ctx, clusterTrx, clusterproperty.StateV1, func(stateV1 *propertiesv1.ClusterState) fail.Error {
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

	svc, xerr := instance.Service()
	if xerr != nil {
		return xerr
	}

	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	clusterTrx, err := newClusterTransaction(ctx, instance)
	if err != nil {
		return fail.Wrap(err)
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	// If the Cluster is stopped, do nothing
	var prevState clusterstate.Enum
	prevState, xerr = clusterTrx.getState(ctx)
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

				state, innerErr := clusterTrx.getState(ctx)
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
	xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.StateV1, func(stateV1 *propertiesv1.ClusterState) fail.Error {
		stateV1.State = clusterstate.Stopping
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Change cluster state in metadata as soon as possible
	xerr = clusterTrx.Commit(ctx)
	if xerr != nil {
		return xerr
	}

	// Then stop it and mark it as STOPPED on success
	return alterClusterMetadata(ctx, clusterTrx, func(_ *abstract.Cluster, props *serialize.JSONProperties) fail.Error {
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
				return clusterTrx.StopHost(ctx, n)
			})
		}
		// Stop masters
		for _, n := range masters {
			n := n
			egStopHosts.Go(func() error {
				return clusterTrx.StopHost(ctx, n)
			})
		}
		// Stop gateway(s)
		egStopHosts.Go(func() error {
			return clusterTrx.StopHost(ctx, gatewayID)
		})

		if secondaryGatewayID != "" {
			egStopHosts.Go(func() error {
				return clusterTrx.StopHost(ctx, secondaryGatewayID)
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

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return state, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.getState(ctx)
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.AddNodes(ctx, count, def, parameters, keepOnFailure)
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	var selectedMaster *Host
	if selectedMasterID != "" {
		selectedMaster, xerr = LoadHost(ctx, selectedMasterID)
	} else {
		selectedMaster, xerr = clusterTrx.FindAvailableMaster(ctx)
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	var node *propertiesv3.ClusterNode
	xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
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

	return clusterTrx.deleteNode(cleanupContextFrom(ctx), node, selectedMaster)
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.ListMasters(ctx)
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.ListMasterIDs(ctx)
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.ListMasterIPs(ctx)
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.FindAvailableMaster(ctx)
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}

	return clusterTrx.ListNodes(ctx)
}

// BeingRemoved tells if the Cluster is currently marked as Removed (meaning a removal operation is running)
func (instance *Cluster) BeingRemoved(ctx context.Context) fail.Error {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	state, xerr := instance.GetState(ctx)
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.ListNodeIDs(ctx)
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.ListNodeIPs(ctx)
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.FindAvailableNode(ctx)
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return false, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	hostInstance, xerr := LoadHost(ctx, ref)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

	found = false
	xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return 0, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	found := false
	xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
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

// Delete deletes the Cluster
func (instance *Cluster) Delete(ctx context.Context, force bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	if !force {
		xerr := instance.BeingRemoved(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	xerr = clusterTrx.Delete(ctx)
	if xerr != nil {
		return xerr
	}

	// Need to explicitly terminate cluster transaction to be able to Delete metadata (dead-lock otherwise)
	clusterTrx.SilentTerminate(ctx)

	// --- Delete metadata ---
	return instance.Core.Delete(cleanupContextFrom(ctx))
}

// ToProtocol converts instance to protocol.ClusterResponse message
func (instance *Cluster) ToProtocol(ctx context.Context) (_ *protocol.ClusterResponse, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	out := &protocol.ClusterResponse{}
	xerr = inspectClusterMetadata(ctx, clusterTrx, func(aci *abstract.Cluster, props *serialize.JSONProperties) fail.Error {
		out.Identity = converters.ClusterFromAbstractToProtocol(aci)

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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptySlice, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	var (
		removedNodes []*propertiesv3.ClusterNode
		errors       []error
		toRemove     []uint
	)

	xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) (innerXErr fail.Error) {
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
		derr := clusterTrx.Rollback(ctx)
		if derr != nil {
			_ = xerr.AddConsequence(derr)
		}
		return emptySlice, xerr
	}

	xerr = clusterTrx.Commit(ctx)
	if xerr != nil {
		return emptySlice, xerr
	}

	// VPL: clusterTrx.Rollback should have done the job
	// defer func() {
	// 	ferr = debug.InjectPlannedFail(ferr)
	// 	if ferr != nil {
	// 		// derr := instance.Alter(jobapi.NewContextPropagatingJob(ctx), func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
	// 		derr := clusterTrx.AlterProperty(cleanupContextFrom(ctx), clusterproperty.NodesV3, func(p clonable.Clonable) fail.Error {
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

		selectedMaster, xerr := clusterTrx.FindAvailableMaster(ctx)
		if xerr != nil {
			return emptySlice, xerr
		}

		for _, v := range removedNodes {
			v := v
			tg.Go(func() error {
				_, err := clusterTrx.deleteNodeWithContext(cleanupContextFrom(ctx), v, selectedMaster)
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
	xerr = clusterTrx.updateClusterAnsibleInventory(ctx)
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

	xerr := instance.BeingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

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

// firstLight contains the code leading to Cluster first metadata written
func (instance *Cluster) firstLight(ctx context.Context, req abstract.ClusterRequest) (_ clusterTransaction, ferr fail.Error) {
	select {
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	default:
	}

	defer fail.OnPanic(&ferr)

	if req.Name = strings.TrimSpace(req.Name); req.Name == "" {
		return nil, fail.InvalidParameterError("req.Name", "cannot be empty string")
	}

	// Initializes instance
	abstractCluster, xerr := abstract.NewCluster(abstract.WithName(req.Name))
	if xerr != nil {
		return nil, xerr
	}

	abstractCluster.Flavor = req.Flavor
	abstractCluster.Complexity = req.Complexity
	abstractCluster.Tags["CreationDate"] = time.Now().Format(time.RFC3339)
	abstractCluster.Local = newExtraInAbstract()

	// Create a KeyPair for the user cladm
	kpName := "cluster_" + req.Name + "_cladm_key"
	kp, xerr := abstract.NewKeyPair(kpName)
	if xerr != nil {
		return nil, xerr
	}

	abstractCluster.Keypair = kp

	// Generate needed password for account cladm
	cladmPassword, innerErr := utils.GeneratePassword(16)
	if innerErr != nil {
		return nil, fail.Wrap(innerErr)
	}

	abstractCluster.AdminPassword = cladmPassword

	xerr = instance.Carry(ctx, abstractCluster)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer func() {
		if ferr != nil {
			clusterTrx.TerminateFromError(ctx, &ferr)
		}
	}()

	// Links maker based on Flavor
	xerr = clusterTrx.Bootstrap(ctx, abstractCluster.Flavor)
	if xerr != nil {
		return nil, xerr
	}

	xerr = alterClusterMetadata(ctx, clusterTrx, func(aci *abstract.Cluster, props *serialize.JSONProperties) fail.Error {
		innerXErr := props.Alter(clusterproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
			featuresV1, err := lang.Cast[*propertiesv1.ClusterFeatures](p)
			if err != nil {
				return fail.Wrap(err)
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

		// Sets initial state of the new Cluster and create metadata
		innerXErr = props.Alter(clusterproperty.StateV1, func(p clonable.Clonable) fail.Error {
			stateV1, err := lang.Cast[*propertiesv1.ClusterState](p)
			if err != nil {
				return fail.Wrap(err)
			}

			stateV1.State = clusterstate.Creating
			return nil
		})
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to set initial state of Cluster")
		}

		// sets default sizing from req
		innerXErr = props.Alter(clusterproperty.DefaultsV3, func(p clonable.Clonable) fail.Error {
			defaultsV3, err := lang.Cast[*propertiesv3.ClusterDefaults](p)
			if err != nil {
				return fail.Wrap(err)
			}

			defaultsV3.GatewaySizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(req.GatewaysDef)
			defaultsV3.MasterSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(req.MastersDef)
			defaultsV3.NodeSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(req.NodesDef)
			defaultsV3.Image = req.NodesDef.Image
			defaultsV3.ImageID = req.NodesDef.Image
			defaultsV3.GatewayTemplateID = req.GatewaysDef.Template
			defaultsV3.NodeTemplateID = req.NodesDef.Template
			defaultsV3.MasterTemplateID = req.MastersDef.Template
			defaultsV3.FeatureParameters = req.FeatureParameters
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// FUTURE: sets the Cluster composition (when we will be able to manage Cluster spread on several tenants...)
		return props.Alter(clusterproperty.CompositeV1, func(p clonable.Clonable) fail.Error {
			compositeV1, err := lang.Cast[*propertiesv1.ClusterComposite](p)
			if err != nil {
				return fail.Wrap(err)
			}

			compositeV1.Tenants = []string{req.Tenant}
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}

	return clusterTrx, clusterTrx.Commit(ctx)
}

// ListEligibleFeatures returns a slice of features eligible to Cluster
func (instance *Cluster) ListEligibleFeatures(ctx context.Context) (_ []*Feature, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var emptySlice []*Feature
	if valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}

	// FIXME: 'allWithEmbedded' should be passed as parameter...
	// walk through the folders that may contain Feature files
	list, xerr := walkInsideFeatureFileFolders(ctx, allWithEmbedded)
	if xerr != nil {
		return nil, xerr
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	var out []*Feature
	for _, v := range list {
		entry, xerr := NewFeature(ctx, v)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// ignore a feature file not found; weird, but fs may have changed (will be handled properly later with fswatcher)
			default:
				return nil, xerr
			}
		}

		ok, xerr := entry.Applicable(ctx, clusterTrx)
		if xerr != nil {
			return nil, xerr
		}

		if ok {
			out = append(out, entry)
		}
	}

	return out, nil
}

// ListInstalledFeatures returns a slice of installed features
func (instance *Cluster) ListInstalledFeatures(ctx context.Context) (_ []*Feature, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	list, xerr := clusterTrx.InstalledFeatures(ctx)
	if xerr != nil {
		return nil, xerr
	}

	out := make([]*Feature, 0, len(list))
	for _, v := range list {
		item, xerr := NewFeature(ctx, v)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		out = append(out, item)
	}
	return out, nil
}

// ComplementFeatureParameters configures parameters that are implicitly defined, based on target
// satisfies interface resources.Targetable
func (instance *Cluster) ComplementFeatureParameters(ctx context.Context, v data.Map[string, any]) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.ComplementFeatureParameters(ctx, v)
}

// InstallMethods returns a list of installation methods usable on the target, ordered from upper to lower preference (1 = the highest preference)
// satisfies resources.Targetable interface
func (instance *Cluster) InstallMethods(ctx context.Context) (_ map[uint8]installmethod.Enum, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.InstallMethods(ctx)
}

// InstalledFeatures returns a list of installed features
func (instance *Cluster) InstalledFeatures(ctx context.Context) (_ []string, ferr fail.Error) {
	if valid.IsNull(instance) {
		return []string{}, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.InstalledFeatures(ctx)
}

// RegisterFeature registers an installed Feature in metadata of a Cluster
// satisfies interface resources.Targetable
func (instance *Cluster) RegisterFeature(ctx context.Context, feat *Feature, requiredBy *Feature, clusterContext bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if feat == nil {
		return fail.InvalidParameterCannotBeNilError("feat")
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.RegisterFeature(ctx, feat, requiredBy, clusterContext)
}

// UnregisterFeature unregisters a Feature from Cluster metadata
// satisfies interface resources.Targetable
func (instance *Cluster) UnregisterFeature(ctx context.Context, feat string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if feat == "" {
		return fail.InvalidParameterError("feat", "cannot be empty string")
	}

	clusterTrx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer clusterTrx.TerminateFromError(ctx, &ferr)

	return clusterTrx.UnregisterFeature(ctx, feat)
}

// TargetType returns the type of the target
// satisfies resources.Targetable interface
func (instance *Cluster) TargetType() featuretargettype.Enum {
	return featuretargettype.Cluster
}
