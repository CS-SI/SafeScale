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
	"context"
	"reflect"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusterstate"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v1"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
)

// unsafeGetIdentity returns the identity of the Cluster
func (instance *Cluster) unsafeGetIdentity(inctx context.Context) (_ abstract.ClusterIdentity, ferr fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  abstract.ClusterIdentity
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer fail.OnPanic(&ferr)

		var clusterIdentity abstract.ClusterIdentity
		xerr := instance.Review(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
			aci, ok := clonable.(*abstract.ClusterIdentity)
			if !ok {
				return fail.InconsistentError("'*abstract.ClusterIdentity' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			clusterIdentity = *aci
			return nil
		})

		chRes <- result{clusterIdentity, xerr}
		return
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return abstract.ClusterIdentity{}, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return abstract.ClusterIdentity{}, fail.ConvertError(inctx.Err())
	}
}

// unsafeGetFlavor returns the flavor of the Cluster
func (instance *Cluster) unsafeGetFlavor(ctx context.Context) (flavor clusterflavor.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	aci, xerr := instance.unsafeGetIdentity(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return aci.Flavor, nil
}

// unsafeGetComplexity returns the complexity of the Cluster
func (instance *Cluster) unsafeGetComplexity(ctx context.Context) (_ clustercomplexity.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	aci, xerr := instance.unsafeGetIdentity(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return aci.Complexity, nil
}

// unsafeGetState returns the current state of the Cluster
// Uses the "maker" ForceGetState
func (instance *Cluster) unsafeGetState(ctx context.Context) (state clusterstate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	state = clusterstate.Unknown
	instance.localCache.RLock()
	makers := instance.localCache.makers
	instance.localCache.RUnlock() // nolint
	if makers.GetState != nil {
		var xerr fail.Error
		state, xerr = makers.GetState(instance)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return clusterstate.Unknown, xerr
		}

		return state, instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
				stateV1, ok := clonable.(*propertiesv1.ClusterState)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				stateV1.State = state
				instance.localCache.Lock()
				instance.localCache.lastStateCollection = time.Now()
				instance.localCache.Unlock() // nolint
				return nil
			})
		})
	}

	xerr := instance.Review(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			state = stateV1.State
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return clusterstate.Unknown, xerr
	}

	return state, nil
}

// unsafeListMasters is the not goroutine-safe equivalent of ListMasters, that does the real work
// Note: must be used with wisdom
func (instance *Cluster) unsafeListMasters(ctx context.Context) (list resources.IndexedListOfClusterNodes, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := resources.IndexedListOfClusterNodes{}

	xerr := instance.Review(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) (innerXErr fail.Error) {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			list = make(resources.IndexedListOfClusterNodes, len(nodesV3.Masters))

			for _, v := range nodesV3.Masters {
				if node, found := nodesV3.ByNumericalID[v]; found {
					list[node.NumericalID] = node
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

// unsafeListMasterIDs is the not goroutine-safe version of ListNodeIDs and no parameter validation, that does the real work
// Note: must be used wisely
func (instance *Cluster) unsafeListMasterIDs(ctx context.Context) (list data.IndexedListOfStrings, ferr fail.Error) {
	emptyList := data.IndexedListOfStrings{}

	xerr := instance.beingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	xerr = instance.Review(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			list = make(data.IndexedListOfStrings, len(nodesV3.Masters))
			for _, v := range nodesV3.Masters {
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

// unsafeListMasterIPs lists the IPs of masters (if there is such masters in the flavor...)
func (instance *Cluster) unsafeListMasterIPs(ctx context.Context) (list data.IndexedListOfStrings, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := data.IndexedListOfStrings{}

	xerr := instance.beingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	xerr = instance.Review(ctx, func(_ data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			list = make(data.IndexedListOfStrings, len(nodesV3.Masters))
			for _, v := range nodesV3.Masters {
				if node, found := nodesV3.ByNumericalID[v]; found {
					list[node.NumericalID] = node.PrivateIP
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

// unsafeListNodeIPs lists the IPs of the nodes in the Cluster
func (instance *Cluster) unsafeListNodeIPs(ctx context.Context) (list data.IndexedListOfStrings, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := data.IndexedListOfStrings{}
	xerr := instance.Review(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			list = make(data.IndexedListOfStrings, len(nodesV3.PrivateNodes))
			for _, v := range nodesV3.PrivateNodes {
				if node, found := nodesV3.ByNumericalID[v]; found {
					list[node.NumericalID] = node.PrivateIP
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

// unsafeFindAvailableMaster is the not go-routine-safe version of FindAvailableMaster, that does the real work
// Must be used with wisdom
func (instance *Cluster) unsafeFindAvailableMaster(ctx context.Context) (master resources.Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	master = nil
	masters, xerr := instance.unsafeListMasters(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return nil, xerr
	}

	var lastError fail.Error
	lastError = fail.NotFoundError("no master found")
	master = nil
	for _, v := range masters {
		if v.ID == "" {
			continue
		}

		master, xerr = LoadHost(ctx, instance.Service(), v.ID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		_, xerr = master.WaitSSHReady(ctx, timings.SSHConnectionTimeout())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrTimeout:
				lastError = xerr
				continue
			default:
				return nil, xerr
			}
		}
		break
	}
	if master == nil {
		return nil, lastError
	}

	return master, nil
}

// unsafeListNodes is the not goroutine-safe version of ListNodes and no parameter validation, that does the real work
// Note: must be used wisely
func (instance *Cluster) unsafeListNodes(ctx context.Context) (list resources.IndexedListOfClusterNodes, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	emptyList := resources.IndexedListOfClusterNodes{}
	xerr := instance.Review(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			list = make(resources.IndexedListOfClusterNodes, len(nodesV3.PrivateNodes))
			for _, v := range nodesV3.PrivateNodes {
				if node, found := nodesV3.ByNumericalID[v]; found {
					list[node.NumericalID] = node
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

// unsafeListNodeIDs is the not goroutine-safe version of ListNodeIDs and no parameter validation, that does the real work
// Note: must be used wisely
func (instance *Cluster) unsafeListNodeIDs(ctx context.Context) (list data.IndexedListOfStrings, ferr fail.Error) {
	emptyList := data.IndexedListOfStrings{}

	xerr := instance.beingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	xerr = instance.Review(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			list = make(data.IndexedListOfStrings, len(nodesV3.PrivateNodes))
			for _, v := range nodesV3.PrivateNodes {
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

// unsafeFindAvailableNode is the package restricted, not goroutine-safe, no parameter validation version of FindAvailableNode, that does the real work
// Note: must be used wisely
func (instance *Cluster) unsafeFindAvailableNode(ctx context.Context) (node resources.Host, ferr fail.Error) {
	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return nil, xerr
	}

	xerr = instance.beingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	list, xerr := instance.unsafeListNodes(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	svc := instance.Service()
	node = nil
	found := false
	for _, v := range list {
		node, xerr = LoadHost(ctx, svc, v.ID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		_, xerr = node.WaitSSHReady(ctx, timings.SSHConnectionTimeout())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrTimeout:
				continue
			default:
				return nil, xerr
			}
		}
		found = true
		break
	}
	if !found {
		return nil, fail.NotAvailableError("failed to find available node")
	}

	return node, nil
}
