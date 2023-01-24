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

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	rscapi "github.com/CS-SI/SafeScale/v22/lib/backend/resources/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
)

// trxGetIdentity returns the identity of the Cluster
func trxGetIdentity(inctx context.Context, clusterTrx clusterTransaction) (_ abstract.Cluster, ferr fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  abstract.Cluster
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		defer fail.OnPanic(&ferr)

		var clusterIdentity abstract.Cluster
		xerr := metadata.ReviewCarried[*abstract.Cluster](ctx, clusterTrx, func(aci *abstract.Cluster) fail.Error {
			clusterIdentity = *aci
			return nil
		})

		chRes <- result{clusterIdentity, xerr}
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return abstract.Cluster{}, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return abstract.Cluster{}, fail.Wrap(inctx.Err())
	}
}

// trxGetFlavor returns the flavor of the Cluster
func trxGetFlavor(ctx context.Context, clusterTrx clusterTransaction) (flavor clusterflavor.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	aci, xerr := trxGetIdentity(ctx, clusterTrx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return aci.Flavor, nil
}

// trxGetComplexity returns the complexity of the Cluster
func trxGetComplexity(ctx context.Context, clusterTrx clusterTransaction) (_ clustercomplexity.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	aci, xerr := trxGetIdentity(ctx, clusterTrx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return aci.Complexity, nil
}

// trxGetState returns the current state of the Cluster
// Uses the "maker" ForceGetState
func (instance *Cluster) trxGetState(inctx context.Context, clusterTrx clusterTransaction) (_ clusterstate.Enum, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  clusterstate.Enum
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		var state = clusterstate.Unknown
		makers := instance.localCache.makers
		if makers.GetState != nil {
			var xerr fail.Error
			state, xerr = makers.GetState(instance)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{clusterstate.Unknown, xerr}
				return
			}

			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.StateV1, func(p clonable.Clonable) fail.Error {
				stateV1, innerErr := clonable.Cast[*propertiesv1.ClusterState](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				stateV1.State = state
				return nil
			})
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
			} else {
				// State change has to be committed as soon as possible
				xerr = clusterTrx.Commit(ctx)
			}

			chRes <- result{state, xerr}
			return
		}

		xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.StateV1, func(p clonable.Clonable) fail.Error {
			stateV1, innerErr := clonable.Cast[*propertiesv1.ClusterState](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			state = stateV1.State
			return nil
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			xerr = fail.Wrap(xerr, callstack.WhereIsThis())
			chRes <- result{clusterstate.Unknown, xerr}
			return
		}

		chRes <- result{state, nil}
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return clusterstate.Unknown, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return clusterstate.Unknown, fail.Wrap(inctx.Err())
	}
}

// trxListMasters is the not goroutine-safe equivalent of ListMasters, that does the real work
// Note: must be used with wisdom
func trxListMasters(inctx context.Context, clusterTrx clusterTransaction) (_ rscapi.IndexedListOfClusterNodes, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  rscapi.IndexedListOfClusterNodes
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			var (
				list, emptyList rscapi.IndexedListOfClusterNodes
			)

			xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
				list = make(rscapi.IndexedListOfClusterNodes, len(nodesV3.Masters))

				for _, v := range nodesV3.Masters {
					if node, found := nodesV3.ByNumericalID[v]; found {
						list[node.NumericalID] = node
					}
				}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{emptyList, xerr}, xerr
			}

			return result{list, nil}, nil
		}()
		chRes <- gres
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

// trxListMasterIDs is the not goroutine-safe version of ListNodeIDs and no parameter validation, that does the real work
// Note: must be used wisely
func (instance *Cluster) trxListMasterIDs(inctx context.Context, clusterTrx clusterTransaction) (_ data.IndexedListOfStrings, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  data.IndexedListOfStrings
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			var list data.IndexedListOfStrings
			emptyList := data.IndexedListOfStrings{}

			xerr := instance.trxBeingRemoved(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{emptyList, xerr}, xerr
			}

			xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(p clonable.Clonable) fail.Error {
				nodesV3, innerErr := clonable.Cast[*propertiesv3.ClusterNodes](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				list = make(data.IndexedListOfStrings, len(nodesV3.Masters))
				for _, v := range nodesV3.Masters {
					if node, found := nodesV3.ByNumericalID[v]; found {
						list[node.NumericalID] = node.ID
					}
				}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{emptyList, xerr}, xerr
			}

			return result{list, nil}, nil
		}()
		chRes <- gres
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

// trxListMasterIPs lists the IPs of masters (if there is such masters in the flavor...)
func (instance *Cluster) trxListMasterIPs(inctx context.Context, clusterTrx clusterTransaction) (_ data.IndexedListOfStrings, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  data.IndexedListOfStrings
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			emptyList := data.IndexedListOfStrings{}
			var list data.IndexedListOfStrings

			xerr := instance.trxBeingRemoved(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{emptyList, xerr}, xerr
			}

			xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
				list = make(data.IndexedListOfStrings, len(nodesV3.Masters))
				for _, v := range nodesV3.Masters {
					if node, found := nodesV3.ByNumericalID[v]; found {
						list[node.NumericalID] = node.PrivateIP
					}
				}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{emptyList, xerr}, xerr
			}

			return result{list, nil}, nil
		}()
		chRes <- gres
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

// trxListNodeIPs lists the IPs of the nodes in the Cluster
func (instance *Cluster) trxListNodeIPs(inctx context.Context, clusterTrx clusterTransaction) (_ data.IndexedListOfStrings, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  data.IndexedListOfStrings
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			emptyList := data.IndexedListOfStrings{}
			var outlist data.IndexedListOfStrings

			xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
				list := make(data.IndexedListOfStrings, len(nodesV3.PrivateNodes))
				for _, v := range nodesV3.PrivateNodes {
					if node, found := nodesV3.ByNumericalID[v]; found {
						list[node.NumericalID] = node.PrivateIP
					}
				}
				outlist = list
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{emptyList, xerr}, xerr
			}
			return result{outlist, nil}, nil
		}()
		chRes <- gres
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

// unsafeFindAvailableMaster is the not go-routine-safe version of FindAvailableMaster, that does the real work
// Must be used with wisdom
func (instance *Cluster) trxFindAvailableMaster(inctx context.Context, clusterTrx clusterTransaction) (_ *Host, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *Host
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			var master *Host

			masters, xerr := trxListMasters(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			var lastError fail.Error
			lastError = fail.NotFoundError("no master found")
			master = nil
			for _, v := range masters {
				if v.ID == "" {
					continue
				}

				master, xerr = LoadHost(ctx, v.ID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return result{nil, xerr}, xerr
				}

				_, xerr = master.WaitSSHReady(ctx, timings.SSHConnectionTimeout())
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *retry.ErrTimeout:
						lastError = xerr
						continue
					default:
						return result{nil, xerr}, xerr
					}
				}
				break
			}
			if master == nil {
				return result{nil, lastError}, lastError
			}

			return result{master, nil}, nil
		}()
		chRes <- gres
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

// trxListNodes is the not goroutine-safe version of ListNodes and no parameter validation, that does the real work
// Note: must be used wisely
func (instance *Cluster) trxListNodes(inctx context.Context, clusterTrx clusterTransaction) (_ rscapi.IndexedListOfClusterNodes, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  rscapi.IndexedListOfClusterNodes
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			emptyList := rscapi.IndexedListOfClusterNodes{}
			var list rscapi.IndexedListOfClusterNodes

			xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(p clonable.Clonable) fail.Error {
				nodesV3, innerErr := clonable.Cast[*propertiesv3.ClusterNodes](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				list = make(rscapi.IndexedListOfClusterNodes, len(nodesV3.PrivateNodes))
				for _, v := range nodesV3.PrivateNodes {
					if node, found := nodesV3.ByNumericalID[v]; found {
						list[node.NumericalID] = node
					}
				}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{emptyList, xerr}, xerr
			}

			return result{list, nil}, nil
		}()
		chRes <- gres
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

// unsafeListNodeIDs is the not goroutine-safe version of ListNodeIDs and no parameter validation, that does the real work
// Note: must be used wisely
func (instance *Cluster) trxListNodeIDs(inctx context.Context, clusterTrx clusterTransaction) (_ data.IndexedListOfStrings, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  data.IndexedListOfStrings
		rErr fail.Error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			emptyList := data.IndexedListOfStrings{}

			xerr := instance.trxBeingRemoved(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{emptyList, xerr}, xerr
			}

			var outlist data.IndexedListOfStrings
			xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
				list := make(data.IndexedListOfStrings, len(nodesV3.PrivateNodes))
				for _, v := range nodesV3.PrivateNodes {
					if node, found := nodesV3.ByNumericalID[v]; found {
						list[node.NumericalID] = node.ID
					}
				}
				outlist = list
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{emptyList, xerr}, xerr
			}

			return result{outlist, nil}, nil
		}()
		chRes <- gres
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

// trxFindAvailableNode is the package restricted, not goroutine-safe, no parameter validation version of FindAvailableNode, that does the real work
// Note: must be used wisely
func (instance *Cluster) trxFindAvailableNode(inctx context.Context, clusterTrx clusterTransaction) (node *Host, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *Host
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			xerr = instance.trxBeingRemoved(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			list, xerr := instance.trxListNodes(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			node = nil
			found := false
			for _, v := range list {
				node, xerr = LoadHost(ctx, v.ID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return result{nil, xerr}, xerr
				}

				_, xerr = node.WaitSSHReady(ctx, timings.SSHConnectionTimeout())
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *retry.ErrTimeout:
						continue
					default:
						return result{nil, xerr}, xerr
					}
				}
				found = true
				break
			}
			if !found {
				ar := result{nil, fail.NotAvailableError("failed to find available node")}
				return ar, ar.rErr
			}

			return result{node, nil}, nil
		}()
		chRes <- gres
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
