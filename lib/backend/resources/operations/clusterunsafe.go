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

package operations

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	"strings"
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// unsafeGetIdentity returns the identity of the ClassicCluster
func (instance *ClassicCluster) unsafeGetIdentity(inctx context.Context) (_ abstract.ClusterIdentity, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	return *instance.cluID, nil
}

// unsafeGetFlavor returns the flavor of the ClassicCluster
func (instance *ClassicCluster) unsafeGetFlavor(ctx context.Context) (flavor clusterflavor.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	return instance.cluID.Flavor, nil
}

// unsafeGetComplexity returns the complexity of the ClassicCluster
func (instance *ClassicCluster) unsafeGetComplexity(ctx context.Context) (_ clustercomplexity.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	return instance.cluID.Complexity, nil
}

// unsafeGetState returns the current state of the ClassicCluster
// Uses the "maker" ForceGetState
func (instance *ClassicCluster) unsafeGetState(inctx context.Context) (_ clusterstate.Enum, _ fail.Error) {
	return instance.state, nil
}

// unsafeListMasters is the not goroutine-safe equivalent of ListMasters, that does the real work
func (instance *ClassicCluster) unsafeListMasters(inctx context.Context) (_ resources.IndexedListOfClusterNodes, _ fail.Error) {
	defer elapsed(inctx, "unsafeListMasters")()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.IndexedListOfClusterNodes
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			licn := make(resources.IndexedListOfClusterNodes)

			linodes, xerr := instance.trueListMasters(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{licn, xerr}, xerr
			}

			for ind, v := range linodes {
				licn[uint(ind)] = &propertiesv3.ClusterNode{
					ID:          v.Core.ID,
					NumericalID: uint(ind),
					Name:        v.Core.Name,
					PublicIP:    v.Networking.PublicIPv4,
				}
			}

			return result{licn, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}

}

// unsafeListMasterIDs is the not goroutine-safe version of ListNodeIDs and no parameter validation, that does the real work
func (instance *ClassicCluster) unsafeListMasterIDs(inctx context.Context) (_ data.IndexedListOfStrings, _ fail.Error) {
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
			res := make(data.IndexedListOfStrings)

			mass := instance.masters

			for ind, v := range mass {
				res[uint(ind)] = v
			}

			return result{res, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// unsafeListMasterIPs lists the IPs of masters (if there is such masters in the flavor...)
func (instance *ClassicCluster) unsafeListMasterIPs(inctx context.Context) (_ data.IndexedListOfStrings, _ fail.Error) {
	return instance.newunsafeListMasterIPs(inctx)
}

// unsafeListMasterIPs lists the IPs of masters (if there is such masters in the flavor...)
func (instance *ClassicCluster) newunsafeListMasterIPs(inctx context.Context) (_ data.IndexedListOfStrings, _ fail.Error) {
	defer elapsed(inctx, "newunsafeListMasterIPs")()
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

			thing := make(data.IndexedListOfStrings)

			newMasters, xerr := instance.unsafeListMasters(ctx)
			if xerr != nil {
				return result{thing, xerr}, xerr
			}

			instance.masters = []string{}
			for _, nm := range newMasters {
				instance.masters = append(instance.masters, nm.ID)
			}

			inflex := make(chan string, 2*len(instance.masters))

			var wg sync.WaitGroup
			wg.Add(len(instance.masters))
			for _, m := range instance.masters {
				m := m
				go func() {
					defer wg.Done()
					ah, xerr := LoadHost(ctx, instance.Service(), m)
					if xerr != nil {
						return
					}
					does, xerr := ah.Exists(ctx)
					if xerr != nil {
						return
					}
					if !does {
						return
					}
					theIP, xerr := ah.GetPrivateIP(ctx)
					if xerr != nil {
						return
					}

					inflex <- theIP
				}()
			}
			wg.Wait()
			close(inflex)
			ind := 0
			for v := range inflex {
				thing[uint(ind)] = v
				ind++
			}

			return result{thing, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}

}

// unsafeListNodeIPs lists the IPs of the nodes in the ClassicCluster
func (instance *ClassicCluster) newunsafeListNodeIPs(inctx context.Context) (_ data.IndexedListOfStrings, _ fail.Error) {
	defer elapsed(inctx, "newunsafeListNodeIPs")()
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
			thing := make(data.IndexedListOfStrings)

			newNodes, xerr := instance.unsafeListNodes(ctx)
			if xerr != nil {
				return result{thing, xerr}, xerr
			}

			if len(instance.nodes) == 0 {
				newm, xerr := instance.trueListNodes(ctx)
				if xerr != nil {
					return result{nil, xerr}, xerr
				}
				for _, v := range newm {
					instance.nodes = append(instance.nodes, v.Core.ID)
				}
			}

			for _, nm := range newNodes {
				instance.nodes = append(instance.nodes, nm.ID)
			}

			inflex := make(chan string, 2*len(instance.nodes))

			var wg sync.WaitGroup
			wg.Add(len(instance.nodes))
			for _, m := range instance.nodes {
				m := m
				go func() {
					defer wg.Done()
					ah, xerr := LoadHost(ctx, instance.Service(), m)
					if xerr != nil {
						return
					}
					does, xerr := ah.Exists(ctx)
					if xerr != nil {
						return
					}
					if !does {
						return
					}
					theIP, xerr := ah.GetPrivateIP(ctx)
					if xerr != nil {
						return
					}
					inflex <- theIP
				}()
			}
			wg.Wait()
			close(inflex)
			ind := 0
			for v := range inflex {
				thing[uint(ind)] = v
				ind++
			}

			return result{thing, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}

}

// unsafeFindAvailableMaster is the not go-routine-safe version of FindAvailableMaster, that does the real work
// Must be used with wisdom
func (instance *ClassicCluster) unsafeFindAvailableMaster(inctx context.Context) (_ resources.Host, _ fail.Error) {
	defer elapsed(inctx, "unsafeFindAvailableMaster")()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.Host
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			masters := instance.masters
			if len(masters) == 0 {
				newm, xerr := instance.trueListMasters(ctx)
				if xerr != nil {
					return result{nil, xerr}, xerr
				}
				for _, v := range newm {
					masters = append(masters, v.Core.ID)
				}
			}

			for _, v := range masters {
				if v == "" {
					continue
				}

				master, xerr := LoadHost(ctx, instance.Service(), v)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					continue
				}

				return result{master, nil}, nil
			}

			return result{nil, fail.NewError("no masters found")}, fail.NewError("no masters found")
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}

}

func (instance *ClassicCluster) trueListNodes(inctx context.Context) (_ []*abstract.HostFull, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  []*abstract.HostFull
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			svc := instance.Service()

			var answer []*abstract.HostFull

			cluID, xerr := instance.GetID()
			if xerr != nil {
				return result{}, fail.ConvertError(xerr)
			}

			tagged, err := svc.ListHostsWithTags(ctx, nil, map[string]string{
				"type":      "node",
				"clusterID": cluID,
			})
			if err != nil {
				return result{}, err
			}

			legacy, err := svc.ListHosts(ctx, true)
			if err != nil {
				return result{}, err
			}

			added := make(map[string]bool)
			for _, v := range legacy {
				if strings.HasPrefix(v.Core.Name, fmt.Sprintf("%s-node-", instance.GetName())) {
					added[v.Core.ID] = true
					answer = append(answer, v)
				}
			}

			for _, v := range tagged {
				if !added[v.Core.ID] {
					answer = append(answer, v)
					added[v.Core.ID] = true
				}
			}

			for _, v := range instance.nodes {
				if !added[v] {
					logrus.WithContext(inctx).Warnf("node %s in cluster %s is in metadata but does not exist", v, instance.GetName())
				}
			}

			return result{answer, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

func (instance *ClassicCluster) trueListMasters(inctx context.Context) (_ []*abstract.HostFull, _ fail.Error) {
	defer elapsed(inctx, "trueListMasters")()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  []*abstract.HostFull
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			svc := instance.Service()

			cluID, xerr := instance.GetID()
			if xerr != nil {
				return result{}, fail.ConvertError(xerr)
			}

			var answer []*abstract.HostFull

			tagged, err := svc.ListHostsWithTags(ctx, nil, map[string]string{
				"type":      "master",
				"clusterID": cluID,
			})
			if err != nil {
				return result{}, err
			}

			legacy, err := svc.ListHosts(ctx, true)
			if err != nil {
				return result{}, err
			}

			added := make(map[string]bool)
			for _, v := range legacy {
				if strings.HasPrefix(v.Core.Name, fmt.Sprintf("%s-master-", instance.GetName())) {
					added[v.Core.ID] = true
					answer = append(answer, v)
				}
			}

			for _, v := range tagged {
				if !added[v.Core.ID] {
					answer = append(answer, v)
					added[v.Core.ID] = true
				}
			}

			for _, v := range instance.masters {
				if !added[v] {
					logrus.WithContext(inctx).Warnf("master %s in cluster %s is in metadata but does not exist", v, instance.GetName())
				}
			}

			return result{answer, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

func (instance *ClassicCluster) trueListGateways(inctx context.Context) (_ []*abstract.HostFull, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  []*abstract.HostFull
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			svc := instance.Service()

			cluID, xerr := instance.GetID()
			if xerr != nil {
				return result{}, fail.ConvertError(xerr)
			}

			var answer []*abstract.HostFull

			tagged, err := svc.ListHostsWithTags(ctx, nil, map[string]string{
				"type":      "gateway",
				"clusterID": cluID,
			})
			if err != nil {
				return result{}, err
			}

			legacy, err := svc.ListHosts(ctx, true)
			if err != nil {
				return result{}, err
			}

			added := make(map[string]bool)
			for _, v := range legacy {
				if strings.HasPrefix(v.Core.Name, fmt.Sprintf("gw-%s", instance.GetName())) {
					added[v.Core.ID] = true
					answer = append(answer, v)
				}
				if strings.HasPrefix(v.Core.Name, fmt.Sprintf("gw2-%s", instance.GetName())) {
					added[v.Core.ID] = true
					answer = append(answer, v)
				}
			}

			for _, v := range tagged {
				if !added[v.Core.ID] {
					answer = append(answer, v)
					added[v.Core.ID] = true
				}
			}

			return result{answer, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// unsafeListNodes is the not goroutine-safe version of ListNodes and no parameter validation, that does the real work
func (instance *ClassicCluster) unsafeListNodes(inctx context.Context) (_ resources.IndexedListOfClusterNodes, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.IndexedListOfClusterNodes
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			licn := make(resources.IndexedListOfClusterNodes)

			linodes, xerr := instance.trueListNodes(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{licn, xerr}, xerr
			}

			for ind, v := range linodes {
				licn[uint(ind)] = &propertiesv3.ClusterNode{
					ID:          v.Core.ID,
					NumericalID: uint(ind),
					Name:        v.Core.Name,
					PublicIP:    v.Networking.PublicIPv4,
				}
			}

			return result{licn, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// unsafeListNodeIDs is the not goroutine-safe version of ListNodeIDs and no parameter validation, that does the real work
func (instance *ClassicCluster) unsafeListNodeIDs(inctx context.Context) (_ data.IndexedListOfStrings, _ fail.Error) {
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
			nodeMap := make(data.IndexedListOfStrings)

			theList, xerr := instance.trueListNodes(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nodeMap, xerr}, xerr
			}

			for ind, tn := range theList {
				nodeMap[uint(ind)] = tn.Core.ID
			}

			return result{nodeMap, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// unsafeFindAvailableNode is the package restricted, not goroutine-safe, no parameter validation version of FindAvailableNode, that does the real work
func (instance *ClassicCluster) unsafeFindAvailableNode(inctx context.Context) (node resources.Host, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.Host
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			xerr := instance.beingRemoved(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			list := instance.nodes
			if len(list) == 0 {
				newm, xerr := instance.trueListNodes(ctx)
				if xerr != nil {
					return result{nil, xerr}, xerr
				}
				for _, v := range newm {
					list = append(list, v.Core.ID)
				}
			}

			svc := instance.Service()

			for _, v := range list {
				node, xerr := LoadHost(ctx, svc, v)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					continue
				}

				return result{node, nil}, nil
			}

			ar := result{nil, fail.NotAvailableError("failed to find available node")}
			return ar, ar.rErr
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}
