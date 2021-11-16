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
	"context"
	"reflect"
	"time"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterstate"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv3 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v3"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// unsafeGetIdentity returns the identity of the Cluster
func (instance *Cluster) unsafeGetIdentity() (clusterIdentity abstract.ClusterIdentity, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		aci, ok := clonable.(*abstract.ClusterIdentity)
		if !ok {
			return fail.InconsistentError("'*abstract.ClusterIdentity' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		clusterIdentity = *aci
		return nil
	})
	return clusterIdentity, xerr
}

// UnsafeGetFlavor returns the flavor of the Cluster
func (instance *Cluster) UnsafeGetFlavor() (flavor clusterflavor.Enum, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	aci, xerr := instance.unsafeGetIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return aci.Flavor, nil
}

// unsafeGetComplexity returns the complexity of the Cluster
func (instance *Cluster) unsafeGetComplexity() (_ clustercomplexity.Enum, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	aci, xerr := instance.unsafeGetIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return aci.Complexity, nil
}

// unsafeGetState returns the current state of the Cluster
// Uses the "maker" ForceGetState
func (instance *Cluster) unsafeGetState() (state clusterstate.Enum, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	state = clusterstate.Unknown
	if instance.makers.GetState != nil {
		state, xerr = instance.makers.GetState(instance)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return clusterstate.Unknown, xerr
		}

		return state, instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
				stateV1, ok := clonable.(*propertiesv1.ClusterState)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				stateV1.State = state
				instance.lastStateCollection = time.Now()
				return nil
			})
		})
	}

	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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

// UnsafeListMasters is the not goroutine-safe equivalent of ListMasters, that does the real work
// Note: must be used with wisdom
func (instance *Cluster) UnsafeListMasters() (list resources.IndexedListOfClusterNodes, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := resources.IndexedListOfClusterNodes{}

	xerr = instance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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

// UnsafeListMasterIDs is the not goroutine-safe version of ListNodeIDs and no parameter validation, that does the real work
// Note: must be used wisely
func (instance *Cluster) UnsafeListMasterIDs(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	emptyList := data.IndexedListOfStrings{}

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return emptyList, xerr
			}
		default:
			return emptyList, xerr
		}
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
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

// UnsafeListMasterIPs lists the IPs of masters (if there is such masters in the flavor...)
func (instance *Cluster) UnsafeListMasterIPs() (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
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
func (instance *Cluster) unsafeListNodeIPs() (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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

// UnsafeFindAvailableMaster is the not go-routine-safe version of FindAvailableMaster, that does the real work
// Must be used with wisdom
func (instance *Cluster) UnsafeFindAvailableMaster(ctx context.Context) (master resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	master = nil
	masters, xerr := instance.UnsafeListMasters()
	xerr = debug.InjectPlannedFail(xerr)
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

		master, xerr = LoadHost(instance.GetService(), v.ID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		_, xerr = master.WaitSSHReady(ctx, temporal.GetConnectSSHTimeout())
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
func (instance *Cluster) unsafeListNodes() (list resources.IndexedListOfClusterNodes, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := resources.IndexedListOfClusterNodes{}
	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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

// UnsafeListNodeIDs is the not goroutine-safe version of ListNodeIDs and no parameter validation, that does the real work
// Note: must be used wisely
func (instance *Cluster) UnsafeListNodeIDs(ctx context.Context) (list data.IndexedListOfStrings, xerr fail.Error) {
	emptyList := data.IndexedListOfStrings{}

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptyList, xerr
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return emptyList, xerr
			}
		default:
			return emptyList, xerr
		}
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
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

// UnsafeFindAvailableNode is the package restricted, not goroutine-safe, no parameter validation version of FindAvailableNode, that does the real work
// Note: must be used wisely
func (instance *Cluster) UnsafeFindAvailableNode(ctx context.Context) (node resources.Host, xerr fail.Error) {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return nil, xerr
			}
		default:
			return nil, xerr
		}
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	xerr = instance.beingRemoved()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	list, xerr := instance.unsafeListNodes()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	svc := instance.GetService()
	node = nil
	found := false
	for _, v := range list {
		if task.Aborted() {
			return nil, fail.AbortedError(nil, "aborted")
		}

		node, xerr = LoadHost(svc, v.ID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		//goland:noinspection ALL
		defer func(hostInstance resources.Host) {
			hostInstance.Released()
		}(node)

		_, xerr = node.WaitSSHReady(ctx, temporal.GetConnectSSHTimeout())
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
