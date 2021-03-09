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
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// unsafeGetIdentity returns the identity of the cluster
func (instance *cluster) unsafeGetIdentity() (clusterIdentity abstract.ClusterIdentity, xerr fail.Error) {
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

// unsafeGetFlavor returns the flavor of the cluster
func (instance *cluster) unsafeGetFlavor() (flavor clusterflavor.Enum, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	aci, xerr := instance.unsafeGetIdentity()
	if xerr != nil {
		return 0, xerr
	}

	return aci.Flavor, nil
}

// unsafeGetComplexity returns the complexity of the cluster
func (instance *cluster) unsafeGetComplexity() (_ clustercomplexity.Enum, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	aci, xerr := instance.unsafeGetIdentity()
	if xerr != nil {
		return 0, xerr
	}

	return aci.Complexity, nil
}

// unsafeGetState returns the current state of the Cluster
// Uses the "maker" ForceGetState
func (instance *cluster) unsafeGetState() (state clusterstate.Enum, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	state = clusterstate.Unknown
	if instance.makers.GetState != nil {
		state, xerr = instance.makers.GetState(instance)
		if xerr != nil {
			return clusterstate.Unknown, xerr
		}

		return state, instance.Alter(/*task,  */func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(/*task, */clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
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
	if xerr != nil {
		return clusterstate.Unknown, xerr
	}
	return state, nil
}

// unsafeListMasters is the not goroutine-safe equivalent of ListMasters, that does the real work
// Note: must be used with wisdom
func (instance *cluster) unsafeListMasters() (list resources.IndexedListOfClusterNodes, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := resources.IndexedListOfClusterNodes{}



	xerr = instance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(/*task, */clusterproperty.NodesV3, func(clonable data.Clonable) (innerXErr fail.Error) {
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
	if xerr != nil {
		return emptyList, xerr
	}

	return list, nil
}

// unsafeListMasterIPs lists the IPs of masters (if there is such masters in the flavor...)
func (instance *cluster) unsafeListMasterIPs(task concurrency.Task) (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	if xerr = instance.beingRemoved(task); xerr != nil {
		return emptyList, xerr
	}

	xerr = instance.Review(task, func(_ data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		return props.Inspect(/*task, */clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
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
					list[node.NumericalID] = node.PrivateIP
				}
			}
			return nil
		})
	})
	if xerr != nil {
		return emptyList, xerr
	}
	return list, nil
}

// unsafeListNodeIPs lists the IPs of the nodes in the cluster
func (instance *cluster) unsafeListNodeIPs() (list data.IndexedListOfStrings, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := data.IndexedListOfStrings{}
	xerr = instance.Review(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(/*task, */clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
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
					list[node.NumericalID] = node.PrivateIP
				}
			}
			return nil
		})
	})
	if xerr != nil {
		return emptyList, xerr
	}
	return list, nil
}

// unsafeFindAvailableMaster is the not go-routine-safe version of FindAvailableMaster, that does the real work
// Must be used with wisdom
func (instance *cluster) unsafeFindAvailableMaster(task concurrency.Task) (master resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	master = nil
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	masters, xerr := instance.unsafeListMasters(task)
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

		master, xerr := LoadHost(task, instance.GetService(), v.ID)
		if xerr != nil {
			return nil, xerr
		}

		if _, xerr = master.WaitSSHReady(task, temporal.GetConnectSSHTimeout()); xerr != nil {
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
// Note: must be used with wisdom
func (instance *cluster) unsafeListNodes(task concurrency.Task) (list resources.IndexedListOfClusterNodes, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	emptyList := resources.IndexedListOfClusterNodes{}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	xerr = instance.Review(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(/*task, */clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			list = make(resources.IndexedListOfClusterNodes, len(nodesV3.PrivateNodes))
			for _, v := range nodesV3.PrivateNodes {
				if node, found := nodesV3.ByNumericalID[v]; found {
					if task.Aborted() {
						return fail.AbortedError(nil, "aborted")
					}

					list[node.NumericalID] = node
				}
			}
			return nil
		})
	})
	if xerr != nil {
		return emptyList, xerr
	}

	return list, nil
}
