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

package cluster

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// List returns a list of available hosts
func List(/* ctx context.Context, */svc iaas.Service) (list []abstract.ClusterIdentity, xerr fail.Error) {
	var nullList []abstract.ClusterIdentity

	if task == nil {
		return nullList, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}
	if svc == nil {
		return nullList, fail.InvalidParameterCannotBeNilError("svc")
	}

	objc, xerr := New(task, svc)
	if xerr != nil {
		return nil, xerr
	}
	list = []abstract.ClusterIdentity{}
	xerr = objc.Browse(task, func(hc *abstract.ClusterIdentity) fail.Error {
		list = append(list, *hc)
		return nil
	})
	return list, xerr
}

// New creates a new instance of resources.Cluster
func New(/* ctx context.Context, */svc iaas.Service) (_ resources.Cluster, xerr fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	if task != nil {
		if task.Aborted() {
			return nil, fail.AbortedError(nil, "aborted")
		}
	}

	return operations.NewCluster(task, svc)
}

// Load loads metadata of a cluster and returns an instance of resources.Cluster
func Load(/* ctx context.Context, */svc iaas.Service, name string) (_ resources.Cluster, xerr fail.Error) {
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	return operations.LoadCluster(task, svc, name)
}
