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
	"context"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// List returns a list of available hosts
func List(ctx context.Context, svc iaas.Service) (list []abstract.ClusterIdentity, xerr fail.Error) {
	var emptyList []abstract.ClusterIdentity

	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if svc == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("svc")
	}

	instance, xerr := New(svc)
	if xerr != nil {
		return nil, xerr
	}

	list = []abstract.ClusterIdentity{}
	xerr = instance.Browse(ctx, func(hc *abstract.ClusterIdentity) fail.Error {
		list = append(list, *hc)
		return nil
	})
	return list, xerr
}

// New creates a new instance of resources.Cluster
func New(svc iaas.Service) (_ resources.Cluster, xerr fail.Error) {
	return operations.NewCluster(svc)
}

// Load loads metadata of a cluster and returns an instance of resources.Cluster
func Load(svc iaas.Service, name string) (_ resources.Cluster, xerr fail.Error) {
	return operations.LoadCluster(svc, name)
}
