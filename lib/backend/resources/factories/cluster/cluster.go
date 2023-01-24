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

package cluster

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// List returns a list of available hosts
func List(ctx context.Context) (list []abstract.Cluster, ferr fail.Error) {
	var emptyList []abstract.Cluster

	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	instance, xerr := New(ctx)
	if xerr != nil {
		return nil, xerr
	}

	list = []abstract.Cluster{}
	xerr = instance.Browse(ctx, func(hc *abstract.Cluster) fail.Error {
		list = append(list, *hc)
		return nil
	})
	return list, xerr
}

// New creates a new instance of *Cluster
func New(ctx context.Context) (_ *resources.Cluster, ferr fail.Error) {
	return resources.NewCluster(ctx)
}

// Load loads metadata of a cluster and returns an instance of *Cluster
func Load(ctx context.Context, name string) (_ *resources.Cluster, ferr fail.Error) {
	return resources.LoadCluster(ctx, name)
}
