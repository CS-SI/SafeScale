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
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"strconv"
	"strings"
)

// List returns a list of available clusters found in the bucket metadata
func List(ctx context.Context, svc iaas.Service, terraform bool) (_ []abstract.ClusterIdentity, ferr fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	list := []abstract.ClusterIdentity{}

	if !terraform { // classic mode
		instance, xerr := New(ctx, svc, false)
		if xerr != nil {
			return nil, xerr
		}

		xerr = instance.Browse(ctx, func(hc *abstract.ClusterIdentity) fail.Error {
			list = append(list, *hc)
			return nil
		})
		return list, xerr
	}

	clul, err := operations.ListTerraformClusters(ctx, svc)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	// FIXME: complete information
	for _, v := range clul {
		cfla := 4
		if val, ok := v.Tags["Flavor"]; ok {
			cfla, _ = strconv.Atoi(val)
		}

		ccom := 1
		if val, ok := v.Tags["Complexity"]; ok {
			ccom, _ = strconv.Atoi(val)
		}

		mk := abstract.ClusterIdentity{
			Name:          strings.Split(v.Name, "-")[1],
			Flavor:        clusterflavor.Enum(cfla),
			Complexity:    clustercomplexity.Enum(ccom),
			Keypair:       nil,
			AdminPassword: "",
			Tags:          v.Tags,
			ID:            v.Identity,
		}
		list = append(list, mk)
	}

	return list, nil
}

// New creates a new instance of resources.Cluster
func New(ctx context.Context, svc iaas.Service, terraform bool) (_ resources.Cluster, ferr fail.Error) {
	if terraform {
		return operations.NewTfCluster(ctx, svc)
	}
	return operations.NewCluster(ctx, svc)
}

// Load loads metadata of a cluster and returns an instance of resources.Cluster
func Load(ctx context.Context, svc iaas.Service, name string, terraform bool) (_ resources.Cluster, ferr fail.Error) {
	if terraform {
		return operations.LoadTerraformCluster(ctx, svc, name)
	}
	return operations.LoadCluster(ctx, svc, name)
}
