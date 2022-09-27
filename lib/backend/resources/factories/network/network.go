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

// Package network contains functions to list, create, load instances of resources.Network
package network

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// List returns a slice of *abstract.Network corresponding to managed networks
func List(ctx context.Context, svc iaasapi.Service) ([]*abstract.Network, fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	rn, xerr := New(svc)
	if xerr != nil {
		return nil, xerr
	}

	var list []*abstract.Network

	withDefaultNetwork, err := svc.HasDefaultNetwork()
	if err != nil {
		return nil, err
	}

	// Default network has no metadata, so we need to "simulate" them.
	if withDefaultNetwork {
		var an *abstract.Network
		an, xerr = svc.DefaultNetwork(ctx)
		if xerr != nil {
			return nil, xerr
		}
		list = append(list, an)
	}

	// Recovers the list with metadata and add them to the list
	xerr = rn.Browse(ctx, func(an *abstract.Network) fail.Error {
		list = append(list, an)
		return nil
	})

	if xerr != nil {
		return nil, xerr
	}

	return list, nil
}

// New creates an instance of resources.Network
func New(svc iaasapi.Service) (resources.Network, fail.Error) {
	return operations.NewNetwork(svc)
}

// Load loads the metadata of a network and returns an instance of resources.Network
func Load(ctx context.Context, svc iaasapi.Service, ref string) (resources.Network, fail.Error) {
	return operations.LoadNetwork(ctx, svc, ref)
}
