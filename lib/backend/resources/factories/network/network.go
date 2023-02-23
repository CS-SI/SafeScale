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

// Package network contains functions to list, create, load instances of *Network
package network

import (
	"context"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// List returns a slice of *abstract.Network corresponding to managed networks
func List(ctx context.Context) ([]*abstract.Network, fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return nil, xerr
	}

	svc, xerr := myjob.Service()
	if xerr != nil {
		return nil, xerr
	}

	networkInstance, xerr := New(ctx)
	if xerr != nil {
		return nil, xerr
	}

	withDefaultNetwork, xerr := svc.HasDefaultNetwork()
	if xerr != nil {
		return nil, xerr
	}

	// Default network has no metadata, so we need to "simulate" them.
	var list []*abstract.Network
	if withDefaultNetwork {
		var an *abstract.Network
		an, xerr = svc.DefaultNetwork(ctx)
		if xerr != nil {
			return nil, xerr
		}

		list = append(list, an)
	}

	// Recovers the list with metadata and add them to the list
	xerr = networkInstance.Browse(ctx, func(an *abstract.Network) fail.Error {
		list = append(list, an)
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	return list, nil
}

// New creates an instance of *Network
func New(ctx context.Context) (*resources.Network, fail.Error) {
	return resources.NewNetwork(ctx)
}

// Load loads the metadata of a network and returns an instance of *Network
func Load(ctx context.Context, ref string) (*resources.Network, fail.Error) {
	return resources.LoadNetwork(ctx, ref)
}
