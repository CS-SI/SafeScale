/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// List returns a slice of *abstract.Network corresponding to managed networks
func List(task concurrency.Task, svc iaas.Service) ([]*abstract.Network, fail.Error) {
	rn, xerr := New(svc)
	if xerr != nil {
		return nil, xerr
	}

	var list []*abstract.Network

	// Default network has no metadata, so we need to "simulate" them.
	if svc.HasDefaultNetwork() {
		an, xerr := svc.GetDefaultNetwork()
		if xerr != nil {
			return nil, xerr
		}
		list = append(list, an)
	}

	// Recovers the list with metadata and add them to the list
	xerr = rn.Browse(task, func(an *abstract.Network) fail.Error {
		list = append(list, an)
		return nil
	})
	return list, nil
}

// New creates an instance of resources.Network
func New(svc iaas.Service) (resources.Network, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	return operations.NewNetwork(svc)
}

// Load loads the metadata of a network and returns an instance of resources.Network
func Load(task concurrency.Task, svc iaas.Service, ref string) (resources.Network, fail.Error) {
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	return operations.LoadNetwork(task, svc, ref)
}
