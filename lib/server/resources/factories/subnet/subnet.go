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

// Package subnet contains methods to load or create instance of resources.Subnet
package subnet

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// List returns a list of available subnets
func List(task concurrency.Task, svc iaas.Service, networkID string, all bool) ([]*abstract.Subnet, fail.Error) {
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if svc.IsNull() {
		return nil, fail.InvalidParameterError("svc", "cannot be null value of 'iaas.Service'")
	}

	if all {
		return svc.ListSubnets(networkID)
	}

	rs, xerr := New(svc)
	if xerr != nil {
		return nil, xerr
	}

	// recover subnets from metadata
	var list []*abstract.Subnet
	xerr = rs.Browse(task, func(as *abstract.Subnet) fail.Error {
		if networkID == "" || as.Network == networkID {
			list = append(list, as)
		}
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	return list, nil
}

// New creates an instance of resources.Subnet
func New(svc iaas.Service) (resources.Subnet, fail.Error) {
	if svc.IsNull() {
		return nil, fail.InvalidParameterError("svc", "cannot be null value of 'iaas.Service'")
	}

	return operations.NewSubnet(svc)
}

// Load loads the metadata of a subnet and returns an instance of resources.Subnet
func Load(task concurrency.Task, svc iaas.Service, networkRef, subnetRef string) (resources.Subnet, fail.Error) {
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if svc.IsNull() {
		return nil, fail.InvalidParameterError("svc", "cannot be null value of 'iaas.Service'")
	}
	if subnetRef == "" {
		return nil, fail.InvalidParameterError("subnetRef", "cannot be empty string")
	}

	return operations.LoadSubnet(task, svc, networkRef, subnetRef)
}
