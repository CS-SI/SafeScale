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

// Package subnet contains methods to load or create instance of resources.Subnet
package subnet

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// List returns a list of available subnets
func List(ctx context.Context, svc iaas.Service, networkID string, all bool, terraform bool) ([]*abstract.Subnet, fail.Error) {
	if !terraform {
		return operations.ListSubnets(ctx, svc, networkID, all)
	}

	var neptune []*abstract.Subnet
	raw, err := operations.ListTerraformSubnets(ctx, svc, networkID, "", terraform)
	if err != nil {
		return nil, err
	}

	for _, val := range raw { // FIXME: Another mapping problem
		ns := abstract.NewSubnet()
		ns.ID = val.Identity
		ns.Name = val.Name
		neptune = append(neptune, ns)
	}

	return neptune, nil
}

// New creates an instance of resources.Subnet
func New(svc iaas.Service, terraform bool) (resources.Subnet, fail.Error) {
	if terraform {
		return operations.NewTerraformSubnet(svc)
	}
	return operations.NewSubnet(svc)
}

// Load loads the metadata of a subnet and returns an instance of resources.Subnet
func Load(ctx context.Context, svc iaas.Service, networkRef, subnetRef string, terraform bool) (resources.Subnet, fail.Error) {
	if terraform {
		return operations.LoadTerraformSubnet(ctx, svc, networkRef, subnetRef)
	}
	return operations.LoadSubnet(ctx, svc, networkRef, subnetRef)
}
