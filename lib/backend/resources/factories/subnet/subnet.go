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

// Package subnet contains methods to load or create instance of *Subnet
package subnet

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// List returns a list of available subnets
func List(ctx context.Context, networkID string, all bool) ([]*abstract.Subnet, fail.Error) {
	return resources.ListSubnets(ctx, networkID, all)
}

// New creates an instance of *Subnet
func New(ctx context.Context) (*resources.Subnet, fail.Error) {
	return resources.NewSubnet(ctx)
}

// Load loads the metadata of a subnet and returns an instance of *Subnet
func Load(ctx context.Context, networkRef, subnetRef string) (*resources.Subnet, fail.Error) {
	return resources.LoadSubnet(ctx, networkRef, subnetRef)
}
