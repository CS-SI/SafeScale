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

package volume

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// New creates an instance of resources.Volume
func New(svc iaas.Service, terraform bool) (resources.Volume, fail.Error) {
	if terraform {
		tv, err := operations.NewTerraformVolume(svc)
		if err != nil {
			return nil, err
		}

		return tv, nil
	}
	return operations.NewVolume(svc)
}

// Load loads the metadata of a volume and returns an instance of resources.Volume
func Load(ctx context.Context, svc iaas.Service, ref string, terraform bool) (resources.Volume, fail.Error) {
	if terraform {
		return operations.LoadTerraformVolume(ctx, svc, ref)
	}
	return operations.LoadVolume(ctx, svc, ref)
}
