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

package volume

import (
	"context"

	"github.com/CS-SI/SafeScale/v21/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

// New creates an instance of resources.Volume
func New(svc iaas.Service) (resources.Volume, fail.Error) {
	return operations.NewVolume(svc)
}

// Load loads the metadata of a volume and returns an instance of resources.Volume
func Load(ctx context.Context, svc iaas.Service, ref string) (resources.Volume, fail.Error) {
	return operations.LoadVolume(ctx, svc, ref, operations.WithReloadOption)
}
