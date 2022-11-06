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

package share

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/common/scope/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// New creates an instance of resources.Share
func New(scope scopeapi.Scope) (resources.Share, fail.Error) {
	return operations.NewShare(scope)
}

// Load loads the metadata of a share and returns an instance of resources.Share
func Load(ctx context.Context, scope scopeapi.Scope, ref string) (resources.Share, fail.Error) {
	return operations.LoadShare(ctx, scope, ref)
}
