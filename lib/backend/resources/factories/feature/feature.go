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

package feature

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// New searches for a spec file name 'name' and initializes a new Feature object
// with its content
func New(ctx context.Context, svc iaasapi.Service, name string) (resources.Feature, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	feat, xerr := operations.NewFeature(ctx, svc, name)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// feature not found, continue to try with embedded ones
		default:
			return nil, xerr
		}

		// Failed to find a spec file on filesystem, trying with embedded ones
		if feat, xerr = operations.NewEmbeddedFeature(ctx, svc, name); xerr != nil {
			return nil, xerr
		}
	}
	return feat, nil
}

// NewEmbedded searches for an embedded feature called 'name' and initializes a new Feature object
// with its content
func NewEmbedded(ctx context.Context, svc iaasapi.Service, name string) (resources.Feature, fail.Error) {
	return operations.NewEmbeddedFeature(ctx, svc, name)
}
