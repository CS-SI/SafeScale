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

package bucket

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// List retrieves all available buckets
func List(svc iaas.Service) ([]string, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	return svc.ListBuckets(objectstorage.RootPath)
}

// New creates a bucket instance
func New(svc iaas.Service) (resources.Bucket, fail.Error) { // nolint
	return operations.NewBucket(svc)
}

// Load initializes the bucket with metadata from provider
func Load(ctx context.Context, svc iaas.Service, name string) (resources.Bucket, fail.Error) { // nolint
	return operations.LoadBucket(ctx, svc, name)
}
