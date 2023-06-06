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

package bucket

import (
	"context"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// New creates a bucket instance
func New(svc iaas.Service, terraform bool) (resources.Bucket, fail.Error) { // nolint
	if terraform {
		return operations.NewTerraformBucket(svc)
	}
	return operations.NewBucket(svc)
}

// Load initializes the bucket with metadata from provider
func Load(ctx context.Context, svc iaas.Service, name string, terraform bool) (resources.Bucket, fail.Error) { // nolint
	if terraform {
		return operations.LoadTerraformBucket(ctx, svc, name)
	}
	return operations.LoadBucket(ctx, svc, name)
}

func List(ctx context.Context, svc iaas.Service, terraform bool) ([]resources.Bucket, fail.Error) { // nolint
	if terraform {
		var answer []resources.Bucket
		thelist, xerr := operations.ListTerraformBuckets(ctx, svc)
		if xerr != nil {
			return nil, xerr
		}
		for _, v := range thelist {
			answer = append(answer, v)
		}
		return answer, nil
	}

	lib, xerr := svc.ListBuckets(ctx, objectstorage.RootPath)
	if xerr != nil {
		return nil, xerr
	}

	var answer []resources.Bucket
	for _, v := range lib {
		bucket, xerr := Load(ctx, svc, v, terraform)
		if xerr != nil {
			logrus.WithContext(ctx).Debugf("failed to load bucket %s: %s", v, xerr.Error())
			continue
		}
		answer = append(answer, bucket)
	}
	return answer, nil
}
