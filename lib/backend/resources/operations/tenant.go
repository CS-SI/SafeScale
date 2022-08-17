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

package operations

import (
	"context"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Tenant structure to handle name and Service for a tenant
type Tenant struct {
	Name       string
	BucketName string
	Service    iaas.Service
}

// currentTenant contains the current tenant
var currentTenant atomic.Value

// CurrentTenant returns the tenant used for commands or, if not set, set the tenant to use if it is the only one registered
func CurrentTenant(ctx context.Context) *Tenant {
	anon := currentTenant.Load()
	if anon == nil {
		tenants, err := iaas.GetTenants()
		if err != nil || len(tenants) != 1 {
			return nil
		}

		// Set unique tenant as selected
		logrus.Infoln("No tenant set yet, but found only one tenant in configuration; setting it as current.")
		for _, tenant := range tenants {
			name, ok := tenant["name"].(string)
			if !ok {
				logrus.WithContext(ctx).Warnf("tenant names should be strings: %v is not", tenant["name"])
				continue
			}

			service, xerr := loadTenant(ctx, name)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				debug.IgnoreError(xerr)
				return nil
			}

			bucket, xerr := service.GetMetadataBucket(ctx)
			if xerr != nil {
				debug.IgnoreError(xerr)
				return nil
			}

			currentTenant.Store(&Tenant{Name: name, BucketName: bucket.GetName(), Service: service})
			break // nolint
		}
		anon = currentTenant.Load()
	}
	return anon.(*Tenant)
}

// SetCurrentTenant sets the tenant to use for upcoming commands
func SetCurrentTenant(ctx context.Context, tenantName string) error {
	tenant := CurrentTenant(ctx)
	if tenant != nil && tenant.Name == tenantName {
		return nil
	}

	service, xerr := loadTenant(ctx, tenantName)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	bucket, xerr := service.GetMetadataBucket(ctx)
	if xerr != nil {
		return xerr
	}

	tenant = &Tenant{Name: tenantName, BucketName: bucket.GetName(), Service: service}
	currentTenant.Store(tenant)
	return nil
}

func loadTenant(ctx context.Context, tenantName string) (iaas.Service, fail.Error) {
	service, xerr := iaas.UseService(tenantName, MinimumMetadataVersion)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	_, xerr = CheckMetadataVersion(ctx, service)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to set tenant '%s'", tenantName)
	}

	return service, nil
}
