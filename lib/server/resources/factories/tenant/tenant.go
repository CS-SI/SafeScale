/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package factory

import (
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
)

// Tenant structure to handle name and Service for a tenant
type Tenant struct {
	Name    string
	Service iaas.Service
}

// currentTenant contains the current tenant
var currentTenant atomic.Value

// GetCurrentTenant returns the tenant used for commands or, if not set, set the tenant to use if it is the only one registerd
func GetCurrentTenant() *Tenant {
	anon := currentTenant.Load()
	if anon == nil {
		tenants, err := iaas.GetTenants()
		if err != nil || len(tenants) != 1 {
			return nil
		}

		// Set unique tenant as selected
		logrus.Infoln("No tenant set yet, but found only one tenant in configuration; setting it as current.")
		for _, anon := range tenants {
			name := anon.(string)
			service, err := iaas.UseService(name)
			if err != nil {
				return nil
			}
			currentTenant.Store(&Tenant{Name: name, Service: service})
			break
		}
		anon = currentTenant.Load()
	}
	return anon.(*Tenant)
}

// SetCurrentTenant sets  the tenant to use for upcoming commands
func SetCurrentTenant(tenantName string) error {
	tenant := GetCurrentTenant()
	if tenant != nil && tenant.Name == tenantName {
		return nil
	}

	service, err := iaas.UseService(tenantName)
	if err != nil {
		return err
	}
	tenant = &Tenant{Name: tenantName, Service: service}
	currentTenant.Store(tenant)
	return nil
}
